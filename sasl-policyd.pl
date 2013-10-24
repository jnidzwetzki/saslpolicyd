#!/usr/bin/perl
#
# SASL Policy service for Postfix
#
# This service observes the postfix sasl 
# logins. If a misuse of a account is detected,
# no new mails from this account will be accepted.
#
# 
# ## Installation ##
#
# Add the following line to your main.cf
#
# smtpd_recipient_restrictions = permit_mynetworks, 
#           check_policy_service inet:127.0.0.1:25025, 
#           ....
# 
# 
# ## License ##
#
# Copyright 2013 Jan Kristof Nidzwetzki 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#####################################

use warnings;
use strict;

use threads;

use DBI;
use DBIx::Connector;

use POSIX qw(setsid);
use Sys::Syslog qw(:DEFAULT setlogsock);
use IO::Socket::UNIX;
use IO::Select;

our $NAME = "sasl-policyd";
our $VERSION = "0.1 alpha";
our $FOREGROUND = 0;
our $TCP_PORT = 25025;
our $DEBUG = 0;
our $VERBOSE = 1;

our $DATABASE = "/tmp/.sasl_db";

our $POSTFIX_SASL_LIMIT_MESSAGE = "action=510 Your account is blocked due "
    . "rate limits. Please contact your technical support.\n\n";

our $POSTFIX_OK = "action=dunno\n\n";

our $USER = "postfix";
our $GROUP = "postfix";

# IPs per time period
our $DIFFERNT_IPS = 10;

# Logins per time period
our $TOTAL_LOGINS = 100;

# Time period for calculation
our $TIME_PERIOD = 60 * 60; # 1h

# Database cleanup
our $CLEANUP_PERIOD = 2 * 24 * 60 * 60; # 2d

# Logging 
our $syslog_socktype = 'unix';
our $syslog_facility = "mail";
our $syslog_options  = "pid";
our $syslog_priority = "info";
our $syslog_ident    = "postfix/$NAME";

# Whitelist - for example: googlemail
our $IP_WHITELIST = qr/209\.85\.\d+\.\d+/;

# Configuration file
our $CONFIGURATION = "/etc/saslpolicyd.conf";

# Special user rate limit, read from configuration file
our %USER_RATE_LIMIT = ();

# Subs
sub log_debug($);
sub log_verbose($);
sub log_info($);
sub writelog($);
sub handle_connection($);
sub sqlite_table_exists($$);
sub create_tables($);
sub database_clanup($);
sub insert_login($$$);
sub get_ips_for_login($$$);
sub get_logins($$$);

# Open Databse
my $conn = DBIx::Connector -> new("dbi:SQLite:dbname=$DATABASE", "", "");

# Open Logfiles
setlogsock($syslog_socktype);
openlog($syslog_ident, $syslog_options, $syslog_facility);

# Read configuration
if(-f $CONFIGURATION) {
   log_info("Read configuration from $CONFIGURATION");

   open(CONF, "<$CONFIGURATION");
   my @configuration_data = <CONF>;
   close(CONF);

   for(@configuration_data) {
      
      # Special rate configuration
      if($_ =~ /userlimit:\s+(.*)\s+(\d+)/) {
          my $conf_user = $1;
          my $conf_rate = $2;

          log_debug("Set rate limit for user $conf_user to $conf_rate");

          $USER_RATE_LIMIT{ $conf_user } = $conf_rate;
      }
   }
}

log_info("$NAME started");

# Install signal handlers
$SIG{'TERM'} = sub {
   writelog("Got TERM signal, exiting");
   exit 0;
};

$SIG{'QUIT'} = sub {
   writelog("Got QUIT signal, exiting");
   exit 0;
};

$SIG{CHLD} = "IGNORE";

# daemonize
if(! $FOREGROUND) {
   
   defined(my $pid = fork()) or die "Can't fork: $!";
   
   # Parent process
   if($pid) {
       exit();
   }

   open(STDIN, "< /dev/null");
   open(STDERR, "> /dev/null");
   open(STDOUT, "> /dev/null");

   setsid();

   # Open pidfile
   open(PIF, ">/var/run/sasl-policyd.pid") or die $!;

   # Drop priviliges
   my $uid = getpwnam($USER)  or die "User $USER doesn't exist!";
   my $gid = getgrnam($GROUP) or die "Group $GROUP doesn't exist!";

   $> = $uid;
   $) = $gid;
   
   log_debug("New daemon process started");

   # Write pid
   print PIF $$;
   close(PIF);
}

# Init database
if(! sqlite_table_exists($conn, "LOGIN")) {
   log_info("Create new Database structure");
   create_tables($conn);
}

my $socket = IO::Socket::INET->new(    
              Proto  => 'tcp',
              LocalPort   => $TCP_PORT,
              Listen      => 10,
              Reuse       => 1);

$socket->autoflush(1);

# Accept connections, start a new thread for every connection
while(1) {
   my $client_socket = $socket -> accept();

   defined(my $pid = fork()) or die "Can't fork: $!";
   
   # Parent process
   if(! $pid) {
       handle_connection($client_socket);
       exit();
   }

}

###
# Handle connections
###
sub handle_connection($) {
   my $client_socket = shift;
   my $answer = $POSTFIX_OK;

   log_debug("Handle new connection");

   $SIG{ALRM} = sub { 
      log_info("Connection timed out"); 
      exit() 
   };

   # Timeout: 60 seconds to handle the connection
   alarm 60;

   # data
   my $ip = "";
   my $username = "";

   # Read and parse data
   CLIENT_DATA: while(my $client_data = <$client_socket>) {

       log_debug("Got $client_data");

       # All data read
       if($client_data !~ /=/) {
          last CLIENT_DATA;
       }

       if($client_data =~ m/.*sasl_username=(.*)/) {
          $username = $1;
       }

       if($client_data =~ m/.*client_address=(.*)/) {
          $ip = $1;
       }
   }

   # SASL Username and IP known?
   if($ip && $username) {

      # Insert login into database
      insert_login($conn, $username, $ip);

      # Check whitelist
      my $on_whitelist = 0;
      if($ip =~ $IP_WHITELIST) {
         $on_whitelist = 1;
      }

      if(! $on_whitelist) {
         my $ips = get_ips_for_login($conn, $username, $TIME_PERIOD);
   
         # Missuse detected, block login
         if($ips > $DIFFERNT_IPS) {
            log_info("Reject user $username from ip $ip - got logins from "
             . "$ips different IPs in the last time period");

            $answer = $POSTFIX_SASL_LIMIT_MESSAGE;
         }

         my $logins = get_logins($conn, $username, $TIME_PERIOD);

         # Special configuration for user, or global rate limit?
         my $number_of_logins = $TOTAL_LOGINS;

         if($USER_RATE_LIMIT{$username}) {
            $number_of_logins = $USER_RATE_LIMIT{$username};
         }

         # Number of logins reached
         if($logins > $number_of_logins) {
            log_info("Reject user $username - got $logins logins "
             . "in the last time period");

            $answer = $POSTFIX_SASL_LIMIT_MESSAGE;
         }
      }
   }

   log_debug("Send $answer to postfix");

   $client_socket -> send($answer);
   $client_socket -> close();
   
   log_debug("Connection closed");

   # Do some database cleanup
   database_clanup($conn);

   exit();
}


###
# Does table exisits?
###
sub sqlite_table_exists($$) {
   my $conn = shift;
   my $table = shift;

   my $dbh = $conn->dbh;
   
   my $sth = $dbh->prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='$table'");

   $sth->execute();
   
   my $found = 0;
   if($sth -> fetch()) {
      $found = 1;
   }   
   $sth->finish();
   return $found;
}

###
# Create Database structure
###
sub create_tables($) {
   my $conn = shift;
   
   my $dbh = $conn->dbh;

   my $sth = $dbh->prepare(
      "CREATE table LOGIN (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, "
      . "ip TEXT, logintime INTEGER)");

    $sth->execute(); 
    $sth->finish();
}

###
# Insert new login into database
###
sub insert_login($$$) {
   my $conn = shift;
   my $username = shift;
   my $ip = shift;

   my $dbh = $conn->dbh;

   my $timestamp = time();

   my $sth = $dbh->prepare
      ("INSERT INTO LOGIN (username, ip, logintime) values (?, ?, ?)");

  $sth -> execute($username, $ip, $timestamp);
  $sth -> finish();
}

### 
# Calculate the number of different IPs for a given SASL user in
# a given timeperiod
###
sub get_ips_for_login($$$) {
   my $conn = shift;
   my $username = shift;
   my $time_period = shift;

   my $dbh = $conn -> dbh;

   my $timestamp = time() - $time_period;

   my $sth = $dbh -> prepare
      ("SELECT count(DISTINCT IP) from LOGIN where username = ? "
      . "and logintime > ?");

   $sth -> execute($username, $timestamp);
   my $row = $sth->fetchrow_arrayref();
   my $ips = $row->[0];
   $sth -> finish();

   unless($ips) {
      $ips = 0;
   }

   return $ips;
}

###
# Do sime Database cleanup
###
sub database_clanup($) {
   my $conn = shift;
   my $dbh = $conn -> dbh;

   # Do some database cleanup
   my $timestamp = time() - $CLEANUP_PERIOD;

   my $sth = $dbh->prepare(
      "DELETE from LOGIN where logintime < ?");

   $sth -> execute($timestamp);
   $sth -> finish();
}

###
# Calculate the total number of logins for a given timeperiod
###
sub get_logins($$$) {
   my $conn = shift;
   my $username = shift;
   my $time_period = shift;

   my $dbh = $conn -> dbh;

   my $timestamp = time() - $time_period;

   my $sth = $dbh -> prepare
      ("SELECT count(*) from LOGIN where username = ? "
      . "and logintime > ?");

   $sth -> execute($username, $timestamp);
   my $row = $sth->fetchrow_arrayref();
   my $logins = $row->[0];
   $sth -> finish();
   
   unless($logins) {
      $logins = 0;
   }

   return $logins;
}

###
# Write info message to logfile
###
sub log_info($) {
   writelog(shift);
}

###
# Write verbose message to logfile
###
sub log_verbose($) {
   writelog(shift) if $VERBOSE;
}

###
# Write debug message to logfile
###
sub log_debug($) {
   writelog(shift) if $DEBUG;
}

###
# Write message to logfile
###
sub writelog($) {
   my $message = shift;
   syslog($syslog_priority, $message);
}
