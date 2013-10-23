saslpolicyd
===========

saslpolicyd is a policy daemon for postfix. The software is written in perl and licensed under the Apache License.

As a service provider you have to deal with stolen passwords. Such accounts are often used for abusive actions. Nowadays, botnets are using the password for relaying huge amounts of spam mails over your systems. Your infrastructure will slow down and many blacklists will list your IPs as a known source of spam. 

Often this missuse follows the same pattern: normally a customer relays only a handful of mails during the week. The mails are delivered from a few source ips. In a missuse case, more than 1000 mails are relayed from more then 30 ips in one hour. This is the reason why i wrote this tool. saslpolicyd tracks all sasl logins and reject the relay if a missuse case is detected.



Installation
-------------
* Download and unpack the software
* Install the policy daemon
* Start the service

If you are using Debian or Ubuntu you can build your own dpkg-package by using the content of the debian/ folder.


* Add the policy service to your postfix configuration:

   smtpd\_recipient\_restrictions = permit\_mynetworks,
   check\_policy\_service inet:127.0.0.1:25025,
   ...


