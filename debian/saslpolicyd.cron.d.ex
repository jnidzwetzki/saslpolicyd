#
# Regular cron jobs for the saslpolicyd package
#
0 4	* * *	root	[ -x /usr/bin/saslpolicyd_maintenance ] && /usr/bin/saslpolicyd_maintenance
