install:
	cp -v ../sasl-policyd.pl /usr/sbin/
	cp -v saslpolicyd /etc/init.d 
	update-rc.d saslpolicyd defaults

uninstall:
	/etc/init.d/saslpolicyd stop
	rm /etc/init.d/saslpolicyd
	update-rc.d saslpolicyd remove
	rm /usr/sbin/sasl-policyd.pl
