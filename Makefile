default: all

all:

clean:

install:
	mkdir -p $(DESTDIR)/usr/sbin/
	mkdir -p $(DESTDIR)/etc/init.d/
	cp -v sasl-policyd.pl $(DESTDIR)/usr/sbin/
	cp -v saslpolicyd $(DESTDIR)/etc/init.d 
	/usr/sbin/update-rc.d saslpolicyd defaults

uninstall:
	$(DESTDIR)/etc/init.d/saslpolicyd stop
	rm $(DESTDIR)/etc/init.d/saslpolicyd
	/usr/sbin/update-rc.d saslpolicyd remove
	rm $(DESTDIR)/usr/sbin/sasl-policyd.pl
