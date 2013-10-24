default: all

all:

clean:

install:
	mkdir -p $(DESTDIR)/usr/sbin/
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/etc/

	cp -v sasl-policyd.pl $(DESTDIR)/usr/sbin/
	cp -v saslpolicyd $(DESTDIR)/etc/init.d
	cp -v saslpolicyd.conf $(DESTDIR)/etc/

uninstall:
	$(DESTDIR)/etc/init.d/saslpolicyd stop
	rm $(DESTDIR)/etc/init.d/saslpolicyd
	rm $(DESTDIR)/usr/sbin/sasl-policyd.pl
	rm $(DESTDIR)/etc/saslpolicyd.conf
