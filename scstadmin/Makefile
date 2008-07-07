all:

install:
	install -m 755 init.d/scst /etc/init.d
	install -m 755 scstadmin /usr/local/sbin
	mkdir -p /usr/local/lib/site_perl/SCST
	install -m 644 SCST/SCST.pm /usr/local/lib/site_perl/SCST/SCST.pm

uninstall:
	-rm -f /etc/init.d/scst
	-rm -f /usr/local/sbin/scstadmin
	-rm -rf /usr/local/lib/site_perl/SCST

.PHONY: all install uninstall
