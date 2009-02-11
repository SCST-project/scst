MODULE_VERSION = 0.7.4
TOOL = scstadmin

all: perl-module

install:
	install -m 755 $(TOOL) /usr/local/sbin
	install -m 755 init.d/scst /etc/init.d
	/usr/lib/lsb/install_initd scst
	install -m 755 init.d/qla2x00t /etc/init.d
	/usr/lib/lsb/install_initd qla2x00t
	$(MAKE) -C scst-$(MODULE_VERSION) install

uninstall:
	-/usr/lib/lsb/remove_initd qla2x00t
	-rm -f /etc/init.d/qla2x00t
	-/usr/lib/lsb/remove_initd scst
	-rm -f /etc/init.d/scst
	-rm -f /usr/local/sbin/$(TOOL)
	$(MAKE) -C scst-$(MODULE_VERSION) uninstall

perl-module:
	@cd ./scst-$(MODULE_VERSION); \
	perl Makefile.PL;
	$(MAKE) -C scst-$(MODULE_VERSION)

clean:
	-$(MAKE) -C scst-$(MODULE_VERSION) clean

distclean: clean
	-rm -f scst-$(MODULE_VERSION)/Makefile.old

extraclean: distclean

.PHONY: all install uninstall perl-module clean distclean extraclean
