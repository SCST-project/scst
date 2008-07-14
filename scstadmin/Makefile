MODULE_VERSION = 0.7.4
TOOL = scstadmin

all: perl-module

install:
	install -m 755 $(TOOL) /usr/local/sbin
	install -m 755 init.d/scst /etc/init.d
	$(MAKE) -C scst-$(MODULE_VERSION) install
	@echo
	@echo "The SCST init file has been installed in /etc/init.d,"
	@echo "be sure to enable it with your favorite SysV init editor."
	@echo

uninstall:
	-rm -f /etc/init.d/scst
	-rm -f /usr/local/sbin/$(TOOL)
	$(MAKE) -C scst-$(MODULE_VERSION) uninstall

perl-module:
	@cd ./scst-$(MODULE_VERSION); \
	perl Makefile.PL;
	$(MAKE) -C scst-$(MODULE_VERSION)

clean:
	$(MAKE) -C scst-$(MODULE_VERSION) clean

distclean:
	$(MAKE) -C scst-$(MODULE_VERSION) clean
	-rm -f scst-$(MODULE_VERSION)/Makefile.old

.PHONY: all install uninstall
