MODULE_VERSION = 0.7.4
TOOL = scstadmin

SBINDIR := $(PREFIX)/usr/local/sbin
INITDIR := $(PREFIX)/etc/init.d

all: perl-module

install:
	$(MAKE) -C scst-$(MODULE_VERSION) install
	install -m 755 $(TOOL) $(DESTDIR)$(SBINDIR)
	install -m 755 init.d/scst $(DESTDIR)$(INITDIR)
	install -m 755 init.d/qla2x00t $(DESTDIR)$(INITDIR)
	-/usr/lib/lsb/install_initd scst
	-/usr/lib/lsb/install_initd qla2x00t

uninstall:
	-/usr/lib/lsb/remove_initd qla2x00t
	-/usr/lib/lsb/remove_initd scst
	-rm -f $(DESTDIR)$(PATH_INITD)/qla2x00t
	-rm -f $(DESTDIR)$(PATH_INITD)/scst
	-rm -f $(DESTDIR)$(PATH_SBIN)/$(TOOL)
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
