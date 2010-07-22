MODULE_VERSION = 0.9.00
TOOL = scstadmin

SBINDIR := $(PREFIX)/usr/local/sbin

all: perl-module

install:
	$(MAKE) -C scst-$(MODULE_VERSION) install
	install -m 755 $(TOOL) $(DESTDIR)$(SBINDIR)

uninstall:
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
