ifndef PREFIX
        PREFIX=/usr/local
endif

MODULE_VERSION = 0.9.10
TOOL = scstadmin

SBINDIR := $(PREFIX)/sbin

all: perl-module

install install_vendor: all
	$(MAKE) -C scst-$(MODULE_VERSION) $@ DESTDIR=$(DESTDIR)
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 $(TOOL) $(DESTDIR)$(SBINDIR)

uninstall:
	-rm -f $(DESTDIR)$(SBINDIR)/$(TOOL)
	$(MAKE) -C scst-$(MODULE_VERSION) uninstall

perl-module:
	@cd ./scst-$(MODULE_VERSION); \
	perl Makefile.PL;
	$(MAKE) -C scst-$(MODULE_VERSION)

test:
	$(MAKE) -C scst-$(MODULE_VERSION) test

clean:
	-$(MAKE) -C scst-$(MODULE_VERSION) clean

distclean: clean
	-rm -f scst-$(MODULE_VERSION)/Makefile.old
	rm -f *.orig *.rej

extraclean: distclean

.PHONY: all install uninstall perl-module clean distclean extraclean
