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
	regex="s|%INSTALLSITELIB%|$$(make -sC scst-$(MODULE_VERSION) print-INSTALLSITELIB | grep -v ^make)|"; echo "$${regex}"; sed -i "$${regex}" $(DESTDIR)$(SBINDIR)/$(TOOL)

uninstall:
	-rm -f $(DESTDIR)$(SBINDIR)/$(TOOL)
	$(MAKE) -C scst-$(MODULE_VERSION) uninstall

perl-module:
	@cd ./scst-$(MODULE_VERSION) &&		\
	perl Makefile.PL PREFIX=$(PREFIX) &&	\
	printf '\nprint-%%:\n\t@echo '"'"'$$($$*)'"'"'\n' >> Makefile
	$(MAKE) -C scst-$(MODULE_VERSION)

test:
	$(MAKE) -C scst-$(MODULE_VERSION) test #TEST_VERBOSE=1

clean:
	-$(MAKE) -C scst-$(MODULE_VERSION) clean

distclean: clean
	-rm -f scst-$(MODULE_VERSION)/Makefile.old
	rm -f *.orig *.rej

extraclean: distclean

.PHONY: all install uninstall perl-module clean distclean extraclean
