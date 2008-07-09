VERSION = 0.7.4
TOOL = scstadmin

all: perl-module

install:
	install -m 755 $(TOOL) /usr/local/sbin
	install -m 755 init.d/scst /etc/init.d
	$(MAKE) -C scst-$(VERSION) install

uninstall:
	-rm -f /etc/init.d/scst
	-rm -f /usr/local/sbin/$(TOOL)
	$(MAKE) -C scst-$(VERSION) uninstall

perl-module:
	@cd ./scst-$(VERSION); \
	perl Makefile.PL;
	$(MAKE) -C scst-$(VERSION)

clean:
	$(MAKE) -C scst-$(VERSION) clean

distclean:
	$(MAKE) -C scst-$(VERSION) clean
	-rm -f scst-$(VERSION)/Makefile.old

.PHONY: all install uninstall
