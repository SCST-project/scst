SCSTADMIN_DIR = scstadmin

INITDIR := $(PREFIX)/etc/init.d

all:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

install:
	@if ! perl -MExtUtils::MakeMaker -e '' >/dev/null 2>&1; then \
	echo Error: the Perl module ExtUtils::MakeMaker must be installed \
	first; false; fi
	@if [ ! -e /usr/lib/lsb/install_initd ]; then \
	echo Error: the lsb-core package must be installed first; false; fi
	cd $(SCSTADMIN_DIR) && $(MAKE) $@
	-/usr/lib/lsb/install_initd scst
	-/usr/lib/lsb/install_initd qla2x00t
	mkdir -m 755 -p $(DESTDIR)$(INITDIR)
	install -m 755 init.d/scst $(DESTDIR)$(INITDIR)
	install -m 755 init.d/qla2x00t $(DESTDIR)$(INITDIR)

uninstall:
	-/usr/lib/lsb/remove_initd qla2x00t
	-/usr/lib/lsb/remove_initd scst
	-rm -f $(DESTDIR)$(PATH_INITD)/qla2x00t
	-rm -f $(DESTDIR)$(PATH_INITD)/scst
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

perl-module:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

clean:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

distclean:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

extraclean:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

disable_proc:
	-rm -f scstadmin
	ln -s scstadmin.sysfs scstadmin

enable_proc:
	-rm -f scstadmin
	ln -s scstadmin.procfs scstadmin

.PHONY: all install uninstall perl-module clean distclean extraclean disable_proc enable_proc
