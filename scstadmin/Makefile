SCSTADMIN_DIR = scstadmin

INITDIR := $(shell if [ -f /etc/slackware-version ]; then	\
                     echo $(PREFIX)/etc/rc.d;			\
                   else						\
                     echo $(PREFIX)/etc/init.d;			\
                   fi)
DEFAULTDIR := $(PREFIX)/etc/default

all:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

install:
	@if ! perl -MExtUtils::MakeMaker -e '' >/dev/null 2>&1; then \
	echo Error: the Perl module ExtUtils::MakeMaker must be installed \
	first; false; fi
	@if [ ! -e /etc/slackware-version -a ! -e /lib/lsb/init-functions ]; \
	then \
	echo "Error: the lsb-core (Debian, Ubuntu), redhat-lsb (RHEL, Fedora) "\
	"or insserv (SLES, openSUSE) package must be installed first"; false; fi
	cd $(SCSTADMIN_DIR) && $(MAKE) $@
	install -d $(DESTDIR)$(INITDIR)
	install -m 755 init.d/scst $(DESTDIR)$(INITDIR)
	if [ ! -e  $(DESTDIR)$(DEFAULTDIR)/scst ]; then		\
	  install -m 755 default/scst $(DESTDIR)$(DEFAULTDIR);	\
	fi
	@echo
	@echo 'If you want SCST to start automatically at boot time, run' \
	      'the following command:'
	@if [ ! -z "$(DESTDIR)" ]; then echo -n "chroot $(DESTDIR) "; fi
	@echo '/usr/lib/lsb/install_initd scst'
	@echo

uninstall:
	if [ -e $(DESTDIR)$(DEFAULTDIR)/scst ]; then	\
	  mv $(DESTDIR)$(DEFAULTDIR)/scst		\
	    $(DESTDIR)$(DEFAULTDIR)/scst.`date +%F,%T`;	\
	fi
	if [ -e $(DESTDIR)$(INITDIR)/scst ]; then		\
	  if [ -z "$(DESTDIR)" ]; then				\
	    /usr/lib/lsb/remove_initd scst;			\
	  else							\
	    chroot $(DESTDIR) /usr/lib/lsb/remove_initd scst;	\
	  fi;							\
	  rm -f $(DESTDIR)$(INITDIR)/scst;			\
	fi
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
