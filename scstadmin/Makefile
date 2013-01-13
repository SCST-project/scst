SCSTADMIN_DIR = $(shell if [ ! -h scstadmin ]; then		\
			    rm -f scstadmin;			\
			    ln -s scstadmin.sysfs scstadmin;	\
			fi;					\
			echo scstadmin)

MANDIR := $(DESTDIR)/usr/local/man
INITDIR := $(shell if [ -f /etc/slackware-version ]; then	\
                     echo /etc/rc.d;				\
                   else						\
                     echo /etc/init.d;				\
                   fi)

ECHO_INSTALL_FN =							\
	if [ -n "$(DESTDIR)" ]; then					\
	  chr="chroot $(DESTDIR)";					\
	else								\
	  chr="";							\
	fi;								\
	if type systemctl >/dev/null 2>&1; then				\
	    echo $$chr systemctl enable "$(1).service";			\
	elif type chkconfig >/dev/null 2>&1; then			\
	    echo $$chr chkconfig --add "$(1)";				\
	elif type update-rc.d >/dev/null 2>&1; then			\
	    echo $$chr update-rc.d "$(1)" defaults;			\
	elif type rc-update >/dev/null 2>&1; then			\
	    echo $$chr rc-update add "$(1)" default;			\
	elif type /usr/lib/lsb/install_initd >/dev/null 2>&1; then	\
	    echo $$chr /usr/lib/lsb/install_initd "$(1)";		\
	fi

REMOVE_FN =								\
	if [ -n "$(DESTDIR)" ]; then					\
	  chr="chroot $(DESTDIR)";					\
	else								\
	  chr="";							\
	fi;								\
	if type systemctl >/dev/null 2>&1; then				\
	    $$chr systemctl disable "$(1).service";			\
	elif type chkconfig >/dev/null 2>&1; then			\
	    $$chr chkconfig --del "$(1)";				\
	elif type update-rc.d >/dev/null 2>&1; then			\
	    $$chr update-rc.d -f "$(1)" remove;				\
	elif type rc-update >/dev/null 2>&1; then			\
	    $$chr rc-update del "$(1)";					\
	elif type /usr/lib/lsb/remove_initd >/dev/null 2>&1; then	\
	    $$chr /usr/lib/lsb/remove_initd "$(1)";			\
	fi;								\
	rm -f $(DESTDIR)$(INITDIR)/$(1)

DEFAULTDIR := $(shell if [ -f /etc/gentoo-release ]; then	        \
                          echo /etc/conf.d;                             \
		      else                                              \
                          echo /etc/default;                            \
		      fi)

all:
	cd $(SCSTADMIN_DIR) && $(MAKE) $@

install:
	@if ! perl -MExtUtils::MakeMaker -e '' >/dev/null 2>&1; then \
	echo Error: the Perl module ExtUtils::MakeMaker must be installed \
	first; false; fi
	@if [ ! -e /etc/slackware-version -a ! -e /etc/gentoo-release	      \
	      -a ! -e /lib/lsb/init-functions ]; then			      \
	echo "Error: the lsb-core (Debian, Ubuntu), redhat-lsb (RHEL, CentOS,"\
	"Scientific Linux, Fedora) or insserv (SLES, openSUSE) package must"  \
	"be installed first"; false; fi
	cd $(SCSTADMIN_DIR) && $(MAKE) $@
	for m in scstadmin/man*/*.[1-9]; do				\
	  if [ -e $$m ]; then						\
	    d=$(MANDIR)/$$(basename $$(dirname $$m));			\
	    if install -d $$d; then					\
	      install -m 644 $$m $$d;					\
	    fi								\
	  fi								\
	done
	install -d $(DESTDIR)$(INITDIR)
	tmp=/tmp/scst-initd-$$$$ && init.d/scst >$$tmp &&               \
	  install -m 755 $$tmp $(DESTDIR)$(INITDIR)/scst &&             \
	  rm -f $$tmp
	if [ ! -e  $(DESTDIR)$(DEFAULTDIR)/scst ]; then		\
	  mkdir -p $(DESTDIR)$(DEFAULTDIR);			\
	  install -m 755 default/scst $(DESTDIR)$(DEFAULTDIR);	\
	fi
	for s in iscsi-scst qla2x00t; do			\
	  { $(call REMOVE_FN,$$s); } >/dev/null 2>&1;		\
	done
	echo
	echo 'If you want SCST to start automatically at boot time, run'  \
	     'the following command:'
	$(call ECHO_INSTALL_FN,scst)
	echo

uninstall:
	if [ -e $(DESTDIR)$(DEFAULTDIR)/scst ]; then	\
	  mv $(DESTDIR)$(DEFAULTDIR)/scst		\
	    $(DESTDIR)$(DEFAULTDIR)/scst.`date +%F,%T`;	\
	fi
	if [ -e $(DESTDIR)$(INITDIR)/scst ]; then	\
	  $(call REMOVE_FN,scst);			\
	fi
	for m in scstadmin/man*/*.[1-9]; do		\
	  if [ -e $$m ]; then				\
	    d=$(MANDIR)/$$(basename $$(dirname $$m));	\
	    rm -f $$d/$$(basename $$m);			\
	  fi						\
	done
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

release-archive:
	../scripts/generate-release-archive scstadmin "$$(sed -n 's/^\$$Version[[:blank:]]*=[[:blank:]]*'"'"'SCST Configurator v\([^'"'"']*\)'"'"'.*/\1/p' scstadmin.sysfs/scstadmin)"

.PHONY: all install uninstall perl-module clean distclean extraclean disable_proc enable_proc
