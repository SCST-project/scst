SCSTADMIN_DIR = scstadmin

MANDIR := $(DESTDIR)/usr/local/man
INITDIR := $(shell if [ -f /etc/slackware-version ]; then	\
                     echo /etc/rc.d;				\
                   else						\
                     echo /etc/init.d;				\
                   fi)
INSTALL_INITD_CMD := $(shell if [ -f /etc/gentoo-release ]; then	\
			       echo rc-update add;			\
			     elif [ -f /etc/slackware-version ]; then	\
			       echo none;				\
			     else					\
			       echo /usr/lib/lsb/install_initd;		\
			     fi)
INSTALL_INITD_ARGS := $(shell [ -f /etc/gentoo-release ] && echo default)
REMOVE_INITD_CMD := $(shell if [ -f /etc/gentoo-release ]; then		\
			      echo rc-update del;			\
			    elif [ -f /etc/slackware-version ]; then	\
			      echo none;				\
			    else					\
			      echo /usr/lib/lsb/remove_initd;		\
			    fi)
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
	  if [ -e $$m ]; then			    			\
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
	  install -m 755 default/scst $(DESTDIR)$(DEFAULTDIR);	\
	fi
	@if [ "$(INSTALL_INITD_CMD)" != "none" ]; then			    \
	  echo;								    \
	  echo 'If you want SCST to start automatically at boot time, run'  \
	      'the following command:';					    \
	  if [ ! -z "$(DESTDIR)" ]; then echo -n "chroot $(DESTDIR) "; fi;  \
	  echo '$(INSTALL_INITD_CMD) scst $(INSTALL_INITD_ARGS)';	    \
	  echo; \
	fi

uninstall:
	if [ -e $(DESTDIR)$(DEFAULTDIR)/scst ]; then	\
	  mv $(DESTDIR)$(DEFAULTDIR)/scst		\
	    $(DESTDIR)$(DEFAULTDIR)/scst.`date +%F,%T`;	\
	fi
	if [ -e $(DESTDIR)$(INITDIR)/scst -a "$(REMOVE_INITD_CMD)" != "none" ];\
	then							\
	  if [ -z "$(DESTDIR)" ]; then				\
	    $(REMOVE_INITD_CMD) scst;				\
	  else							\
	    chroot $(DESTDIR) $(REMOVE_INITD_CMD) scst;		\
	  fi;							\
	  rm -f $(DESTDIR)$(INITDIR)/scst;			\
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

.PHONY: all install uninstall perl-module clean distclean extraclean disable_proc enable_proc
