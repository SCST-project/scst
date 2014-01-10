ifndef PREFIX
        PREFIX=/usr/local
endif

VERSION = $(shell echo -n "$$(sed -n 's/^[[:blank:]]*\$$VERSION[[:blank:]]*=[[:blank:]]*[\"'"'"']\([0-9.]*\)[\"'"'"'];$$/\1/p' scstadmin/scst-*/lib/SCST/SCST.pm).";	\
		   if svn info >/dev/null 2>&1;				\
		   then svn info | sed -n 's/^Revision:[[:blank:]]*/r/p';\
		   else git show | sed -n 's/^commit[[:blank:]]*\(.......\).*/\1/p'; \
		   fi)

SCSTADMIN_DIR = $(shell if [ ! -h scstadmin ]; then		\
			    rm -f scstadmin;			\
			    ln -s scstadmin.sysfs scstadmin;	\
			fi;					\
			echo scstadmin)

MANDIR ?= $(DESTDIR)$(PREFIX)/man

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

install install_vendor:
	@if [ -z "$(DESTDIR)" ] && rpm -q scstadmin >/dev/null 2>&1; then \
	echo Error: the scstadmin RPM must be uninstalled first; false; fi
	@if ! perl -MExtUtils::MakeMaker -e '' >/dev/null 2>&1; then \
	echo Error: the Perl module ExtUtils::MakeMaker must be installed \
	first; false; fi
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

test:
	$(MAKE) -C scstadmin test

dist-gzip:
	name=$(shell basename $$PWD) &&					\
	mkdir $${name}-$(VERSION) &&					\
	{ ../scripts/list-source-files | tar -T- -cf- |			\
	  tar -C $${name}-$(VERSION) -xf-; } &&				\
	rm -f $${name}-$(VERSION).tar.bz2 &&				\
	tar -cjf $${name}-$(VERSION).tar.bz2 $${name}-$(VERSION) &&	\
	rm -rf $${name}-$(VERSION)

rpm:
	name=$(shell basename $$PWD) &&					\
	rpmtopdir="$$(if [ $$(id -u) = 0 ]; then echo /usr/src/packages;\
		      else echo $$PWD/rpmbuilddir; fi)" &&		\
	$(MAKE) dist-gzip &&						\
	rm -rf $${rpmtopdir} &&						\
	for d in BUILD RPMS SOURCES SPECS SRPMS; do			\
	  mkdir -p $${rpmtopdir}/$$d;					\
	done &&								\
	cp $${name}-$(VERSION).tar.bz2 $${rpmtopdir}/SOURCES &&		\
	sed "s/@rpm_version@/$(VERSION)/g"				\
		<$${name}.spec.in >$${name}.spec &&			\
	MAKE="$(MAKE)"							\
	rpmbuild --define="%_topdir $${rpmtopdir}" -ba $${name}.spec &&	\
	rm -f $${name}-$(VERSION).tar.bz2

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
