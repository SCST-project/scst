LINUXINCLUDE := $(PRE_CFLAGS) $(LINUXINCLUDE)
CPPFLAGS     := $(PRE_CFLAGS) $(CPPFLAGS)
KBUILD_EXTRA_SYMBOLS=$(src)/../../scst/src/Module.symvers \
		$(shell for d in /usr/src/ofa_kernel/default/Module.symvers; do\
			[ -e $$d ] || continue; echo $$d; break; done)
ccflags-y    += -I$(src)/../../scst/include

obj-m		+= ib_srpt.o
