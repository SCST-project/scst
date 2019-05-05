LINUXINCLUDE := $(PRE_CFLAGS) $(LINUXINCLUDE)
CPPFLAGS     := $(PRE_CFLAGS) $(CPPFLAGS)
ccflags-y    += -I$(KBUILD_EXTMOD)/../../scst/include

#ccflags-y += -Wextra -Wno-unused-parameter

obj-m		+= ib_srpt.o
