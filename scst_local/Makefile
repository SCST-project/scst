#
# A Makefile for the scst-local ...
#

#SCST_INC_DIR := /usr/local/include/scst
#SCST_DIR := $(SCST_INC_DIR)
SCST_INC_DIR	:= $(SUBDIRS)/../scst/include/
SCST_DIR	:= $(shell pwd)/../scst/src

EXTRA_CFLAGS	+= -I$(SCST_INC_DIR) -I$(SCST_DIR)
EXTRA_CFLAGS	+=  -Wextra -Wno-unused-parameter -Wno-missing-field-initializers

#EXTRA_CFLAGS	+= -DCONFIG_SCST_LOCAL_FORCE_DIRECT_PROCESSING

EXTRA_CFLAGS	+= -DCONFIG_SCST_EXTRACHECKS

#EXTRA_CFLAGS	+= -DCONFIG_SCST_TRACING
EXTRA_CFLAGS	+= -DCONFIG_SCST_DEBUG

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(shell uname -r)/build
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifneq ($(KERNELRELEASE),)
obj-m	:= scst_local.o
else

all: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

tgt: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		modules_install
	-/sbin/depmod -aq $(KVER)

SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Modules.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Modules.symvers: $(SCST_DIR)/Modules.symvers
	cp $(SCST_DIR)/Modules.symvers .
else
.PHONY: Modules.symvers
endif

# It's renamed in 2.6.18
SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Module.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Module.symvers: $(SCST_DIR)/Module.symvers
	cp $(SCST_DIR)/Module.symvers .
else
.PHONY: Module.symvers
endif

uninstall:
	rm -f $(INSTALL_DIR)/scst_local.kp
	-/sbin/depmod -a $(KVER)
endif

clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean
	@$(RM) tags Modules.symvers module.symvers Module.markers modules.order

extraclean: clean

.PHONY: all tgt install uninstall clean extraclean
