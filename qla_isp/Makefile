ifndef KVER
KVER = $(shell uname -r)
endif

ifndef KDIR
KDIR := /lib/modules/$(KVER)/build
endif

export KDIR

all:
	$(MAKE) -C linux-2.6 tgt

clean:
	$(MAKE) -C linux-2.6 clean

extraclean:
	$(MAKE) -C linux-2.6 extraclean

install:
	$(MAKE) -C linux-2.6 install

uninstall:
	$(MAKE) -C linux-2.6 uninstall

