ifndef KDIR
KDIR := /lib/modules/$(shell uname -r)/build
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

