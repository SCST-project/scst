ifndef PREFIX
	PREFIX=/usr/local
endif

SHELL=/bin/bash

SRCS_F = events.c debug.c
OBJS_F = $(SRCS_F:.c=.o)

#SRCS_C =
#OBJS_C = $(SRCS_C:.c=.o)

SCST_INC_DIR := $(shell if [ -e "$$PWD/../../scst" ];			\
                  then echo "$$PWD/../../scst/include";			\
                  else echo "$(DESTDIR)$(PREFIX)/include/scst"; fi)
DEBUG_INC_DIR := ../include
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/scst

CFLAGS += -O2 -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes \
	-I$(SCST_INC_DIR) -I$(DEBUG_INC_DIR) -D_GNU_SOURCE -D__USE_FILE_OFFSET64 \
	-D__USE_LARGEFILE64
PROGS = events
LIBS = -lpthread

CFLAGS += -W -Wno-unused-parameter
CFLAGS += $(LOCAL_CFLAGS)
#CFLAGS += -DDEBUG_NOMEM

-include ../../scst/build_mode

echo := $(shell echo "usr/events build mode: $(BUILD_MODE)" >& 2)

BUILD_MODE_CFLAGS_ = -DTRACING -DDEBUG -DEXTRACHECKS \
	-fno-inline -fno-inline-functions
BUILD_MODE_CFLAGS_RELEASE = -DTRACING
BUILD_MODE_CFLAGS_PERF =
CFLAGS += $(BUILD_MODE_CFLAGS_$(BUILD_MODE))

all: $(PROGS)

events: .depend_f $(OBJS_F)
	$(CC) $(OBJS_F) $(LIBS) $(LOCAL_LD_FLAGS) -o $@

#cdrom_tgt: .depend_c  $(OBJS_C)
#	$(CC) $(OBJS_C) $(LIBS) $(LOCAL_LD_FLAGS) -o $@

ifeq (.depend_f,$(wildcard .depend_f))
-include .depend_f
endif

#ifeq (.depend_c,$(wildcard .depend_c))
#-include .depend_c
#endif

%.o: %.c Makefile
	$(CC) -c -o $(@) $(CFLAGS) $(<)

.depend_f:
	$(CC) -M $(CFLAGS) $(SRCS_F) >$(@)

#.depend_c:
#	$(CC) -M $(CFLAGS) $(SRCS_C) >$(@)

install: all
	install -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(PROGS)

clean:
	rm -f *.o $(PROGS) .depend*

extraclean: clean
	rm -f *.orig *.rej

2release:
	-$(MAKE) clean

2debug:
	-$(MAKE) clean

2perf:
	-$(MAKE) clean

release-archive:
	../../scripts/generate-release-archive events "$$(sed -n 's/^#define[[:blank:]]VERSION_STR[[:blank:]]*\"\([^\"]*\)\".*/\1/p' ../include/version.h)"

.PHONY: all install uninstall clean extraclean 2release 2debug 2perf
