ifndef PREFIX
	PREFIX=/usr/local
endif

SHELL=/bin/bash

SRCS_F = stpgd_main.c debug.c
OBJS_F = $(SRCS_F:.c=.o)

#SRCS_C =
#OBJS_C = $(SRCS_C:.c=.o)

SCST_INC_DIR := $(shell if [ -e "$$PWD/../../scst" ];			\
                  then echo "$$PWD/../../scst/include";			\
                  else echo "$(DESTDIR)$(PREFIX)/include/scst"; fi)
DEBUG_INC_DIR := ../include
INSTALL_DIR := $(DESTDIR)$(PREFIX)/sbin
ON_STPG := $(DESTDIR)$(PREFIX)/bin/scst/scst_on_stpg

CFLAGS += -O2 -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes \
	-I$(SCST_INC_DIR) -I$(DEBUG_INC_DIR) -D_GNU_SOURCE -D__USE_FILE_OFFSET64 \
	-D__USE_LARGEFILE64
PROGS = stpgd
LIBS = -lpthread

CFLAGS += -DEXTRACHECKS
#CFLAGS += -DTRACING
CFLAGS += -DDEBUG -g -fno-inline -fno-inline-functions
CFLAGS += -W -Wno-unused-parameter
CFLAGS += $(LOCAL_CFLAGS)

#CFLAGS += -DDEBUG_NOMEM

all: $(PROGS)

stpgd: .depend_f $(OBJS_F)
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
	install -m 700 $(PROGS) $(INSTALL_DIR)
	install -m 700 scst_on_stpg $(ON_STPG)

uninstall:
	rm -f $(INSTALL_DIR)/$(PROGS)
	rm -rf $(INSTALL_DIR)

clean:
	rm -f *.o $(PROGS) .depend*

extraclean: clean
	rm -f *.orig *.rej

2release:
	sed -i.aa s/"^C\?FLAGS += \-DEXTRACHECKS"/"#CFLAGS += \-DEXTRACHECKS"/ Makefile
	grep "^#CFLAGS += \-DEXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^#\?CFLAGS += \-DTRACING"/"CFLAGS += \-DTRACING"/ Makefile
	grep "^CFLAGS += \-DTRACING" Makefile >/dev/null
	sed -i.aa s/"^C\?FLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/"#CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^#CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

2debug:
	sed -i.aa s/"^#\?CFLAGS += \-DEXTRACHECKS"/"CFLAGS += \-DEXTRACHECKS"/ Makefile
	grep "^CFLAGS += \-DEXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^C\?FLAGS += \-DTRACING"/"#CFLAGS += \-DTRACING"/ Makefile
	grep "^#CFLAGS += \-DTRACING" Makefile >/dev/null
	sed -i.aa s/"^#\?CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/"CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

2perf:
	sed -i.aa s/"^C\?FLAGS += \-DEXTRACHECKS"/"#CFLAGS += \-DEXTRACHECKS"/ Makefile
	grep "^#CFLAGS += \-DEXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^C\?FLAGS += \-DTRACING"/"#CFLAGS += \-DTRACING"/ Makefile
	grep "^#CFLAGS += \-DTRACING" Makefile >/dev/null
	sed -i.aa s/"^C\?FLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/"#CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^#CFLAGS += \-DDEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

release-archive:
	../../scripts/generate-release-archive stpgd "$$(sed -n 's/^#define[[:blank:]]VERSION_STR[[:blank:]]*\"\([^\"]*\)\".*/\1/p' ../include/version.h)"

.PHONY: all install uninstall clean extraclean 2release 2debug 2perf
