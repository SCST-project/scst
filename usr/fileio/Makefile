#
#  SCSI target mid-level makefile
#  
#  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2007 - 2010 ID7 Ltd.
#  Copyright (C) 2010 - 2013 SCST Ltd.
#  
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

ifndef PREFIX
        PREFIX=/usr/local
endif

SHELL=/bin/bash

SRCS_F = fileio.c common.c debug.c crc32.c
OBJS_F = $(SRCS_F:.c=.o)

#SRCS_C = 
#OBJS_C = $(SRCS_C:.c=.o)

SCST_INC_DIR := ../../scst/include
#SCST_INC_DIR := $(PREFIX)/include/scst
INSTALL_DIR := $(PREFIX)/bin/scst

CFLAGS += -O2 -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes \
	-I$(SCST_INC_DIR) -D_GNU_SOURCE -D__USE_FILE_OFFSET64 \
	-D__USE_LARGEFILE64
PROGS = fileio_tgt
LIBS = -lpthread

CFLAGS += -DEXTRACHECKS
#CFLAGS += -DTRACING
CFLAGS += -DDEBUG -g -fno-inline -fno-inline-functions
CFLAGS += -W -Wno-unused-parameter
CFLAGS += $(LOCAL_CFLAGS)

#CFLAGS += -DDEBUG_NOMEM
#CFLAGS += -DDEBUG_SENSE
#CFLAGS += -DDEBUG_TM_IGNORE
#CFLAGS += -DDEBUG_TM_IGNORE -DDEBUG_TM_FN_IGNORE
#CFLAGS += -DDEBUG_TM_IGNORE_ALL

all: $(PROGS)

fileio_tgt: .depend_f $(OBJS_F)
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
	../../scripts/generate-release-archive fileio_tgt "$$(sed -n 's/^#define[[:blank:]]VERSION_STR[[:blank:]]*\"\([^\"]*\)\".*/\1/p' fileio.c)"

.PHONY: all install uninstall clean extraclean 2release 2debug 2perf
