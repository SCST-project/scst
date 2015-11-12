ccflags-y += -Wno-unused-parameter

scst-y        += scst_copy_mgr.o
scst-y        += scst_debug.o
scst-y        += scst_dlm.o
scst-y        += scst_event.o
scst-y        += scst_lib.o
scst-y        += scst_main.o
scst-y        += scst_mem.o
scst-y        += scst_no_dlm.o
scst-y        += scst_pres.o
scst-y        += scst_sysfs.o
scst-y        += scst_targ.o
scst-y        += scst_tg.o

obj-$(CONFIG_SCST)   += scst.o dev_handlers/ fcst/ iscsi-scst/ qla2xxx-target/ \
			srpt/ scst_local/
