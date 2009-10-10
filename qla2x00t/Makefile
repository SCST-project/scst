qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o

obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

# The qla2xxx-orig/% targets are not built correctly when parallel building
# (make -j...) is enabled, so disable parallel builds.
.NOTPARALLEL:

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -f in-tree-patches/*.patch
	rm -rf qla2xxx-orig
	rm -rf .tmp_versions

extraclean: clean

DOWNLOAD_DIR=$(HOME)/software/downloads

QLA2XXX_ORIG =   \
  Kconfig        \
  Makefile       \
  qla_attr.c     \
  qla_dbg.c      \
  qla_dbg.h      \
  qla_def.h      \
  qla_devtbl.h   \
  qla_dfs.c      \
  qla_fw.h       \
  qla_gbl.h      \
  qla_gs.c       \
  qla_init.c     \
  qla_inline.h   \
  qla_iocb.c     \
  qla_isr.c      \
  qla_mbx.c      \
  qla_mid.c      \
  qla_os.c       \
  qla_settings.h \
  qla_sup.c      \
  qla_version.h

GENERATED_PATCHES = \
  in-tree-patches/qla2xxx-Kconfig-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_def.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_gs.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_mbx.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_version.h-2.6.26.patch \
  in-tree-patches/qla2xxx-Makefile-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_devtbl.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_init.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_mid.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_attr.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_dfs.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_inline.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_os.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_dbg.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_fw.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_iocb.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_settings.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_dbg.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_gbl.h-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_isr.c-2.6.26.patch \
  in-tree-patches/qla2xxx-qla_sup.c-2.6.26.patch

$(DOWNLOAD_DIR)/linux-%:
	cd $(DOWNLOAD_DIR) \
	&& wget -q -nc ftp://ftp.eu.kernel.org/pub/linux/kernel/v2.6/$(@F)

$(DOWNLOAD_DIR)/patch-%:
	cd $(DOWNLOAD_DIR) \
	&& wget -q -nc ftp://ftp.eu.kernel.org/pub/linux/kernel/v2.6/$(@F)

qla2xxx-orig/%: $(DOWNLOAD_DIR)/linux-2.6.26.tar.bz2 \
		$(DOWNLOAD_DIR)/patch-2.6.26.8.bz2
	rm -rf linux-2.6.26
	tar -xjf $(DOWNLOAD_DIR)/linux-2.6.26.tar.bz2
	cd linux-2.6.26 \
	&& bzip2 -cd < $(DOWNLOAD_DIR)/patch-2.6.26.8.bz2 | patch -p1 -f -s
	touch linux-2.6.26/drivers/scsi/qla2xxx/*
	mkdir -p qla2xxx-orig
	mv linux-2.6.26/drivers/scsi/qla2xxx/* qla2xxx-orig
	rm -rf linux-2.6.26

in-tree-patches/qla2xxx-%-2.6.26.patch: % qla2xxx-orig/%
	f="$$(echo "$@" | sed -e 's:^in-tree-patches/qla2xxx-::' -e 's:-2.6.26.patch$$::')"; diff -up "qla2xxx-orig/$$f" "$$f" >"$@"; true

patches: $(GENERATED_PATCHES)

.PHONY: clean extraclean patches
