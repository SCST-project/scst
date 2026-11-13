# SPDX-License-Identifier: GPL-2.0-only
FROM fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80 AS base
RUN dnf install -y --setopt=install_weak_deps=False \
        make git python3 diffutils findutils && dnf clean all
WORKDIR /scst
ENV PYTHONDONTWRITEBYTECODE=1

COPY scripts/ci/install-analyzers /opt/scst-ci/

# Extract the pinned package once; consumers copy only the assets they use.
FROM base AS kernel-files
RUN dnf install -y --setopt=install_weak_deps=False curl-minimal rpm cpio && dnf clean all
COPY scripts/ci/kernel.env scripts/ci/kernel.SHA256SUMS /opt/scst-ci/
RUN bash /opt/scst-ci/install-analyzers kernel

FROM base AS kernel-build
COPY --from=kernel-files /opt/kernel-devel.rpm /tmp/kernel-devel.rpm
RUN dnf install -y --setopt=install_weak_deps=False \
        gcc perl elfutils-libelf-devel openssl openssl-devel flex bison \
        pkgconf-pkg-config dwarves /tmp/kernel-devel.rpm && \
    ln -s /usr/src/kernels/* /opt/kernel && \
    rm /tmp/kernel-devel.rpm && dnf clean all
ENV KDIR=/opt/kernel

FROM kernel-build AS sparse
# A fresh build argument invalidates only this stage's source/build layer.
ARG ANALYZER_REFRESH
RUN bash /opt/scst-ci/install-analyzers sparse

FROM kernel-build AS smatch
RUN dnf install -y --setopt=install_weak_deps=False sqlite-devel && dnf clean all
COPY scripts/sparse_smatch/patches/typeof-address-space.patch \
     scripts/sparse_smatch/patches/install-assets.patch /opt/scst-ci/
# Refresh Smatch sources without invalidating its package or kernel layers.
ARG ANALYZER_REFRESH
RUN bash /opt/scst-ci/install-analyzers smatch

FROM kernel-build AS cppcheck
RUN dnf install -y --setopt=install_weak_deps=False cppcheck && dnf clean all

FROM base AS coccicheck
RUN dnf install -y --setopt=install_weak_deps=False coccinelle cpp && dnf clean all
COPY --from=kernel-files /opt/kernel/scripts/coccinelle /opt/coccinelle
COPY --from=kernel-files /usr/local/share/scst-ci/coccinelle-rules-source.txt /usr/local/share/scst-ci/
ENV COCCI_RULES_PATH=/opt/coccinelle

FROM base AS analyzer-tests
RUN dnf install -y --setopt=install_weak_deps=False gcc && dnf clean all
