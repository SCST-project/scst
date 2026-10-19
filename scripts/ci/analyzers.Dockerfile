# SPDX-License-Identifier: GPL-2.0-only
FROM fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80
RUN dnf install -y --setopt=install_weak_deps=False \
        gcc make git python3 perl elfutils-libelf-devel openssl openssl-devel \
        sqlite-devel flex bison pkgconf-pkg-config diffutils findutils \
        curl-minimal xz tar gzip dwarves coccinelle cppcheck && dnf clean all

COPY scripts/ci/kernel.env scripts/ci/kernel.SHA256SUMS /opt/scst-ci/
COPY scripts/ci/analyzers.env scripts/ci/install-analyzers /opt/scst-ci/
COPY scripts/sparse_smatch/patches/typeof-address-space.patch /opt/scst-ci/
RUN bash /opt/scst-ci/install-analyzers
WORKDIR /scst
ENV PYTHONDONTWRITEBYTECODE=1
