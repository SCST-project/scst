# SPDX-License-Identifier: GPL-2.0-only
FROM fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80 AS runtime
ARG SUITE
ARG KERNEL_BUILD
# The pinned kernel rpms, matching KERNEL_BUILD. The package split varies by
# release, so the checksum file also lists which rpms to install.
ARG KERNEL_SUMS=kernel.SHA256SUMS
ENV KVER=${KERNEL_BUILD}.x86_64
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOCACHE=/opt/go-cache GOMODCACHE=/opt/go-mod
COPY scripts/ci/${KERNEL_SUMS} /tmp/kernel.SHA256SUMS
RUN dnf install -y --setopt=install_weak_deps=False \
        make kmod python3 perl perl-Config-General perl-Data-Dumper \
        systemd systemd-udev dracut util-linux procps-ng iproute \
        openssh-server openssh-clients iscsi-initiator-utils sg3_utils fio \
        findutils diffutils tar gzip curl-minimal && \
    if [ "$SUITE" = ginkgo ]; then dnf install -y golang; fi && \
    mkdir /tmp/kernel && cd /tmp/kernel && \
    for package in $(awk '{print $2}' /tmp/kernel.SHA256SUMS); do \
        curl --fail --location --retry 3 \
            "https://kojipkgs.fedoraproject.org/packages/kernel/${KERNEL_BUILD%-*}/${KERNEL_BUILD#*-}/x86_64/$package" \
            --output "$package"; \
    done && \
    sha256sum --check /tmp/kernel.SHA256SUMS && \
    dnf install -y --setopt=install_weak_deps=False \
        $(find . -name 'kernel-*.rpm' ! -name 'kernel-devel-*' | sort) && \
    depmod "$KVER" && \
    dracut --force --no-hostonly --no-hostonly-cmdline --no-early-microcode \
        --add-drivers 'virtio_pci virtio_blk virtio_net 9p 9pnet_virtio' \
        --filesystems ext4 /boot/ci-initramfs "$KVER" && \
    cp "/lib/modules/$KVER/vmlinuz" /boot/ci-vmlinuz && \
    cp "/lib/modules/$KVER/config" "/boot/config-$KVER" && \
    dnf clean all

FROM runtime AS build
ARG SUITE
ARG SOURCE_COMMIT
RUN dnf install -y --setopt=install_weak_deps=False \
        gcc elfutils-libelf-devel openssl openssl-devel perl-ExtUtils-MakeMaker git patch \
        /tmp/kernel/kernel-devel-*.rpm && dnf clean all
COPY . /scst
WORKDIR /scst
RUN bash scripts/ci/build-guest "$SUITE" "$SOURCE_COMMIT"

FROM runtime
COPY --from=build /scst /scst
COPY --from=build /opt/go-cache /opt/go-cache
COPY --from=build /opt/go-mod /opt/go-mod
COPY --from=build /opt/ci-build /opt/ci-build
COPY scripts/ci/scst-ci.service /etc/systemd/system/scst-ci.service
COPY scripts/ci/scst-ci.target /etc/systemd/system/scst-ci.target
RUN rm -rf /tmp/kernel /tmp/kernel.SHA256SUMS /var/cache/* && \
    mkdir -p /ci/input /ci/reports /ci/backing /root/.ssh /run/sshd && \
    chmod 700 /root/.ssh && \
    sed -i 's/^root:[^:]*:/root::/' /etc/shadow
ENV GOPROXY=off
