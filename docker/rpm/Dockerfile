ARG BASE_IMAGE
FROM ${BASE_IMAGE}

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ARG KERNEL_PACKAGE=kernel
ARG KERNEL_VERSION
ARG KERNEL_REPOSITORY=

ENV LANG=C \
    LC_ALL=C

RUN : "${KERNEL_PACKAGE:?KERNEL_PACKAGE is required}" \
    && : "${KERNEL_VERSION:?KERNEL_VERSION is required}" \
    && repo_args=() \
    && if [[ -n "${KERNEL_REPOSITORY}" ]]; then \
        repo_args+=(--enablerepo="${KERNEL_REPOSITORY}"); \
    fi \
    && dnf -y install \
        bzip2 \
        elfutils-libelf-devel \
        findutils \
        gcc \
        git \
        kmod \
        make \
        openssl \
        perl \
        perl-Data-Dumper \
        perl-devel \
        perl-ExtUtils-MakeMaker \
        redhat-rpm-config \
        rpm-build \
        systemd-rpm-macros \
        tar \
        which \
    && dnf -y "${repo_args[@]}" install \
        "${KERNEL_PACKAGE}-${KERNEL_VERSION}" \
        "${KERNEL_PACKAGE}-devel-${KERNEL_VERSION}" \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD ["/bin/bash"]
