# syntax=docker/dockerfile:1.10.0
# SPDX-License-Identifier: Apache-2.0

ARG UBUNTU_VERSION=latest
FROM ubuntu:"$UBUNTU_VERSION" AS rootfs-builder

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install prerequisites/common utilities
WORKDIR /
ENV VENV=/.venv
ENV PATH="$VENV/bin:$PATH"
# hadolint ignore=DL3008,DL3013
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        build-essential \
        libglib2.0-dev \
        libfdt-dev \
        libpixman-1-dev \
        libslirp-dev \
        zlib1g-dev \
        libcap-ng-dev \
        libattr1-dev \
        ninja-build \
        libcurl4-openssl-dev \
        libstb-dev \
        git \
        wget \
        python3-pip \
        python3-venv \
        libclang-dev \
        pkg-config \
        iproute2 \
        openssh-client \
        iputils-ping \
        socat \
        vim \
        less \
        ca-certificates && \
    python3 -m venv "$VENV" && \
    pip install --no-cache-dir meson tomli && \
    rm -rf /var/cache/apt /var/lib/apt/lists/*

ARG ARCH_TAG=x86_64
ARG PREBUILT_ARTIFACTS_DIR=.
ARG BUILD_TYPE=release

# Install vAccel
WORKDIR /tmp/prebuilt
ARG VACCEL_VERSION=latest
RUN --mount=type=bind,rw,target=/tmp/prebuilt,source="$PREBUILT_ARTIFACTS_DIR" \
    deb_arch="$(dpkg-architecture -q DEB_BUILD_ARCH)" && \
    if [ "$VACCEL_VERSION" != 'latest' ]; then \
        deb="vaccel_${VACCEL_VERSION}-1_${deb_arch}.deb"; \
    else \
        deb=$(basename "$(find . -name "vaccel_*_${deb_arch}.deb" | \
            sort -r | head -1)") && \
        deb="${deb:-"vaccel_${VACCEL_VERSION}_${deb_arch}.deb"}"; \
    fi && \
    if [ ! -f "$deb" ]; then \
        skip_rm=0 && \
        base_url='https://s3.nbfc.io/nbfc-assets/github/vaccel/rev' && \
        main_url="${base_url}/main/${ARCH_TAG}/${BUILD_TYPE}" && \
        release_url="${base_url}/v${VACCEL_VERSION}/${ARCH_TAG}/${BUILD_TYPE}" && \
        if [ "$VACCEL_VERSION" != 'latest' ] && \
            [ "${VACCEL_VERSION#*-}" = "$VACCEL_VERSION" ]; then \
            wget --progress=dot:binary "${release_url}/${deb}"; \
        else \
            wget --progress=dot:binary "${main_url}/${deb}"; \
        fi; \
    else \
        skip_rm=1; \
    fi && \
    apt-get install -y --no-install-recommends "./${deb}" && \
    ldconfig && \
    if [ "$skip_rm" -ne 1 ]; then \
        rm -rf vaccel*.deb; \
    fi

# Build & install QEMU w/ vAccel backend
WORKDIR /qemu-vaccel
ARG QEMU_VACCEL_SRC=.
# hadolint ignore=DL3003
RUN --mount=type=secret,id=GIT_AUTH_TOKEN \
    --mount=type=bind,rw,target=/qemu-vaccel,source="$QEMU_VACCEL_SRC" \
    GIT_TOKEN_FILE=/run/secrets/GIT_AUTH_TOKEN && \
    if [ -n "$(cat "$GIT_TOKEN_FILE")" ]; then \
        git config --global \
            "url.https://x-access-token:$(cat "$GIT_TOKEN_FILE")@github.com/.insteadOf" \
            "https://github.com/"; \
    fi && \
    build_dir="$(pwd)/build_$$" && \
    docker_dir="$(pwd)/subprojects/vaccel-virtio/docker" && \
    mkdir "$build_dir" && cd "$build_dir" && \
    debug="" && \
    if [ "$BUILD_TYPE" = 'debug' ] || [ "$BUILD_TYPE" = 'debugoptimized' ]; then \
        debug="true"; \
    fi && \
    ../configure --target-list="${ARCH_TAG}-softmmu" --enable-virtfs \
        ${debug:+"--enable-debug"} && \
    make -j"$(nproc)" && make install && \
    cp "${docker_dir}/qemu-ifup" /usr/local/etc/qemu-ifup && \
    cp "${docker_dir}/qemu-script.sh" /run.sh && \
    cd - && rm -rf "$build_dir" && \
    if [ -n "$(cat "$GIT_TOKEN_FILE")" ]; then \
        git config --global --unset-all \
            "url.https://x-access-token:$(cat "$GIT_TOKEN_FILE")@github.com/.insteadOf"; \
    fi

VOLUME /data
WORKDIR /data
ENTRYPOINT ["/run.sh"]
