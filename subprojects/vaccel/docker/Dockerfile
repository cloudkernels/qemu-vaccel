FROM ubuntu:24.04

WORKDIR /

# Install common build utilities
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yy eatmydata && \
    DEBIAN_FRONTEND=noninteractive eatmydata \
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
        git \
        python3-pip \
        libclang-dev \
        pkg-config \
        iproute2 \
        openssh-client \
        iputils-ping \
        socat \
        vim \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --break-system-packages meson

# Build & install vAccel
RUN git clone https://github.com/nubificus/vaccel && \
    cd vaccel && \
    meson setup -Dplugins=enabled -Dexamples=enabled build && \
    meson compile -C build && \
    meson install -C build && \
    ldconfig && \
    cd .. && rm -rf vaccel

ARG BRANCH=master+vaccel
ARG ARCHTAG=x86_64
ARG DOCKER_DIR=.
COPY ${DOCKER_DIR}/vq-size.patch /vq-size.patch
# Build & install QEMU w/ vAccel backend
RUN git clone -b ${BRANCH} --depth 1 \
    https://github.com/cloudkernels/qemu-vaccel && \
    cd qemu-vaccel && \
    mv /vq-size.patch . && \
    git apply vq-size.patch && \
    mkdir build && cd build && \
    ../configure --target-list=${ARCHTAG}-softmmu --enable-virtfs && \
    make -j$(nproc) && make install && \
    cd ../.. && rm -rf qemu-vaccel

COPY ${DOCKER_DIR}/qemu-ifup /usr/local/etc/qemu-ifup
COPY ${DOCKER_DIR}/qemu-script.sh /run.sh

VOLUME /data
WORKDIR /data
ENTRYPOINT ["/run.sh"]
