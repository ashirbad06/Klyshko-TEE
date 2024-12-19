# Base image
FROM ghcr.io/carbynestack/spdz:5350e66

ARG UBUNTU_CODENAME=focal
ARG RELEASE_PAGE="https://github.com/carbynestack/klyshko/releases"
ARG MBEDTLS_VERSION="3.4.0"

# Update and install core dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl gnupg2 binutils ca-certificates

# Add Intel SGX and Gramine repositories
COPY azure_sgx_qcnl.conf /etc/sgx_default_qcnl.conf
RUN echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" > /etc/apt/sources.list.d/intel-sgx.list

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/gramine.list

# Install SGX and Gramine-related dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gramine \
    sgx-aesm-service \
    libsgx-aesm-launch-plugin \
    libsgx-aesm-epid-plugin \
    libsgx-aesm-quote-ex-plugin \
    libsgx-aesm-ecdsa-plugin \
    libsgx-dcap-quote-verify \
    psmisc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Additional development dependencies
RUN apt-get update && apt-get install -y \
    busybox \
    cargo \
    clang \
    cmake \
    cpio \
    curl \
    dwarves \
    g++-12 \
    gcc-12 \
    gdb \
    jq \
    kmod \
    libevent-dev \
    libmemcached-tools \
    libomp-dev \
    libssl-dev \
    libunwind8 \
    musl-tools \
    ncat \
    nginx \
    python3-numpy \
    python3-pytest \
    python3-pytest-xdist \
    python3-scipy \
    qemu-kvm \
    shellcheck \
    sqlite3 \
    zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install mbedTLS from source
RUN curl -fsSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz | tar -xz && \
    cd mbedtls-${MBEDTLS_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF .. && \
    make -j$(nproc) && \
    make install && \
    cd ../../ && rm -rf mbedtls-${MBEDTLS_VERSION}

# Set GCC-12 as the default compiler
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 10 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 10 && \
    update-alternatives --set gcc /usr/bin/gcc-12 && \
    update-alternatives --set g++ /usr/bin/g++-12

# Install wrk2 benchmark
RUN git clone https://github.com/giltene/wrk2.git && \
    cd wrk2 && \
    git checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7 && \
    make && \
    cp wrk /usr/local/bin && \
    cd .. && \
    rm -rf wrk2

# SGX configuration
COPY azure_sgx_qcnl.conf /etc/sgx_default_qcnl.conf
ENV SGX_AESM_ADDR=1
RUN mkdir -p /var/run/aesmd/
COPY restart_aesm.sh /restart_aesm.sh

# Application and build
COPY 3RD-PARTY-LICENSES /3RD-PARTY-LICENSES
COPY . .

RUN make clean && make SGX=1

# Generate Gramine manifest
RUN gramine-manifest -Dlog_level=error file_2.manifest.template file_2.manifest

# (Optional) Sign the Gramine manifest for SGX mode
# RUN gramine-sgx-sign --manifest file_2.manifest --output file_2.manifest.sgx

# Add third-party license information
RUN printf "\n## Klyshko MP-SPDZ\n\
General information about third-party software components and their licenses, \
which are distributed with Klyshko MP-SPDZ, can be found in the \
[SBOM](./sbom.json). Further details are available in the subfolder for the \
respective component or can be downloaded from the \
[Klyshko Release Page](%s).\n" "${RELEASE_PAGE}" \
  >> /3RD-PARTY-LICENSES/disclosure.md

# Default entry point
ENTRYPOINT ["/bin/bash", "-c", "gramine-sgx kii-run"]
