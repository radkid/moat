FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# Optional build args to install Ubuntu mainline kernel headers (e.g., 6.10)
# Note: Container still uses host kernel; headers are for building only.
ARG INSTALL_MAINLINE_HEADERS=false
ARG KERNEL_VER=6.10.14
ARG KERNEL_UBUNTU_TAG=061014

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    zlib1g-dev libzstd-dev pkg-config \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    gcc \
    make \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    openssh-client \
    git \
    curl \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Build bpftool from source
RUN git clone --depth=1 --branch v6.10 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git /tmp/linux
RUN make -C /tmp/linux/tools/bpf/bpftool -j$(nproc)

# Create non-root user to match devcontainer settings
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Optional Rust install (kept from original); runs as root by default
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

USER $USERNAME
WORKDIR /home/$USERNAME/workspace