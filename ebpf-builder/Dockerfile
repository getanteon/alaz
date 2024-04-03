FROM ubuntu:22.04

ENV LIBBPF_VERSION 1.2.2
ENV GOLANG_VERSION 1.22.1

# Install Clang and LLVM Strip
RUN apt-get update && apt-get install -y clang-14 llvm && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Make
RUN apt-get update && apt-get install -y make
RUN apt-get install -y gcc-multilib

# Install libbpf dependencies
RUN apt-get update && apt-get install -y bison build-essential cmake flex git libelf-dev libssl-dev libudev-dev pkg-config wget

# Install libbpf
RUN wget --quiet https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz && \
    tar -xzf v${LIBBPF_VERSION}.tar.gz && \
    rm v${LIBBPF_VERSION}.tar.gz && \
    cd libbpf-${LIBBPF_VERSION}/src && \
    make && make install

# Install Go
RUN wget -q https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Set the working directory
WORKDIR /app

# Copy your application code to the container
COPY . /app

# Run your application
CMD ["bash"]
