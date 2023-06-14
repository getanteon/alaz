FROM ubuntu:22.04

# Install Clang and LLVM Strip
RUN apt-get update && apt-get install -y clang-14 llvm && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Make
RUN apt-get update && apt-get install -y make
RUN apt-get install -y gcc-multilib

# Install libbpf dependencies
RUN apt-get update && apt-get install -y bison build-essential cmake flex git libelf-dev libssl-dev libudev-dev pkg-config

# Install libbpf
RUN git clone --depth 1 https://github.com/libbpf/libbpf && \
    cd libbpf/src && \
    make && make install

# Install Go 1.20.5
ENV GOLANG_VERSION 1.20.5
RUN apt-get update && apt-get install -y wget && \
    wget -q https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Set the working directory
WORKDIR /app

# Copy your application code to the container
COPY . /app

# Run your application
CMD ["bash"]
