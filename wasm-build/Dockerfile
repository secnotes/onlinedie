# Dockerfile for building DIE WebAssembly module
# This provides a consistent build environment with all dependencies

FROM emscripten/emsdk:3.1.51

LABEL maintainer="DIE WebAssembly Builder"
LABEL description="Build environment for DIE WASM module"

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y \
    cmake \
    git \
    python3 \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Copy build scripts
COPY scripts/build-deps.sh /build/scripts/build-deps.sh
COPY build.sh /build/build.sh
COPY src/ /build/src/

# Make scripts executable
RUN chmod +x /build/scripts/build-deps.sh /build/build.sh

# Build dependencies
RUN cd /build/scripts && ./build-deps.sh all

# Build WASM module
RUN cd /build/src && \
    mkdir -p build-wasm && cd build-wasm && \
    DEPS_INSTALL=/build/deps/install && \
    emcmake cmake .. \
        -DZLIB_ROOT=$DEPS_INSTALL \
        -DBZIP2_ROOT=$DEPS_INSTALL \
        -DLIBLZMA_ROOT=$DEPS_INSTALL \
        -DCAPSTONE_ROOT=$DEPS_INSTALL \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_CAPSTONE=OFF \
    && \
    emmake make -j4

# Output directory
RUN mkdir -p /output

# Copy output files
RUN cp /build/src/build-wasm/diec.* /output/ 2>/dev/null || \
    echo "Note: WASM files need to be built separately"

# Default command - show usage
CMD ["bash", "-c", "echo 'WASM build ready. To extract files, run:' && echo 'docker cp <container>:/build/src/build-wasm/. ./docs/wasm/'"]

# Alternative: Build and copy to output volume
# Mount output volume: docker run -v ./docs/wasm:/output die-wasm-builder