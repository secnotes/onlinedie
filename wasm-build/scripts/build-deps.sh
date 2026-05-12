#!/bin/bash
# Build individual dependencies for WASM
# Usage: ./build-deps.sh [zlib|bzip2|lzma|capstone|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="$SCRIPT_DIR/../deps"
INSTALL_DIR="$DEPS_DIR/install"

mkdir -p "$DEPS_DIR" "$INSTALL_DIR"

build_zlib() {
    echo "Building zlib for WASM..."

    if [ ! -d "$DEPS_DIR/zlib" ]; then
        git clone --depth 1 https://github.com/madler/zlib.git "$DEPS_DIR/zlib"
    fi

    cd "$DEPS_DIR/zlib"
    rm -rf build-wasm
    mkdir -p build-wasm && cd build-wasm

    emcmake cmake .. \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-O3"

    emmake make -j$(nproc) install
    echo "zlib installed to $INSTALL_DIR"
}

build_bzip2() {
    echo "Building bzip2 for WASM..."

    if [ ! -d "$DEPS_DIR/bzip2" ]; then
        git clone --depth 1 https://github.com/libarchive/bzip2.git "$DEPS_DIR/bzip2"
    fi

    cd "$DEPS_DIR/bzip2"
    rm -rf build-wasm
    mkdir -p build-wasm && cd build-wasm

    emcmake cmake .. \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_SHARED_LIB=OFF \
        -DCMAKE_C_FLAGS="-O3"

    emmake make -j$(nproc) install
    echo "bzip2 installed to $INSTALL_DIR"
}

build_lzma() {
    echo "Building liblzma for WASM..."

    if [ ! -d "$DEPS_DIR/xz" ]; then
        git clone --depth 1 https://github.com/tukaani-project/xz.git "$DEPS_DIR/xz"
    fi

    cd "$DEPS_DIR/xz"
    rm -rf build-wasm
    mkdir -p build-wasm && cd build-wasm

    emcmake cmake .. \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_C_FLAGS="-O3"

    emmake make -j$(nproc) install
    echo "liblzma installed to $INSTALL_DIR"
}

build_capstone() {
    echo "Building capstone for WASM..."

    if [ ! -d "$DEPS_DIR/capstone" ]; then
        git clone --depth 1 --branch next https://github.com/capstone-engine/capstone.git "$DEPS_DIR/capstone"
    fi

    cd "$DEPS_DIR/capstone"
    rm -rf build-wasm
    mkdir -p build-wasm && cd build-wasm

    emcmake cmake .. \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCAPSTONE_BUILD_SHARED=OFF \
        -DCAPSTONE_ARCHITECTURES="x86;arm;arm64;mips" \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCMAKE_C_FLAGS="-O3"

    emmake make -j$(nproc) install
    echo "capstone installed to $INSTALL_DIR"
}

case "$1" in
    zlib)   build_zlib ;;
    bzip2)  build_bzip2 ;;
    lzma)   build_lzma ;;
    capstone) build_capstone ;;
    all)
        build_zlib
        build_bzip2
        build_lzma
        build_capstone
        ;;
    *)
        echo "Usage: $0 [zlib|bzip2|lzma|capstone|all]"
        echo "Building all dependencies..."
        build_zlib
        build_bzip2
        build_lzma
        build_capstone
        ;;
esac

echo "All dependencies built successfully!"