#!/bin/bash
# DIE WebAssembly Build Script
# This script compiles DIE engine and dependencies to WebAssembly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "${GREEN}=== DIE WebAssembly Build Script ===${NC}"

# Check for Emscripten
check_emscripten() {
    if ! command -v emcc &> /dev/null; then
        echo "${RED}Error: Emscripten not found!${NC}"
        echo "Please install Emscripten SDK:"
        echo "  git clone https://github.com/emscripten-core/emsdk.git"
        echo "  cd emsdk && ./emsdk install latest && ./emsdk activate latest"
        echo "  source ./emsdk_env.sh"
        exit 1
    fi
    echo "${GREEN}Emscripten found: $(emcc --version)${NC}"
}

# Check for Qt WASM
check_qt_wasm() {
    if [ -z "$QT_WASM_DIR" ]; then
        echo "${YELLOW}Warning: QT_WASM_DIR not set${NC}"
        echo "Qt for WebAssembly is optional but recommended for full functionality"
        echo "Set QT_WASM_DIR to your Qt WASM installation path"
    else
        echo "${GREEN}Qt WASM found at: $QT_WASM_DIR${NC}"
    fi
}

# Build dependencies
build_deps() {
    echo "${YELLOW}Building dependencies...${NC}"

    DEPS_DIR="$(pwd)/deps"
    INSTALL_DIR="$DEPS_DIR/install"

    mkdir -p "$INSTALL_DIR"

    # zlib
    if [ ! -d "$DEPS_DIR/zlib" ]; then
        echo "Downloading zlib..."
        git clone --depth 1 https://github.com/madler/zlib.git "$DEPS_DIR/zlib"
    fi

    echo "Building zlib for WASM..."
    cd "$DEPS_DIR/zlib"
    mkdir -p build-wasm && cd build-wasm
    emcmake cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DCMAKE_BUILD_TYPE=Release -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_STATIC=ON
    emmake make -j$(nproc) install
    cd "$DEPS_DIR"

    # bzip2
    if [ ! -d "$DEPS_DIR/bzip2" ]; then
        echo "Downloading bzip2..."
        git clone --depth 1 https://github.com/libarchive/bzip2.git "$DEPS_DIR/bzip2"
    fi

    echo "Building bzip2 for WASM..."
    cd "$DEPS_DIR/bzip2"
    mkdir -p build-wasm && cd build-wasm
    emcmake cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DCMAKE_BUILD_TYPE=Release -DENABLE_SHARED_LIB=OFF
    emmake make -j$(nproc) install
    cd "$DEPS_DIR"

    # liblzma (xz)
    if [ ! -d "$DEPS_DIR/xz" ]; then
        echo "Downloading xz (liblzma)..."
        git clone --depth 1 https://github.com/tukaani-project/xz.git "$DEPS_DIR/xz"
    fi

    echo "Building liblzma for WASM..."
    cd "$DEPS_DIR/xz"
    mkdir -p build-wasm && cd build-wasm
    emcmake cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
    emmake make -j$(nproc) install
    cd "$DEPS_DIR"

    # capstone
    if [ ! -d "$DEPS_DIR/capstone" ]; then
        echo "Downloading capstone..."
        git clone --depth 1 https://github.com/capstone-engine/capstone.git "$DEPS_DIR/capstone"
    fi

    echo "Building capstone for WASM..."
    cd "$DEPS_DIR/capstone"
    mkdir -p build-wasm && cd build-wasm
    emcmake cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_SHARED=OFF
    emmake make -j$(nproc) install
    cd "$DEPS_DIR"

    echo "${GREEN}Dependencies built successfully!${NC}"
}

# Clone DIE-engine
clone_die() {
    DIE_DIR="$(pwd)/DIE-engine"

    if [ ! -d "$DIE_DIR" ]; then
        echo "${YELLOW}Cloning DIE-engine...${NC}"
        git clone --recursive --depth 1 https://github.com/horsicq/DIE-engine.git "$DIE_DIR"
    else
        echo "${GREEN}DIE-engine already cloned${NC}"
    fi
}

# Build standalone WASM (simplified version without dependencies)
build_wasm_standalone() {
    echo "${YELLOW}Building standalone WASM module...${NC}"

    BUILD_DIR="$(pwd)/build"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Build using our custom CMakeLists (no dependencies needed)
    emcmake cmake ../src \
        -DCMAKE_BUILD_TYPE=Release

    emmake make -j$(nproc)

    echo "${GREEN}WASM build complete!${NC}"
}

# Package signature database
package_signatures() {
    echo "${YELLOW}Packaging signature database...${NC}"

    DIE_DIR="$(pwd)/DIE-engine"
    OUTPUT_DIR="$(pwd)/../docs/wasm"

    if [ -d "$DIE_DIR/Detect-It-Easy/db" ]; then
        # Copy signature database
        mkdir -p "$OUTPUT_DIR/db"
        cp -r "$DIE_DIR/Detect-It-Easy/db"/* "$OUTPUT_DIR/db/"

        # Count signatures
        PE_COUNT=$(find "$OUTPUT_DIR/db/PE" -name "*.sg" 2>/dev/null | wc -l)
        ELF_COUNT=$(find "$OUTPUT_DIR/db/ELF" -name "*.sg" 2>/dev/null | wc -l)
        MSDOS_COUNT=$(find "$OUTPUT_DIR/db/MSDOS" -name "*.sg" 2>/dev/null | wc -l)

        echo "${GREEN}Signatures packaged:${NC}"
        echo "  PE: $PE_COUNT signatures"
        echo "  ELF: $ELF_COUNT signatures"
        echo "  MSDOS: $MSDOS_COUNT signatures"
    else
        echo "${YELLOW}Warning: DIE signature database not found${NC}"
        echo "Using JavaScript fallback signatures"
    fi
}

# Optimize WASM output
optimize_wasm() {
    echo "${YELLOW}Optimizing WASM output...${NC}"

    OUTPUT_DIR="$(pwd)/../docs/wasm"

    if [ -f "$OUTPUT_DIR/diec.wasm" ]; then
        # WASM files are already copied by CMake POST_BUILD
        # Optimize with wasm-opt if available
        if command -v wasm-opt &> /dev/null; then
            echo "Running wasm-opt optimization..."
            wasm-opt -O3 "$OUTPUT_DIR/diec.wasm" -o "$OUTPUT_DIR/diec.optimized.wasm"
            mv "$OUTPUT_DIR/diec.optimized.wasm" "$OUTPUT_DIR/diec.wasm"
        fi

        echo "${GREEN}WASM files ready in docs/wasm/${NC}"
        ls -lh "$OUTPUT_DIR/diec.*"
    else
        echo "${RED}WASM build failed - no output files${NC}"
        exit 1
    fi
}

# Main execution
main() {
    check_emscripten
    check_qt_wasm

    # If --deps flag, only build dependencies
    if [ "$1" == "--deps" ]; then
        build_deps
        exit 0
    fi

    # If --wasm flag, only build WASM (assumes deps are built)
    if [ "$1" == "--wasm" ]; then
        build_wasm_standalone
        optimize_wasm
        exit 0
    fi

    # Full build
    build_deps
    clone_die
    build_wasm_standalone
    package_signatures
    optimize_wasm

    echo "${GREEN}=== Build Complete ===${NC}"
    echo "WASM files located in: docs/wasm/"
}

main "$@"