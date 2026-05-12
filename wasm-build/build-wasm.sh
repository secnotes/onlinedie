#!/bin/bash
# Build DIE WASM from DIE-engine source
# This script clones DIE-engine and compiles diec to WebAssembly

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
DIE_DIR="$SCRIPT_DIR/DIE-engine"
OUTPUT_DIR="$SCRIPT_DIR/../docs/wasm"

echo "=== DIE WASM Build Script ==="

# Check Emscripten
check_emscripten() {
    if ! command -v emcc &> /dev/null; then
        echo "Error: Emscripten not found!"
        echo "Install Emscripten SDK:"
        echo "  git clone https://github.com/emscripten-core/emsdk.git"
        echo "  cd emsdk && ./emsdk install latest && ./emsdk activate latest"
        echo "  source ./emsdk_env.sh"
        exit 1
    fi
    echo "Emscripten: $(emcc --version | head -1)"
}

# Clone DIE-engine
clone_die() {
    if [ -d "$DIE_DIR" ]; then
        echo "DIE-engine already exists, updating..."
        cd "$DIE_DIR" && git pull
    else
        echo "Cloning DIE-engine..."
        git clone --recursive --depth 1 https://github.com/horsicq/DIE-engine.git "$DIE_DIR"
    fi
}

# Create WASM export wrapper
create_wasm_wrapper() {
    echo "Creating WASM export wrapper..."

    WRAPPER_FILE="$DIE_DIR/console_source/die_wasm_export.cpp"

    cat > "$WRAPPER_FILE" << 'EXPORTCODE'
// WASM Export Interface for DIE-engine
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/bind.h>
#include <string>
#include <QFile>
#include <QFileInfo>
#include "die_scriptengine.h"

// Global result storage
static std::string g_result;

// Simple detection function
extern "C" EMSCRIPTEN_KEEPALIVE
const char* die_detect(const char* filename) {
    g_result.clear();

    try {
        // Create signature engine
        XScriptEngine engine;

        // Get file info
        QFileInfo info(filename);
        if (!info.exists()) {
            g_result = "{\"error\":\"File not found\"}";
            return g_result.c_str();
        }

        // Run detection
        QString result = engine.detect(filename);

        // Convert to JSON format
        // Parse DIE output and format as JSON
        g_result = parseResultToJson(result.toStdString());
    } catch (const std::exception& e) {
        g_result = "{\"error\":\"" + std::string(e.what()) + "\"}";
    }

    return g_result.c_str();
}

// Parse DIE text output to JSON
std::string parseResultToJson(const std::string& dieOutput) {
    std::string json = "{";
    json += "\"raw\":\"" + escapeJson(dieOutput) + "\",";
    json += "\"detections\":[";

    // Parse DIE format: "Compiler(GCC)(Library: libstdc++)"
    // Extract compiler, packer, etc.

    std::vector<std::string> detections;

    // Match patterns
    std::regex compilerRegex("Compiler\\(([^)]+)\\)");
    std::regex packerRegex("Packer\\(([^)]+)\\)");
    std::regex linkerRegex("Linker\\(([^)]+)\\)");
    std::regex protectorRegex("Protector\\(([^)]+)\\)");
    std::regex libraryRegex("Library\\(([^)]+)\\)");

    std::string text = dieOutput;

    // Find all matches
    auto addDetection = [&](const std::string& type, const std::string& name) {
        detections.push_back("{\"type\":\"" + type + "\",\"name\":\"" + escapeJson(name) + "\"}");
    };

    std::sregex_iterator it(text.begin(), text.end(), compilerRegex);
    std::sregex_iterator end;
    while (it != end) {
        addDetection("compiler", it->str(1));
        ++it;
    }

    it = std::sregex_iterator(text.begin(), text.end(), packerRegex);
    while (it != end) {
        addDetection("packer", it->str(1));
        ++it;
    }

    it = std::sregex_iterator(text.begin(), text.end(), linkerRegex);
    while (it != end) {
        addDetection("compiler", it->str(1));
        ++it;
    }

    it = std::sregex_iterator(text.begin(), text.end(), protectorRegex);
    while (it != end) {
        addDetection("protector", it->str(1));
        ++it;
    }

    it = std::sregex_iterator(text.begin(), text.end(), libraryRegex);
    while (it != end) {
        addDetection("library", it->str(1));
        ++it;
    }

    // Join detections
    for (size_t i = 0; i < detections.size(); i++) {
        json += detections[i];
        if (i < detections.size() - 1) json += ",";
    }

    json += "]}";

    return json;
}

// Escape string for JSON
std::string escapeJson(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

// Emscripten bindings
EMSCRIPTEN_BINDINGS(die_module) {
    emscripten::function("die_detect", &die_detect);
}

#endif // __EMSCRIPTEN__
EXPORTCODE

    echo "WASM wrapper created"
}

# Modify CMakeLists for WASM
modify_cmake() {
    echo "Modifying CMakeLists for WASM..."

    CMAKE_FILE="$DIE_DIR/console_source/CMakeLists.txt"

    # Backup original
    cp "$CMAKE_FILE" "$CMAKE_FILE.bak"

    # Add WASM configuration
    cat >> "$CMAKE_FILE" << 'CMAKECODE'

# WASM Configuration
if(EMSCRIPTEN)
    message(STATUS "Building for WebAssembly")

    # Add WASM export source
    target_sources(diec PRIVATE die_wasm_export.cpp)

    # WASM compile flags
    set_target_properties(diec PROPERTIES
        OUTPUT_NAME "diec"
        SUFFIX ".js"
    )

    target_compile_options(diec PRIVATE
        -sUSE_QT=6
        -sEXPORT_ES6=1
        -sMODULARIZE=1
        -sEXPORT_NAME="createDieModule"
        -sALLOW_MEMORY_GROWTH=1
        -sINITIAL_MEMORY=32MB
    )

    # WASM link flags
    target_link_options(diec PRIVATE
        -sUSE_QT=6
        -sEXPORT_ES6=1
        -sMODULARIZE=1
        -sEXPORT_NAME="createDieModule"
        -sALLOW_MEMORY_GROWTH=1
        -sINITIAL_MEMORY=32MB
        -sEXPORTED_RUNTIME_METHODS=['FS','ccall','cwrap','UTF8ToString','allocate','ALLOC_NORMAL']
        -sEXPORTED_FUNCTIONS=['_die_detect','_malloc','_free','main']
        --embind
        -sFORCE_FILESYSTEM=1
        --preload-file "${CMAKE_SOURCE_DIR}/Detect-It-Easy/db@/db"
        -O3
    )
endif()
CMAKECODE

    echo "CMakeLists modified"
}

# Build WASM
build_wasm() {
    echo "Building WASM..."

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure with Emscripten
    emcmake cmake "$DIE_DIR" \
        -DQt6_DIR="${QT_WASM_DIR:-$HOME/Qt/6.8.0/wasm_singlethread}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF

    # Build
    emmake make -j$(nproc) diec

    echo "WASM build complete"
}

# Copy output
copy_output() {
    echo "Copying WASM output..."

    mkdir -p "$OUTPUT_DIR"

    # Copy generated files
    cp "$BUILD_DIR/console_source/diec.js" "$OUTPUT_DIR/"
    cp "$BUILD_DIR/console_source/diec.wasm" "$OUTPUT_DIR/" 2>/dev/null || true
    cp "$BUILD_DIR/console_source/diec.data" "$OUTPUT_DIR/" 2>/dev/null || true

    # Show output
    ls -lh "$OUTPUT_DIR"

    echo "WASM files copied to docs/wasm/"
}

# Main
main() {
    check_emscripten
    clone_die
    create_wasm_wrapper
    modify_cmake
    build_wasm
    copy_output

    echo ""
    echo "=== Build Complete ==="
    echo "WASM files: docs/wasm/diec.js, diec.wasm"
    echo "Open docs/index.html to test"
}

main "$@"