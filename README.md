<div align="center">

# Detect It Easy - Web

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/Platform-WebAssembly-orange.svg)](https://webassembly.org/)
[![Qt](https://img.shields.io/badge/Qt-6.11.1-green.svg)](https://doc.qt.io/qt-6/wasm.html)
[![Emscripten](https://img.shields.io/badge/Emscripten-4.0.7-purple.svg)](https://emscripten.org/)
[![Signatures](https://img.shields.io/badge/Signatures-800+-red.svg)](#signature-coverage)
[![Demo](https://img.shields.io/badge/Demo-Live-brightgreen.svg)](https://secnotes.github.io/onlinedie/)

**[Detect It Easy](https://github.com/horsicq/DIE-engine) compiled to WebAssembly, running entirely in the browser.**

</div>

## Features

- **Pure Frontend**: No server required, runs entirely in browser
- **100% Signature Coverage**: All 800+ DIE signatures included
- **Multiple Formats**: PE, ELF, Mach-O, MSDOS, COM, ZIP, APK, JAR, DEX, Java Class, PDF, PNG, JPEG, etc.
- **Multiple Output Formats**: Text, JSON, XML
- **Detailed Analysis**: File hashes (MD5, SHA256), entropy calculation
- **Offline**: Works without network connection

## Demo

Upload any file to detect:
- File format with detailed info (e.g., `PNG[512x512, 8 bits, RGBA]`)
- Compiler/Linker identification (Visual C++, GCC, Rust, Go, etc.)
- Packer/Protector detection (UPX, ASPack, MPRESS, etc.)
- Library/Framework detection (.NET, MFC, Unity, etc.)

## Usage

1. Start HTTP server (WASM requires HTTP protocol):
```bash
cd docs
python3 -m http.server 8080
```

2. Open http://localhost:8080

3. Upload or drag-drop a file

**Note**: WASM cannot load from `file://` protocol. Must use HTTP server.

## Project Structure

```
.
├── docs/                    # Frontend
│   ├── index.html           # Main page
│   ├── css/style.css        # Styles
│   ├── js/
│   │   ├── app.js           # Application logic
│   │   └── md5.js           # MD5 calculation
│   └── wasm/                # WASM module
│       ├── diec.js          # ES6 loader (~309KB)
│       ├── diec.wasm        # WASM binary (~11MB)
│       └── diec.data        # Signature database (~2.8MB)
│
├── wasm-build/              # WASM build scripts
│   └── deps/DIE-engine/     # DIE-engine source
│
└── README.md
```

## Build WASM

### Prerequisites

1. **Emscripten 4.0.7** (matches Qt 6.11.1):
```bash
git clone https://github.com/emscripten-core/emsdk.git ~/emsdk
cd ~/emsdk
./emsdk install 4.0.7
./emsdk activate 4.0.7
source ~/emsdk/emsdk_env.sh
```

2. **Qt 6.11.1 WASM**:
```bash
pip install aqtinstall
aqt install-qt all_os wasm 6.11.1 wasm_singlethread -O ~/Qt
aqt install-qt linux desktop 6.11.1 linux_gcc_64 -O ~/Qt
```

### Build

```bash
cd wasm-build
source ~/emsdk/emsdk_env.sh

# Clone DIE-engine with submodules
git clone --recursive https://github.com/horsicq/DIE-engine.git deps/DIE-engine

# Build
cd deps/DIE-engine
mkdir build-wasm && cd build-wasm
cmake .. \
    -DCMAKE_PREFIX_PATH=$HOME/Qt/6.11.1/wasm_singlethread/lib/cmake/Qt6 \
    --toolchain $HOME/Qt/6.11.1/wasm_singlethread/lib/cmake/Qt6/qt.toolchain.cmake \
    -DQT_HOST_PATH=$HOME/Qt/6.11.1/gcc_64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-Dregister=''"
emmake make -j4 diec

# Copy output
cp release/diec.* ../../docs/wasm/
```

## Output Format

### Text (default, similar to `diec -p`)
```
PNG
    Format: PNG[48x48, 8 bits, RGBA, bKGD: rgb=(255,255,255)]
```

### JSON
```json
{"format":{"format":"PNG","fullName":"Portable Network Graphics"...}}
```

### XML
```xml
<?xml version="1.0" encoding="UTF-8"?>
<detect><format><name>PNG</name>...</format></detect>
```

## Signature Coverage

| Format | Signatures |
|--------|------------|
| PE | 781 |
| ELF | 43 |
| MSDOS | 349 |
| APK | 42 |
| Archive | 60+ |
| Image | 20+ |
| PDF | 15+ |
| **Total** | **800+** |

## Technical Details

- **WASM Size**: ~14MB total (engine + Qt + signatures)
- **Qt WASM**: Uses Qt 6.11.1 for QJSEngine (signature execution)
- **Emscripten**: Version 4.0.7 (ABI compatible with Qt)
- **FS**: Virtual filesystem for file handling

## Credits

- [DIE-engine](https://github.com/horsicq/DIE-engine) - Original project
- [Qt WASM](https://doc.qt.io/qt-6/wasm.html) - Qt WebAssembly
- [Emscripten](https://emscripten.org/) - WASM toolchain

## License

MIT License