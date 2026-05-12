<div align="center">

# Detect It Easy - Web

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/Platform-WebAssembly-orange.svg)](https://webassembly.org/)
[![Qt](https://img.shields.io/badge/Qt-6.11.1-green.svg)](https://doc.qt.io/qt-6/wasm.html)
[![Emscripten](https://img.shields.io/badge/Emscripten-4.0.7-purple.svg)](https://emscripten.org/)
[![Signatures](https://img.shields.io/badge/Signatures-800+-red.svg)](#签名覆盖)
[![Demo](https://img.shields.io/badge/Demo-Live-brightgreen.svg)](https://secnotes.github.io/onlinedie/)

**[Detect It Easy](https://github.com/horsicq/DIE-engine) 编译为 WebAssembly，完全在浏览器中运行。**

</div>

## 特性

- **纯前端**：无需服务器，完全在浏览器运行
- **100% 签名覆盖**：包含全部 800+ DIE 签名
- **多格式支持**：PE、ELF、Mach-O、MSDOS、COM、ZIP、APK、JAR、DEX、Java Class、PDF、PNG、JPEG 等
- **多种输出格式**：文本、JSON、XML
- **详细分析**：文件哈希（MD5、SHA256）、熵值计算
- **离线可用**：无需网络连接即可工作

## 演示

上传任意文件可检测：
- 文件格式详细信息（如 `PNG[512x512, 8 bits, RGBA]`）
- 编译器/链接器识别（Visual C++、GCC、Rust、Go 等）
- 打包器/保护器检测（UPX、ASPack、MPRESS 等）
- 库/框架检测（.NET、MFC、Unity 等）

## 使用方法

1. 启动 HTTP 服务器（WASM 需要 HTTP 协议）：
```bash
cd docs
python3 -m http.server 8080
```

2. 打开 http://localhost:8080

3. 上传或拖放文件

**注意**：WASM 无法从 `file://` 协议加载，必须使用 HTTP 服务器。

## 项目结构

```
.
├── docs/                    # 前端
│   ├── index.html           # 主页面
│   ├── css/style.css        # 样式
│   ├── js/
│   │   ├── app.js           # 应用逻辑
│   │   └── md5.js           # MD5 计算
│   └── wasm/                # WASM 模块
│       ├── diec.js          # ES6 加载器（约309KB）
│       ├── diec.wasm        # WASM 二进制（约11MB）
│       └── diec.data        # 签名数据库（约2.8MB）
│
├── wasm-build/              # WASM 构建脚本
│   └── deps/DIE-engine/     # DIE-engine 源码
│
└── README.md
```

## 编译 WASM

### 前置要求

1. **Emscripten 4.0.7**（需与 Qt 6.11.1 匹配）：
```bash
git clone https://github.com/emscripten-core/emsdk.git ~/emsdk
cd ~/emsdk
./emsdk install 4.0.7
./emsdk activate 4.0.7
source ~/emsdk/emsdk_env.sh
```

2. **Qt 6.11.1 WASM**：
```bash
pip install aqtinstall
aqt install-qt all_os wasm 6.11.1 wasm_singlethread -O ~/Qt
aqt install-qt linux desktop 6.11.1 linux_gcc_64 -O ~/Qt
```

### 编译步骤

```bash
cd wasm-build
source ~/emsdk/emsdk_env.sh

# 克隆 DIE-engine 及子模块
git clone --recursive https://github.com/horsicq/DIE-engine.git deps/DIE-engine

# 编译
cd deps/DIE-engine
mkdir build-wasm && cd build-wasm
cmake .. \
    -DCMAKE_PREFIX_PATH=$HOME/Qt/6.11.1/wasm_singlethread/lib/cmake/Qt6 \
    --toolchain $HOME/Qt/6.11.1/wasm_singlethread/lib/cmake/Qt6/qt.toolchain.cmake \
    -DQT_HOST_PATH=$HOME/Qt/6.11.1/gcc_64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-Dregister=''"
emmake make -j4 diec

# 复制输出
cp release/diec.* ../../docs/wasm/
```

## 输出格式

### 文本（默认，类似 `diec -p`）
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

## 签名覆盖

| 格式 | 签名数 |
|------|--------|
| PE | 781 |
| ELF | 43 |
| MSDOS | 349 |
| APK | 42 |
| Archive | 60+ |
| Image | 20+ |
| PDF | 15+ |
| **总计** | **800+** |

## 技术细节

- **WASM 大小**：总计约 14MB（引擎 + Qt + 签名）
- **Qt WASM**：使用 Qt 6.11.1 的 QJSEngine（签名脚本执行）
- **Emscripten**：版本 4.0.7（ABI 与 Qt 兼容）
- **虚拟文件系统**：用于文件处理

## 致谢

- [DIE-engine](https://github.com/horsicq/DIE-engine) - 原始项目
- [Qt WASM](https://doc.qt.io/qt-6/wasm.html) - Qt WebAssembly
- [Emscripten](https://emscripten.org/) - WASM 工具链

## 许可证

MIT License