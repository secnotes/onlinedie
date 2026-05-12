# DIE WebAssembly 编译指南

## 当前状态

前端已准备好使用 WASM 版本的 diec。但 WASM 模块需要您在有 Emscripten 的环境中编译。

**WASM 未编译时**，页面会显示 "WASM 加载失败，请检查编译"。

## 编译 WASM

### 方式一：使用 Qt WASM（推荐，完整签名支持）

DIE-engine 使用 Qt 的 QJSEngine 执行签名脚本，需要 Qt WASM 支持：

```bash
# 1. 安装 Emscripten
git clone https://github.com/emscripten-core/emsdk.git ~/emsdk
cd ~/emsdk && ./emsdk install latest && ./emsdk activate latest
source ~/emsdk/emsdk_env.sh

# 2. 安装 Qt WASM
pip install aqtinstall
aqt install-qt wasm desktop 6.6.0 wasm_singlethread -O ~/Qt
export QT_WASM_DIR=~/Qt/6.6.0/wasm_singlethread

# 3. 运行编译脚本
cd wasm-build
./build-wasm.sh
```

编译后输出：
- `docs/wasm/diec.js` - WASM 加载器
- `docs/wasm/diec.wasm` - WASM 二进制
- `docs/wasm/diec.data` - 签名数据库

### 方式二：使用 Docker（简化版，无 Qt）

如果不需要完整签名执行，可以使用简化版本：

```bash
cd wasm-build
docker build -t die-wasm .
docker run -v $(pwd)/../docs/wasm:/output die-wasm
```

### 方式三：手动编译简化版

不依赖 Qt，使用纯 C++ 实现：

```bash
source ~/emsdk/emsdk_env.sh

cd wasm-build/src
mkdir build && cd build

emcmake cmake .. -DCMAKE_BUILD_TYPE=Release -DUSE_QT=OFF
emmake make

cp diec.js diec.wasm ../../../docs/wasm/
```

## 编译输出位置

编译产物需要放在 `docs/wasm/` 目录：

```
docs/wasm/
├── diec.js      # Emscripten 生成的 JS 加载器
├── diec.wasm    # WASM 二进制（核心）
├── diec.data    # 签名数据（可选）
└── README.md
```

## 验证编译

打开 `docs/index.html`：
- 成功：显示 "🚀 WASM 引擎已就绪"
- 失败：显示 "❌ WASM 加载失败"

## 问题排查

### Emscripten 未安装
```
Error: emcc not found
```
解决：`source ~/emsdk/emsdk_env.sh`

### Qt 未找到
```
Error: Qt6_DIR not set
```
解决：`export QT_WASM_DIR=/path/to/Qt/wasm`

### 编译失败
检查 DIE-engine 是否完整克隆：
```bash
cd wasm-build/DIE-engine
git submodule update --init --recursive
```

## 文件说明

| 文件 | 说明 |
|-----|------|
| `wasm-build/build-wasm.sh` | 主编译脚本（使用 Qt） |
| `wasm-build/build.sh` | 简化编译脚本 |
| `wasm-build/src/die_wasm.cpp` | C++ WASM 源码 |
| `wasm-build/src/CMakeLists.txt` | CMake 配置 |
| `docs/js/die-wasm.js` | JS WASM 加载器 |
| `docs/wasm/diec.js` | 编译输出 stub（需替换） |