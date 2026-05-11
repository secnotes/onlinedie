# Detect It Easy - Web 版

[Detect It Easy](https://github.com/horsicq/detect-it-easy) 的纯前端网页实现，用于文件签名识别。

## 特性

- **纯前端**: 无需服务器，完全在浏览器中运行
- **多格式支持**: PE、ELF、Mach-O、MSDOS、COM、ZIP、APK、JAR、DEX、Java Class
- **签名检测**: 编译器、打包器、保护器、安装器识别
- **详细分析**: 文件结构解析，可折叠展示
- **离线使用**: 无需网络连接

## 使用方法

1. 在浏览器中打开 `docs/index.html`
2. 上传或拖放文件
3. 查看检测结果和文件详情

## 项目结构

```
detect-it-easy-web/
├── docs/                  # 前端文件
│   ├── index.html         # 主页面
│   ├── css/               # 样式
│   └── js/                # JavaScript 模块
│       ├── app.js         # 应用逻辑
│       ├── file-parser.js # 文件解析
│       ├── die-engine.js  # 检测引擎
│       ├── die-signatures-full.js  # PE 签名
│       ├── elf-signatures-full.js  # ELF 签名
│       └── msdos-signatures.js     # MSDOS 签名
├── src/                   # 签名提取脚本
│   ├── extract_clean_sigs.py    # PE/MACH 提取
│   ├── extract_elf_sigs.py      # ELF 提取
│   └── extract_msdos_signatures.py # MSDOS 提取
└── README.md
└── README_CN.md
```

## 签名提取

从 DIE 数据库重新生成签名：

```bash
# 先下载 DIE 签名数据库
# 然后在 src/ 目录运行提取脚本
cd src
python3 extract_clean_sigs.py
python3 extract_elf_sigs.py
python3 extract_msdos_signatures.py
```

## 检测方法

- **entry_point_bytes**: 匹配文件入口点字节
- **section_name**: 检查特定段名
- **import_dll**: 检测导入的 DLL（PE）
- **needed_lib**: 检测依赖库（ELF）
- **dynstr_string**: 在动态字符串表中搜索（ELF）
- **find_string**: 搜索特定字符串

## 当前签名覆盖情况

| 格式 | DIE 原始 | 已提取 | 覆盖率 |
|------|----------|--------|--------|
| PE   | 781      | 412    | 52.8%  |
| ELF  | 43       | 36     | 83.7%  |
| MSDOS| 349      | 333    | 95.4%  |
| **总计** | **1173** | **781** | **66.6%** |

覆盖率差异原因：
- **PE (52.8%)**: 过滤掉了通用检测方法（is_dotnet、rich_header等），这些方法会匹配所有文件导致误报
- **ELF (83.7%)**: 已增强提取，包含 needed_lib、dynstr_string、section 等检测方法
- **MSDOS (95.4%)**: 几乎完整提取，主要使用入口点字节和字符串匹配

## 致谢

- 原始 DIE 项目: [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy)
- 签名数据库来源于 DIE

## 许可证

MIT License