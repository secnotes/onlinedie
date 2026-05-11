#!/usr/bin/env python3
"""
增强的 ELF 签名提取脚本
"""

import os
import re
import json

DIE_DB_PATH = "/tmp/die-temp/db/ELF"

def normalize_pattern(pattern):
    """规范化十六进制模式"""
    result = pattern.replace('#', '??').replace('$', '??')
    return result.upper()

def parse_elf_sg(filepath):
    """解析 ELF 签名文件"""
    result = {
        "file": os.path.basename(filepath),
        "signatures": []
    }

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return result

    # 提取 meta 信息
    meta_match = re.search(r'meta\("([^"]+)",\s*"([^"]+)"\)', content)
    if meta_match:
        result["type"] = meta_match.group(1)
        result["name"] = meta_match.group(2)
    else:
        return result

    # 提取语言信息
    lang_match = re.search(r'sLang\s*=\s*"([^"]+)"', content)
    if lang_match:
        result["language"] = lang_match.group(1)

    # 1. ELF.compareEP - 入口点字节
    ep_patterns = re.findall(r'ELF\.compareEP\("([^"]+)"\)', content)
    for pattern in ep_patterns:
        if len(pattern) >= 10 and len(pattern) <= 200:
            result["signatures"].append({
                "method": "entry_point_bytes",
                "pattern": normalize_pattern(pattern)
            })

    # 2. ELF.isSectionNamePresent - 段名检测
    section_matches = re.findall(r'ELF\.isSectionNamePresent\("([^"]+)"\)', content)
    for name in section_matches:
        if len(name) >= 2:
            result["signatures"].append({
                "method": "section_name",
                "pattern": name
            })

    # 3. ELF.isStringInTablePresent - 动态字符串表检测
    dynstr_matches = re.findall(r'ELF\.isStringInTablePresent\("([^"]+)",\s*"([^"]+)"\)', content)
    for table, string in dynstr_matches:
        result["signatures"].append({
            "method": "dynstr_string",
            "table": table,
            "pattern": string
        })

    # 4. ELF.findString - 字符串查找
    find_matches = re.findall(r'ELF\.findString\([^,]+,\s*[^,]+,\s*"([^"]+)"\)', content)
    for pattern in find_matches:
        if len(pattern) >= 3 and len(pattern) <= 50:
            result["signatures"].append({
                "method": "find_string",
                "pattern": pattern
            })

    # 5. ELF.getString - 获取字符串后检测
    get_string_matches = re.findall(r'ELF\.getString\([^)]+\)', content)

    # 6. 段名正则检测
    section_regex = re.findall(r"ELF\.isSectionNamePresent\('([^']+)'", content)
    for pattern in section_regex:
        result["signatures"].append({
            "method": "section_name_regex",
            "pattern": pattern
        })

    # 7. 特定字符串在段中的检测 (如 GLIBC_2.x)
    glibc_pattern = re.search(r'"GLIBC_', content)
    if glibc_pattern:
        result["signatures"].append({
            "method": "find_string",
            "pattern": "GLIBC_"
        })

    # 8. 检测特定库函数名
    lib_funcs = re.findall(r'"(SDL_Init|ffmpeg|libav|libcurl|libssl|libcrypto|libX11|libfreetype|libpulse|libdbus|libz|libpng)"', content)
    for func in lib_funcs:
        result["signatures"].append({
            "method": "find_string",
            "pattern": func
        })

    # 9. ELF.isLibraryPresent - 动态库检测
    lib_present = re.findall(r'ELF\.isLibraryPresent\("([^"]+)"\)', content)
    for lib in lib_present:
        result["signatures"].append({
            "method": "needed_lib",
            "pattern": lib
        })

    # 10. ELF.isSymbolPresent - 符号检测
    symbol_present = re.findall(r'ELF\.isSymbolPresent\("([^"]+)"\)', content)
    for sym in symbol_present:
        result["signatures"].append({
            "method": "symbol",
            "pattern": sym
        })

    return result

def extract_all_elf():
    """提取所有 ELF 签名"""
    results = {
        "compilers": [],
        "libraries": [],
        "packers": [],
        "protectors": []
    }

    for filename in os.listdir(DIE_DB_PATH):
        if not filename.endswith(".sg") or filename.startswith("_"):
            continue

        filepath = os.path.join(DIE_DB_PATH, filename)
        parsed = parse_elf_sg(filepath)

        if not parsed.get("name") or not parsed.get("signatures"):
            continue

        entry = {
            "name": parsed["name"],
            "signatures": parsed["signatures"],
            "file": parsed["file"]
        }

        if parsed.get("language"):
            entry["language"] = parsed["language"]

        sig_type = parsed.get("type", "")

        if sig_type == "compiler" or "compiler" in filename:
            results["compilers"].append(entry)
        elif sig_type == "library" or "library" in filename:
            results["libraries"].append(entry)
        elif sig_type == "packer" or "packer" in filename:
            results["packers"].append(entry)
        elif sig_type == "protector" or "protector" in filename:
            results["protectors"].append(entry)

    return results

def generate_js(elf_sigs):
    """生成 JavaScript 签名"""
    def escape_js(s):
        if isinstance(s, str):
            return s.replace('\\', '\\\\').replace('"', '\\"')
        return s

    lines = [
        "// ELF 签名数据库 - 增强版",
        "",
        "const ELFSignaturesFull = {"
    ]

    for cat in ["compilers", "libraries", "packers", "protectors"]:
        entries = elf_sigs.get(cat, [])
        if not entries:
            continue

        lines.append(f"    {cat}: [")
        for entry in entries:
            name = escape_js(entry.get("name", ""))
            sigs = entry.get("signatures", [])

            sig_list = []
            for sig in sigs[:5]:
                method = sig.get("method", "")
                pattern = sig.get("pattern", "")
                table = sig.get("table", "")

                if method == "dynstr_string":
                    sig_list.append(f'{{ method: "{method}", table: "{escape_js(table)}", pattern: "{escape_js(pattern)}" }}')
                elif pattern:
                    if isinstance(pattern, str):
                        if len(pattern) > 80:
                            pattern = pattern[:80]
                        sig_list.append(f'{{ method: "{method}", pattern: "{escape_js(pattern)}" }}')

            if sig_list:
                sig_str = ", ".join(sig_list)
                lang = entry.get("language", "")
                if lang:
                    lines.append(f'        {{ name: "{name}", language: "{escape_js(lang)}", signatures: [{sig_str}] }},')
                else:
                    lines.append(f'        {{ name: "{name}", signatures: [{sig_str}] }},')

        lines.append("    ],")

    lines.append("};")
    lines.append("")
    lines.append("if (typeof module !== 'undefined' && module.exports) {")
    lines.append("    module.exports = ELFSignaturesFull;")
    lines.append("}")

    return "\n".join(lines)

# 执行
print("正在提取 ELF 签名...")
elf_sigs = extract_all_elf()

# 统计
total = 0
for cat, entries in elf_sigs.items():
    count = len(entries)
    if count > 0:
        print(f"  ELF/{cat}: {count}")
        total += count
        for entry in entries:
            print(f"    - {entry['name']}: {len(entry.get('signatures', []))} 个模式")

print(f"\n总计: {total} 条签名")

# 生成 JS
js_content = generate_js(elf_sigs)
with open("../docs/js/elf-signatures-full.js", "w") as f:
    f.write(js_content)

print(f"已保存到 ../docs/js/elf-signatures-full.js ({len(js_content)} 字符)")