#!/usr/bin/env python3
"""
提取 DIE 签名并生成过滤后的 JavaScript 文件
"""

import os
import re
import json

DIE_DB_PATH = "/tmp/die-temp/db"

def normalize_pattern(pattern):
    """规范化十六进制模式"""
    result = pattern.replace('#', '??').replace('$', '??')
    return result.upper()

def parse_sg_file(filepath, format_type):
    """解析签名文件"""
    result = {
        "file": os.path.basename(filepath),
        "format": format_type,
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

    # 提取语言信息
    lang_match = re.search(r'sLang\s*=\s*"([^"]+)"', content)
    if lang_match:
        result["language"] = lang_match.group(1)

    # 提取签名模式（排除通用检测方法）
    exclude_methods = ["isNet()", "isRichSignaturePresent()", "isDotNet()"]

    # PE.compareEP / ELF.compareEP / MACH.compareEP
    ep_patterns = re.findall(r'(?:PE|ELF|MACH)\.compareEP\("([^"]+)"\)', content)
    for pattern in ep_patterns:
        if len(pattern) >= 10 and len(pattern) <= 150:
            result["signatures"].append({
                "method": "entry_point_bytes",
                "pattern": normalize_pattern(pattern)
            })

    # PE.isSectionNamePresent / ELF.isSectionNamePresent
    section_matches = re.findall(r'(?:PE|ELF)\.isSectionNamePresent\("([^"]+)"\)', content)
    for name in section_matches:
        if len(name) >= 2:
            result["signatures"].append({
                "method": "section_name",
                "pattern": name
            })

    # PE.isLibraryPresent (导入DLL)
    lib_matches = re.findall(r'PE\.isLibraryPresent\("([^"]+)"\)', content)
    for dll in lib_matches:
        if len(dll) >= 3:
            result["signatures"].append({
                "method": "import_dll",
                "pattern": dll.lower()
            })

    # findSignature / findString
    find_matches = re.findall(r'(?:PE|ELF)\.(?:findSignature|findString)\([^,]+,\s*[^,]+,\s*"([^"]+)"\)', content)
    for pattern in find_matches:
        if len(pattern) >= 4 and len(pattern) <= 50:
            result["signatures"].append({
                "method": "find_string",
                "pattern": pattern
            })

    return result

def extract_all():
    """提取所有签名"""
    all_sigs = {
        "PE": {},
        "ELF": {},
        "MACH": {}
    }

    for fmt in ["PE", "ELF", "MACH"]:
        fmt_path = os.path.join(DIE_DB_PATH, fmt)
        if not os.path.exists(fmt_path):
            continue

        all_sigs[fmt] = {
            "compilers": [],
            "packers": [],
            "protectors": [],
            "installers": [],
            "tools": [],
            "libraries": []
        }

        for filename in os.listdir(fmt_path):
            if not filename.endswith(".sg"):
                continue

            filepath = os.path.join(fmt_path, filename)
            parsed = parse_sg_file(filepath, fmt)

            if not parsed.get("name") or not parsed.get("signatures"):
                continue

            sig_type = parsed.get("type", "")
            entry = {
                "name": parsed["name"],
                "signatures": parsed["signatures"],
                "file": parsed["file"]
            }

            if parsed.get("language"):
                entry["language"] = parsed["language"]

            # 分类
            if sig_type == "compiler" or filename.startswith("compiler_"):
                all_sigs[fmt]["compilers"].append(entry)
            elif sig_type == "packer" or filename.startswith("packer_"):
                all_sigs[fmt]["packers"].append(entry)
            elif sig_type in ["protector", "cryptor"]:
                all_sigs[fmt]["protectors"].append(entry)
            elif sig_type == "installer":
                all_sigs[fmt]["installers"].append(entry)
            elif sig_type == "tool":
                all_sigs[fmt]["tools"].append(entry)
            elif sig_type == "library":
                all_sigs[fmt]["libraries"].append(entry)

    return all_sigs

def generate_js(all_sigs):
    """生成 JavaScript 签名文件"""
    def escape_js(s):
        if isinstance(s, str):
            return s.replace('\\', '\\\\').replace('"', '\\"')
        return s

    lines = [
        "// Detect It Easy - Web 签名数据库",
        "// 仅保留特定特征模式",
        "",
        "const DIESignaturesFull = {"
    ]

    for fmt in ["PE", "ELF", "MACH"]:
        if fmt not in all_sigs:
            continue

        lines.append(f"    {fmt}: {{")
        for cat in ["compilers", "packers", "protectors", "installers", "libraries"]:
            entries = all_sigs[fmt].get(cat, [])
            if not entries:
                continue

            lines.append(f"        {cat}: [")
            for entry in entries:
                name = escape_js(entry.get("name", ""))
                sigs = entry.get("signatures", [])

                sig_list = []
                for sig in sigs[:3]:  # 每个签名最多保留3个模式
                    method = sig.get("method", "")
                    pattern = sig.get("pattern", "")
                    if isinstance(pattern, str):
                        if len(pattern) > 80:
                            pattern = pattern[:80]
                        sig_list.append(f'{{ method: "{method}", pattern: "{escape_js(pattern)}" }}')

                if sig_list:
                    sig_str = ", ".join(sig_list)
                    lang = entry.get("language", "")
                    if lang:
                        lines.append(f'            {{ name: "{name}", language: "{escape_js(lang)}", signatures: [{sig_str}] }},')
                    else:
                        lines.append(f'            {{ name: "{name}", signatures: [{sig_str}] }},')

            lines.append("        ],")

        lines.append("    },")
        lines.append("")

    lines.append("};")
    lines.append("")
    lines.append("if (typeof module !== 'undefined' && module.exports) {")
    lines.append("    module.exports = DIESignaturesFull;")
    lines.append("}")

    return "\n".join(lines)

# 执行
print("正在提取 DIE 签名...")
all_sigs = extract_all()

# 统计
total_sigs = 0
total_entries = 0
for fmt, cats in all_sigs.items():
    for cat, entries in cats.items():
        count = len(entries)
        if count > 0:
            print(f"  {fmt}/{cat}: {count}")
            total_entries += count
            for entry in entries:
                total_sigs += len(entry.get("signatures", []))

print(f"\n总计: {total_entries} 个签名条目, {total_sigs} 个模式")

# 生成 JS
js_content = generate_js(all_sigs)
with open("../docs/js/die-signatures-full.js", "w") as f:
    f.write(js_content)

print(f"已保存到 ../docs/js/die-signatures-full.js ({len(js_content)} 字符)")