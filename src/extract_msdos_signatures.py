#!/usr/bin/env python3
"""
提取 MSDOS 签名
"""

import os
import re

DIE_DB_PATH = "/tmp/die-temp/db/MSDOS"

def normalize_pattern(pattern):
    """规范化十六进制模式"""
    # DIE 使用 # 和 $ 作为通配符
    result = pattern.replace('#', '??').replace('$', '??')
    return result.upper()

def parse_msdos_sg(filepath):
    """解析 MSDOS 签名文件"""
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

    # 提取 compareEP 模式（入口点字节）
    ep_patterns = re.findall(r'MSDOS\.compareEP\("([^"]+)"\)', content)
    for pattern in ep_patterns:
        if len(pattern) >= 10 and len(pattern) <= 200:  # 合理长度
            result["signatures"].append({
                "method": "entry_point_bytes",
                "pattern": normalize_pattern(pattern)
            })

    # 提取 compare 模式（指定偏移）
    compare_patterns = re.findall(r'MSDOS\.compare\("([^"]+)"\s*,\s*([^)]+)\)', content)
    for pattern, offset in compare_patterns:
        if len(pattern) >= 4 and len(pattern) <= 100:
            result["signatures"].append({
                "method": "bytes_at_offset",
                "pattern": normalize_pattern(pattern),
                "offset": offset.strip()
            })

    # 提取 findString 模式
    find_string = re.findall(r'MSDOS\.findString\([^,]+,\s*[^,]+,\s*"([^"]+)"\)', content)
    for s in find_string:
        if len(s) <= 50:
            result["signatures"].append({
                "method": "find_string",
                "pattern": s
            })

    # 提取 compare 模式中的字符串部分
    string_in_compare = re.findall(r"MSDOS\.compare\('([^']+)'", content)
    for s in string_in_compare:
        if len(s) <= 30:
            result["signatures"].append({
                "method": "find_string",
                "pattern": s
            })

    # 提取版本信息
    version_match = re.search(r'sVersion\s*=\s*"([^"]+)"', content)
    if version_match:
        result["version"] = version_match.group(1)

    return result

def extract_all_msdos():
    """提取所有 MSDOS 签名"""
    results = {
        "compilers": [],
        "packers": [],
        "protectors": [],
        "tools": [],
        "linkers": [],
        "converters": [],
        "other": []
    }

    if not os.path.exists(DIE_DB_PATH):
        return results

    for filename in os.listdir(DIE_DB_PATH):
        if not filename.endswith(".sg"):
            continue

        filepath = os.path.join(DIE_DB_PATH, filename)
        parsed = parse_msdos_sg(filepath)

        if not parsed.get("name") or not parsed.get("signatures"):
            continue

        entry = {
            "name": parsed["name"],
            "signatures": parsed["signatures"],
            "file": parsed["file"]
        }

        if parsed.get("version"):
            entry["version"] = parsed["version"]

        # 根据文件名分类
        sig_type = parsed.get("type", "")

        if sig_type == "compiler" or filename.startswith("compiler_"):
            results["compilers"].append(entry)
        elif sig_type == "packer" or filename.startswith("packer_"):
            results["packers"].append(entry)
        elif sig_type in ["protector", "cryptor"] or filename.startswith("cryptor_") or filename.startswith("protector_"):
            results["protectors"].append(entry)
        elif sig_type == "linker" or filename.startswith("linker_"):
            results["linkers"].append(entry)
        elif sig_type == "tool" or filename.startswith("tool_"):
            results["tools"].append(entry)
        elif sig_type == "converter" or filename.startswith("converter_"):
            results["converters"].append(entry)
        else:
            results["other"].append(entry)

    return results

def generate_js(msdos_sigs):
    """生成 JavaScript 签名文件"""
    def escape_js(s):
        if isinstance(s, str):
            return s.replace('\\', '\\\\').replace('"', '\\"')
        return s

    lines = [
        "// MSDOS 签名数据库 - 从 DIE 提取",
        "",
        "const MSDOSSignatures = {"
    ]

    for cat in ["compilers", "packers", "protectors", "converters", "other"]:
        entries = msdos_sigs.get(cat, [])
        if not entries:
            continue

        lines.append(f"    {cat}: [")
        for entry in entries:
            name = escape_js(entry.get("name", ""))
            sig_list = []

            for sig in entry.get("signatures", [])[:5]:  # 每个签名最多 5 个模式
                method = sig.get("method", "")
                pattern = sig.get("pattern", "")
                if isinstance(pattern, str):
                    if len(pattern) > 100:
                        pattern = pattern[:100]
                    sig_list.append(f'{{ method: "{method}", pattern: "{escape_js(pattern)}" }}')

            if sig_list:
                sig_str = ", ".join(sig_list)
                lines.append(f'        {{ name: "{name}", signatures: [{sig_str}] }},')

        lines.append("    ],")

    lines.append("};")
    lines.append("")
    lines.append("if (typeof module !== 'undefined' && module.exports) {")
    lines.append("    module.exports = MSDOSSignatures;")
    lines.append("}")

    return "\n".join(lines)

if __name__ == "__main__":
    print("正在提取 MSDOS 签名...")
    msdos_sigs = extract_all_msdos()

    # 统计
    total = 0
    for cat, entries in msdos_sigs.items():
        count = len(entries)
        if count > 0:
            print(f"  MSDOS/{cat}: {count}")
            for entry in entries:
                total += len(entry.get("signatures", []))

    print(f"\n总计提取: {total} 个签名模式")

    # 生成 JS
    js_content = generate_js(msdos_sigs)
    with open("../docs/js/msdos-signatures.js", "w") as f:
        f.write(js_content)

    print(f"已保存到 ../docs/js/msdos-signatures.js ({len(js_content)} 字符)")