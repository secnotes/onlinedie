/**
 * DIE WebAssembly - 简化版
 * 独立文件检测引擎，无外部依赖
 */

#include <emscripten.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstring>
#include <memory>
#include <algorithm>

// ============================================================================
// File Buffer
// ============================================================================
class FileBuffer {
public:
    FileBuffer(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t size() const { return size_; }

    uint8_t readUint8(size_t offset) const {
        if (offset >= size_) return 0;
        return data_[offset];
    }

    uint16_t readUint16LE(size_t offset) const {
        if (offset + 2 > size_) return 0;
        return data_[offset] | (data_[offset + 1] << 8);
    }

    uint32_t readUint32LE(size_t offset) const {
        if (offset + 4 > size_) return 0;
        return data_[offset] | (data_[offset + 1] << 8) |
               (data_[offset + 2] << 16) | (data_[offset + 3] << 24);
    }

    std::string readString(size_t offset, size_t maxLen) const {
        if (offset >= size_) return "";
        size_t len = 0;
        while (len < maxLen && offset + len < size_ && data_[offset + len]) len++;
        return std::string((char*)data_ + offset, len);
    }

    int findString(const std::string& str, size_t start, size_t end) const {
        if (start >= size_) return -1;
        if (end > size_) end = size_;
        for (size_t i = start; i <= end - str.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < str.size(); j++) {
                if (data_[i + j] != str[j]) { match = false; break; }
            }
            if (match) return (int)i;
        }
        return -1;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

// ============================================================================
// Format Detection
// ============================================================================
struct FormatInfo {
    std::string format;
    std::string fullName;
    std::string type;
    std::string platform;
    std::string arch;
};

struct DetectionResult {
    FormatInfo format;
    std::vector<std::string> compilers;
    std::vector<std::string> packers;
    std::vector<std::string> libraries;
};

class Detector {
public:
    static DetectionResult detect(const uint8_t* data, size_t size) {
        DetectionResult result;
        FileBuffer buf(data, size);

        // PE detection
        if (buf.readUint16LE(0) == 0x5A4D) {  // MZ header
            uint32_t peOff = buf.readUint32LE(0x3C);
            if (peOff > 0 && peOff + 4 <= size && buf.readUint32LE(peOff) == 0x00004550) {
                result.format.format = "PE";
                result.format.fullName = "Portable Executable";
                result.format.type = "Executable";
                result.format.platform = "Windows";

                uint16_t machine = buf.readUint16LE(peOff + 4);
                result.format.arch = (machine == 0x8664) ? "x64" :
                                     (machine == 0x14c) ? "x86" :
                                     (machine == 0x1c0) ? "ARM" : "Unknown";

                // Compiler detection
                if (buf.findString("GCC:", 0, size) != -1) result.compilers.push_back("GCC/MinGW");
                if (buf.findString("Microsoft Visual", 0, size) != -1) result.compilers.push_back("Visual C++");
                if (buf.findString("Borland", 0, size) != -1) result.compilers.push_back("Borland C++");
                if (buf.findString("Delphi", 0, size) != -1) result.compilers.push_back("Delphi");
                if (buf.findString("rustc", 0, size) != -1) result.compilers.push_back("Rust");
                if (buf.findString("io.nim", 0, size) != -1) result.compilers.push_back("Nim");
                if (buf.findString("Go build", 0, size) != -1) result.compilers.push_back("Go");
                if (buf.findString("PureBasic", 0, size) != -1) result.compilers.push_back("PureBasic");
                if (buf.findString("TControl", 0, size) != -1) result.compilers.push_back("Delphi");

                // Packer detection
                if (buf.findString("UPX", 0, 50000) != -1) result.packers.push_back("UPX");
                if (buf.findString("ASPack", 0, size) != -1) result.packers.push_back("ASPack");
                if (buf.findString("PECompact", 0, size) != -1) result.packers.push_back("PECompact");
                if (buf.findString("MPRESS", 0, size) != -1) result.packers.push_back("MPRESS");

                // Library detection
                if (buf.findString(".NET", 0, size) != -1) result.libraries.push_back(".NET");
                if (buf.findString("Unity", 0, size) != -1) result.libraries.push_back("Unity");
                if (buf.findString("MFC", 0, size) != -1) result.libraries.push_back("MFC");

                return result;
            }
        }

        // ELF detection
        if (size >= 16 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            result.format.format = "ELF";
            result.format.fullName = "Executable and Linkable Format";
            result.format.type = "Executable";

            uint8_t elfClass = data[4];
            result.format.arch = (elfClass == 2) ? "x64" : "x86";

            uint8_t osAbi = data[7];
            result.format.platform = (osAbi == 0 || osAbi == 3) ? "Linux" : "UNIX";

            // Compiler detection
            if (buf.findString("GCC:", 0, size) != -1) result.compilers.push_back("GCC");
            if (buf.findString("clang", 0, size) != -1) result.compilers.push_back("Clang");
            if (buf.findString("rustc", 0, size) != -1) result.compilers.push_back("Rust");
            if (buf.findString("zig", 0, size) != -1) result.compilers.push_back("Zig");

            return result;
        }

        // Mach-O detection
        uint32_t magic = buf.readUint32LE(0);
        if (magic == 0xFEEDFACE || magic == 0xFEEDFADE || magic == 0xCAFEBABE) {
            result.format.format = "Mach-O";
            result.format.fullName = "Mach Object";
            result.format.type = "Executable";
            result.format.platform = "macOS/iOS";
            result.format.arch = (magic == 0xFEEDFADE) ? "x64" : "x86";

            // Compiler detection
            if (buf.findString("$s", 0, size) != -1) result.compilers.push_back("Swift");
            if (buf.findString("_OBJC_", 0, size) != -1) result.compilers.push_back("Objective-C");

            return result;
        }

        // ZIP/APK/JAR detection
        if (buf.readUint32LE(0) == 0x04034B50) {  // PK
            result.format.format = "ZIP";
            result.format.fullName = "ZIP Archive";
            result.format.type = "Archive";

            if (buf.findString("AndroidManifest.xml", 0, size) != -1) {
                result.format.format = "APK";
                result.format.fullName = "Android Package";
                result.format.platform = "Android";
            }
            if (buf.findString("META-INF/MANIFEST.MF", 0, size) != -1) {
                result.format.format = "JAR";
                result.format.fullName = "Java Archive";
            }

            return result;
        }

        // DEX detection
        std::string dexMagic = buf.readString(0, 4);
        if (dexMagic == "dex\n" || dexMagic == "dex\035") {
            result.format.format = "DEX";
            result.format.fullName = "Dalvik Executable";
            result.format.type = "Executable";
            result.format.platform = "Android";
            return result;
        }

        // Magic signatures
        if (buf.readString(0, 4) == "%PDF") {
            result.format.format = "PDF";
            result.format.fullName = "Portable Document Format";
            result.format.type = "Document";
            return result;
        }
        if (size >= 6 && data[0] == 0x52 && data[1] == 0x61 && data[2] == 0x72) {  // Rar!
            result.format.format = "RAR";
            result.format.fullName = "RAR Archive";
            result.format.type = "Archive";
            return result;
        }
        if (size >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) {
            result.format.format = "PNG";
            result.format.fullName = "PNG Image";
            result.format.type = "Image";
            return result;
        }
        if (size >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
            result.format.format = "JPEG";
            result.format.fullName = "JPEG Image";
            result.format.type = "Image";
            return result;
        }
        if (buf.readString(0, 3) == "GIF") {
            result.format.format = "GIF";
            result.format.fullName = "GIF Image";
            result.format.type = "Image";
            return result;
        }
        if (buf.readString(0, 4) == "\xCA\xFE\xBA\xBE" || buf.readString(0, 4) == "\xBA\xBE\xCA\xFE") {
            result.format.format = "Java Class";
            result.format.fullName = "Java Class File";
            result.format.type = "Class";
            result.format.platform = "Java";
            return result;
        }
        if (size >= 4 && data[0] == 0x00 && data[1] == 0x61 && data[2] == 0x73 && data[3] == 0x6D) {
            result.format.format = "WASM";
            result.format.fullName = "WebAssembly";
            result.format.type = "Binary";
            return result;
        }

        // Unknown
        result.format.format = "Binary";
        result.format.fullName = "Binary File";
        result.format.type = "Binary";

        return result;
    }
};

// ============================================================================
// WASM Exports
// ============================================================================
static std::string g_resultJson;
static std::string g_resultText;
static std::string g_resultXml;

// Build JSON from result
std::string buildJson(const DetectionResult& r) {
    std::string json = "{";

    // Format
    json += "\"format\":{";
    json += "\"format\":\"" + r.format.format + "\",";
    json += "\"fullName\":\"" + r.format.fullName + "\",";
    json += "\"type\":\"" + r.format.type + "\"";
    if (!r.format.platform.empty()) json += ",\"platform\":\"" + r.format.platform + "\"";
    if (!r.format.arch.empty()) json += ",\"architecture\":\"" + r.format.arch + "\"";
    json += "},";

    // Arrays
    json += "\"compiler\":[";
    for (size_t i = 0; i < r.compilers.size(); i++) {
        json += "\"" + r.compilers[i] + "\"";
        if (i < r.compilers.size() - 1) json += ",";
    }
    json += "],";

    json += "\"packer\":[";
    for (size_t i = 0; i < r.packers.size(); i++) {
        json += "\"" + r.packers[i] + "\"";
        if (i < r.packers.size() - 1) json += ",";
    }
    json += "],";

    json += "\"library\":[";
    for (size_t i = 0; i < r.libraries.size(); i++) {
        json += "\"" + r.libraries[i] + "\"";
        if (i < r.libraries.size() - 1) json += ",";
    }
    json += "]";

    json += "}";
    return json;
}

// Build plain text output (similar to diec -p)
std::string buildText(const DetectionResult& r) {
    std::string text;

    // Format line
    text += r.format.format;
    if (!r.format.arch.empty()) text += " (" + r.format.arch + ")";
    text += "\n";

    // Compiler
    for (const auto& c : r.compilers) {
        text += "  Compiler: " + c + "\n";
    }

    // Packer
    for (const auto& p : r.packers) {
        text += "  Packer: " + p + "\n";
    }

    // Library
    for (const auto& l : r.libraries) {
        text += "  Library: " + l + "\n";
    }

    // Linker (placeholder - same as compiler for now)
    // Installer, Protector, SignTool could be added later

    return text;
}

// Build XML from result
std::string buildXml(const DetectionResult& r) {
    std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml += "<detect>\n";

    // Format
    xml += "  <format>\n";
    xml += "    <name>" + r.format.format + "</name>\n";
    xml += "    <fullname>" + r.format.fullName + "</fullname>\n";
    xml += "    <type>" + r.format.type + "</type>\n";
    if (!r.format.platform.empty()) xml += "    <platform>" + r.format.platform + "</platform>\n";
    if (!r.format.arch.empty()) xml += "    <architecture>" + r.format.arch + "</architecture>\n";
    xml += "  </format>\n";

    // Compiler
    if (!r.compilers.empty()) {
        xml += "  <compilers>\n";
        for (const auto& c : r.compilers) {
            xml += "    <compiler>" + c + "</compiler>\n";
        }
        xml += "  </compilers>\n";
    }

    // Packer
    if (!r.packers.empty()) {
        xml += "  <packers>\n";
        for (const auto& p : r.packers) {
            xml += "    <packer>" + p + "</packer>\n";
        }
        xml += "  </packers>\n";
    }

    // Library
    if (!r.libraries.empty()) {
        xml += "  <libraries>\n";
        for (const auto& l : r.libraries) {
            xml += "    <library>" + l + "</library>\n";
        }
        xml += "  </libraries>\n";
    }

    xml += "</detect>";
    return xml;
}

// Exported function: detect file plain text (similar to diec -p)
extern "C" EMSCRIPTEN_KEEPALIVE
const char* detect_file_text(const uint8_t* data, size_t size) {
    DetectionResult result = Detector::detect(data, size);
    g_resultText = buildText(result);
    return g_resultText.c_str();
}

// Exported function: detect file (returns JSON)
extern "C" EMSCRIPTEN_KEEPALIVE
const char* detect_file(const uint8_t* data, size_t size) {
    DetectionResult result = Detector::detect(data, size);
    g_resultJson = buildJson(result);
    return g_resultJson.c_str();
}

// Exported function: detect file XML format
extern "C" EMSCRIPTEN_KEEPALIVE
const char* detect_file_xml(const uint8_t* data, size_t size) {
    DetectionResult result = Detector::detect(data, size);
    g_resultXml = buildXml(result);
    return g_resultXml.c_str();
}

// Exported function: calculate entropy
extern "C" EMSCRIPTEN_KEEPALIVE
double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    uint64_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Exported function: get format name
extern "C" EMSCRIPTEN_KEEPALIVE
const char* get_file_format(const uint8_t* data, size_t size) {
    DetectionResult result = Detector::detect(data, size);
    static std::string formatName;
    formatName = result.format.format;
    return formatName.c_str();
}