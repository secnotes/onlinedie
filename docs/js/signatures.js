// Detect It Easy - Web 签名数据库
// 基于 DIE 项目的签名规则转换为纯 JavaScript 格式

const Signatures = {
    // 魔数签名 - 用于文件类型快速识别
    magic: {
        // 可执行文件格式
        pe: {
            signature: [0x4D, 0x5A], // MZ
            offset: 0,
            name: "PE",
            fullName: "Portable Executable",
            description: "Windows可执行文件格式",
            extensions: [".exe", ".dll", ".sys", ".drv", ".ocx", ".scr"]
        },
        elf: {
            signature: [0x7F, 0x45, 0x4C, 0x46], // \x7FELF
            offset: 0,
            name: "ELF",
            fullName: "Executable and Linkable Format",
            description: "Linux/Unix可执行文件格式",
            extensions: [".so", ".elf", ".bin", ".out"]
        },
        macho_32: {
            signature: [0xFE, 0xED, 0xFA, 0xCE],
            offset: 0,
            name: "MACH-O 32",
            fullName: "Mach-O 32-bit",
            description: "macOS 32位可执行文件"
        },
        macho_64: {
            signature: [0xFE, 0xED, 0xFA, 0xCF],
            offset: 0,
            name: "MACH-O 64",
            fullName: "Mach-O 64-bit",
            description: "macOS 64位可执行文件"
        },
        macho_fat: {
            signature: [0xCA, 0xFE, 0xBA, 0xBE],
            offset: 0,
            name: "MACH-O Fat",
            fullName: "Mach-O Universal Binary",
            description: "macOS通用二进制文件"
        },
        dex: {
            signature: [0x64, 0x65, 0x78, 0x0A], // dex\n
            offset: 0,
            name: "DEX",
            fullName: "Dalvik Executable",
            description: "Android DEX文件"
        },
        java_class: {
            signature: [0xCA, 0xFE, 0xBA, 0xBE],
            offset: 0,
            name: "Java Class",
            fullName: "Java Class File",
            description: "Java字节码文件"
        },

        // 压缩文件
        zip: {
            signature: [0x50, 0x4B, 0x03, 0x04],
            offset: 0,
            name: "ZIP",
            fullName: "ZIP Archive",
            description: "ZIP压缩文件",
            extensions: [".zip", ".jar", ".apk", ".ipa", ".docx", ".xlsx", ".pptx", ".odt"]
        },
        rar: {
            signature: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
            offset: 0,
            name: "RAR",
            fullName: "RAR Archive",
            description: "RAR压缩文件"
        },
        '7z': {
            signature: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            offset: 0,
            name: "7-Zip",
            fullName: "7-Zip Archive",
            description: "7-Zip压缩文件"
        },
        gzip: {
            signature: [0x1F, 0x8B],
            offset: 0,
            name: "GZIP",
            fullName: "GZIP Archive",
            description: "GZIP压缩文件"
        },
        bzip2: {
            signature: [0x42, 0x5A], // BZ
            offset: 0,
            name: "BZIP2",
            fullName: "BZIP2 Archive",
            description: "BZIP2压缩文件"
        },
        xz: {
            signature: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            offset: 0,
            name: "XZ",
            fullName: "XZ Archive",
            description: "XZ压缩文件"
        },
        tar: {
            signature: [0x75, 0x73, 0x74, 0x61, 0x72], // "ustar" at offset 257
            offset: 257,
            name: "TAR",
            fullName: "TAR Archive",
            description: "TAR归档文件"
        },
        cab: {
            signature: [0x4D, 0x53, 0x43, 0x46], // MSCF
            offset: 0,
            name: "CAB",
            fullName: "Cabinet Archive",
            description: "Windows Cabinet文件"
        },

        // 镜像文件
        iso: {
            signature: [0x43, 0x44, 0x30, 0x30, 0x31], // CD001
            offset: 32769,
            name: "ISO",
            fullName: "ISO9660",
            description: "ISO镜像文件"
        },
        vhd: {
            signature: [0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78],
            offset: 0,
            name: "VHD",
            fullName: "Virtual Hard Disk",
            description: "虚拟硬盘文件"
        },

        // 图片文件
        png: {
            signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            offset: 0,
            name: "PNG",
            fullName: "Portable Network Graphics",
            description: "PNG图片文件"
        },
        jpeg: {
            signature: [0xFF, 0xD8, 0xFF],
            offset: 0,
            name: "JPEG",
            fullName: "JPEG Image",
            description: "JPEG图片文件"
        },
        gif: {
            signature: [0x47, 0x49, 0x46, 0x38], // GIF8
            offset: 0,
            name: "GIF",
            fullName: "Graphics Interchange Format",
            description: "GIF图片文件"
        },
        bmp: {
            signature: [0x42, 0x4D], // BM
            offset: 0,
            name: "BMP",
            fullName: "Bitmap Image",
            description: "BMP位图文件"
        },
        webp: {
            signature: [0x52, 0x49, 0x46, 0x46], // RIFF
            offset: 0,
            webPCheck: true,
            name: "WebP",
            fullName: "WebP Image",
            description: "WebP图片文件"
        },
        ico: {
            signature: [0x00, 0x00, 0x01, 0x00],
            offset: 0,
            name: "ICO",
            fullName: "Windows Icon",
            description: "Windows图标文件"
        },

        // 音频文件
        mp3_id3: {
            signature: [0x49, 0x44, 0x33], // ID3
            offset: 0,
            name: "MP3",
            fullName: "MPEG Audio Layer 3",
            description: "MP3音频文件"
        },
        mp3_frame: {
            signature: [0xFF, 0xFB],
            offset: 0,
            name: "MP3",
            fullName: "MPEG Audio Layer 3",
            description: "MP3音频文件"
        },
        ogg: {
            signature: [0x4F, 0x67, 0x67, 0x53], // OggS
            offset: 0,
            name: "OGG",
            fullName: "OGG Vorbis",
            description: "OGG音频文件"
        },
        wav: {
            signature: [0x52, 0x49, 0x46, 0x46], // RIFF
            offset: 0,
            riffType: "WAVE",
            name: "WAV",
            fullName: "Waveform Audio",
            description: "WAV音频文件"
        },
        flac: {
            signature: [0x66, 0x4C, 0x61, 0x43], // fLaC
            offset: 0,
            name: "FLAC",
            fullName: "Free Lossless Audio Codec",
            description: "FLAC无损音频"
        },

        // 视频文件
        mp4: {
            signature: [0x66, 0x74, 0x79, 0x70], // ftyp (usually at offset 4)
            offset: 4,
            name: "MP4",
            fullName: "MPEG-4",
            description: "MP4视频文件"
        },
        avi: {
            signature: [0x52, 0x49, 0x46, 0x46], // RIFF
            offset: 0,
            riffType: "AVI ",
            name: "AVI",
            fullName: "Audio Video Interleave",
            description: "AVI视频文件"
        },
        mkv: {
            signature: [0x1A, 0x45, 0xDF, 0xA3],
            offset: 0,
            name: "MKV",
            fullName: "Matroska Video",
            description: "MKV视频文件"
        },
        flv: {
            signature: [0x46, 0x4C, 0x56], // FLV
            offset: 0,
            name: "FLV",
            fullName: "Flash Video",
            description: "Flash视频文件"
        },

        // 文档文件
        pdf: {
            signature: [0x25, 0x50, 0x44, 0x46], // %PDF
            offset: 0,
            name: "PDF",
            fullName: "Portable Document Format",
            description: "PDF文档"
        },
        ps: {
            signature: [0x25, 0x21, 0x50, 0x53], // %!PS
            offset: 0,
            name: "PS",
            fullName: "PostScript",
            description: "PostScript文件"
        },
        rtf: {
            signature: [0x7B, 0x5C, 0x72, 0x74, 0x66], // {\rtf
            offset: 0,
            name: "RTF",
            fullName: "Rich Text Format",
            description: "RTF文档"
        },

        // 数据库
        sqlite: {
            signature: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00],
            offset: 0,
            name: "SQLite",
            fullName: "SQLite Database",
            description: "SQLite数据库"
        },

        // 其他
        swf: {
            signature: [0x46, 0x57, 0x53], // FWS (uncompressed) or CWS (compressed)
            offset: 0,
            altSignature: [0x43, 0x57, 0x53],
            name: "SWF",
            fullName: "Shockwave Flash",
            description: "Flash动画文件"
        },
        pcap: {
            signature: [0xD4, 0xC3, 0xB2, 0xA1],
            offset: 0,
            name: "PCAP",
            fullName: "Packet Capture",
            description: "网络数据包捕获文件"
        },
        pcapng: {
            signature: [0x0A, 0x0D, 0x0D, 0x0A],
            offset: 0,
            name: "PCAPNG",
            fullName: "PCAP Next Generation",
            description: "新一代网络数据包捕获格式"
        }
    },

    // PE 编译器签名
    peCompilers: [
        {
            name: "Microsoft Visual C++",
            signatures: [
                { pattern: "MSVCRT", section: ".rdata" },
                { pattern: "Microsoft Visual C++ Runtime Library", section: ".rdata" },
                { pattern: "VCRUNTIME", section: ".rdata" }
            ],
            richHeader: true
        },
        {
            name: "Microsoft Visual Basic",
            signatures: [
                { pattern: "VBA", section: null },
                { pattern: "VB.Form", section: null }
            ]
        },
        {
            name: "Borland Delphi",
            signatures: [
                { pattern: "TForm", section: null },
                { pattern: "PACKAGEINFO", section: null },
                { pattern: "Borland", section: null }
            ],
            sectionNames: ["CODE", "DATA", "BSS"]
        },
        {
            name: "Borland C++",
            signatures: [
                { pattern: "Borland C++", section: null }
            ]
        },
        {
            name: "GNU GCC / MinGW",
            signatures: [
                { pattern: "__mingw", section: null },
                { pattern: "libgcc", section: null },
                { pattern: "cygwin1.dll", section: null }
            ]
        },
        {
            name: "Go (Golang)",
            signatures: [
                { pattern: "runtime.main", section: ".text" },
                { pattern: "go.buildid", section: ".go.buildinfo" }
            ],
            sectionNames: [".text", ".rodata", ".typelink", ".itablink", ".gosymtab", ".gopclntab"]
        },
        {
            name: "Rust",
            signatures: [
                { pattern: "rustc", section: null },
                { pattern: ".rustc", section: null }
            ]
        },
        {
            name: ".NET / C#",
            signatures: [
                { pattern: "mscoree.dll", section: null }
            ],
            directoryEntry: "CLR"
        },
        {
            name: "Python (PyInstaller)",
            signatures: [
                { pattern: "PYZ-00", section: null },
                { pattern: "MEI", section: null }
            ]
        },
        {
            name: "AutoIt",
            signatures: [
                { pattern: "AU3!", section: null },
                { pattern: "AutoIt", section: null }
            ]
        },
        {
            name: "NSIS",
            signatures: [
                { pattern: "NullsoftInstall", section: null },
                { pattern: "NSIS", section: null }
            ]
        },
        {
            name: "Inno Setup",
            signatures: [
                { pattern: "Inno Setup", section: null }
            ]
        },
        {
            name: "Electron",
            signatures: [
                { pattern: "electron", section: null },
                { pattern: "node.dll", section: null }
            ]
        },
        {
            name: "Qt Framework",
            signatures: [
                { pattern: "Qt5", section: null },
                { pattern: "Qt6", section: null },
                { pattern: "QtCore", section: null }
            ]
        },
        {
            name: "FFmpeg",
            signatures: [
                { pattern: "ffmpeg", section: null },
                { pattern: "libavcodec", section: null }
            ]
        }
    ],

    // PE 打包器/保护器签名
    pePackers: [
        {
            name: "UPX",
            signatures: [
                { pattern: "UPX", section: null },
                { pattern: "UPX!", section: null }
            ],
            sectionNames: ["UPX0", "UPX1", "UPX2"]
        },
        {
            name: "ASPack",
            signatures: [
                { pattern: ".aspack", section: null }
            ],
            sectionNames: [".aspack", ".adata"]
        },
        {
            name: "PECompact",
            signatures: [
                { pattern: "PECompact", section: null },
                { pattern: "PEC2", section: null }
            ]
        },
        {
            name: "Themida/WinLicense",
            signatures: [
                { pattern: "Themida", section: null },
                { pattern: "WinLicense", section: null }
            ],
            sectionNames: [".themida", ".winlice"]
        },
        {
            name: "VMProtect",
            signatures: [
                { pattern: "VMProtect", section: null }
            ],
            sectionNames: [".vmp0", ".vmp1", ".vmp2"]
        },
        {
            name: "Enigma",
            signatures: [
                { pattern: "Enigma", section: null }
            ]
        },
        {
            name: "Armadillo",
            signatures: [
                { pattern: "Armadillo", section: null },
                { pattern: ".data1", section: null }
            ]
        },
        {
            name: "Petite",
            signatures: [
                { pattern: "Petite", section: null }
            ]
        },
        {
            name: "MPRESS",
            signatures: [
                { pattern: "MPRESS", section: null },
                { pattern: "MPRS", section: null }
            ]
        },
        {
            name: "Arxan",
            signatures: [
                { pattern: "Arxan", section: null }
            ]
        },
        {
            name: "Safeguard",
            signatures: [
                { pattern: "Safeguard", section: null }
            ]
        }
    ],

    // ELF 编译器签名
    elfCompilers: [
        {
            name: "GCC",
            signatures: [
                { pattern: "GCC:", section: ".comment" },
                { pattern: "GNU C", section: ".comment" }
            ]
        },
        {
            name: "Clang/LLVM",
            signatures: [
                { pattern: "clang", section: ".comment" },
                { pattern: "LLVM", section: ".comment" }
            ]
        },
        {
            name: "Go (Golang)",
            signatures: [
                { pattern: "runtime.main", section: ".text" },
                { pattern: "go.buildinfo", section: null }
            ],
            sectionNames: [".text", ".rodata", ".typelink", ".itablink", ".gosymtab", ".gopclntab"]
        },
        {
            name: "Rust",
            signatures: [
                { pattern: "rustc", section: ".comment" }
            ]
        },
        {
            name: "Intel C++",
            signatures: [
                { pattern: "Intel", section: ".comment" }
            ]
        }
    ],

    // APK/DEX 检测
    apkSignatures: [
        {
            name: "Unity",
            signatures: [
                { pattern: "libunity.so", section: null },
                { pattern: "assets/bin/Data", section: null }
            ]
        },
        {
            name: "Flutter",
            signatures: [
                { pattern: "libflutter.so", section: null },
                { pattern: "flutter_assets", section: null }
            ]
        },
        {
            name: "React Native",
            signatures: [
                { pattern: "libreactnativejni.so", section: null },
                { pattern: "assets/index.android.bundle", section: null }
            ]
        },
        {
            name: "Xamarin",
            signatures: [
                { pattern: "libxamarin-app.so", section: null },
                { pattern: "libmonodroid.so", section: null }
            ]
        },
        {
            name: "Cordova/Ionic",
            signatures: [
                { pattern: "cordova.js", section: null },
                { pattern: "ionic", section: null }
            ]
        }
    ],

    // ZIP/JAR 检测
    zipSignatures: [
        {
            name: "Java Archive (JAR)",
            signatures: [
                { pattern: "META-INF/MANIFEST.MF", section: null }
            ],
            extension: ".jar"
        },
        {
            name: "Android APK",
            signatures: [
                { pattern: "AndroidManifest.xml", section: null },
                { pattern: "classes.dex", section: null }
            ],
            extension: ".apk"
        },
        {
            name: "Java Web Start (JNLP)",
            signatures: [
                { pattern: "META-INF/JNLP", section: null }
            ]
        },
        {
            name: "Electron App",
            signatures: [
                { pattern: "app.asar", section: null },
                { pattern: "electron.asar", section: null }
            ]
        },
        {
            name: "NW.js App",
            signatures: [
                { pattern: "package.json", section: null },
                { pattern: "nwjs", section: null }
            ]
        }
    ],

    // DEX 检测
    dexSignatures: [
        {
            name: "ProGuard/R8 Obfuscated",
            signatures: [
                { pattern: "a/b/c", section: null }
            ]
        },
        {
            name: "DexGuard",
            signatures: [
                { pattern: "DexGuard", section: null }
            ]
        }
    ]
};

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Signatures;
}