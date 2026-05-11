// Detect It Easy - Web 签名数据库
// MACH/DEX/APK/JavaClass 签名 - PE/ELF 已移至独立文件

const DIESignatures = {
    // Mach-O 文件签名
    MACH: {
        compilers: [
            {
                name: "Clang/LLVM",
                language: "C/C++",
                signatures: [
                    { method: "load_command", cmd: "LC_VERSION_MIN_MACOSX" },
                    { method: "dylib", pattern: "libclang" }
                ]
            },
            {
                name: "Swift",
                language: "Swift",
                signatures: [
                    { method: "dylib", pattern: "libswiftCore" },
                    { method: "section_name", pattern: "__swift" }
                ]
            },
            {
                name: "Objective-C",
                language: "Objective-C",
                signatures: [
                    { method: "section_name", pattern: "__objc_classrefs" },
                    { method: "section_name", pattern: "__objc_methname" }
                ]
            },
            {
                name: "Go",
                language: "Go",
                signatures: [
                    { method: "section_name", pattern: "__gosymtab" },
                    { method: "section_name", pattern: "__gopclntab" }
                ]
            },
            {
                name: "Rust",
                language: "Rust",
                signatures: [
                    { method: "dylib", pattern: "libstd" }
                ]
            }
        ],
        libraries: [
            {
                name: "AppKit",
                signatures: [
                    { method: "dylib", pattern: "AppKit" }
                ]
            },
            {
                name: "UIKit",
                signatures: [
                    { method: "dylib", pattern: "UIKit" }
                ]
            },
            {
                name: "Cocoa",
                signatures: [
                    { method: "dylib", pattern: "Cocoa" }
                ]
            },
            {
                name: "Foundation",
                signatures: [
                    { method: "dylib", pattern: "Foundation" }
                ]
            }
        ]
    },

    // APK/DEX 文件签名
    DEX: {
        compilers: [
            {
                name: "Kotlin",
                signatures: [
                    { method: "class_name", pattern: "kotlin/" }
                ]
            },
            {
                name: "Scala",
                signatures: [
                    { method: "class_name", pattern: "scala/" }
                ]
            }
        ],
        packers: [
            {
                name: "ProGuard/R8",
                signatures: [
                    { method: "class_name_pattern", pattern: "a/b/c/d" }
                ]
            },
            {
                name: "DexGuard",
                signatures: [
                    { method: "find_string", pattern: "DexGuard" }
                ]
            }
        ]
    },

    APK: {
        libraries: [
            {
                name: "Unity",
                signatures: [
                    { method: "file_present", pattern: "libunity.so" },
                    { method: "file_present", pattern: "assets/bin/Data" }
                ]
            },
            {
                name: "Flutter",
                signatures: [
                    { method: "file_present", pattern: "libflutter.so" },
                    { method: "file_present", pattern: "flutter_assets" }
                ]
            },
            {
                name: "React Native",
                signatures: [
                    { method: "file_present", pattern: "libreactnativejni.so" },
                    { method: "file_present", pattern: "assets/index.android.bundle" }
                ]
            },
            {
                name: "Xamarin",
                signatures: [
                    { method: "file_present", pattern: "libxamarin-app.so" },
                    { method: "file_present", pattern: "libmonodroid.so" }
                ]
            },
            {
                name: "IL2CPP",
                signatures: [
                    { method: "file_present", pattern: "libil2cpp.so" }
                ]
            },
            {
                name: "Cordova/Ionic",
                signatures: [
                    { method: "file_present", pattern: "cordova.js" }
                ]
            }
        ],
        packers: [
            {
                name: "APKProtect",
                signatures: [
                    { method: "find_string", pattern: "APKProtect" }
                ]
            },
            {
                name: "Bangcle",
                signatures: [
                    { method: "file_present", pattern: "libsecexe.so" }
                ]
            },
            {
                name: "360 Protect",
                signatures: [
                    { method: "file_present", pattern: "libjiagu.so" }
                ]
            },
            {
                name: "Alibaba",
                signatures: [
                    { method: "file_present", pattern: "libmobsecexe.so" }
                ]
            }
        ]
    },

    // Java Class 文件签名
    JavaClass: {
        compilers: [
            {
                name: "Kotlin",
                signatures: [
                    { method: "class_name", pattern: "kotlin/" }
                ]
            },
            {
                name: "Scala",
                signatures: [
                    { method: "class_name", pattern: "scala/" }
                ]
            },
            {
                name: "Groovy",
                signatures: [
                    { method: "class_name", pattern: "groovy/" }
                ]
            }
        ],
        libraries: [
            {
                name: "Spring",
                signatures: [
                    { method: "class_name", pattern: "org/springframework/" }
                ]
            },
            {
                name: "Hibernate",
                signatures: [
                    { method: "class_name", pattern: "org/hibernate/" }
                ]
            },
            {
                name: "JUnit",
                signatures: [
                    { method: "class_name", pattern: "org/junit/" }
                ]
            },
            {
                name: "Android",
                signatures: [
                    { method: "class_name", pattern: "android/" }
                ]
            }
        ]
    }
};

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DIESignatures;
}