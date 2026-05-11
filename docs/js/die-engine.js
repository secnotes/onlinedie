// DIE 检测引擎 - 基于签名数据库进行文件识别

class DIEEngine {
    constructor() {
        this.results = [];
    }

    // 检测文件类型
    detect(parser) {
        const results = {
            format: null,
            compiler: [],
            packer: [],
            protector: [],
            library: [],
            details: {}
        };

        // 首先检测文件格式
        const formatResult = this.detectFormat(parser);
        if (formatResult) {
            results.format = formatResult;

            // 根据文件格式进行进一步检测
            if (formatResult.format === 'PE') {
                this.detectPE(parser, results, formatResult);
            } else if (formatResult.format === 'ELF') {
                this.detectELF(parser, results, formatResult);
            } else if (formatResult.format === 'Mach-O' || formatResult.format === 'Mach-O Universal') {
                this.detectMachO(parser, results, formatResult);
            } else if (formatResult.format === 'MS-DOS' || formatResult.format === 'COM') {
                this.detectMSDOS(parser, results, formatResult);
            } else if (formatResult.format === 'DEX') {
                this.detectDEX(parser, results, formatResult);
            } else if (formatResult.format === 'ZIP' || formatResult.format === 'APK' || formatResult.format === 'JAR') {
                this.detectZIP(parser, results, formatResult);
            } else if (formatResult.format === 'Java Class') {
                this.detectJavaClass(parser, results, formatResult);
            }
        } else {
            // 通用检测
            results.format = this.detectGeneric(parser);
        }

        // 去重
        results.compiler = [...new Set(results.compiler)];
        results.packer = [...new Set(results.packer)];
        results.protector = [...new Set(results.protector)];
        results.library = [...new Set(results.library)];

        return results;
    }

    // 检测文件格式
    detectFormat(parser) {
        // 按优先级检测
        const checks = [
            { check: () => parser.parsePE(), name: 'PE' },
            { check: () => parser.parseELF(), name: 'ELF' },
            { check: () => parser.parseMachO(), name: 'Mach-O' },
            { check: () => parser.parseDEX(), name: 'DEX' },
            { check: () => parser.parseJavaClass(), name: 'Java Class' },
            { check: () => parser.parseZIP(), name: 'ZIP' }
        ];

        for (const { check, name } of checks) {
            const result = check();
            if (result) {
                return result;
            }
        }

        // 魔数检测
        return this.detectMagic(parser);
    }

    // 魔数检测
    detectMagic(parser) {
        for (const [key, sig] of Object.entries(Signatures.magic)) {
            const bytes = parser.readBytes(sig.offset, sig.signature.length);
            if (!bytes) continue;

            let match = true;
            for (let i = 0; i < sig.signature.length; i++) {
                if (bytes[i] !== sig.signature[i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                // 特殊检查
                if (sig.webPCheck) {
                    const webpMarker = parser.readString(8, 4);
                    if (webpMarker !== 'WEBP') continue;
                }

                if (sig.riffType) {
                    const riffType = parser.readString(8, 4);
                    if (riffType !== sig.riffType) continue;
                }

                return {
                    format: sig.name,
                    fullName: sig.fullName,
                    type: 'File',
                    details: { description: sig.description }
                };
            }
        }

        return null;
    }

    // 通用检测
    detectGeneric(parser) {
        const sampleSize = Math.min(1024, parser.size);
        const sample = parser.readBytes(0, sampleSize);

        if (sample) {
            let textRatio = 0;
            for (let i = 0; i < sample.length; i++) {
                const byte = sample[i];
                if ((byte >= 32 && byte < 127) || byte === 10 || byte === 13 || byte === 9) {
                    textRatio++;
                }
            }

            const ratio = textRatio / sampleSize;
            if (ratio > 0.95) {
                return {
                    format: 'Text',
                    type: 'Text File',
                    details: { textRatio: ratio.toFixed(2) }
                };
            }
        }

        return {
            format: 'Binary',
            type: 'Binary File',
            details: { description: '未知文件格式' }
        };
    }

    // ===== PE 文件检测 =====
    detectPE(parser, results, data) {
        // 使用完整签名数据库
        const sigDB = typeof DIESignaturesFull !== 'undefined' ? DIESignaturesFull :
                      (typeof DIESignatures !== 'undefined' ? DIESignatures : null);

        if (sigDB && sigDB.PE) {
            const sigs = sigDB.PE;

            // 检测编译器
            if (sigs.compilers) {
                for (const sig of sigs.compilers) {
                    if (this.matchPESignature(parser, sig, data)) {
                        results.compiler.push(sig.name);
                        if (sig.language) results.library.push(sig.language);
                    }
                }
            }

            // 检测打包器
            if (sigs.packers) {
                for (const sig of sigs.packers) {
                    if (this.matchPESignature(parser, sig, data)) {
                        results.packer.push(sig.name);
                        if (sig.language) results.library.push(sig.language);
                    }
                }
            }

            // 检测保护器
            if (sigs.protectors) {
                for (const sig of sigs.protectors) {
                    if (this.matchPESignature(parser, sig, data)) {
                        results.protector.push(sig.name);
                    }
                }
            }

            // 检测安装器
            if (sigs.installers) {
                for (const sig of sigs.installers) {
                    if (this.matchPESignature(parser, sig, data)) {
                        results.packer.push(sig.name);
                    }
                }
            }
        }

        // 传统签名检测（兼容）
        this.detectPELegacy(parser, results, data);

        // 从导入表检测库
        this.detectFromImports(results, data);

        // 添加详细信息
        results.details = data.details || {};
        results.sections = data.sections || [];
        results.imports = data.imports || [];
    }

    // 匹配 PE 签名
    matchPESignature(parser, sig, data) {
        if (!sig.signatures) return false;

        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'section_name':
                    if (this.checkSectionName(data.sections, pattern.pattern)) return true;
                    break;

                case 'section_name_regex':
                    if (this.checkSectionNameRegex(data.sections, pattern.pattern)) return true;
                    break;

                case 'find_string':
                    if (this.findString(parser, pattern.pattern)) return true;
                    break;

                case 'find_bytes':
                    if (this.findBytes(parser, pattern.pattern)) return true;
                    break;

                case 'entry_point_bytes':
                    const epOffset = parser.getPEEntryPointOffset();
                    if (epOffset && parser.matchHexPattern(epOffset, pattern.pattern)) return true;
                    break;

                case 'import_dll':
                    if (this.checkImportDLL(data.imports, pattern.pattern)) return true;
                    break;

                case 'import_dll_regex':
                    if (this.checkImportDLLRegex(data.imports, pattern.pattern)) return true;
                    break;

                case 'bytes_at_offset':
                    // 特定偏移的字节匹配（暂时跳过）
                    break;

                // 移除了 is_dotnet 和 rich_header 等通用检测方法
            }
        }
        return false;
    }

    // 传统 PE 检测（兼容旧签名）
    detectPELegacy(parser, results, data) {
        if (typeof Signatures !== 'undefined' && Signatures.peCompilers) {
            for (const compiler of Signatures.peCompilers) {
                if (this.checkCompilerLegacy(parser, data, compiler)) {
                    results.compiler.push(compiler.name);
                }
            }

            for (const packer of Signatures.pePackers) {
                if (this.checkPackerLegacy(parser, data, packer)) {
                    results.packer.push(packer.name);
                }
            }
        }
    }

    checkCompilerLegacy(parser, data, signature) {
        if (signature.sectionNames) {
            const hasSection = signature.sectionNames.some(name =>
                data.sections && data.sections.some(s => s.name === name)
            );
            if (hasSection) return true;
        }

        if (signature.signatures) {
            for (const sig of signature.signatures) {
                if (parser.searchString(sig.pattern, 0, Math.min(parser.size, 1000000)) !== -1) {
                    return true;
                }
            }
        }

        return false;
    }

    checkPackerLegacy(parser, data, signature) {
        if (signature.sectionNames) {
            const hasSection = signature.sectionNames.some(name =>
                data.sections && data.sections.some(s => s.name === name)
            );
            if (hasSection) return true;
        }

        if (signature.signatures) {
            for (const sig of signature.signatures) {
                if (parser.searchString(sig.pattern, 0, Math.min(parser.size, 1000000)) !== -1) {
                    return true;
                }
            }
        }

        return false;
    }

    // ===== ELF 文件检测 =====
    detectELF(parser, results, data) {
        // 使用完整 ELF 签名数据库
        const sigDB = typeof ELFSignaturesFull !== 'undefined' ? ELFSignaturesFull :
                      (typeof DIESignaturesFull !== 'undefined' ? DIESignaturesFull.ELF : null);

        if (sigDB) {
            // 检测编译器
            if (sigDB.compilers) {
                for (const sig of sigDB.compilers) {
                    if (this.matchELFSignature(parser, sig, data)) {
                        results.compiler.push(sig.name);
                        if (sig.language) results.library.push(sig.language);
                    }
                }
            }

            // 检测库
            if (sigDB.libraries) {
                for (const sig of sigDB.libraries) {
                    if (this.matchELFSignature(parser, sig, data)) {
                        results.library.push(sig.name);
                    }
                }
            }

            // 检测打包器
            if (sigDB.packers) {
                for (const sig of sigDB.packers) {
                    if (this.matchELFSignature(parser, sig, data)) {
                        results.packer.push(sig.name);
                    }
                }
            }

            // 检测保护器
            if (sigDB.protectors) {
                for (const sig of sigDB.protectors) {
                    if (this.matchELFSignature(parser, sig, data)) {
                        results.protector.push(sig.name);
                    }
                }
            }
        }

        // 从 .comment 段检测编译器
        this.detectFromCommentSection(parser, results, data);

        // 从 needed libs 检测库
        this.detectFromNeededLibs(results, data);

        results.details = data.details || {};
        results.sections = data.sections || [];
        results.neededLibs = data.neededLibs || [];
    }

    // 匹配 ELF 签名
    matchELFSignature(parser, sig, data) {
        if (!sig.signatures) return false;

        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'section_name':
                    if (this.checkSectionName(data.sections, pattern.pattern)) return true;
                    break;

                case 'section_name_regex':
                    if (this.checkSectionNameRegex(data.sections, pattern.pattern)) return true;
                    break;

                case 'find_string':
                    if (this.findString(parser, pattern.pattern)) return true;
                    break;

                case 'find_string_section':
                    if (this.findStringInSection(parser, data.sections, pattern.table, pattern.pattern)) return true;
                    break;

                case 'dynstr_string':
                    // 在 .dynstr 段中查找字符串
                    if (this.findDynstrString(parser, data.sections, pattern.pattern)) return true;
                    break;

                case 'find_string_end':
                    if (this.findStringAtEnd(parser, pattern.pattern, pattern.offset_from_end || 0)) return true;
                    break;

                case 'needed_lib':
                    if (this.checkNeededLib(data.neededLibs, pattern.pattern)) return true;
                    break;

                case 'symbol':
                    // 检测符号表（需要解析）
                    break;

                case 'entry_point_bytes':
                    const epOffset = parser.getELFEntryPointOffset();
                    if (epOffset && parser.matchHexPattern(epOffset, pattern.pattern)) return true;
                    break;
            }
        }
        return false;
    }

    // 在 .dynstr 段中查找字符串
    findDynstrString(parser, sections, str) {
        if (!sections) return false;
        const dynstr = sections.find(s => s.name === '.dynstr');
        if (!dynstr) return false;

        const offset = parseInt(dynstr.offset, 16) || dynstr.offset;
        const size = Math.min(dynstr.size, 50000);

        return parser.searchString(str, offset, offset + size) !== -1;
    }

    // 从 .comment 段检测
    detectFromCommentSection(parser, results, data) {
        if (!data.sections) return;

        const commentSection = data.sections.find(s => s.name === '.comment');
        if (!commentSection) return;

        const offset = parseInt(commentSection.offset, 16) || commentSection.offset;
        const size = Math.min(commentSection.size, 10000);

        if (size > 0) {
            const comment = parser.readString(offset, size);
            if (comment) {
                if (comment.includes('GCC')) {
                    results.compiler.push('GCC');
                }
                if (comment.includes('clang')) {
                    results.compiler.push('Clang/LLVM');
                }
                if (comment.includes('rustc')) {
                    results.compiler.push('Rust');
                }
                if (comment.includes('zig')) {
                    results.compiler.push('Zig');
                }
            }
        }
    }

    // 从依赖库检测
    detectFromNeededLibs(results, data) {
        if (!data.neededLibs) return;

        const libPatterns = {
            'glibc': ['libc.so', 'libc-'],
            'Qt': ['libQt'],
            'SDL': ['libSDL'],
            'FFmpeg': ['libav', 'libffmpeg'],
            'OpenSSL': ['libssl', 'libcrypto'],
            'SQLite': ['libsqlite'],
            'curl': ['libcurl'],
            'zlib': ['libz'],
            'Boost': ['libboost'],
            'Python': ['libpython'],
            'X11': ['libX11'],
            'OpenGL': ['libGL'],
            'FreeType': ['libfreetype'],
            'PulseAudio': ['libpulse'],
            'DBus': ['libdbus']
        };

        for (const lib of data.neededLibs) {
            for (const [name, patterns] of Object.entries(libPatterns)) {
                if (patterns.some(p => lib.includes(p))) {
                    results.library.push(name);
                }
            }
        }
    }

    // 传统 ELF 检测
    detectELFLegacy(parser, results, data) {
        if (typeof Signatures !== 'undefined' && Signatures.elfCompilers) {
            for (const compiler of Signatures.elfCompilers) {
                if (this.checkELFCompilerLegacy(parser, data, compiler)) {
                    results.compiler.push(compiler.name);
                }
            }
        }

        // 搜索特定段名
        if (data.sections) {
            if (data.sections.some(s => s.name === '.gosymtab' || s.name === '.gopclntab')) {
                results.compiler.push('Go');
                results.library.push('Go');
            }
            if (data.sections.some(s => s.name.includes('.note.rust') || s.name === '.note.rust')) {
                results.compiler.push('Rust');
            }
        }
    }

    checkELFCompilerLegacy(parser, data, signature) {
        if (signature.sectionNames) {
            const hasSection = signature.sectionNames.some(name =>
                data.sections && data.sections.some(s => s.name === name)
            );
            if (hasSection) return true;
        }

        if (signature.signatures) {
            for (const sig of signature.signatures) {
                if (parser.searchString(sig.pattern, 0, Math.min(parser.size, 500000)) !== -1) {
                    return true;
                }
            }
        }

        return false;
    }

    // ===== Mach-O 检测 =====
    detectMachO(parser, results, data) {
        if (typeof DIESignatures !== 'undefined' && DIESignatures.MACH) {
            const sigs = DIESignatures.MACH;

            for (const sig of sigs.compilers) {
                if (this.matchMachOSignature(sig, data)) {
                    results.compiler.push(sig.name);
                    if (sig.language) results.library.push(sig.language);
                }
            }

            for (const sig of sigs.libraries) {
                if (this.matchMachOSignature(sig, data)) {
                    results.library.push(sig.name);
                }
            }
        }

        // Swift 检测
        const swiftOffset = parser.searchString('$s', 0, Math.min(parser.size, 100000));
        if (swiftOffset !== -1) {
            results.compiler.push('Swift');
        }

        // Objective-C 检测
        const objcOffset = parser.searchString('_OBJC_', 0, Math.min(parser.size, 100000));
        if (objcOffset !== -1) {
            results.compiler.push('Objective-C');
        }

        // 从 dylibs 检测
        if (data.dylibs) {
            for (const dylib of data.dylibs) {
                if (dylib.includes('libswift')) {
                    results.compiler.push('Swift');
                }
                if (dylib.includes('UIKit') || dylib.includes('AppKit')) {
                    results.library.push('AppKit/UIKit');
                }
                if (dylib.includes('Foundation')) {
                    results.library.push('Foundation');
                }
            }
        }

        results.details = data.details || {};
        results.dylibs = data.dylibs || [];
    }

    matchMachOSignature(sig, data) {
        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'section_name':
                    if (this.checkMachOSectionName(data.sections || [], pattern.pattern)) return true;
                    break;

                case 'dylib':
                    if (data.dylibs && data.dylibs.some(d => d.includes(pattern.pattern))) return true;
                    break;

                case 'load_command':
                    if (data.loadCommands && data.loadCommands.some(lc => lc.cmd.includes(pattern.cmd))) return true;
                    break;
            }
        }
        return false;
    }

    checkMachOSectionName(sections, name) {
        return sections.some(s => {
            if (s.segment && s.section) {
                return `${s.segment}.${s.section}`.includes(name);
            }
            return s.name && s.name.includes(name);
        });
    }

    // ===== MSDOS 检测 =====
    detectMSDOS(parser, results, data) {
        // 使用 MSDOS 签名数据库
        if (typeof MSDOSSignatures !== 'undefined') {
            const sigs = MSDOSSignatures;

            // 检测编译器
            if (sigs.compilers) {
                for (const sig of sigs.compilers) {
                    if (this.matchMSDOSignature(parser, sig, data)) {
                        results.compiler.push(sig.name);
                    }
                }
            }

            // 检测打包器
            if (sigs.packers) {
                for (const sig of sigs.packers) {
                    if (this.matchMSDOSignature(parser, sig, data)) {
                        results.packer.push(sig.name);
                    }
                }
            }

            // 检测保护器
            if (sigs.protectors) {
                for (const sig of sigs.protectors) {
                    if (this.matchMSDOSignature(parser, sig, data)) {
                        results.protector.push(sig.name);
                    }
                }
            }
        }

        // 传统 MSDOS 检测
        this.detectMSDOSLegacy(parser, results, data);

        results.details = data.details || {};
    }

    // 匹配 MSDOS 签名
    matchMSDOSignature(parser, sig, data) {
        if (!sig.signatures) return false;

        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'entry_point_bytes':
                    const epOffset = parser.getMSDOSEntryPointOffset();
                    if (epOffset && parser.matchHexPattern(epOffset, pattern.pattern)) {
                        return true;
                    }
                    break;

                case 'find_string':
                    if (this.findString(parser, pattern.pattern)) {
                        return true;
                    }
                    break;

                case 'bytes_at_offset':
                    // 特定偏移匹配
                    break;
            }
        }
        return false;
    }

    // 传统 MSDOS 检测
    detectMSDOSLegacy(parser, results, data) {
        // Borland Pascal 检测
        const pascalOffset = parser.searchString('Turbo Pascal', 0, Math.min(parser.size, 100000));
        if (pascalOffset !== -1) {
            results.compiler.push('Borland Pascal');
        }

        // Borland C 检测
        const borlandOffset = parser.searchString('Borland C++', 0, Math.min(parser.size, 100000));
        if (borlandOffset !== -1) {
            results.compiler.push('Borland C/C++');
        }

        // Turbo C 检测
        const turboOffset = parser.searchString('Turbo C', 0, Math.min(parser.size, 100000));
        if (turboOffset !== -1) {
            results.compiler.push('Turbo C');
        }

        // Microsoft C 检测
        const msCOffset = parser.searchString('Microsoft C', 0, Math.min(parser.size, 100000));
        if (msCOffset !== -1) {
            results.compiler.push('Microsoft C');
        }

        // Watcom C 检测
        const watcomOffset = parser.searchString('Watcom', 0, Math.min(parser.size, 100000));
        if (watcomOffset !== -1) {
            results.compiler.push('Watcom C/C++');
        }

        // UPX DOS 检测
        const upxOffset = parser.searchString('UPX', 0, Math.min(parser.size, 50000));
        if (upxOffset !== -1) {
            results.packer.push('UPX');
        }
    }

    // ===== DEX 检测 =====
    detectDEX(parser, results, data) {
        if (typeof DIESignatures !== 'undefined' && DIESignatures.DEX) {
            for (const sig of DIESignatures.DEX.compilers) {
                if (this.matchDEXSignature(parser, sig, data)) {
                    results.compiler.push(sig.name);
                }
            }

            for (const sig of DIESignatures.DEX.packers) {
                if (this.matchDEXSignature(parser, sig, data)) {
                    results.packer.push(sig.name);
                }
            }
        }

        // Kotlin 检测
        const kotlinOffset = parser.searchString('kotlin/', 0, Math.min(parser.size, 500000));
        if (kotlinOffset !== -1) {
            results.compiler.push('Kotlin');
        }

        // Scala 检测
        const scalaOffset = parser.searchString('scala/', 0, Math.min(parser.size, 500000));
        if (scalaOffset !== -1) {
            results.compiler.push('Scala');
        }

        // ProGuard 检测
        if (data.details && data.details.classes) {
            const obfuscatedClassPattern = /^[a-z]{1,2}$/;
            if (data.details.classes.some(c => obfuscatedClassPattern.test(c))) {
                results.packer.push('ProGuard/R8');
            }
        }

        results.details = data.details || {};
    }

    matchDEXSignature(parser, sig, data) {
        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'find_string':
                    if (this.findString(parser, pattern.pattern)) return true;
                    break;

                case 'class_name':
                    // 需要类名解析
                    break;
            }
        }
        return false;
    }

    // ===== ZIP/APK/JAR 检测 =====
    detectZIP(parser, results, data) {
        if (typeof DIESignatures !== 'undefined' && DIESignatures.APK && data.format === 'APK') {
            for (const sig of DIESignatures.APK.libraries) {
                if (this.matchAPKSignature(sig, data)) {
                    results.library.push(sig.name);
                }
            }

            for (const sig of DIESignatures.APK.packers) {
                if (this.matchAPKSignature(sig, data)) {
                    results.packer.push(sig.name);
                }
            }
        }

        // 传统检测
        if (typeof Signatures !== 'undefined' && data.format === 'APK') {
            for (const sig of Signatures.apkSignatures) {
                if (this.checkAPKFramework(data, sig)) {
                    results.library.push(sig.name);
                }
            }
        }

        if (data.format === 'JAR') {
            const hasSpring = data.files && data.files.some(f =>
                f.name.includes('spring') || f.name.includes('org/springframework')
            );
            if (hasSpring) {
                results.library.push('Spring Framework');
            }
        }

        results.details = data.details || {};
        results.files = data.files || [];
    }

    matchAPKSignature(sig, data) {
        for (const pattern of sig.signatures) {
            switch (pattern.method) {
                case 'file_present':
                    if (data.files && data.files.some(f => f.name.includes(pattern.pattern))) return true;
                    if (data.entries && data.entries.some(e => e.name.includes(pattern.pattern))) return true;
                    break;

                case 'find_string':
                    // APK 内文件搜索
                    break;
            }
        }
        return false;
    }

    checkAPKFramework(zipData, signature) {
        if (signature.signatures) {
            for (const sig of signature.signatures) {
                const hasFile = zipData.files && zipData.files.some(f =>
                    f.name.includes(sig.pattern) || f.name === sig.pattern
                );
                if (hasFile) return true;
            }
        }
        return false;
    }

    // ===== Java Class 检测 =====
    detectJavaClass(parser, results, data) {
        if (typeof DIESignatures !== 'undefined' && DIESignatures.JavaClass) {
            for (const sig of DIESignatures.JavaClass.compilers) {
                if (this.matchJavaClassSignature(sig, data)) {
                    results.compiler.push(sig.name);
                }
            }

            for (const sig of DIESignatures.JavaClass.libraries) {
                if (this.matchJavaClassSignature(sig, data)) {
                    results.library.push(sig.name);
                }
            }
        }

        results.details = data.details || {};
    }

    matchJavaClassSignature(sig, data) {
        for (const pattern of sig.signatures) {
            if (pattern.method === 'class_name') {
                if (data.details && data.details.className && data.details.className.includes(pattern.pattern)) {
                    return true;
                }
            }
        }
        return false;
    }

    // ===== 辅助方法 =====

    // 检查段名
    checkSectionName(sections, name) {
        if (!sections) return false;
        return sections.some(s => s.name === name || s.name.includes(name));
    }

    // 检查段名正则
    checkSectionNameRegex(sections, pattern) {
        if (!sections) return false;
        try {
            const regex = new RegExp(pattern, 'i');
            return sections.some(s => regex.test(s.name));
        } catch (e) {
            return false;
        }
    }

    // 检查导入 DLL
    checkImportDLL(imports, dllName) {
        if (!imports) return false;
        return imports.some(imp => {
            if (typeof imp === 'string') {
                return imp.toLowerCase().includes(dllName.toLowerCase());
            }
            return false;
        });
    }

    // 检查导入 DLL 正则
    checkImportDLLRegex(imports, pattern) {
        if (!imports) return false;
        try {
            const regex = new RegExp(pattern, 'i');
            return imports.some(imp => {
                if (typeof imp === 'string') {
                    return regex.test(imp);
                }
                return false;
            });
        } catch (e) {
            return false;
        }
    }

    // 检查依赖库
    checkNeededLib(neededLibs, libName) {
        if (!neededLibs) return false;
        return neededLibs.some(lib => lib.includes(libName));
    }

    // 查找字符串
    findString(parser, str) {
        return parser.searchString(str, 0, Math.min(parser.size, 500000)) !== -1;
    }

    // 查找字节
    findBytes(parser, hexPattern) {
        const pattern = hexPattern.replace(/\?/g, 'XX').replace(/\$/g, 'XX');
        const bytes = [];

        for (let i = 0; i < pattern.length; i += 2) {
            const hex = pattern.substr(i, 2);
            if (hex === 'XX' || hex === '??') {
                bytes.push(null);
            } else {
                bytes.push(parseInt(hex, 16));
            }
        }

        const maxSearch = Math.min(parser.size, 500000);
        for (let i = 0; i < maxSearch - bytes.length; i++) {
            let match = true;
            for (let j = 0; j < bytes.length && j < 100; j++) {
                if (bytes[j] !== null) {
                    const actualByte = parser.readUint8(i + j);
                    if (actualByte !== bytes[j]) {
                        match = false;
                        break;
                    }
                }
            }
            if (match) return true;
        }
        return false;
    }

    // 在特定段中查找字符串
    findStringInSection(parser, sections, sectionName, str) {
        if (!sections) return false;
        const section = sections.find(s => s.name === sectionName);
        if (!section) return false;

        const offset = parseInt(section.offset, 16) || section.offset;
        const size = Math.min(section.size, 100000);

        return parser.searchString(str, offset, offset + size) !== -1;
    }

    // 在文件末尾查找字符串
    findStringAtEnd(parser, str, offsetFromEnd) {
        const fileSize = parser.size;
        const searchOffset = fileSize - str.length - offsetFromEnd;
        if (searchOffset < 0) return false;

        const searchBytes = new TextEncoder().encode(str);
        for (let j = 0; j < searchBytes.length; j++) {
            if (parser.readUint8(searchOffset + j) !== searchBytes[j]) {
                return false;
            }
        }
        return true;
    }

    // 从导入表检测库
    detectFromImports(results, data) {
        if (!data.imports) return;

        const importPatterns = {
            'MFC': ['MFC', 'AFX'],
            'ATL': ['ATL'],
            'GDI+': ['GDIPLUS'],
            'DirectX': ['d3d', 'D3D', 'dxgi'],
            'OpenGL': ['OPENGL32', 'GL'],
            'WinSock': ['ws2_32', 'wsock32'],
            'Crypto': ['CRYPT32', 'bcrypt'],
            'SQLite': ['sqlite3'],
            'MySQL': ['libmysql'],
            'libcurl': ['libcurl', 'curl'],
            'OpenSSL': ['libssl', 'openssl'],
            'zlib': ['zlib'],
            'FFmpeg': ['ffmpeg', 'avcodec', 'avformat'],
            'SDL': ['SDL', 'SDL2'],
            'Boost': ['boost'],
            'Node.js': ['node'],
            'Electron': ['electron', 'node']
        };

        for (const [name, patterns] of Object.entries(importPatterns)) {
            for (const pattern of patterns) {
                if (data.imports.some(imp => imp.toLowerCase().includes(pattern.toLowerCase()))) {
                    results.library.push(name);
                    break;
                }
            }
        }
    }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DIEEngine;
}