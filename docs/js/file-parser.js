// 文件解析器 - 解析各种文件格式

class FileParser {
    constructor(buffer) {
        this.buffer = buffer;
        this.view = new DataView(buffer);
        this.uint8 = new Uint8Array(buffer);
        this.size = buffer.byteLength;
    }

    // 读取指定偏移处的字节
    readBytes(offset, length) {
        if (offset + length > this.size) return null;
        return this.uint8.slice(offset, offset + length);
    }

    // 读取字符串
    readString(offset, length, encoding = 'utf-8') {
        const bytes = this.readBytes(offset, length);
        if (!bytes) return null;
        try {
            return new TextDecoder(encoding).decode(bytes);
        } catch {
            return String.fromCharCode.apply(null, bytes);
        }
    }

    // 读取以null结尾的字符串
    readNullTerminatedString(offset, maxLength = 256) {
        let end = offset;
        while (end < offset + maxLength && end < this.size && this.uint8[end] !== 0) {
            end++;
        }
        return this.readString(offset, end - offset);
    }

    // 读取 uint8
    readUint8(offset) {
        if (offset >= this.size) return null;
        return this.view.getUint8(offset);
    }

    // 读取 uint16 (little endian)
    readUint16LE(offset) {
        if (offset + 2 > this.size) return null;
        return this.view.getUint16(offset, true);
    }

    // 读取 uint32 (little endian)
    readUint32LE(offset) {
        if (offset + 4 > this.size) return null;
        return this.view.getUint32(offset, true);
    }

    // 读取 uint64 (little endian)
    readUint64LE(offset) {
        if (offset + 8 > this.size) return null;
        const low = this.view.getUint32(offset, true);
        const high = this.view.getUint32(offset + 4, true);
        return high * 0x100000000 + low;
    }

    // 读取 uint16 (big endian)
    readUint16BE(offset) {
        if (offset + 2 > this.size) return null;
        return this.view.getUint16(offset, false);
    }

    // 读取 uint32 (big endian)
    readUint32BE(offset) {
        if (offset + 4 > this.size) return null;
        return this.view.getUint32(offset, false);
    }

    // 搜索字节序列
    searchBytes(pattern, startOffset = 0, endOffset = null) {
        const end = endOffset || this.size;
        for (let i = startOffset; i < end - pattern.length; i++) {
            let found = true;
            for (let j = 0; j < pattern.length; j++) {
                if (this.uint8[i + j] !== pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    // 搜索字符串
    searchString(str, startOffset = 0, endOffset = null, encoding = 'utf-8') {
        const pattern = new TextEncoder().encode(str);
        return this.searchBytes(pattern, startOffset, endOffset);
    }

    // 检查魔数
    checkMagic(expected, offset = 0) {
        const actual = this.readBytes(offset, expected.length);
        if (!actual) return false;
        for (let i = 0; i < expected.length; i++) {
            if (actual[i] !== expected[i]) return false;
        }
        return true;
    }

    // 匹配十六进制字节模式（支持 ?? 通配符）
    matchHexPattern(offset, hexPattern) {
        if (offset >= this.size) return false;

        // 解析十六进制模式
        const bytes = [];
        for (let i = 0; i < hexPattern.length; i += 2) {
            const hex = hexPattern.substr(i, 2);
            if (hex === '??' || hex === '**') {
                bytes.push(null); // 通配符
            } else {
                bytes.push(parseInt(hex, 16));
            }
        }

        // 匹配
        for (let i = 0; i < bytes.length && i < 200; i++) {
            if (offset + i >= this.size) return false;
            if (bytes[i] !== null) {
                const actualByte = this.readUint8(offset + i);
                if (actualByte !== bytes[i]) {
                    return false;
                }
            }
        }
        return true;
    }

    // 获取 PE 入口点文件偏移
    getPEEntryPointOffset() {
        try {
            // 检查是否是 PE 文件
            if (!this.checkMagic([0x4D, 0x5A])) return null;

            const peOffset = this.readUint32LE(0x3C);
            if (!this.checkMagic([0x50, 0x45, 0x00, 0x00], peOffset)) return null;

            const optOffset = peOffset + 24;
            const magic = this.readUint16LE(optOffset);
            const isPE32Plus = magic === 0x20b;

            // AddressOfEntryPoint
            const entryRVA = this.readUint32LE(optOffset + 16);
            if (!entryRVA) return null;

            // 解析段表找到入口点所在的段
            const numSections = this.readUint16LE(peOffset + 6);
            const sizeOfOptionalHeader = this.readUint16LE(peOffset + 20);
            const sectionOffset = optOffset + sizeOfOptionalHeader;

            for (let i = 0; i < numSections && i < 50; i++) {
                const secOff = sectionOffset + i * 40;
                const vaddr = this.readUint32LE(secOff + 12);
                const vsize = this.readUint32LE(secOff + 8);
                const rawOffset = this.readUint32LE(secOff + 20);

                if (entryRVA >= vaddr && entryRVA < vaddr + vsize) {
                    return rawOffset + (entryRVA - vaddr);
                }
            }
        } catch (e) {}
        return null;
    }

    // 获取 ELF 入口点文件偏移
    getELFEntryPointOffset() {
        try {
            if (!this.checkMagic([0x7F, 0x45, 0x4C, 0x46])) return null;

            const eiClass = this.readUint8(4);
            const eiData = this.readUint8(5);
            const is64Bit = eiClass === 2;
            const isLittleEndian = eiData === 1;

            const read32 = (offset) => isLittleEndian ? this.readUint32LE(offset) : this.readUint32BE(offset);
            const read64 = (offset) => {
                if (isLittleEndian) return this.readUint64LE(offset);
                const high = this.readUint32BE(offset);
                const low = this.readUint32BE(offset + 4);
                return high * 0x100000000 + low;
            };

            // 入口点虚拟地址
            const eEntry = is64Bit ? read64(24) : read32(24);
            if (!eEntry) return null;

            // 程序头
            const ePhoff = is64Bit ? read64(32) : read32(28);
            const ePhentsize = read16(is64Bit ? 54 : 42);
            const ePhnum = read16(is64Bit ? 56 : 44);

            const read16 = (offset) => isLittleEndian ? this.readUint16LE(offset) : this.readUint16BE(offset);

            // 找入口点所在的段
            for (let i = 0; i < ePhnum; i++) {
                const phOff = ePhoff + i * ePhentsize;
                const pType = read32(phOff);

                // 只看 PT_LOAD 段
                if (pType !== 1) continue;

                const pVaddr = is64Bit ? read64(phOff + (is64Bit ? 16 : 8)) : read32(phOff + 8);
                const pMemsz = is64Bit ? read64(phOff + (is64Bit ? 32 : 20)) : read32(phOff + 20);
                const pOffset = is64Bit ? read64(phOff + (is64Bit ? 8 : 4)) : read32(phOff + 4);

                if (eEntry >= pVaddr && eEntry < pVaddr + pMemsz) {
                    return pOffset + (eEntry - pVaddr);
                }
            }
        } catch (e) {}
        return null;
    }

    // 解析 PE 文件 - 详细版本（性能优化）
    parsePE() {
        if (!this.checkMagic([0x4D, 0x5A])) return null;

        const result = {
            format: 'PE',
            type: 'Executable',
            platform: 'Windows',
            sections: [],
            imports: [],
            exports: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {},
            dosHeader: {},
            coffHeader: {},
            optionalHeader: {},
            dataDirectories: []
        };

        try {
            const peOffset = this.readUint32LE(0x3C);
            if (!this.checkMagic([0x50, 0x45, 0x00, 0x00], peOffset)) {
                if (this.size > 512) return this.parseMSDOS();
                return null;
            }

            // DOS Header
            result.dosHeader = {
                e_magic: 'MZ',
                e_lfanew: '0x' + peOffset.toString(16).toUpperCase()
            };

            // COFF Header
            const coffOffset = peOffset + 4;
            const machine = this.readUint16LE(coffOffset);
            const numberOfSections = this.readUint16LE(coffOffset + 2);
            const timestamp = this.readUint32LE(coffOffset + 4);
            const pointerToSymbolTable = this.readUint32LE(coffOffset + 8);
            const numberOfSymbols = this.readUint32LE(coffOffset + 12);
            const sizeOfOptionalHeader = this.readUint16LE(coffOffset + 16);
            const characteristics = this.readUint16LE(coffOffset + 18);

            const machineTypes = {
                0x14c: 'i386 (Intel 386)', 0x8664: 'AMD64 (x64)',
                0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA64',
                0x5032: 'RISCV32', 0x5064: 'RISCV64', 0x5128: 'RISCV128'
            };

            result.coffHeader = {
                machine: machineTypes[machine] || `Unknown (0x${machine.toString(16)})`,
                machineCode: '0x' + machine.toString(16),
                numberOfSections,
                timestamp,
                compileDate: new Date(timestamp * 1000).toISOString(),
                numberOfSymbols,
                characteristics: this.parseCOFFCharacteristics(characteristics)
            };

            result.details.machine = machineTypes[machine] || `0x${machine.toString(16)}`;
            result.architecture = machineTypes[machine] ? machineTypes[machine].split(' ')[0] : 'Unknown';

            // Optional Header
            const optOffset = peOffset + 24;
            const magic = this.readUint16LE(optOffset);
            const isPE32Plus = magic === 0x20b;

            const linkerMajor = this.readUint8(optOffset + 2);
            const linkerMinor = this.readUint8(optOffset + 3);
            const linkerVersion = `${linkerMajor}.${linkerMinor}`;

            const linkerMap = {
                '2.0': 'MSVC 2.x', '3.0': 'MSVC 3.x', '4.0': 'MSVC 4.x',
                '5.0': 'MSVC 5.x', '6.0': 'MSVC 6.0', '7.0': 'VS.NET 2002',
                '7.1': 'VS.NET 2003', '8.0': 'VS 2005', '9.0': 'VS 2008',
                '10.0': 'VS 2010', '11.0': 'VS 2012', '12.0': 'VS 2013',
                '14.0': 'VS 2015', '14.1': 'VS 2017', '14.2': 'VS 2019', '14.3': 'VS 2022'
            };

            const sizeOfCode = this.readUint32LE(optOffset + 4);
            const sizeOfInitData = this.readUint32LE(optOffset + 8);
            const sizeOfUninitData = this.readUint32LE(optOffset + 12);
            const entryPoint = this.readUint32LE(optOffset + 16);
            const baseOfCode = this.readUint32LE(optOffset + 20);

            let baseOfData = 0, imageBase, dirsOffset;
            if (isPE32Plus) {
                imageBase = this.readUint64LE(optOffset + 24);
                dirsOffset = optOffset + 112;
            } else {
                baseOfData = this.readUint32LE(optOffset + 24);
                imageBase = this.readUint32LE(optOffset + 28);
                dirsOffset = optOffset + 96;
            }

            const sectionAlign = this.readUint32LE(optOffset + (isPE32Plus ? 32 : 32));
            const fileAlign = this.readUint32LE(optOffset + (isPE32Plus ? 36 : 36));
            const majorOSVer = this.readUint16LE(optOffset + (isPE32Plus ? 40 : 40));
            const minorOSVer = this.readUint16LE(optOffset + (isPE32Plus ? 42 : 42));
            const majorImageVer = this.readUint16LE(optOffset + (isPE32Plus ? 44 : 44));
            const minorImageVer = this.readUint16LE(optOffset + (isPE32Plus ? 46 : 46));
            const majorSubVer = this.readUint16LE(optOffset + (isPE32Plus ? 48 : 48));
            const minorSubVer = this.readUint16LE(optOffset + (isPE32Plus ? 50 : 50));
            const sizeOfImage = this.readUint32LE(optOffset + (isPE32Plus ? 56 : 56));
            const sizeOfHeaders = this.readUint32LE(optOffset + (isPE32Plus ? 60 : 60));
            const checksum = this.readUint32LE(optOffset + (isPE32Plus ? 64 : 64));
            const subsystem = this.readUint16LE(optOffset + (isPE32Plus ? 68 : 68));
            const dllChars = this.readUint16LE(optOffset + (isPE32Plus ? 70 : 70));

            const subsystems = { 1: 'Native', 2: 'GUI', 3: 'Console', 5: 'OS/2', 7: 'POSIX', 9: 'WinCE', 10: 'EFI', 14: 'XBOX' };

            result.optionalHeader = {
                magic: isPE32Plus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
                linkerVersion,
                linkerInfo: linkerMap[linkerVersion] || 'Unknown',
                entryPoint: '0x' + entryPoint.toString(16).toUpperCase(),
                imageBase: '0x' + imageBase.toString(16).toUpperCase(),
                baseOfCode: '0x' + baseOfCode.toString(16).toUpperCase(),
                baseOfData: baseOfData ? '0x' + baseOfData.toString(16).toUpperCase() : 'N/A',
                sizeOfCode: this.formatSize(sizeOfCode),
                sizeOfInitData: this.formatSize(sizeOfInitData),
                sizeOfUninitData: this.formatSize(sizeOfUninitData),
                sectionAlign,
                fileAlign,
                osVersion: `${majorOSVer}.${minorOSVer}`,
                imageVersion: `${majorImageVer}.${minorImageVer}`,
                subsystem: subsystems[subsystem] || `Type ${subsystem}`,
                dllCharacteristics: this.parseDLLCharacteristics(dllChars),
                sizeOfImage: this.formatSize(sizeOfImage),
                sizeOfHeaders: this.formatSize(sizeOfHeaders),
                checksum: '0x' + checksum.toString(16).toUpperCase()
            };

            result.details.peType = result.optionalHeader.magic;
            result.details.entryPoint = result.optionalHeader.entryPoint;
            result.details.imageBase = result.optionalHeader.imageBase;
            result.details.subsystem = result.optionalHeader.subsystem;
            result.details.linker = linkerMap[linkerVersion] || linkerVersion;
            result.details.fileType = (characteristics & 0x2000) ? 'DLL' : 'Executable';

            // Data Directories
            const numDirs = Math.min(this.readUint32LE(dirsOffset - 8), 16);
            const dirNames = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Relocations', 'Debug', 'Architecture', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT', 'DelayImport', 'CLR', 'Reserved'];

            for (let i = 0; i < numDirs; i++) {
                const rva = this.readUint32LE(dirsOffset + i * 8);
                const size = this.readUint32LE(dirsOffset + i * 8 + 4);
                result.dataDirectories.push({
                    name: dirNames[i],
                    rva: rva ? '0x' + rva.toString(16).toUpperCase() : 'None',
                    size: size
                });
            }

            // .NET 检测
            if (numDirs >= 15) {
                const clrRva = this.readUint32LE(dirsOffset + 14 * 8);
                if (clrRva !== 0) {
                    result.details.isDotNet = true;
                    result.compilers.push('.NET');
                }
            }

            // Sections (不计算熵值)
            const secOffset = optOffset + sizeOfOptionalHeader;
            for (let i = 0; i < numberOfSections && i < 50; i++) {
                const off = secOffset + i * 40;
                const name = this.readString(off, 8).replace(/\0/g, '');
                const vsize = this.readUint32LE(off + 8);
                const vaddr = this.readUint32LE(off + 12);
                const rawSize = this.readUint32LE(off + 16);
                const rawOffset = this.readUint32LE(off + 20);
                const chars = this.readUint32LE(off + 36);

                result.sections.push({
                    name,
                    virtualAddress: '0x' + vaddr.toString(16).toUpperCase(),
                    virtualSize: vsize,
                    rawSize: rawSize,
                    rawOffset,
                    characteristics: this.parseSectionCharacteristics(chars)
                });
            }

            // 快速导入表解析
            const importRva = this.readUint32LE(dirsOffset);
            if (importRva && importRva < this.size) {
                const importSection = this.findSectionByRVA(result.sections, importRva);
                if (importSection) {
                    const importOffset = importSection.rawOffset + (importRva - parseInt(importSection.virtualAddress, 16));
                    this.parseImportsQuick(importOffset, result, 200);
                }
            }

            // Rich Header 快速检测
            if (peOffset > 128) {
                for (let i = 128; i < peOffset - 4; i += 4) {
                    if (this.readUint32LE(i) === 0x68636952) {
                        result.details.richHeader = 'Found at 0x' + i.toString(16);
                        if (!result.compilers.includes('MSVC')) result.compilers.push('MSVC');
                        break;
                    }
                }
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    parseCOFFCharacteristics(chars) {
        const flags = [];
        if (chars & 0x0001) flags.push('RELOCS_STRIPPED');
        if (chars & 0x0002) flags.push('EXECUTABLE');
        if (chars & 0x0020) flags.push('LARGE_ADDR');
        if (chars & 0x0100) flags.push('32BIT');
        if (chars & 0x0200) flags.push('DEBUG_STRIPPED');
        if (chars & 0x1000) flags.push('SYSTEM');
        if (chars & 0x2000) flags.push('DLL');
        return flags;
    }

    parseDLLCharacteristics(chars) {
        const flags = [];
        if (chars & 0x0020) flags.push('HIGH_ENTROPY');
        if (chars & 0x0040) flags.push('ASLR');
        if (chars & 0x0100) flags.push('NX_COMPAT');
        if (chars & 0x0400) flags.push('NO_SEH');
        if (chars & 0x1000) flags.push('APPCONTAINER');
        if (chars & 0x4000) flags.push('GUARD_CF');
        if (chars & 0x8000) flags.push('TERMINAL_SERVER');
        return flags;
    }

    parseImportsQuick(offset, result, maxDlls) {
        try {
            let pos = offset;
            let count = 0;
            while (pos < this.size - 20 && count < maxDlls) {
                const nameRva = this.readUint32LE(pos + 12);
                if (nameRva === 0) break;
                const nameSection = this.findSectionByRVA(result.sections, nameRva);
                if (nameSection) {
                    const nameOffset = nameSection.rawOffset + (nameRva - parseInt(nameSection.virtualAddress, 16));
                    if (nameOffset < this.size) {
                        const dllName = this.readNullTerminatedString(nameOffset, 128);
                        if (dllName) result.imports.push(dllName);
                    }
                }
                pos += 20;
                count++;
            }
        } catch (e) {}
    }

    // 计算段熵值（仅在显示时调用，不在解析时调用）
    calculateSectionEntropy(offset, size) {
        if (!offset || !size || offset + size > this.size) return null;
        const sampleSize = Math.min(size, 4096);
        const sectionData = this.uint8.slice(offset, offset + sampleSize);
        const frequency = new Array(256).fill(0);
        for (let i = 0; i < sectionData.length; i++) {
            frequency[sectionData[i]]++;
        }
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                const p = frequency[i] / sectionData.length;
                entropy -= p * Math.log2(p);
            }
        }
        return entropy.toFixed(2);
    }

    // 格式化大小
    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
    }

    // 解析段属性
    parseSectionCharacteristics(characteristics) {
        const flags = [];
        if (characteristics & 0x00000020) flags.push('CODE');
        if (characteristics & 0x00000040) flags.push('INIT_DATA');
        if (characteristics & 0x00000080) flags.push('UNINIT_DATA');
        if (characteristics & 0x02000000) flags.push('DISCARDABLE');
        if (characteristics & 0x04000000) flags.push('NOT_CACHED');
        if (characteristics & 0x08000000) flags.push('NOT_PAGED');
        if (characteristics & 0x10000000) flags.push('SHARED');
        if (characteristics & 0x20000000) flags.push('EXECUTE');
        if (characteristics & 0x40000000) flags.push('READ');
        if (characteristics & 0x80000000) flags.push('WRITE');
        return flags;
    }

    // 根据RVA查找段 (PE)
    findSectionByRVA(sections, rva) {
        for (const section of sections) {
            const sectionStart = parseInt(section.virtualAddress, 16);
            const sectionEnd = sectionStart + section.virtualSize;
            if (rva >= sectionStart && rva < sectionEnd) {
                return section;
            }
        }
        return null;
    }

    // 将 ELF 虚拟地址转换为文件偏移
    elfVaddrToFileOffset(sections, vaddr) {
        for (const section of sections) {
            const sectionStart = parseInt(section.address, 16);
            const sectionEnd = sectionStart + section.size;
            if (vaddr >= sectionStart && vaddr < sectionEnd) {
                const fileOffset = parseInt(section.offset, 16);
                return fileOffset + (vaddr - sectionStart);
            }
        }
        return null;
    }

    // 获取 MSDOS 入口点偏移
    getMSDOSEntryPointOffset() {
        try {
            // 检查是否是 MZ 文件
            if (!this.checkMagic([0x4D, 0x5A])) {
                // 可能是 COM 文件，入口点就是文件开头
                return 0;
            }

            // MZ 文件入口点计算
            // e_ip 和 e_cs 在 DOS Header 中
            const eIP = this.readUint16LE(20);  // Initial IP
            const eCS = this.readUint16LE(22);  // Initial CS

            // 计算入口点在文件中的位置
            // 对于纯 DOS MZ 文件，入口点通常在文件开头附近
            // 简化处理：返回文件开头（大多数 DOS exe 入口点在开头）
            return 0;
        } catch (e) {}
        return 0;
    }

    // 解析导入表
    parseImports(offset, result) {
        try {
            let descriptorOffset = offset;
            while (true) {
                const importLookupTableRVA = this.readUint32LE(descriptorOffset);
                const timeDateStamp = this.readUint32LE(descriptorOffset + 4);
                const forwarderChain = this.readUint32LE(descriptorOffset + 8);
                const nameRVA = this.readUint32LE(descriptorOffset + 12);
                const importAddressTableRVA = this.readUint32LE(descriptorOffset + 16);

                if (nameRVA === 0) break;

                // Find section for name
                const nameSection = this.findSectionByRVA(result.sections, nameRVA);
                if (nameSection) {
                    const nameOffset = parseInt(nameSection.rawOffset, 16) + (nameRVA - parseInt(nameSection.virtualAddress, 16));
                    const dllName = this.readNullTerminatedString(nameOffset);
                    if (dllName) {
                        result.imports.push(dllName);
                    }
                }

                descriptorOffset += 20;
                if (descriptorOffset > this.size - 20) break;
            }
        } catch (e) {
            // Ignore import parsing errors
        }
    }

    // 解析导出表
    parseExports(offset, result) {
        try {
            const characteristics = this.readUint32LE(offset);
            const timestamp = this.readUint32LE(offset + 4);
            const majorVersion = this.readUint16LE(offset + 8);
            const minorVersion = this.readUint16LE(offset + 10);
            const nameRVA = this.readUint32LE(offset + 12);
            const ordinalBase = this.readUint32LE(offset + 16);
            const numberOfFunctions = this.readUint32LE(offset + 20);
            const numberOfNames = this.readUint32LE(offset + 24);
            const addressOfFunctionsRVA = this.readUint32LE(offset + 28);
            const addressOfNamesRVA = this.readUint32LE(offset + 32);
            const addressOfNameOrdinalsRVA = this.readUint32LE(offset + 36);

            // 读取 DLL 名称
            if (nameRVA !== 0) {
                const nameSection = this.findSectionByRVA(result.sections, nameRVA);
                if (nameSection) {
                    const nameOffset = parseInt(nameSection.rawOffset, 16) + (nameRVA - parseInt(nameSection.virtualAddress, 16));
                    result.details.exportName = this.readNullTerminatedString(nameOffset);
                }
            }

            result.details.exportCount = numberOfFunctions;
            result.details.exportNamedCount = numberOfNames;
            result.details.exportOrdinalBase = ordinalBase;

        } catch (e) {
            // Ignore export parsing errors
        }
    }

    // 解析 MS-DOS MZ 可执行文件 (无 PE)
    parseMSDOS() {
        const result = {
            format: 'MS-DOS',
            type: 'Executable',
            platform: 'DOS',
            details: {},
            dosHeader: {}
        };

        try {
            // DOS Header
            const e_cblp = this.readUint16LE(2);
            const e_cp = this.readUint16LE(4);
            const e_crlc = this.readUint16LE(6);
            const e_cparhdr = this.readUint16LE(8);
            const e_minalloc = this.readUint16LE(10);
            const e_maxalloc = this.readUint16LE(12);
            const e_ss = this.readUint16LE(14);
            const e_sp = this.readUint16LE(16);
            const e_ip = this.readUint16LE(20);
            const e_cs = this.readUint16LE(22);
            const e_lfarlc = this.readUint16LE(24);

            result.dosHeader = {
                e_cblp,
                e_cp,
                e_crlc,
                e_cparhdr,
                e_minalloc,
                e_maxalloc,
                e_ss: '0x' + e_ss.toString(16),
                e_sp: '0x' + e_sp.toString(16),
                e_ip: '0x' + e_ip.toString(16),
                e_cs: '0x' + e_cs.toString(16),
                e_lfarlc
            };

            result.details.initialSP = '0x' + e_sp.toString(16);
            result.details.initialIP = '0x' + e_ip.toString(16);
            result.details.minAlloc = e_minalloc + ' paragraphs';
            result.details.maxAlloc = e_maxalloc + ' paragraphs';

            // 计算文件大小 (页数 * 512 - 最后一页的字节数)
            const fileSize = e_cp * 512 - (e_cblp ? 512 - e_cblp : 0);
            result.details.filePages = e_cp;
            result.details.lastPageSize = e_cblp || 512;

            // 检查是否有重定位表
            if (e_crlc > 0) {
                result.details.hasRelocations = true;
                result.details.relocationCount = e_crlc;
            }

            // 检查是否是 COM 文件模式
            if (e_lfarlc === 0 && this.size <= 65536) {
                result.details.mzMode = 'Small MZ (COM-like)';
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 COM 文件 (无 MZ 头)
    parseCOM() {
        const result = {
            format: 'COM',
            type: 'Executable',
            platform: 'DOS',
            details: {}
        };

        // COM 文件没有文件头，直接加载到 0x100
        result.details.loadAddress = '0x100';
        result.details.entryPoint = '0x100';
        result.details.fileSize = this.size;
        result.details.maxSize = '65536 - 256 = 65280 bytes';

        // 检查常见 COM 文件特征
        if (this.size > 65280) {
            result.details.warning = 'File exceeds maximum COM size';
        }

        // 检查开头是否有 JMP 指令
        const firstByte = this.readUint8(0);
        if (firstByte === 0xE9) { // JMP rel16
            const jumpOffset = this.readUint16LE(1);
            result.details.hasJump = true;
            result.details.jumpTarget = '0x' + (0x100 + 3 + jumpOffset).toString(16);
        } else if (firstByte === 0xEB) { // JMP rel8
            const jumpOffset = this.readUint8(1);
            result.details.hasJump = true;
            result.details.jumpTarget = '0x' + (0x100 + 2 + jumpOffset).toString(16);
        }

        return result;
    }

    // 解析 ELF 文件
    parseELF() {
        if (!this.checkMagic([0x7F, 0x45, 0x4C, 0x46])) return null;

        const result = {
            format: 'ELF',
            type: 'Executable',
            platform: 'Linux/Unix',
            sections: [],
            programHeaders: [],
            dynamicEntries: [],
            symbols: [],
            notes: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {},
            elfHeader: {}
        };

        try {
            const eiClass = this.readUint8(4);
            const eiData = this.readUint8(5);
            const eiVersion = this.readUint8(6);
            const eiOSABI = this.readUint8(7);

            const is64Bit = eiClass === 2;
            const isLittleEndian = eiData === 1;

            result.details.elfClass = is64Bit ? 'ELF64' : 'ELF32';
            result.details.endianness = isLittleEndian ? 'Little Endian' : 'Big Endian';
            result.architecture = is64Bit ? 'x86-64' : 'i386';

            const read16 = (offset) => isLittleEndian ? this.readUint16LE(offset) : this.readUint16BE(offset);
            const read32 = (offset) => isLittleEndian ? this.readUint32LE(offset) : this.readUint32BE(offset);
            const read64 = (offset) => {
                if (isLittleEndian) {
                    return this.readUint64LE(offset);
                } else {
                    const high = this.readUint32BE(offset);
                    const low = this.readUint32BE(offset + 4);
                    return high * 0x100000000 + low;
                }
            };

            // ELF Header
            const eType = read16(16);
            const eMachine = read16(18);
            const eVersion = read32(20);
            const eEntry = is64Bit ? read64(24) : read32(24);
            const ePhoff = is64Bit ? read64(32) : read32(28);
            const eShoff = is64Bit ? read64(40) : read32(32);
            const eFlags = read32(is64Bit ? 48 : 36);
            const eEhsize = read16(is64Bit ? 52 : 40);
            const ePhentsize = read16(is64Bit ? 54 : 42);
            const ePhnum = read16(is64Bit ? 56 : 44);
            const eShentsize = read16(is64Bit ? 58 : 46);
            const eShnum = read16(is64Bit ? 60 : 48);
            const eShstrndx = read16(is64Bit ? 62 : 50);

            // 保存 ELF Header 信息
            result.elfHeader = {
                eType,
                eMachine,
                eVersion,
                eEntry: '0x' + eEntry.toString(16).toUpperCase(),
                ePhoff,
                eShoff,
                eFlags,
                eEhsize,
                ePhentsize,
                ePhnum,
                eShentsize,
                eShnum,
                eShstrndx,
                eiClass,
                eiData,
                eiVersion,
                eiOSABI
            };

            // OS ABI
            const osAbis = {
                0: 'UNIX System V',
                1: 'HP-UX',
                2: 'NetBSD',
                3: 'Linux',
                4: 'GNU Hurd',
                6: 'Solaris',
                7: 'AIX',
                8: 'IRIX',
                9: 'FreeBSD',
                10: 'Tru64',
                11: 'Novell Modesto',
                12: 'OpenBSD',
                13: 'OpenVMS',
                14: 'NonStop Kernel',
                15: 'AROS',
                16: 'Fenix OS',
                17: 'CloudABI',
                64: 'ARM EABI',
                97: 'ARM',
                255: 'Standalone'
            };
            result.details.osAbi = osAbis[eiOSABI] || `Unknown (${eiOSABI})`;

            // Machine types
            const machineTypes = {
                0x00: 'None',
                0x02: 'SPARC',
                0x03: 'i386',
                0x08: 'MIPS',
                0x14: 'PowerPC',
                0x15: 'PowerPC64',
                0x28: 'ARM',
                0x2A: 'SuperH',
                0x32: 'IA-64',
                0x3E: 'x86-64',
                0xB7: 'AArch64',
                0xF3: 'RISC-V',
                0x18A: 'AVR',
                0x903: 'Alpha'
            };
            result.details.machine = machineTypes[eMachine] || `Unknown (${eMachine.toString(16)})`;
            result.architecture = result.details.machine;

            // File types
            const fileTypes = {
                0: 'None',
                1: 'Relocatable (ET_REL)',
                2: 'Executable (ET_EXEC)',
                3: 'Shared Object (ET_DYN)',
                4: 'Core (ET_CORE)'
            };
            result.details.fileType = fileTypes[eType] || `Unknown (${eType})`;
            result.type = result.details.fileType.split(' ')[0];

            result.details.entryPoint = '0x' + eEntry.toString(16).toUpperCase();

            // Program Headers (Segments)
            result.programHeaders = this.parseELFProgramHeaders(ePhoff, ePhnum, ePhentsize, is64Bit, read32, read64);

            // Section headers
            let stringTableOffset = 0;
            if (eShnum > 0 && eShstrndx < eShnum) {
                const stringTableHeaderOffset = eShoff + eShstrndx * eShentsize;
                const shOffset = is64Bit ? read64(stringTableHeaderOffset + 24) : read32(stringTableHeaderOffset + 16);
                stringTableOffset = shOffset;
            }

            // Parse sections
            for (let i = 0; i < eShnum; i++) {
                const sectionOffset = eShoff + i * eShentsize;
                const shName = read32(sectionOffset);
                const shType = read32(sectionOffset + 4);
                const shFlags = is64Bit ? read64(sectionOffset + 8) : read32(sectionOffset + 8);
                const shAddr = is64Bit ? read64(sectionOffset + 16) : read32(sectionOffset + 12);
                const shOffset = is64Bit ? read64(sectionOffset + 24) : read32(sectionOffset + 16);
                const shSize = is64Bit ? read64(sectionOffset + 32) : read32(sectionOffset + 20);
                const shLink = read32(is64Bit ? sectionOffset + 40 : sectionOffset + 24);
                const shInfo = read32(is64Bit ? sectionOffset + 44 : sectionOffset + 28);
                const shAddralign = is64Bit ? read64(sectionOffset + 48) : read32(sectionOffset + 32);
                const shEntsize = is64Bit ? read64(sectionOffset + 56) : read32(sectionOffset + 36);

                let name = '';
                if (stringTableOffset && shName) {
                    name = this.readNullTerminatedString(stringTableOffset + shName);
                }

                // Section types
                const sectionTypes = {
                    0: 'NULL',
                    1: 'PROGBITS',
                    2: 'SYMTAB',
                    3: 'STRTAB',
                    4: 'RELA',
                    5: 'HASH',
                    6: 'DYNAMIC',
                    7: 'NOTE',
                    8: 'NOBITS',
                    9: 'REL',
                    10: 'SHLIB',
                    11: 'DYNSYM',
                    12: 'INIT_ARRAY',
                    13: 'FINI_ARRAY',
                    14: 'PREINIT_ARRAY',
                    15: 'GROUP',
                    16: 'SYMTAB_SHNDX',
                    17: 'GNU_HASH',
                    0x6ffffff5: 'GNU_ATTRIBUTES',
                    0x6ffffff6: 'GNU_HASH',
                    0x6ffffff7: 'GNU_LIBLIST',
                    0x6ffffffd: 'VERDEF',
                    0x6ffffffe: 'VERNEED',
                    0x6fffffff: 'VERSYM'
                };

                result.sections.push({
                    name: name || `Section ${i}`,
                    type: sectionTypes[shType] || `Type ${shType.toString(16)}`,
                    address: '0x' + shAddr.toString(16).toUpperCase(),
                    offset: '0x' + shOffset.toString(16).toUpperCase(),
                    size: shSize,
                    flags: this.parseELFSectionFlags(shFlags),
                    link: shLink,
                    info: shInfo,
                    align: shAddralign,
                    entsize: shEntsize
                });
            }

            // 解析 Dynamic Section
            const dynamicSection = result.sections.find(s => s.type === 'DYNAMIC');
            if (dynamicSection) {
                result.dynamicEntries = this.parseELFDynamic(
                    parseInt(dynamicSection.offset, 16),
                    dynamicSection.size,
                    is64Bit, read32, read64,
                    result.sections
                );
            }

            // 解析 NOTE sections
            const noteSections = result.sections.filter(s => s.type === 'NOTE');
            for (const noteSection of noteSections) {
                const notes = this.parseELFNotes(parseInt(noteSection.offset, 16), noteSection.size);
                result.notes.push(...notes);
            }

            // 从 dynamic entries 获取需要的库
            result.neededLibs = result.dynamicEntries.filter(e => e.tag === 'NEEDED').map(e => e.value);

            // Check for interpreter
            const interpSection = result.sections.find(s => s.name === '.interp');
            if (interpSection) {
                const interpOffset = parseInt(interpSection.offset, 16);
                result.details.interpreter = this.readNullTerminatedString(interpOffset, 128);
            }

            // Check for Go
            const gopclntabSection = result.sections.find(s => s.name === '.gopclntab');
            if (gopclntabSection) {
                result.compilers.push('Go (Golang)');
            }

            // Check for Rust
            const noteRustSection = result.sections.find(s => s.name.includes('rust') || s.name.includes('note.rust'));
            if (noteRustSection) {
                result.compilers.push('Rust');
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 ELF Program Headers
    parseELFProgramHeaders(phoff, phnum, phentsize, is64Bit, read32, read64) {
        const programHeaders = [];

        const phTypes = {
            0: 'NULL',
            1: 'LOAD',
            2: 'DYNAMIC',
            3: 'INTERP',
            4: 'NOTE',
            5: 'SHLIB',
            6: 'PHDR',
            7: 'TLS',
            0x6474e550: 'GNU_EH_FRAME',
            0x6474e551: 'GNU_STACK',
            0x6474e552: 'GNU_RELRO',
            0x6474e553: 'GNU_PROPERTY',
            0x6474e554: 'GNU_PHDR'
        };

        for (let i = 0; i < phnum; i++) {
            const offset = phoff + i * phentsize;

            const pType = read32(offset);
            const pFlags = is64Bit ? read32(offset + 4) : read32(offset + 24);
            const pOffset = is64Bit ? read64(offset + 8) : read32(offset + 4);
            const pVaddr = is64Bit ? read64(offset + 16) : read32(offset + 8);
            const pPaddr = is64Bit ? read64(offset + 24) : read32(offset + 12);
            const pFilesz = is64Bit ? read64(offset + 32) : read32(offset + 16);
            const pMemsz = is64Bit ? read64(offset + 40) : read32(offset + 20);
            const pAlign = is64Bit ? read64(offset + 48) : read32(offset + 28);

            programHeaders.push({
                type: phTypes[pType] || `Type ${pType.toString(16)}`,
                typeNum: pType,
                offset: '0x' + pOffset.toString(16).toUpperCase(),
                vaddr: '0x' + pVaddr.toString(16).toUpperCase(),
                paddr: '0x' + pPaddr.toString(16).toUpperCase(),
                filesz: pFilesz,
                memsz: pMemsz,
                flags: this.parseELFProgramFlags(pFlags),
                align: pAlign
            });
        }

        return programHeaders;
    }

    // 解析 ELF Program Flags
    parseELFProgramFlags(flags) {
        const flagList = [];
        if (flags & 0x1) flagList.push('X (Execute)');
        if (flags & 0x2) flagList.push('W (Write)');
        if (flags & 0x4) flagList.push('R (Read)');
        return flagList.length > 0 ? flagList.join(' | ') : 'None';
    }

    // 解析 ELF Dynamic Section
    parseELFDynamic(offset, size, is64Bit, read32, read64, sections) {
        const entries = [];
        const entrySize = is64Bit ? 16 : 8;
        const count = Math.floor(size / entrySize);

        const dTags = {
            0: 'NULL',
            1: 'NEEDED',
            2: 'PLTRELSZ',
            3: 'PLTGOT',
            4: 'HASH',
            5: 'STRTAB',
            6: 'SYMTAB',
            7: 'RELA',
            8: 'RELASZ',
            9: 'RELAENT',
            10: 'STRSZ',
            11: 'SYMENT',
            12: 'INIT',
            13: 'FINI',
            14: 'SONAME',
            15: 'RPATH',
            16: 'SYMBOLIC',
            17: 'REL',
            18: 'RELSZ',
            19: 'RELENT',
            20: 'PLTREL',
            21: 'DEBUG',
            22: 'TEXTREL',
            23: 'JMPREL',
            24: 'BIND_NOW',
            25: 'INIT_ARRAY',
            26: 'FINI_ARRAY',
            27: 'INIT_ARRAYSZ',
            28: 'FINI_ARRAYSZ',
            29: 'RUNPATH',
            30: 'FLAGS',
            0x6ffffef5: 'GNU_HASH',
            0x6ffffff0: 'VERSYM',
            0x6ffffffe: 'VERNEED',
            0x6fffffff: 'VERNEEDNUM',
            0x6ffffff9: 'RELACOUNT',
            0x6ffffffb: 'FLAGS_1',
            0x6ffffffd: 'VERDEF',
            0x6ffffffe: 'VERDEFNUM'
        };

        // Find string table for dynamic strings
        let dynstrVaddr = 0;
        let dynstrSize = 0;
        let dynstrFileOffset = 0;

        // First pass to find STRTAB and STRSZ
        for (let i = 0; i < count; i++) {
            const entryOffset = offset + i * entrySize;
            const dTag = is64Bit ? read64(entryOffset) : read32(entryOffset);
            const dVal = is64Bit ? read64(entryOffset + 8) : read32(entryOffset + 4);

            if (dTag === 5) { // STRTAB - 获取虚拟地址
                dynstrVaddr = dVal;
            }
            if (dTag === 10) { // STRSZ
                dynstrSize = dVal;
            }
        }

        // 将虚拟地址转换为文件偏移
        if (dynstrVaddr && sections) {
            dynstrFileOffset = this.elfVaddrToFileOffset(sections, dynstrVaddr);
        }

        // Second pass to parse all entries
        for (let i = 0; i < count; i++) {
            const entryOffset = offset + i * entrySize;
            const dTag = is64Bit ? read64(entryOffset) : read32(entryOffset);
            const dVal = is64Bit ? read64(entryOffset + 8) : read32(entryOffset + 4);

            if (dTag === 0) break; // NULL entry marks end

            let value = '0x' + dVal.toString(16).toUpperCase();

            // For NEEDED and SONAME, try to read the string from dynstr
            if ((dTag === 1 || dTag === 14) && dynstrFileOffset && dVal < dynstrSize) {
                const stringOffset = dynstrFileOffset + dVal;
                if (stringOffset < this.size) {
                    const str = this.readNullTerminatedString(stringOffset, 256);
                    if (str && str.length > 0 && !str.includes('\x00')) {
                        value = str;
                    }
                }
            }

            entries.push({
                tag: dTags[dTag] || `Tag ${dTag.toString(16)}`,
                tagNum: dTag,
                value: value
            });
        }

        return entries;
    }

    // 解析 ELF Notes
    parseELFNotes(offset, size) {
        const notes = [];
        let pos = offset;

        while (pos < offset + size) {
            const namesz = this.readUint32LE(pos);
            const descsz = this.readUint32LE(pos + 4);
            const type = this.readUint32LE(pos + 8);

            if (namesz === 0) break;

            const name = this.readString(pos + 12, namesz).replace(/\0/g, '');
            const desc = this.readBytes(pos + 12 + ((namesz + 3) & ~3), descsz);

            const noteTypes = {
                1: 'NT_ABI_TAG',
                2: 'NT_VERSION_TAG',
                3: 'NT_ARCH_TAG',
                4: 'NT_GNU_BUILD_ID',
                5: 'NT_GNU_GOLD_VERSION',
                10: 'NT_GNU_PROPERTY_TYPE_0',
                0x100: 'NT_GNU_BUILD_ATTRIBUTE_OPEN',
                0x101: 'NT_GNU_BUILD_ATTRIBUTE_FUNC'
            };

            notes.push({
                name,
                type: noteTypes[type] || `Type ${type}`,
                typeNum: type,
                descSize: descsz,
                desc: desc ? Array.from(desc.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join('') + (descsz > 20 ? '...' : '') : ''
            });

            pos += 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3);
        }

        return notes;
    }

    // 解析 ELF 段属性
    parseELFSectionFlags(flags) {
        const flagList = [];
        if (flags & 0x1) flagList.push('WRITE');
        if (flags & 0x2) flagList.push('ALLOC');
        if (flags & 0x4) flagList.push('EXECINSTR');
        return flagList;
    }

    // 解析 Mach-O 文件
    parseMachO() {
        const magic = this.readUint32BE(0);

        let is64Bit, isBigEndian;

        if (magic === 0xFEEDFACE) {
            is64Bit = false;
            isBigEndian = false;
        } else if (magic === 0xFEEDFACF) {
            is64Bit = true;
            isBigEndian = false;
        } else if (magic === 0xCEFAEDFE) {
            is64Bit = false;
            isBigEndian = true;
        } else if (magic === 0xCFFAEDFE) {
            is64Bit = true;
            isBigEndian = true;
        } else if (magic === 0xCAFEBABE) {
            // Fat binary
            return this.parseFatBinary();
        } else {
            return null;
        }

        const result = {
            format: 'Mach-O',
            type: 'Executable',
            platform: 'macOS',
            architecture: is64Bit ? 'x86-64/ARM64' : 'i386/ARM',
            sections: [],
            loadCommands: [],
            dylibs: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {},
            machHeader: {}
        };

        try {
            const read16 = (offset) => isBigEndian ? this.readUint16BE(offset) : this.readUint16LE(offset);
            const read32 = (offset) => isBigEndian ? this.readUint32BE(offset) : this.readUint32LE(offset);

            result.details.machoType = is64Bit ? 'Mach-O 64-bit' : 'Mach-O 32-bit';
            result.details.endianness = isBigEndian ? 'Big Endian' : 'Little Endian';

            const cputype = read32(4);
            const cpusubtype = read32(8);
            const filetype = read32(12);
            const ncmds = read32(16);
            const sizeofcmds = read32(20);
            const flags = read32(24);
            const reserved = is64Bit ? read32(28) : 0;

            // CPU types
            const cpuTypes = {
                0x00000001: 'VAX',
                0x00000006: 'MC680x0',
                0x00000007: 'x86 (i386)',
                0x01000007: 'x86_64',
                0x0000000C: 'ARM',
                0x0100000C: 'ARM64',
                0x00000012: 'PowerPC',
                0x01000012: 'PowerPC64'
            };
            result.details.cpu = cpuTypes[cputype] || `CPU Type ${cputype.toString(16)}`;
            result.architecture = result.details.cpu;

            // File types
            const fileTypes = {
                1: 'Object (.o)',
                2: 'Executable (MH_EXECUTE)',
                3: 'Core Dump (MH_CORE)',
                4: 'Preloaded Executable (MH_PRELOAD)',
                5: 'Dynamic Library (MH_DYLIB)',
                6: 'Bundle (MH_BUNDLE)',
                7: 'Dynamic Linker (MH_DYLINKER)',
                8: 'Object Image (MH_OBJECT_IMAGE)',
                9: 'Snapshot (MH_SNAPSHOT)'
            };
            result.details.fileType = fileTypes[filetype] || `Type ${filetype}`;
            result.type = fileTypes[filetype]?.split(' ')[0] || 'Unknown';

            // Mach-O Flags
            const machFlags = [];
            if (flags & 0x1) machFlags.push('MH_NOUNDEFS');
            if (flags & 0x2) machFlags.push('MH_INCRLINK');
            if (flags & 0x4) machFlags.push('MH_DYLDLINK');
            if (flags & 0x8) machFlags.push('MH_BINDATLOAD');
            if (flags & 0x10) machFlags.push('MH_PREBOUND');
            if (flags & 0x20) machFlags.push('MH_SPLIT_SEGS');
            if (flags & 0x40) machFlags.push('MH_LAZY_INIT');
            if (flags & 0x80) machFlags.push('MH_TWOLEVEL');
            if (flags & 0x100) machFlags.push('MH_FORCE_FLAT');
            if (flags & 0x200) machFlags.push('MH_NOMULTIDEFS');
            if (flags & 0x400) machFlags.push('MH_NOFIXPREBINDING');
            if (flags & 0x800) machFlags.push('MH_PREBINDABLE');
            if (flags & 0x1000) machFlags.push('MH_ALLMODSBOUND');
            if (flags & 0x2000) machFlags.push('MH_SUBSECTIONS_VIA_SYMBOLS');
            if (flags & 0x4000) machFlags.push('MH_CANONICAL');
            if (flags & 0x8000) machFlags.push('MH_WEAK_DEFINES');
            if (flags & 0x10000) machFlags.push('MH_BINDS_TO_WEAK');
            if (flags & 0x20000) machFlags.push('MH_ALLOW_STACK_EXECUTION');
            if (flags & 0x40000) machFlags.push('MH_ROOT_SAFE');
            if (flags & 0x80000) machFlags.push('MH_SETUID_SAFE');
            if (flags & 0x100000) machFlags.push('MH_NO_REEXPORTED_DYLIBS');
            if (flags & 0x200000) machFlags.push('MH_PIE');
            if (flags & 0x400000) machFlags.push('MH_DEAD_STRIPS_DYLIBS');
            if (flags & 0x800000) machFlags.push('MH_HAS_TLV_DESCRIPTORS');
            if (flags & 0x1000000) machFlags.push('MH_NO_HEAP_EXECUTION');

            result.machHeader = {
                magic: '0x' + magic.toString(16).toUpperCase(),
                cputype: result.details.cpu,
                cpusubtype,
                filetype: result.details.fileType,
                ncmds,
                sizeofcmds,
                flags: machFlags,
                reserved
            };

            // Parse Load Commands
            const headerSize = is64Bit ? 32 : 28;
            let cmdOffset = headerSize;

            const loadCommandTypes = {
                0x1: 'LC_SEGMENT',
                0x2: 'LC_SYMTAB',
                0x3: 'LC_SYMSEG',
                0x4: 'LC_THREAD',
                0x5: 'LC_UNIXTHREAD',
                0x6: 'LC_LOADFVMLIB',
                0x7: 'LC_IDFVMLIB',
                0x8: 'LC_IDENT',
                0x9: 'LC_FVMFILE',
                0xa: 'LC_PREPAGE',
                0xb: 'LC_DYSYMTAB',
                0xc: 'LC_LOAD_DYLIB',
                0xd: 'LC_ID_DYLIB',
                0xe: 'LC_LOAD_DYLINKER',
                0xf: 'LC_ID_DYLINKER',
                0x10: 'LC_PREBOUND_DYLIB',
                0x11: 'LC_ROUTINES',
                0x12: 'LC_SUB_FRAMEWORK',
                0x13: 'LC_SUB_UMBRELLA',
                0x14: 'LC_SUB_CLIENT',
                0x15: 'LC_SUB_LIBRARY',
                0x16: 'LC_TWOLEVEL_HINTS',
                0x17: 'LC_PREBIND_CKSUM',
                0x18: 'LC_LOAD_WEAK_DYLIB',
                0x19: 'LC_SEGMENT_64',
                0x1a: 'LC_ROUTINES_64',
                0x1b: 'LC_UUID',
                0x1c: 'LC_RPATH',
                0x1d: 'LC_CODE_SIGNATURE',
                0x1e: 'LC_SEGMENT_SPLIT_INFO',
                0x1f: 'LC_REEXPORT_DYLIB',
                0x20: 'LC_LAZY_LOAD_DYLIB',
                0x21: 'LC_ENCRYPTION_INFO',
                0x22: 'LC_DYLD_INFO',
                0x23: 'LC_DYLD_INFO_ONLY',
                0x24: 'LC_LOAD_UPWARD_DYLIB',
                0x25: 'LC_VERSION_MIN_MACOSX',
                0x26: 'LC_VERSION_MIN_IPHONEOS',
                0x27: 'LC_FUNCTION_STARTS',
                0x28: 'LC_DYLD_ENVIRONMENT',
                0x29: 'LC_MAIN',
                0x2a: 'LC_DATA_IN_CODE',
                0x2b: 'LC_SOURCE_VERSION',
                0x2c: 'LC_DYLIB_CODE_SIGN_DRS',
                0x2d: 'LC_ENCRYPTION_INFO_64',
                0x2e: 'LC_LINKER_OPTION',
                0x2f: 'LC_LINKER_OPTIMIZATION_HINT',
                0x30: 'LC_VERSION_MIN_TVOS',
                0x31: 'LC_VERSION_MIN_WATCHOS',
                0x32: 'LC_NOTE',
                0x33: 'LC_BUILD_VERSION',
                0x34: 'LC_DYLD_EXPORTS_TRIE',
                0x35: 'LC_DYLD_CHAINED_FIXUPS'
            };

            for (let i = 0; i < ncmds && cmdOffset < this.size; i++) {
                const cmd = read32(cmdOffset);
                const cmdsize = read32(cmdOffset + 4);

                const cmdInfo = {
                    cmd: loadCommandTypes[cmd] || `Unknown (0x${cmd.toString(16)})`,
                    cmdType: cmd,
                    cmdsize
                };

                // 解析 LC_LOAD_DYLIB
                if (cmd === 0xc || cmd === 0x18 || cmd === 0x1f) {
                    const dylibNameOffset = read32(cmdOffset + 8);
                    const dylibTimestamp = read32(cmdOffset + 12);
                    const dylibCurrentVersion = read32(cmdOffset + 16);
                    const dylibCompatVersion = read32(cmdOffset + 20);
                    const nameOffset = cmdOffset + dylibNameOffset;
                    const dylibName = this.readNullTerminatedString(nameOffset);
                    cmdInfo.dylib = dylibName;
                    result.dylibs.push(dylibName);
                }

                // 解析 LC_UUID
                if (cmd === 0x1b) {
                    const uuidBytes = this.readBytes(cmdOffset + 8, 16);
                    if (uuidBytes) {
                        const uuid = Array.from(uuidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        cmdInfo.uuid = uuid.slice(0,8) + '-' + uuid.slice(8,12) + '-' + uuid.slice(12,16) + '-' + uuid.slice(16,20) + '-' + uuid.slice(20);
                        result.details.uuid = cmdInfo.uuid;
                    }
                }

                // 解析 LC_MAIN
                if (cmd === 0x29) {
                    const entryoff = this.readUint64LE(cmdOffset + 8);
                    const stacksize = this.readUint64LE(cmdOffset + 16);
                    cmdInfo.entryOffset = '0x' + entryoff.toString(16).toUpperCase();
                    cmdInfo.stackSize = stacksize;
                    result.details.entryPoint = cmdInfo.entryOffset;
                }

                // 解析 LC_SEGMENT/LC_SEGMENT_64
                if (cmd === 0x1 || cmd === 0x19) {
                    const segName = this.readString(cmdOffset + 8, 16).replace(/\0/g, '');
                    const vmaddr = cmd === 0x19 ? this.readUint64LE(cmdOffset + 24) : read32(cmdOffset + 24);
                    const vmsize = cmd === 0x19 ? this.readUint64LE(cmdOffset + 32) : read32(cmdOffset + 28);
                    const fileoff = cmd === 0x19 ? this.readUint64LE(cmdOffset + 40) : read32(cmdOffset + 32);
                    const filesize = cmd === 0x19 ? this.readUint64LE(cmdOffset + 48) : read32(cmdOffset + 36);
                    const maxprot = read32(cmd === 0x19 ? cmdOffset + 56 : cmdOffset + 40);
                    const initprot = read32(cmd === 0x19 ? cmdOffset + 60 : cmdOffset + 44);
                    const nsects = read32(cmd === 0x19 ? cmdOffset + 64 : cmdOffset + 48);
                    const segFlags = read32(cmd === 0x19 ? cmdOffset + 68 : cmdOffset + 52);

                    cmdInfo.segment = {
                        name: segName,
                        vmaddr: '0x' + vmaddr.toString(16).toUpperCase(),
                        vmsize,
                        fileoff: '0x' + fileoff.toString(16).toUpperCase(),
                        filesize,
                        maxprot: this.parseMachProt(maxprot),
                        initprot: this.parseMachProt(initprot),
                        nsects
                    };

                    result.sections.push({
                        name: segName,
                        address: cmdInfo.segment.vmaddr,
                        size: vmsize,
                        protection: cmdInfo.segment.maxprot
                    });
                }

                // 解析 LC_VERSION_MIN_MACOSX
                if (cmd === 0x25) {
                    const version = read32(cmdOffset + 8);
                    const major = (version >> 16) & 0xffff;
                    const minor = (version >> 8) & 0xff;
                    const patch = version & 0xff;
                    cmdInfo.minVersion = `macOS ${major}.${minor}.${patch}`;
                    result.details.minOSVersion = cmdInfo.minVersion;
                }

                // 解析 LC_BUILD_VERSION
                if (cmd === 0x33) {
                    const platform = read32(cmdOffset + 8);
                    const minos = read32(cmdOffset + 12);
                    const sdk = read32(cmdOffset + 16);
                    const platforms = {
                        1: 'macOS',
                        2: 'iOS',
                        3: 'tvOS',
                        4: 'watchOS',
                        5: 'bridgeOS',
                        6: 'macCatalyst',
                        7: 'iOS Simulator',
                        8: 'tvOS Simulator',
                        9: 'watchOS Simulator',
                        10: 'driverKit'
                    };
                    cmdInfo.platform = platforms[platform] || `Platform ${platform}`;
                    const parseVer = (v) => `${(v>>16)&0xffff}.${(v>>8)&0xff}.${v&0xff}`;
                    cmdInfo.minOS = parseVer(minos);
                    cmdInfo.sdk = parseVer(sdk);
                    result.details.platform = cmdInfo.platform;
                    result.details.minOSVersion = cmdInfo.minOS;
                    result.details.sdkVersion = cmdInfo.sdk;
                }

                result.loadCommands.push(cmdInfo);
                cmdOffset += cmdsize;
            }

            // 检测 Swift
            const hasSwift = result.dylibs.some(d => d.includes('libswift'));
            if (hasSwift) {
                result.compilers.push('Swift');
            }

            // 检测 Objective-C
            const hasObjC = result.sections.some(s => s.name.includes('objc') || s.name === '__objc_classrefs');
            if (hasObjC) {
                result.compilers.push('Objective-C');
            }

            result.details.loadCommands = ncmds;
            result.details.dylibCount = result.dylibs.length;

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 Mach-O 权限标志
    parseMachProt(prot) {
        const prots = [];
        if (prot & 1) prots.push('R');
        if (prot & 2) prots.push('W');
        if (prot & 4) prots.push('X');
        return prots.length > 0 ? prots.join('/') : 'None';
    }

    // 解析 Fat Binary
    parseFatBinary() {
        const result = {
            format: 'Mach-O Universal',
            type: 'Fat Binary',
            platform: 'macOS',
            architectures: [],
            loadCommands: [],
            dylibs: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {}
        };

        try {
            const nfatArch = this.readUint32BE(4);
            result.details.archCount = nfatArch;

            const cpuTypes = {
                0x00000007: 'i386',
                0x01000007: 'x86_64',
                0x0000000C: 'arm',
                0x0100000C: 'arm64',
                0x00000012: 'ppc',
                0x01000012: 'ppc64'
            };

            for (let i = 0; i < nfatArch && i < 10; i++) {
                const offset = 8 + i * 20;
                const cputype = this.readUint32BE(offset);
                const cpusubtype = this.readUint32BE(offset + 4);
                const archOffset = this.readUint32BE(offset + 8);
                const archSize = this.readUint32BE(offset + 12);
                const align = this.readUint32BE(offset + 16);

                const archName = cpuTypes[cputype] || `CPU ${cputype.toString(16)}`;
                result.architectures.push({
                    cpu: archName,
                    subtype: cpusubtype,
                    offset: '0x' + archOffset.toString(16),
                    size: archSize,
                    align: align
                });
            }

            result.details.architectures = result.architectures.map(a => a.cpu).join(', ');
            result.details.totalSize = this.size;

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 DEX 文件
    parseDEX() {
        if (!this.checkMagic([0x64, 0x65, 0x78, 0x0A])) return null;

        const result = {
            format: 'DEX',
            type: 'Android Dalvik Executable',
            platform: 'Android',
            classes: [],
            methods: [],
            fields: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {},
            dexHeader: {}
        };

        try {
            // DEX magic + version
            const magic = this.readString(0, 8);
            const version = magic.slice(4, 7);

            const checksum = this.readUint32LE(8);
            const signature = this.readBytes(12, 20);

            const fileSize = this.readUint32LE(32);
            const headerSize = this.readUint32LE(36);

            const endianTag = this.readUint32LE(40);
            const linkSize = this.readUint32LE(44);
            const linkOff = this.readUint32LE(48);
            const stringIdsSize = this.readUint32LE(56);
            const stringIdsOff = this.readUint32LE(60);
            const typeIdsSize = this.readUint32LE(64);
            const typeIdsOff = this.readUint32LE(68);
            const protoIdsSize = this.readUint32LE(72);
            const protoIdsOff = this.readUint32LE(76);
            const fieldIdsSize = this.readUint32LE(80);
            const fieldIdsOff = this.readUint32LE(84);
            const methodIdsSize = this.readUint32LE(88);
            const methodIdsOff = this.readUint32LE(92);
            const classDefsSize = this.readUint32LE(96);
            const classDefsOff = this.readUint32LE(100);
            const dataSize = this.readUint32LE(104);
            const dataOff = this.readUint32LE(108);

            result.dexHeader = {
                magic: magic.replace(/\n/g, '\\n'),
                version,
                checksum: '0x' + checksum.toString(16).toUpperCase(),
                signature: signature ? Array.from(signature).map(b => b.toString(16).padStart(2, '0')).join('') : '',
                fileSize,
                headerSize,
                endianTag: endianTag === 0x12345678 ? 'Little Endian (0x12345678)' : 'Big Endian',
                linkSize,
                linkOff: '0x' + linkOff.toString(16),
                stringIdsSize,
                stringIdsOff: '0x' + stringIdsOff.toString(16),
                typeIdsSize,
                typeIdsOff: '0x' + typeIdsOff.toString(16),
                protoIdsSize,
                protoIdsOff: '0x' + protoIdsOff.toString(16),
                fieldIdsSize,
                fieldIdsOff: '0x' + fieldIdsOff.toString(16),
                methodIdsSize,
                methodIdsOff: '0x' + methodIdsOff.toString(16),
                classDefsSize,
                classDefsOff: '0x' + classDefsOff.toString(16),
                dataSize,
                dataOff: '0x' + dataOff.toString(16)
            };

            result.details.version = version;
            result.details.checksum = result.dexHeader.checksum;
            result.details.signature = result.dexHeader.signature.slice(0, 16) + '...';
            result.details.fileSize = fileSize;
            result.details.endianness = result.dexHeader.endianTag.split(' ')[0];
            result.details.stringCount = stringIdsSize;
            result.details.typeCount = typeIdsSize;
            result.details.protoCount = protoIdsSize;
            result.details.fieldCount = fieldIdsSize;
            result.details.methodCount = methodIdsSize;
            result.details.classCount = classDefsSize;

            // 检测混淆特征
            const classNamePatterns = ['a/', 'b/', 'c/', 'd/', 'e/', 'f/', 'g/', 'h/'];
            let obfuscated = false;

            // 检测 ProGuard/R8
            if (this.size > 1000) {
                const searchString = this.searchString('ProGuard', 0, this.size);
                if (searchString !== -1) {
                    result.compilers.push('ProGuard/R8 Obfuscation');
                }
            }

            // 检测 DexGuard
            const dexGuard = this.searchString('DexGuard', 0, this.size);
            if (dexGuard !== -1) {
                result.compilers.push('DexGuard');
            }

            // 检测 ART/AOT
            result.details.targetRuntime = version >= '037' ? 'ART (Android 7+)' : version >= '035' ? 'ART/Dalvik' : 'Dalvik';

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 Java Class 文件
    parseJavaClass() {
        if (!this.checkMagic([0xCA, 0xFE, 0xBA, 0xBE])) return null;

        const result = {
            format: 'Java Class',
            type: 'Java Bytecode',
            platform: 'Java VM',
            constantPool: [],
            fields: [],
            methods: [],
            attributes: [],
            compilers: [],
            packers: [],
            libraries: [],
            details: {},
            classHeader: {}
        };

        try {
            const minorVersion = this.readUint16LE(4);
            const majorVersion = this.readUint16LE(6);

            const versionMap = {
                45: 'JDK 1.1',
                46: 'JDK 1.2',
                47: 'JDK 1.3',
                48: 'JDK 1.4',
                49: 'JDK 5',
                50: 'JDK 6',
                51: 'JDK 7',
                52: 'JDK 8',
                53: 'JDK 9',
                54: 'JDK 10',
                55: 'JDK 11',
                56: 'JDK 12',
                57: 'JDK 13',
                58: 'JDK 14',
                59: 'JDK 15',
                60: 'JDK 16',
                61: 'JDK 17',
                62: 'JDK 18',
                63: 'JDK 19',
                64: 'JDK 20',
                65: 'JDK 21',
                66: 'JDK 22',
                67: 'JDK 23'
            };

            const constantPoolCount = this.readUint16LE(8);
            const accessFlags = this.readUint16LE(10);
            const thisClass = this.readUint16LE(12);
            const superClass = this.readUint16LE(14);
            const interfacesCount = this.readUint16LE(16);
            const fieldsCount = this.readUint16LE(18);
            const methodsCount = this.readUint16LE(20);
            const attributesCount = this.readUint16LE(22);

            // Access flags
            const accessFlagsList = [];
            if (accessFlags & 0x0001) accessFlagsList.push('ACC_PUBLIC');
            if (accessFlags & 0x0002) accessFlagsList.push('ACC_PRIVATE');
            if (accessFlags & 0x0004) accessFlagsList.push('ACC_PROTECTED');
            if (accessFlags & 0x0008) accessFlagsList.push('ACC_STATIC');
            if (accessFlags & 0x0010) accessFlagsList.push('ACC_FINAL');
            if (accessFlags & 0x0020) accessFlagsList.push('ACC_SUPER');
            if (accessFlags & 0x0040) accessFlagsList.push('ACC_SYNCHRONIZED');
            if (accessFlags & 0x0080) accessFlagsList.push('ACC_VOLATILE');
            if (accessFlags & 0x0100) accessFlagsList.push('ACC_TRANSIENT');
            if (accessFlags & 0x0200) accessFlagsList.push('ACC_NATIVE');
            if (accessFlags & 0x0400) accessFlagsList.push('ACC_INTERFACE');
            if (accessFlags & 0x0800) accessFlagsList.push('ACC_ABSTRACT');
            if (accessFlags & 0x1000) accessFlagsList.push('ACC_STRICT');
            if (accessFlags & 0x2000) accessFlagsList.push('ACC_SYNTHETIC');
            if (accessFlags & 0x4000) accessFlagsList.push('ACC_ANNOTATION');
            if (accessFlags & 0x8000) accessFlagsList.push('ACC_ENUM');

            result.classHeader = {
                magic: '0xCAFEBABE',
                minorVersion,
                majorVersion,
                javaVersion: versionMap[majorVersion] || `JDK ${majorVersion - 44}`,
                constantPoolCount,
                accessFlags: accessFlagsList,
                accessFlagsRaw: '0x' + accessFlags.toString(16),
                thisClass,
                superClass,
                interfacesCount,
                fieldsCount,
                methodsCount,
                attributesCount
            };

            result.details.majorVersion = majorVersion;
            result.details.minorVersion = minorVersion;
            result.details.javaVersion = result.classHeader.javaVersion;
            result.details.constantPoolCount = constantPoolCount - 1;
            result.details.accessFlags = accessFlagsList.join(', ');
            result.details.fieldCount = fieldsCount;
            result.details.methodCount = methodsCount;
            result.details.interfaceCount = interfacesCount;

            // 判断类类型
            if (accessFlags & 0x0400) {
                result.details.classType = 'Interface';
            } else if (accessFlags & 0x4000) {
                result.details.classType = 'Annotation';
            } else if (accessFlags & 0x8000) {
                result.details.classType = 'Enum';
            } else if (accessFlags & 0x0800) {
                result.details.classType = 'Abstract Class';
            } else {
                result.details.classType = 'Class';
            }

            // 检测 Kotlin
            if (this.size > 100) {
                const kotlinMeta = this.searchString('kotlin/Metadata', 0, this.size);
                if (kotlinMeta !== -1) {
                    result.compilers.push('Kotlin');
                }
            }

            // 检测 Scala
            const scala = this.searchString('scala/', 0, this.size);
            if (scala !== -1) {
                result.compilers.push('Scala');
            }

            // 检测 Groovy
            const groovy = this.searchString('groovy/', 0, this.size);
            if (groovy !== -1) {
                result.compilers.push('Groovy');
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 解析 ZIP 文件
    parseZIP() {
        if (!this.checkMagic([0x50, 0x4B, 0x03, 0x04])) return null;

        const result = {
            format: 'ZIP',
            type: 'Archive',
            files: [],
            details: {}
        };

        try {
            let offset = 0;
            let fileCount = 0;
            const maxFiles = 1000; // Limit to prevent slow parsing

            while (offset < this.size - 30 && fileCount < maxFiles) {
                // Local file header signature
                const signature = this.readUint32LE(offset);
                if (signature !== 0x04034B50) break;

                const compressionMethod = this.readUint16LE(offset + 8);
                const compressedSize = this.readUint32LE(offset + 18);
                const uncompressedSize = this.readUint32LE(offset + 22);
                const fileNameLength = this.readUint16LE(offset + 26);
                const extraFieldLength = this.readUint16LE(offset + 28);

                const fileName = this.readString(offset + 30, fileNameLength);

                result.files.push({
                    name: fileName,
                    compressedSize,
                    uncompressedSize,
                    compressionMethod: compressionMethod === 0 ? 'Stored' : (compressionMethod === 8 ? 'Deflated' : `Method ${compressionMethod}`)
                });

                offset += 30 + fileNameLength + extraFieldLength + compressedSize;
                fileCount++;
            }

            result.details.fileCount = fileCount;

            // Detect ZIP sub-types
            const hasAndroidManifest = result.files.some(f => f.name === 'AndroidManifest.xml' || f.name === 'classes.dex');
            const hasManifest = result.files.some(f => f.name === 'META-INF/MANIFEST.MF');
            const hasClassFiles = result.files.some(f => f.name.endsWith('.class'));

            if (hasAndroidManifest) {
                result.format = 'APK';
                result.type = 'Android Application';
                result.platform = 'Android';
                result.details.subType = 'Android Package';
            } else if (hasManifest && hasClassFiles) {
                result.format = 'JAR';
                result.type = 'Java Archive';
                result.platform = 'Java';
                result.details.subType = 'Java Archive';
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 提取可打印字符串
    extractStrings(minLength = 4, maxLength = 100) {
        const strings = [];
        let current = [];
        let startOffset = 0;

        for (let i = 0; i < this.size; i++) {
            const byte = this.uint8[i];
            if (byte >= 32 && byte < 127) {
                if (current.length === 0) startOffset = i;
                current.push(byte);
                if (current.length >= maxLength) {
                    strings.push({
                        offset: startOffset,
                        value: String.fromCharCode.apply(null, current)
                    });
                    current = [];
                }
            } else {
                if (current.length >= minLength) {
                    strings.push({
                        offset: startOffset,
                        value: String.fromCharCode.apply(null, current)
                    });
                }
                current = [];
            }
        }

        if (current.length >= minLength) {
            strings.push({
                offset: startOffset,
                value: String.fromCharCode.apply(null, current)
            });
        }

        return strings;
    }

    // 计算熵值
    calculateEntropy() {
        const frequency = new Array(256).fill(0);
        for (let i = 0; i < this.size; i++) {
            frequency[this.uint8[i]]++;
        }

        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                const p = frequency[i] / this.size;
                entropy -= p * Math.log2(p);
            }
        }

        return entropy;
    }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FileParser;
}