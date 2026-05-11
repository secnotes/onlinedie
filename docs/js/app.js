// 应用主逻辑

// 计算哈希
async function calculateHash(buffer, algorithm) {
    if (algorithm === 'MD5') {
        // 使用纯 JavaScript MD5 实现
        return md5(buffer);
    } else {
        // 使用 Web Crypto API 计算 SHA-256 等
        try {
            const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            return '-';
        }
    }
}

// 格式化文件大小
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

// 创建可折叠区域
function createCollapsibleSection(title, content, collapsed = true) {
    const sectionId = 'collapse-' + Math.random().toString(36).substr(2, 9);
    const html = `
        <div class="collapsible-section">
            <div class="collapsible-header" onclick="toggleCollapse('${sectionId}')">
                <span class="collapse-icon">${collapsed ? '▶' : '▼'}</span>
                <span class="collapse-title">${title}</span>
            </div>
            <div class="collapsible-content" id="${sectionId}" style="display: ${collapsed ? 'none' : 'block'}">
                ${content}
            </div>
        </div>
    `;
    return html;
}

// 切换折叠状态
function toggleCollapse(id) {
    const content = document.getElementById(id);
    const header = content.previousElementSibling;
    const icon = header.querySelector('.collapse-icon');

    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.textContent = '▼';
    } else {
        content.style.display = 'none';
        icon.textContent = '▶';
    }
}

// 显示检测结果
function displayResults(results, file, parser) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.style.display = 'block';

    // 格式信息
    const formatSection = document.getElementById('formatSection');
    const formatResult = document.getElementById('formatResult');

    if (results.format) {
        let formatHTML = `<div class="result-item">`;
        formatHTML += `<span class="result-label">${results.format.format || 'Unknown'}</span>`;
        if (results.format.fullName) {
            formatHTML += `<span class="result-value">${results.format.fullName}</span>`;
        }
        if (results.format.type) {
            formatHTML += `<span class="result-type">${results.format.type}</span>`;
        }
        if (results.format.platform) {
            formatHTML += `<span class="result-platform">${results.format.platform}</span>`;
        }
        if (results.format.architecture) {
            formatHTML += `<span class="result-arch">${results.format.architecture}</span>`;
        }
        formatHTML += '</div>';
        formatResult.innerHTML = formatHTML;
    }

    // 编译器信息
    const compilerSection = document.getElementById('compilerSection');
    const compilerResult = document.getElementById('compilerResult');

    if (results.compiler && results.compiler.length > 0) {
        compilerSection.style.display = 'block';
        compilerResult.innerHTML = results.compiler.map(c =>
            `<div class="result-tag compiler">${c}</div>`
        ).join('');
    } else {
        compilerSection.style.display = 'none';
    }

    // 打包器信息
    const packerSection = document.getElementById('packerSection');
    const packerResult = document.getElementById('packerResult');

    if (results.packer && results.packer.length > 0) {
        packerSection.style.display = 'block';
        packerResult.innerHTML = results.packer.map(p =>
            `<div class="result-tag packer">${p}</div>`
        ).join('');
    } else {
        packerSection.style.display = 'none';
    }

    // 库信息
    const librarySection = document.getElementById('librarySection');
    const libraryResult = document.getElementById('libraryResult');

    if (results.library && results.library.length > 0) {
        librarySection.style.display = 'block';
        libraryResult.innerHTML = results.library.map(l =>
            `<div class="result-tag library">${l}</div>`
        ).join('');
    } else {
        librarySection.style.display = 'none';
    }

    // 详细信息区域
    const detailSection = document.getElementById('detailSection');
    const detailResult = document.getElementById('detailResult');
    detailSection.style.display = 'block';

    let detailHTML = '';

    // 基本信息
    if (results.details && Object.keys(results.details).length > 0) {
        detailHTML += createCollapsibleSection('📋 基本信息', createDetailTable(results.details), false);
    }

    // ELF 特殊信息
    if (results.format && results.format.format === 'ELF') {
        // ELF Header
        if (results.format.elfHeader) {
            const elfHeaderContent = createDetailTable({
                'Class': results.format.details.elfClass,
                'Endianness': results.format.details.endianness,
                'OS/ABI': results.format.details.osAbi,
                'Machine': results.format.details.machine,
                'Type': results.format.details.fileType,
                'Entry Point': results.format.details.entryPoint,
                'Program Headers': results.format.elfHeader.ePhnum,
                'Section Headers': results.format.elfHeader.eShnum,
                'Header Size': results.format.elfHeader.eEhsize + ' bytes',
                'Program Header Size': results.format.elfHeader.ePhentsize + ' bytes',
                'Section Header Size': results.format.elfHeader.eShentsize + ' bytes'
            });
            detailHTML += createCollapsibleSection('📖 ELF Header', elfHeaderContent, true);
        }

        // Program Headers (Segments)
        if (results.format.programHeaders && results.format.programHeaders.length > 0) {
            let phHTML = '<table class="info-table"><tr><th>Type</th><th>Offset</th><th>VAddr</th><th>FileSize</th><th>MemSize</th><th>Flags</th><th>Align</th></tr>';
            for (const ph of results.format.programHeaders) {
                phHTML += `<tr>
                    <td class="ph-type">${ph.type}</td>
                    <td>${ph.offset}</td>
                    <td>${ph.vaddr}</td>
                    <td>${formatSize(ph.filesz)}</td>
                    <td>${formatSize(ph.memsz)}</td>
                    <td class="ph-flags">${ph.flags}</td>
                    <td>${ph.align}</td>
                </tr>`;
            }
            phHTML += '</table>';
            detailHTML += createCollapsibleSection(`🔄 Program Headers (${results.format.programHeaders.length})`, phHTML, true);
        }

        // Sections
        if (results.format.sections && results.format.sections.length > 0) {
            let sectionHTML = '<table class="info-table"><tr><th>Name</th><th>Type</th><th>Address</th><th>Offset</th><th>Size</th><th>Flags</th></tr>';
            for (const section of results.format.sections) {
                sectionHTML += `<tr>
                    <td class="section-name">${section.name}</td>
                    <td>${section.type}</td>
                    <td>${section.address}</td>
                    <td>${section.offset}</td>
                    <td>${formatSize(section.size)}</td>
                    <td class="section-flags">${(section.flags || []).join(', ')}</td>
                </tr>`;
            }
            sectionHTML += '</table>';
            detailHTML += createCollapsibleSection(`📑 Sections (${results.format.sections.length})`, sectionHTML, true);
        }

        // Dynamic Section
        if (results.format.dynamicEntries && results.format.dynamicEntries.length > 0) {
            let dynHTML = '<table class="info-table"><tr><th>Tag</th><th>Value</th></tr>';
            for (const entry of results.format.dynamicEntries) {
                dynHTML += `<tr>
                    <td class="dyn-tag">${entry.tag}</td>
                    <td>${entry.value}</td>
                </tr>`;
            }
            dynHTML += '</table>';
            detailHTML += createCollapsibleSection(`⚡ Dynamic Section (${results.format.dynamicEntries.length})`, dynHTML, true);
        }

        // Needed Libraries
        if (results.format.neededLibs && results.format.neededLibs.length > 0) {
            let libsHTML = '<div class="needed-list">';
            for (const lib of results.format.neededLibs) {
                libsHTML += `<div class="needed-item">${lib}</div>`;
            }
            libsHTML += '</div>';
            detailHTML += createCollapsibleSection(`📚 Needed Libraries (${results.format.neededLibs.length})`, libsHTML, true);
        }

        // Notes
        if (results.format.notes && results.format.notes.length > 0) {
            let notesHTML = '<table class="info-table"><tr><th>Name</th><th>Type</th><th>Data</th></tr>';
            for (const note of results.format.notes) {
                notesHTML += `<tr>
                    <td>${note.name}</td>
                    <td>${note.type}</td>
                    <td class="note-data">${note.desc}</td>
                </tr>`;
            }
            notesHTML += '</table>';
            detailHTML += createCollapsibleSection(`📝 Notes (${results.format.notes.length})`, notesHTML, true);
        }
    }

    // PE 特殊信息
    if (results.format && results.format.format === 'PE') {
        // DOS Header
        if (results.format.dosHeader) {
            detailHTML += createCollapsibleSection('🖥️ DOS Header', createDetailTable(results.format.dosHeader), true);
        }

        // COFF Header
        if (results.format.coffHeader) {
            detailHTML += createCollapsibleSection('📦 COFF Header', createDetailTable(results.format.coffHeader), true);
        }

        // Optional Header
        if (results.format.optionalHeader) {
            detailHTML += createCollapsibleSection('⚙️ Optional Header', createDetailTable(results.format.optionalHeader), true);
        }

        // Data Directories
        if (results.format.dataDirectories && results.format.dataDirectories.length > 0) {
            let dirsHTML = '<table class="info-table"><tr><th>Directory</th><th>RVA</th><th>Size</th></tr>';
            for (const dir of results.format.dataDirectories) {
                dirsHTML += `<tr><td>${dir.name}</td><td>${dir.rva}</td><td>${dir.size}</td></tr>`;
            }
            dirsHTML += '</table>';
            detailHTML += createCollapsibleSection('📂 Data Directories', dirsHTML, true);
        }

        // Sections
        if (results.format.sections && results.format.sections.length > 0) {
            let sectionHTML = '<table class="info-table"><tr><th>Name</th><th>VAddr</th><th>VSize</th><th>RawSize</th><th>Entropy</th><th>Flags</th></tr>';
            for (const section of results.format.sections) {
                sectionHTML += `<tr>
                    <td class="section-name">${section.name}</td>
                    <td>${section.virtualAddress}</td>
                    <td>${formatSize(section.virtualSize)}</td>
                    <td>${formatSize(section.rawSize)}</td>
                    <td>${section.entropy || '-'}</td>
                    <td class="section-flags">${(section.characteristics || []).join(', ')}</td>
                </tr>`;
            }
            sectionHTML += '</table>';
            detailHTML += createCollapsibleSection(`📑 Sections (${results.format.sections.length})`, sectionHTML, true);
        }

        // Imports
        if (results.format.imports && results.format.imports.length > 0) {
            let importsHTML = '<div class="imports-list">';
            importsHTML += results.format.imports.map(dll =>
                `<div class="import-item">${dll}</div>`
            ).join('');
            importsHTML += '</div>';
            detailHTML += createCollapsibleSection(`🔗 Imports (${results.format.imports.length})`, importsHTML, true);
        }

        // Exports
        if (results.format.exports && results.format.exports.length > 0) {
            let exportsHTML = '<div class="imports-list">';
            exportsHTML += results.format.exports.map(exp =>
                `<div class="export-item">${exp}</div>`
            ).join('');
            exportsHTML += '</div>';
            detailHTML += createCollapsibleSection(`📤 Exports (${results.format.exports.length})`, exportsHTML, true);
        }
    }

    // Mach-O 特殊信息
    if (results.format && (results.format.format === 'Mach-O' || results.format.format === 'Mach-O Universal')) {
        // Mach Header
        if (results.format.machHeader) {
            const machInfo = {
                'Magic': results.format.machHeader.magic,
                'CPU Type': results.format.machHeader.cputype,
                'CPU Subtype': results.format.machHeader.cpusubtype,
                'File Type': results.format.machHeader.filetype,
                'Load Commands': results.format.machHeader.ncmds,
                'Commands Size': results.format.machHeader.sizeofcmds + ' bytes',
                'Flags': (results.format.machHeader.flags || []).join(', ')
            };
            detailHTML += createCollapsibleSection('🔧 Mach Header', createDetailTable(machInfo), true);
        }

        // Load Commands
        if (results.format.loadCommands && results.format.loadCommands.length > 0) {
            let lcHTML = '<table class="info-table"><tr><th>Command</th><th>Size</th><th>Details</th></tr>';
            for (const lc of results.format.loadCommands.slice(0, 50)) {
                let details = '';
                if (lc.dylib) details = lc.dylib;
                if (lc.uuid) details = lc.uuid;
                if (lc.segment) details = `${lc.segment.name} (${lc.segment.maxprot})`;
                if (lc.entryOffset) details = `Entry: ${lc.entryOffset}`;
                if (lc.minVersion) details = lc.minVersion;
                if (lc.platform) details = `${lc.platform} (${lc.minOS})`;
                lcHTML += `<tr><td class="lc-type">${lc.cmd}</td><td>${lc.cmdsize}</td><td>${details}</td></tr>`;
            }
            if (results.format.loadCommands.length > 50) {
                lcHTML += `<tr><td colspan="3" class="more-files">... and ${results.format.loadCommands.length - 50} more commands</td></tr>`;
            }
            lcHTML += '</table>';
            detailHTML += createCollapsibleSection(`📋 Load Commands (${results.format.loadCommands.length})`, lcHTML, true);
        }

        // Dylibs
        if (results.format.dylibs && results.format.dylibs.length > 0) {
            let libsHTML = '<div class="needed-list">';
            libsHTML += results.format.dylibs.map(lib =>
                `<div class="needed-item">${lib}</div>`
            ).join('');
            libsHTML += '</div>';
            detailHTML += createCollapsibleSection(`📚 Dylibs (${results.format.dylibs.length})`, libsHTML, true);
        }

        // Fat Binary architectures
        if (results.format.architectures && results.format.architectures.length > 0) {
            let archHTML = '<table class="info-table"><tr><th>Architecture</th><th>Offset</th><th>Size</th><th>Align</th></tr>';
            for (const arch of results.format.architectures) {
                archHTML += `<tr><td>${arch.cpu}</td><td>${arch.offset}</td><td>${formatSize(arch.size)}</td><td>${arch.align}</td></tr>`;
            }
            archHTML += '</table>';
            detailHTML += createCollapsibleSection(`🏗️ Architectures (${results.format.architectures.length})`, archHTML, true);
        }
    }

    // DEX 特殊信息
    if (results.format && results.format.format === 'DEX') {
        if (results.format.dexHeader) {
            const dexInfo = {
                'Magic': results.format.dexHeader.magic,
                'Version': results.format.dexHeader.version,
                'Checksum': results.format.dexHeader.checksum,
                'Signature': results.format.dexHeader.signature.slice(0, 32) + '...',
                'File Size': formatSize(results.format.dexHeader.fileSize),
                'Header Size': results.format.dexHeader.headerSize + ' bytes',
                'Endian Tag': results.format.dexHeader.endianTag,
                'Strings': results.format.dexHeader.stringIdsSize,
                'Types': results.format.dexHeader.typeIdsSize,
                'Protos': results.format.dexHeader.protoIdsSize,
                'Fields': results.format.dexHeader.fieldIdsSize,
                'Methods': results.format.dexHeader.methodIdsSize,
                'Classes': results.format.dexHeader.classDefsSize,
                'Data Size': formatSize(results.format.dexHeader.dataSize)
            };
            detailHTML += createCollapsibleSection('🤖 DEX Header', createDetailTable(dexInfo), true);
        }
    }

    // Java Class 特殊信息
    if (results.format && results.format.format === 'Java Class') {
        if (results.format.classHeader) {
            const classInfo = {
                'Magic': results.format.classHeader.magic,
                'Version': `${results.format.classHeader.majorVersion}.${results.format.classHeader.minorVersion}`,
                'Java Version': results.format.classHeader.javaVersion,
                'Class Type': results.format.details.classType,
                'Access Flags': (results.format.classHeader.accessFlags || []).join(', '),
                'Constant Pool': results.format.classHeader.constantPoolCount - 1 + ' entries',
                'Fields': results.format.classHeader.fieldsCount,
                'Methods': results.format.classHeader.methodsCount,
                'Interfaces': results.format.classHeader.interfacesCount,
                'Attributes': results.format.classHeader.attributesCount
            };
            detailHTML += createCollapsibleSection('☕ Class Header', createDetailTable(classInfo), true);
        }
    }

    // MS-DOS / COM 特殊信息
    if (results.format && (results.format.format === 'MS-DOS' || results.format.format === 'COM')) {
        if (results.format.dosHeader) {
            detailHTML += createCollapsibleSection('🖥️ DOS Header', createDetailTable(results.format.dosHeader), true);
        }
        if (results.format.details) {
            detailHTML += createCollapsibleSection('📋 Details', createDetailTable(results.format.details), false);
        }
    }

    // ZIP/APK 文件列表
    if (results.format && results.format.files && results.format.files.length > 0) {
        let filesHTML = '<table class="info-table"><tr><th>Name</th><th>Compressed</th><th>Original</th><th>Method</th></tr>';
        for (const f of results.format.files.slice(0, 100)) {
            filesHTML += `<tr>
                <td class="file-name">${f.name}</td>
                <td>${formatSize(f.compressedSize)}</td>
                <td>${formatSize(f.uncompressedSize)}</td>
                <td>${f.compressionMethod}</td>
            </tr>`;
        }
        if (results.format.files.length > 100) {
            filesHTML += `<tr><td colspan="4" class="more-files">... and ${results.format.files.length - 100} more files</td></tr>`;
        }
        filesHTML += '</table>';
        detailHTML += createCollapsibleSection(`📁 Contents (${results.format.files.length})`, filesHTML, true);
    }

    // 可打印字符串
    const stringsSection = document.getElementById('stringsSection');
    const stringsResult = document.getElementById('stringsResult');

    if (results.format && results.format.format !== 'Text') {
        const strings = parser.extractStrings(6, 200);
        const interestingStrings = strings
            .filter(s => {
                const value = s.value;
                return value.length >= 10 &&
                    (value.includes('.') ||
                        value.includes('/') ||
                        value.includes('\\') ||
                        value.toLowerCase().includes('http') ||
                        value.toLowerCase().includes('version') ||
                        value.toLowerCase().includes('copyright') ||
                        value.toLowerCase().includes('license') ||
                        value.toLowerCase().includes('error') ||
                        value.toLowerCase().includes('debug') ||
                        /[A-Z][a-z]+/.test(value));
            })
            .slice(0, 100);

        if (interestingStrings.length > 0) {
            stringsSection.style.display = 'block';
            let stringsHTML = '<div class="strings-list">';
            stringsHTML += interestingStrings.map(s =>
                `<div class="string-item"><span class="string-offset">0x${s.offset.toString(16).toUpperCase()}</span><span class="string-value">${escapeHtml(s.value)}</span></div>`
            ).join('');
            stringsHTML += '</div>';
            stringsResult.innerHTML = createCollapsibleSection(`📝 Interesting Strings (${interestingStrings.length})`, stringsHTML, true);
        } else {
            stringsSection.style.display = 'none';
        }
    } else {
        stringsSection.style.display = 'none';
    }

    detailResult.innerHTML = detailHTML;
}

// 创建详情表格
function createDetailTable(details) {
    let html = '<table class="detail-table">';
    for (const [key, value] of Object.entries(details)) {
        if (value !== null && value !== undefined && value !== '') {
            html += `<tr><td class="detail-key">${key}</td><td class="detail-value">${value}</td></tr>`;
        }
    }
    html += '</table>';
    return html;
}

// HTML 转义
function escapeHtml(str) {
    return str.replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// 处理文件上传
async function handleFile(file) {
    const loading = document.getElementById('loading');
    const fileInfo = document.getElementById('fileInfo');
    const results = document.getElementById('results');

    loading.style.display = 'block';
    fileInfo.style.display = 'none';
    results.style.display = 'none';

    try {
        const buffer = await file.arrayBuffer();

        // 显示文件信息
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = formatSize(buffer.byteLength);

        // 计算哈希
        const md5Hash = await calculateHash(buffer, 'MD5');
        const sha256Hash = await calculateHash(buffer, 'SHA-256');

        document.getElementById('hashMD5').textContent = md5Hash || '-';
        document.getElementById('hashSHA256').textContent = sha256Hash || '-';

        // 计算熵值
        const parser = new FileParser(buffer);
        const entropy = parser.calculateEntropy();
        document.getElementById('entropy').textContent = entropy.toFixed(3);

        fileInfo.style.display = 'block';

        // 检测文件
        const engine = new DIEEngine();
        const detectResults = engine.detect(parser);

        // 显示结果
        displayResults(detectResults, file, parser);

    } catch (e) {
        console.error('Error analyzing file:', e);
        alert('分析文件时出错: ' + e.message);
    }

    loading.style.display = 'none';
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    // 拖放事件
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    // 点击上传
    fileInput.addEventListener('change', (e) => {
        const files = e.target.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    // 隐藏所有结果区域
    document.getElementById('compilerSection').style.display = 'none';
    document.getElementById('packerSection').style.display = 'none';
    document.getElementById('librarySection').style.display = 'none';
    document.getElementById('detailSection').style.display = 'none';
    document.getElementById('stringsSection').style.display = 'none';
});