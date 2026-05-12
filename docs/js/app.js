// 应用主逻辑 - 完整 DIE WASM 版本

let engineReady = false;
let dieModule = null;
let currentFileBuffer = null;
let currentFormat = 'text';

// 初始化 WASM 引擎
async function initEngine() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');

    // 等待 WASM 加载器
    if (!window.dieWasmInit) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (!window.dieWasmInit) {
        statusIndicator.textContent = '❌';
        statusText.textContent = 'WASM 加载器未找到';
        showError('WASM 模块加载失败，请刷新页面');
        return;
    }

    try {
        const success = await window.dieWasmInit();

        if (success && window.dieModule) {
            dieModule = window.dieModule;
            engineReady = true;
            statusIndicator.textContent = '🚀';
            statusText.textContent = '完整 DIE 引擎已就绪';
            statusIndicator.className = 'status-indicator wasm-active';
            console.log('完整 DIE WASM 已就绪');
            console.log('FS available:', dieModule.FS ? 'yes' : 'no');
            console.log('callMain available:', dieModule.callMain ? 'yes' : 'no');
        } else {
            throw new Error('初始化失败');
        }
    } catch (error) {
        console.error('引擎初始化失败:', error);
        statusIndicator.textContent = '❌';
        statusText.textContent = 'WASM 加载失败';
        statusIndicator.className = 'status-indicator error';
        showError('WASM 模块加载失败: ' + error.message);
    }
}

// 计算哈希
async function calculateHash(buffer, algorithm) {
    if (algorithm === 'MD5') {
        return md5(buffer);
    } else {
        try {
            const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
            return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
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

// 使用完整 DIE WASM 检测文件
function wasmDetect(buffer, format = 'text') {
    if (!engineReady || !dieModule) {
        throw new Error('WASM 未初始化');
    }

    // 重置全局输出缓冲区
    window.dieOutputBuffer = '';

    const uint8 = new Uint8Array(buffer);
    const fileName = '/input.bin';

    // 写入文件到虚拟文件系统
    try {
        if (dieModule.FS) {
            dieModule.FS.writeFile(fileName, uint8);
        } else {
            throw new Error('FS not available');
        }
    } catch (e) {
        console.error('Failed to write file:', e);
        throw e;
    }

    // 构建命令行参数
    let args = [];
    if (format === 'json') {
        args = ['-j', fileName];
    } else if (format === 'xml') {
        args = ['-x', fileName];
    } else {
        args = ['-p', fileName];
    }

    // 调用 diec - 不需要传程序名
    try {
        dieModule.callMain(args);
    } catch (e) {
        // 预期的异常
    }

    // 获取输出并过滤掉 "Cannot find" 警告
    let output = window.dieOutputBuffer || '';

    // 过滤掉启动警告
    const lines = output.split('\n');
    const filteredLines = lines.filter(line =>
        !line.startsWith('Cannot find:') &&
        !line.includes('argument list cannot be empty')
    );
    output = filteredLines.join('\n').trim();

    // 清理文件
    try {
        dieModule.FS.unlink(fileName);
    } catch (e) {}

    return output;
}

// 切换输出格式
function switchOutputFormat(format) {
    if (!currentFileBuffer) return;

    currentFormat = format;

    // 更新按钮状态
    document.getElementById('btnText').classList.toggle('active', format === 'text');
    document.getElementById('btnJson').classList.toggle('active', format === 'json');
    document.getElementById('btnXml').classList.toggle('active', format === 'xml');

    // 获取对应格式的输出
    const output = wasmDetect(currentFileBuffer, format);
    document.getElementById('rawOutput').innerHTML = `<pre>${escapeHtml(output)}</pre>`;
}

// 显示检测结果
function displayResults(textOutput) {
    document.getElementById('results').style.display = 'block';

    if (!textOutput || textOutput.length === 0) {
        document.getElementById('formatResult').innerHTML = '<div class="result-item"><span class="result-label">无输出</span></div>';
        document.getElementById('rawOutputSection').style.display = 'block';
        document.getElementById('rawOutput').innerHTML = '<pre>检测无结果</pre>';
        return;
    }

    // 解析纯文本输出
    const lines = textOutput.trim().split('\n');
    const formatLine = lines[0] || 'Unknown';

    // 显示格式（第一行）
    const formatResult = document.getElementById('formatResult');
    let html = `<div class="result-item">`;
    html += `<span class="result-label">${escapeHtml(formatLine)}</span>`;
    html += '</div>';
    formatResult.innerHTML = html;

    // 提取并显示其他信息
    const compilers = [];
    const packers = [];
    const libraries = [];

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.match(/^\s*Compiler:/)) {
            compilers.push(line.replace(/Compiler:\s*/, '').trim());
        } else if (line.match(/^\s*Packer:/)) {
            packers.push(line.replace(/Packer:\s*/, '').trim());
        } else if (line.match(/^\s*Library:/)) {
            libraries.push(line.replace(/Library:\s*/, '').trim());
        } else if (line.match(/^\s*Linker:/)) {
            compilers.push('Linker: ' + line.replace(/Linker:\s*/, '').trim());
        } else if (line.match(/^\s*Protector:/)) {
            packers.push('Protector: ' + line.replace(/Protector:\s*/, '').trim());
        }
    }

    const compilerSection = document.getElementById('compilerSection');
    compilerSection.style.display = compilers.length ? 'block' : 'none';
    document.getElementById('compilerResult').innerHTML = compilers.map(c => `<div class="result-tag compiler">${escapeHtml(c)}</div>`).join('');

    const packerSection = document.getElementById('packerSection');
    packerSection.style.display = packers.length ? 'block' : 'none';
    document.getElementById('packerResult').innerHTML = packers.map(p => `<div class="result-tag packer">${escapeHtml(p)}</div>`).join('');

    const librarySection = document.getElementById('librarySection');
    librarySection.style.display = libraries.length ? 'block' : 'none';
    document.getElementById('libraryResult').innerHTML = libraries.map(l => `<div class="result-tag library">${escapeHtml(l)}</div>`).join('');

    // 显示原始输出
    const rawOutputSection = document.getElementById('rawOutputSection');
    rawOutputSection.style.display = 'block';
    document.getElementById('rawOutput').innerHTML = `<pre>${escapeHtml(textOutput)}</pre>`;
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showError(message) {
    document.getElementById('errorMessage').style.display = 'block';
    document.getElementById('errorText').textContent = message;
}

function hideError() {
    document.getElementById('errorMessage').style.display = 'none';
}

// 处理文件
async function handleFile(file) {
    const loading = document.getElementById('loading');
    const fileInfo = document.getElementById('fileInfo');
    const results = document.getElementById('results');

    hideError();
    loading.style.display = 'block';
    fileInfo.style.display = 'none';
    results.style.display = 'none';

    try {
        if (!engineReady) {
            throw new Error('WASM 引擎未初始化');
        }

        const buffer = await file.arrayBuffer();

        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = formatSize(buffer.byteLength);

        // 计算哈希
        const md5Hash = await calculateHash(buffer, 'MD5');
        const sha256Hash = await calculateHash(buffer, 'SHA-256');
        document.getElementById('hashMD5').textContent = md5Hash || '-';
        document.getElementById('hashSHA256').textContent = sha256Hash || '-';

        // 熵值计算
        const uint8 = new Uint8Array(buffer);
        const freq = new Array(256).fill(0);
        for (const b of uint8) freq[b]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] > 0) entropy -= (freq[i] / uint8.length) * Math.log2(freq[i] / uint8.length);
        }
        document.getElementById('entropy').textContent = entropy.toFixed(3);

        fileInfo.style.display = 'block';

        // 存储 buffer 用于格式切换
        currentFileBuffer = buffer;
        currentFormat = 'text';

        // 重置按钮状态
        document.getElementById('btnText').classList.add('active');
        document.getElementById('btnJson').classList.remove('active');
        document.getElementById('btnXml').classList.remove('active');

        // 使用完整 DIE 检测
        console.log('Starting detection...');
        const detectResult = wasmDetect(buffer, 'text');
        console.log('Detection result:', detectResult);
        displayResults(detectResult);

    } catch (error) {
        console.error('检测失败:', error);
        showError('检测失败: ' + error.message);
    }

    loading.style.display = 'none';
}

// 初始化
document.addEventListener('DOMContentLoaded', async () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    await initEngine();

    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', e => {
        if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });
});