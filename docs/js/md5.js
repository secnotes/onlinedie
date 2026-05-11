// MD5 纯 JavaScript 实现 - RFC 1321
// 简洁可靠版本

var md5 = (function() {
    // MD5 常量
    var K = new Uint32Array([
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]);

    var S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
             5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
             6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];

    var R = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
             1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
             5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
             0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9];

    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    function add(x, y) {
        var l = (x & 0xFFFF) + (y & 0xFFFF);
        return ((x >>> 16) + (y >>> 16) + (l >>> 16) << 16) | (l & 0xFFFF);
    }

    function fF(x, y, z) { return (x & y) | (~x & z); }
    function fG(x, y, z) { return (x & z) | (y & ~z); }
    function fH(x, y, z) { return x ^ y ^ z; }
    function fI(x, y, z) { return y ^ (x | ~z); }

    function processBlock(H, M) {
        var a = H[0], b = H[1], c = H[2], d = H[3];

        for (var i = 0; i < 64; i++) {
            var f, g = R[i];

            if (i < 16) { f = fF(b, c, d); }
            else if (i < 32) { f = fG(b, c, d); g = R[i]; }
            else if (i < 48) { f = fH(b, c, d); }
            else { f = fI(b, c, d); }

            f = add(f, add(a, add(K[i], M[g]))) >>> 0;
            a = d;
            d = c;
            c = b;
            b = add(rotl(f, S[i]), b) >>> 0;
        }

        H[0] = add(H[0], a) >>> 0;
        H[1] = add(H[1], b) >>> 0;
        H[2] = add(H[2], c) >>> 0;
        H[3] = add(H[3], d) >>> 0;
    }

    function toHex(x) {
        var s = '';
        for (var i = 0; i < 32; i += 8) {
            s += ((x >>> i) & 0xFF).toString(16).padStart(2, '0');
        }
        return s;
    }

    return function(buf) {
        var arr = new Uint8Array(buf);
        var len = arr.length;

        var H = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        var M = new Uint32Array(16);

        // 处理完整的 64字节块
        var n = len >>> 6;
        for (var i = 0; i < n; i++) {
            for (var j = 0; j < 16; j++) {
                M[j] = arr[i*64 + j*4] | (arr[i*64 + j*4 + 1] << 8) |
                       (arr[i*64 + j*4 + 2] << 16) | (arr[i*64 + j*4 + 3] << 24);
            }
            processBlock(H, M);
        }

        // 填充
        var padLen = len < 56 ? 64 : 128;
        var pad = new Uint8Array(padLen);
        var off = n * 64;

        for (var i = 0; i < len - off; i++) pad[i] = arr[off + i];
        pad[len - off] = 0x80;

        // 长度 (bits)
        var bitLen = len * 8;
        pad[padLen - 8] = bitLen & 0xFF;
        pad[padLen - 7] = (bitLen >>> 8) & 0xFF;
        pad[padLen - 6] = (bitLen >>> 16) & 0xFF;
        pad[padLen - 5] = (bitLen >>> 24) & 0xFF;
        // 高32位为0（文件大小小于512MB）

        for (var i = 0; i < padLen >>> 6; i++) {
            for (var j = 0; j < 16; j++) {
                M[j] = pad[i*64 + j*4] | (pad[i*64 + j*4 + 1] << 8) |
                       (pad[i*64 + j*4 + 2] << 16) | (pad[i*64 + j*4 + 3] << 24);
            }
            processBlock(H, M);
        }

        return toHex(H[0]) + toHex(H[1]) + toHex(H[2]) + toHex(H[3]);
    };
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = md5;
}