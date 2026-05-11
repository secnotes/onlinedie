// ELF 签名数据库 - 增强版

const ELFSignaturesFull = {
    compilers: [
        { name: "movfuscator", language: "C", signatures: [{ method: "entry_point_bytes", pattern: "A1........8B98........8B03BA........668B9400........8913A1........8B98........" }] },
        { name: "ldc", language: "D", signatures: [{ method: "find_string", pattern: "ldc version " }, { method: "needed_lib", pattern: "libphobos2-ldc-shared.so.98" }, { method: "needed_lib", pattern: "libdruntime-ldc-shared.so.98" }] },
        { name: "gdc", language: "C/C++", signatures: [{ method: "needed_lib", pattern: "libgphobos.so.2" }] },
        { name: "GCC", language: "C", signatures: [{ method: "entry_point_bytes", pattern: "31ED5E89E183E4..50545268........68........515668........E8" }, { method: "entry_point_bytes", pattern: "31ED5589E583E4..8D45..83EC..50FF75..52E8????????????????5589E557565383EC..8B5D.." }, { method: "entry_point_bytes", pattern: "5589E5565383EC..83E4..8B5D..89D18D74....85DB8935........7E..8B45..85C074..A3...." }, { method: "entry_point_bytes", pattern: "55575653E8........81C3........83EC..8B93........8B8B........8B83........8B2A8B93" }, { method: "entry_point_bytes", pattern: "5589E557565383EC..83E4..8B5D..89D78D74....85DB8935........7E..8B45..85C074..A3.." }] },
        { name: "Zig", language: "Zig", signatures: [{ method: "section_name", pattern: ".rodata" }] },
        { name: "Watcom", language: "C/C++", signatures: [{ method: "entry_point_bytes", pattern: "33ED8925........598BF48D44....505651E8" }, { method: "find_string", pattern: "WATCOM" }] },
        { name: "Rust", language: "Rust", signatures: [{ method: "entry_point_bytes", pattern: "F30F1EFB31ED5E89E183E4..505452E8........81C3" }, { method: "entry_point_bytes", pattern: "31ED5E89E183E4..505452E8........81C3" }, { method: "entry_point_bytes", pattern: "31ED89E083E4..5050E8........8104" }, { method: "entry_point_bytes", pattern: "4831ED4889E7488D35........4883E4..E8????????????????488B37488D57..4531C94C8D05.." }, { method: "entry_point_bytes", pattern: "F30F1EFA31ED4989D15E4889E24883E4..50544531C031C9488D3D????????????????504889F148" }] },
        { name: "Oracle Solaris Studio", language: "C/C++", signatures: [{ method: "entry_point_bytes", pattern: "BC1020..E003....1300....E022....A203A0..1300....E222....1300....E222....A52C20.." }, { method: "section_name", pattern: ".SUNW_version" }, { method: "find_string", pattern: "Sun WorkShop" }, { method: "find_string", pattern: "acomp: Sun C" }, { method: "find_string", pattern: "SUNWCC.h" }] },
        { name: "HP C++", language: "C++", signatures: [{ method: "section_name", pattern: ".HP.init" }] },
        { name: "Go", language: "Go", signatures: [{ method: "entry_point_bytes", pattern: "488D742408488B3C24B810174200FFE0B870F94100FFE0000000000000000000" }, { method: "entry_point_bytes", pattern: "488D742408488B3C24B8907F4200FFE0B800564200FFE0000000000000000000" }, { method: "entry_point_bytes", pattern: "488D742408488B3C24B8C07F4200FFE0B830564200FFE0000000000000000000" }, { method: "entry_point_bytes", pattern: "488D742408488B3C24B8E07F4200FFE0B850564200FFE0000000000000000000" }, { method: "entry_point_bytes", pattern: "488D742408488B3C24488D0510000000FFE00000000000000000000000000000" }] },
        { name: "Free Pascal", language: "Pascal", signatures: [{ method: "entry_point_bytes", pattern: "5989E38D44....83E4..8915........A3........890D........891D........E8........8925" }, { method: "entry_point_bytes", pattern: "31ED5989E3" }, { method: "section_name", pattern: ".fpc.resources" }, { method: "section_name", pattern: ".fpcdata" }, { method: "section_name", pattern: ".data" }] },
        { name: "DMD", language: "D", signatures: [{ method: "find_string", pattern: "DMD v" }] },
        { name: "Borland Kylix", language: "Pascal/C/C++", signatures: [{ method: "section_name", pattern: "borland.ressym" }, { method: "section_name", pattern: "borland.reshash" }, { method: "section_name", pattern: "borland.resdata" }, { method: "section_name", pattern: "borland.resspare" }] },
    ],
    libraries: [
        { name: "X11", signatures: [{ method: "needed_lib", pattern: "libX11.so.6" }] },
        { name: "SDL", signatures: [{ method: "dynstr_string", table: ".dynstr", pattern: "SDL_Init" }, { method: "find_string", pattern: "libSDL-" }, { method: "find_string", pattern: "SDL_Init" }] },
        { name: "Qt", signatures: [{ method: "dynstr_string", table: ".dynstr", pattern: "libQtCore.so.4" }, { method: "dynstr_string", table: ".dynstr", pattern: "libQt5Core.so.5" }, { method: "dynstr_string", table: ".dynstr", pattern: "libQt6Core_x86.so" }, { method: "dynstr_string", table: ".dynstr", pattern: "libQt6Core.so.6" }, { method: "find_string", pattern: "/usr/local/Trolltech/Qt-" }] },
        { name: "PulseAudio", signatures: [{ method: "needed_lib", pattern: "libpulse.so.0" }] },
        { name: "OpenAL", signatures: [{ method: "needed_lib", pattern: "libopenal.so.1" }] },
        { name: "OGG", signatures: [{ method: "needed_lib", pattern: "libogg.so.0" }] },
        { name: "Mikmod", signatures: [{ method: "needed_lib", pattern: "libmikmod.so.3" }] },
        { name: "MPEG2", signatures: [{ method: "needed_lib", pattern: "libmpeg2.so.0" }] },
        { name: "Lego1", signatures: [{ method: "needed_lib", pattern: "liblego1.so" }] },
        { name: "LZMA", signatures: [{ method: "needed_lib", pattern: "liblzma.so.5" }] },
        { name: "GLIBC", signatures: [{ method: "section_name", pattern: ".dynstr" }, { method: "find_string", pattern: "GLIBC_" }, { method: "find_string", pattern: "GLIBC_" }] },
        { name: "GLEW", signatures: [{ method: "needed_lib", pattern: "libGLEW.so.2.2" }] },
        { name: "FreeType", signatures: [{ method: "needed_lib", pattern: "libfreetype.so.6" }] },
        { name: "FluidSynth", signatures: [{ method: "needed_lib", pattern: "libfluidsynth.so.3" }] },
        { name: "FLAC", signatures: [{ method: "needed_lib", pattern: "libFLAC.so.14" }] },
        { name: "FFmpeg", signatures: [{ method: "needed_lib", pattern: "libffmpeg.so" }] },
        { name: "Curl", signatures: [{ method: "needed_lib", pattern: "libcurl.so.4" }] },
    ],
    packers: [
        { name: "exepak", signatures: [{ method: "entry_point_bytes", pattern: "B9........81E9........89CB83E9..BE........89F7033D........F3A48B15........B8" }] },
        { name: "Virbox", signatures: [{ method: "find_string", pattern: "Virbox Protector" }] },
        { name: "UPX", signatures: [{ method: "entry_point_bytes", pattern: "E8........EB0E5A585997608A542420E9........60" }, { method: "find_string", pattern: "$Id: UPX" }] },
        { name: "Ezuri", signatures: [{ method: "section_name", pattern: ".strtab" }, { method: "section_name", pattern: ".gopclntab" }, { method: "section_name", pattern: ".noptrdata" }, { method: "section_name", pattern: ".rodata" }, { method: "find_string", pattern: "main.runFromMemory" }] },
    ],
    protectors: [
        { name: "HASP", signatures: [{ method: "section_name", pattern: "protect" }, { method: "find_string", pattern: "hasp" }, { method: "find_string", pattern: "hasp" }] },
        { name: "Burneye", signatures: [{ method: "entry_point_bytes", pattern: "FF35........9C608B0D........E9" }] },
    ],
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ELFSignaturesFull;
}