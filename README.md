# Detect It Easy - Web Version

A pure frontend web implementation of [Detect It Easy](https://github.com/horsicq/detect-it-easy) for file signature identification.

## Features

- **Pure Frontend**: No server required, runs entirely in browser
- **Multi-format Support**: PE, ELF, Mach-O, MSDOS, COM, ZIP, APK, JAR, DEX, Java Class
- **Signature Detection**: Compiler, packer, protector, installer identification
- **Detailed Analysis**: File structure parsing with collapsible sections
- **Offline Usage**: Works without internet connection

## Usage

1. Open `docs/index.html` in a web browser
2. Upload or drag-drop a file
3. View detection results and file details

## Project Structure

```
detect-it-easy-web/
├── docs/                  # Frontend files
│   ├── index.html         # Main page
│   ├── css/               # Styles
│   └── js/                # JavaScript modules
│       ├── app.js         # Application logic
│       ├── file-parser.js # File parsing
│       ├── die-engine.js  # Detection engine
│       ├── die-signatures-full.js  # PE signatures
│       ├── elf-signatures-full.js  # ELF signatures
│       └── msdos-signatures.js     # MSDOS signatures
├── src/                   # Signature extraction scripts
│   ├── extract_clean_sigs.py    # PE/MACH extraction
│   ├── extract_elf_sigs.py      # ELF extraction
│   └── extract_msdos_signatures.py # MSDOS extraction
└── README.md
└── README_CN.md
```

## Signature Extraction

To regenerate signatures from DIE database:

```bash
# Download DIE signatures first
# Then run extraction scripts from src/ directory
cd src
python3 extract_clean_sigs.py
python3 extract_elf_sigs.py
python3 extract_msdos_signatures.py
```

## Detection Methods

- **entry_point_bytes**: Match bytes at file entry point
- **section_name**: Check for specific section names
- **import_dll**: Detect imported DLLs (PE)
- **needed_lib**: Detect needed libraries (ELF)
- **dynstr_string**: Search in dynamic string table (ELF)
- **find_string**: Search for specific strings

## Current Signature Coverage

| Format | DIE Original | Extracted | Coverage |
|--------|--------------|-----------|----------|
| PE     | 781          | 412       | 52.8%    |
| ELF    | 43           | 36        | 83.7%    |
| MSDOS  | 349          | 333       | 95.4%    |
| **Total** | **1173** | **781** | **66.6%** |

Coverage differences:
- **PE (52.8%)**: Generic detection methods (is_dotnet, rich_header, etc.) filtered out to avoid false positives
- **ELF (83.7%)**: Enhanced extraction with needed_lib, dynstr_string, section detection methods
- **MSDOS (95.4%)**: Nearly complete extraction, mainly using entry point bytes and string matching

## Credits

- Original DIE project: [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy)
- Signature database derived from DIE

## License

MIT License