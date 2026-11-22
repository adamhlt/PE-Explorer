<div align="center">

# PE Explorer

**PE file parser in C++ (x86 / x64), retrieve headers, sections, imports and exports**

![Language](https://img.shields.io/badge/C%2B%2B-16171C?logo=cplusplus)
![Platform](https://img.shields.io/badge/Windows-16171C)
![Arch](https://img.shields.io/badge/x86%20%7C%20x64-16171C)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-16171C)](LICENSE)

</div>

---

PE Explorer is a command line tool that parses a PE file (EXE, DLL or driver) and displays everything it contains.

It reads the file without loading it, and every access is checked against the file size, so a malformed PE file produces an error message instead of a crash. The same code base handles x86 and x64 files.

### TEST FILE (EXE - x86)
https://user-images.githubusercontent.com/48086737/170116809-e80fdc5f-a75b-45df-8961-81e4efd8f165.mp4

### TEST FILE (DLL - x64)
https://user-images.githubusercontent.com/48086737/170116974-9bf830f2-814b-435d-a974-820bc0ecfe9d.mp4

## Features

**Headers**
- Every field of the DOS header, NT header and File header
- Every field of the Optional header (x86 / x64)
- DataDirectory entries (address and size)

**Sections**
- Every field of the Section headers, with the protection (`EXECUTE | READ | WRITE`)

**Imports and exports**
- Every imported DLL with its functions (by name or by ordinal)
- Every exported function with its ordinal and address, including forwarded exports

## Usage

```
PEExplorer.exe <pe_file>
```

> **Note**
> You can test the parser with the test files in the "Release" section.

The program returns `0` on success and `1` if the file cannot be read or is not a valid PE file.

## Build

1. Open `PE Explorer.sln` in Visual Studio (C++17).
2. Build in Release (x86 or x64).

- **Output:** every configuration is already set up, the executable is named `PEExplorer.exe`
- **Architecture:** the x86 build can parse x86 and x64 PE files, and so can the x64 build

## License

This project is licensed under the [GNU GPLv3](LICENSE).
