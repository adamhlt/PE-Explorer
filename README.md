![Banner](https://user-images.githubusercontent.com/48086737/170073956-f6100e8b-a6ac-4207-a2d5-da79f69ad05b.png)

# PE Explorer 

[![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/C%2B%2B) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x86](https://img.shields.io/badge/arch-x86-red.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/X86)

## 📖 Project Overview :

This is a PE file parser, it retrieve every informations from the differents headers...

This tool is made in C++ and compiled in x86, it can parse x86 and x64 PE file.

## :books: Features :

The parser retrieve several informations :

- Every fields in DOS header. 
- Every fields in NT header.
- Every fields in File header.
- Every fields in Optional header (x86 / x64).
- Every sections' informations in the Section header.
- Every DLL imported with imported functions.
- Every exported functions (if the DataDirectory exists).

## 🚀 Getting Started :

### Visual Studio :

1. Open the solution file (.sln).
2. Build the project in Realese (x86)

Every configuration in x86 (Debug and Realese) are already configured.

**It is not necessary to build it in x64, the x86 build can parse x86 and x64 PE file.**

### Other IDE using CMAKE :

This **CMakeLists.txt** should compile the project.

```cmake
cmake_minimum_required(VERSION 3.0)
project(explorer)

set(CMAKE_CXX_STANDARD 17)

add_executable(explorer PE_Explorer.cpp)
```

Tested on CLion with MSVC compiler, you can get Visual Studio Build Tools [**here**](https://visualstudio.microsoft.com/fr/downloads/?q=build+tools).

## :test_tube: Usage :
### How to use the program :

Use it in the command line :

```
explorer.exe <pe_file>
```

**You can test the parser with test files in the "Release" section.**

### Demonstration :

### TEST FILE (EXE - x86)

https://user-images.githubusercontent.com/48086737/170114917-3802a688-8ccc-4cac-83a1-633ecf8d9c5d.mp4

### TEST FILE (DLL - x64)

https://user-images.githubusercontent.com/48086737/170115796-b23c4e69-bebd-4fb0-b634-d2b214b54610.mp4
