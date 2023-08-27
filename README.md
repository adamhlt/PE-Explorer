```
                          ____  ______   ______           __                    
                         / __ \/ ____/  / ____/  ______  / /___  ________  _____
                        / /_/ / __/    / __/ | |/_/ __ \/ / __ \/ ___/ _ \/ ___/
                       / ____/ /___   / /____>  </ /_/ / / /_/ / /  /  __/ /
                      /_/   /_____/  /_____/_/|_/ .___/_/\____/_/   \___/_/
                                               /_/                         
                                                                          
                                                                         
                                  PE Explorer in C++ (x86 / x64)
                          PE file parser, retrieve exports and imports
```
<p align="center">
    <img src="https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor" alt="C++">
    <img src="https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor" alt="Windows">
    <img src="https://img.shields.io/badge/arch-x86-red.svg?style=for-the-badge&logo=appveyor" alt="x86">
</p>

## 📖 Project Overview :

This is a PE file parser, it retrieve every informations from the differents headers...

This tool is made in C++, it can parse x86 and x64 PE file.

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
2. Build the project in Realese (x86 or x64)

Every configuration in x86 / x64 (Debug and Realese) are already configured.

> **Note** <br>
> It is not necessary to build it in x64, the x86 build can parse x86 and x64 PE file.

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
> **Note** <br>
> You can test the parser with test files in the "Release" section.

### Demonstration :

### TEST FILE (EXE - x86)

https://user-images.githubusercontent.com/48086737/170116809-e80fdc5f-a75b-45df-8961-81e4efd8f165.mp4

### TEST FILE (DLL - x64)

https://user-images.githubusercontent.com/48086737/170116974-9bf830f2-814b-435d-a974-820bc0ecfe9d.mp4
