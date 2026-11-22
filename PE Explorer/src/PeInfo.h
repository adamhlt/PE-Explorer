#pragma once

#include "Common.h"
#include <cstdint>
#include <string>
#include <vector>

/**
 * Result of the parsing. The parsers only fill these structures, the display is handled by PePrinter.
 */

struct Field
{
    std::string name;
    uint64_t value = 0;
    std::string note; // Optional human readable description of the value.
};

struct HeaderGroup
{
    std::string title;
    std::vector<Field> fields;
};

struct DataDirectoryEntry
{
    std::string name;
    DWORD virtualAddress = 0;
    DWORD size = 0;
};

struct SectionInfo
{
    std::string name;
    std::vector<Field> fields;
};

struct ImportedFunction
{
    bool byOrdinal = false;
    WORD ordinal = 0;
    WORD hint = 0;
    std::string name;
};

struct ImportedDll
{
    std::string name;
    std::vector<Field> fields;
    std::vector<ImportedFunction> functions;
};

struct ExportedFunction
{
    DWORD ordinal = 0;
    DWORD rva = 0;
    bool hasName = false;
    std::string name;
    std::string forwarder; // Not empty when the export is forwarded to another DLL.
};

struct PeInfo
{
    bool is64 = false;
    std::vector<HeaderGroup> headers;
    std::vector<DataDirectoryEntry> dataDirectories;
    std::vector<SectionInfo> sections;
    bool hasImports = false;
    std::vector<ImportedDll> imports;
    bool hasExports = false;
    std::vector<ExportedFunction> exports;
};
