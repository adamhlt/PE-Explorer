#include "PePrinter.h"
#include <cstdio>

namespace
{
    void PrintFields(const std::vector<Field>& fields, const char* lpIndent)
    {
        for (const Field& field : fields)
        {
            printf("%s%s : 0x%llX", lpIndent, field.name.c_str(), static_cast<unsigned long long>(field.value));
            if (!field.note.empty())
                printf(" %s", field.note.c_str());
            printf("\n");
        }
    }

    void PrintDataDirectories(const std::vector<DataDirectoryEntry>& directories)
    {
        for (const DataDirectoryEntry& directory : directories)
        {
            printf("\tDataDirectory (%s) VirtualAddress : 0x%X\n", directory.name.c_str(), directory.virtualAddress);
            printf("\tDataDirectory (%s) Size : 0x%X\n\n", directory.name.c_str(), directory.size);
        }
    }

    void PrintSections(const std::vector<SectionInfo>& sections)
    {
        printf("\n[+] PE IMAGE SECTIONS\n");

        for (const SectionInfo& section : sections)
        {
            printf("\n\tSECTION : %s\n", section.name.c_str());
            PrintFields(section.fields, "\t\t");
        }
    }

    void PrintImports(const std::vector<ImportedDll>& imports)
    {
        printf("\n[+] IMPORTED DLL\n");

        for (const ImportedDll& dll : imports)
        {
            printf("\n\tDLL NAME : %s\n", dll.name.c_str());
            PrintFields(dll.fields, "\t");

            if (dll.functions.empty())
                continue;

            printf("\n\tImported Functions : \n\n");
            for (const ImportedFunction& function : dll.functions)
            {
                if (function.byOrdinal)
                    printf("\t\t#%u (Ordinal)\n", function.ordinal);
                else
                    printf("\t\t%s\n", function.name.c_str());
            }
        }
    }

    void PrintExports(const std::vector<ExportedFunction>& exports)
    {
        printf("\n[+] EXPORTED FUNCTIONS\n\n");

        for (const ExportedFunction& function : exports)
        {
            printf("\t#%u 0x%X %s", function.ordinal, function.rva, function.hasName ? function.name.c_str() : "(no name)");
            if (!function.forwarder.empty())
                printf(" -> %s", function.forwarder.c_str());
            printf("\n");
        }
    }
}

void PrintPe(const PeInfo& info)
{
    if (info.headers.empty())
        return;

    printf("[+] PE IMAGE INFORMATION \n");
    printf("\n[+] Architecture %s \n", info.is64 ? "x64" : "x86");

    for (const HeaderGroup& group : info.headers)
    {
        printf("\n[+] %s\n", group.title.c_str());
        PrintFields(group.fields, "\t");
    }

    printf("\n");
    PrintDataDirectories(info.dataDirectories);
    PrintSections(info.sections);

    if (info.hasImports)
        PrintImports(info.imports);

    if (info.hasExports)
        PrintExports(info.exports);
}
