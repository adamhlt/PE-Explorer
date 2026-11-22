#include "PeParser.h"
#include "ExportParser.h"
#include "ImportParser.h"
#include "PeNames.h"
#include "PeTraits.h"
#include <algorithm>

namespace
{
    void AddField(std::vector<Field>& fields, const char* lpName, const uint64_t value, const std::string& note = {})
    {
        fields.push_back({ lpName, value, note });
    }

#define ADD_FIELD(fields, object, member) AddField(fields, #member, (object).member)

    HeaderGroup ParseDosHeader(const IMAGE_DOS_HEADER& dos)
    {
        HeaderGroup group{ "DOS HEADER", {} };
        ADD_FIELD(group.fields, dos, e_magic);
        ADD_FIELD(group.fields, dos, e_cblp);
        ADD_FIELD(group.fields, dos, e_cp);
        ADD_FIELD(group.fields, dos, e_crlc);
        ADD_FIELD(group.fields, dos, e_cparhdr);
        ADD_FIELD(group.fields, dos, e_minalloc);
        ADD_FIELD(group.fields, dos, e_maxalloc);
        ADD_FIELD(group.fields, dos, e_ss);
        ADD_FIELD(group.fields, dos, e_sp);
        ADD_FIELD(group.fields, dos, e_csum);
        ADD_FIELD(group.fields, dos, e_ip);
        ADD_FIELD(group.fields, dos, e_cs);
        ADD_FIELD(group.fields, dos, e_lfarlc);
        ADD_FIELD(group.fields, dos, e_ovno);
        ADD_FIELD(group.fields, dos, e_oemid);
        ADD_FIELD(group.fields, dos, e_oeminfo);
        AddField(group.fields, "e_lfanew", static_cast<uint32_t>(dos.e_lfanew));
        return group;
    }

    HeaderGroup ParseFileHeader(const IMAGE_FILE_HEADER& header)
    {
        HeaderGroup group{ "FILE HEADER", {} };
        ADD_FIELD(group.fields, header, Machine);
        ADD_FIELD(group.fields, header, NumberOfSections);
        ADD_FIELD(group.fields, header, TimeDateStamp);
        ADD_FIELD(group.fields, header, PointerToSymbolTable);
        ADD_FIELD(group.fields, header, NumberOfSymbols);
        ADD_FIELD(group.fields, header, SizeOfOptionalHeader);
        AddField(group.fields, "Characteristics", header.Characteristics, GetImageCharacteristics(header.Characteristics));
        return group;
    }

    template <class T>
    HeaderGroup ParseOptionalHeader(const typename T::OptionalHeader& header)
    {
        HeaderGroup group{ "OPTIONAL HEADER", {} };
        ADD_FIELD(group.fields, header, Magic);
        ADD_FIELD(group.fields, header, MajorLinkerVersion);
        ADD_FIELD(group.fields, header, MinorLinkerVersion);
        ADD_FIELD(group.fields, header, SizeOfCode);
        ADD_FIELD(group.fields, header, SizeOfInitializedData);
        ADD_FIELD(group.fields, header, SizeOfUninitializedData);
        ADD_FIELD(group.fields, header, AddressOfEntryPoint);
        ADD_FIELD(group.fields, header, BaseOfCode);
        if constexpr (!T::Is64)
            ADD_FIELD(group.fields, header, BaseOfData);
        ADD_FIELD(group.fields, header, ImageBase);
        ADD_FIELD(group.fields, header, SectionAlignment);
        ADD_FIELD(group.fields, header, FileAlignment);
        ADD_FIELD(group.fields, header, MajorOperatingSystemVersion);
        ADD_FIELD(group.fields, header, MinorOperatingSystemVersion);
        ADD_FIELD(group.fields, header, MajorImageVersion);
        ADD_FIELD(group.fields, header, MinorImageVersion);
        ADD_FIELD(group.fields, header, MajorSubsystemVersion);
        ADD_FIELD(group.fields, header, MinorSubsystemVersion);
        ADD_FIELD(group.fields, header, Win32VersionValue);
        ADD_FIELD(group.fields, header, SizeOfImage);
        ADD_FIELD(group.fields, header, SizeOfHeaders);
        ADD_FIELD(group.fields, header, CheckSum);
        AddField(group.fields, "Subsystem", header.Subsystem, GetSubsystemName(header.Subsystem));
        ADD_FIELD(group.fields, header, DllCharacteristics);
        ADD_FIELD(group.fields, header, SizeOfStackReserve);
        ADD_FIELD(group.fields, header, SizeOfStackCommit);
        ADD_FIELD(group.fields, header, SizeOfHeapReserve);
        ADD_FIELD(group.fields, header, SizeOfHeapCommit);
        ADD_FIELD(group.fields, header, LoaderFlags);
        ADD_FIELD(group.fields, header, NumberOfRvaAndSizes);
        return group;
    }

    SectionInfo ParseSection(const IMAGE_SECTION_HEADER& header)
    {
        SectionInfo section;

        // The name is not null terminated when it uses the 8 characters.
        section.name.assign(reinterpret_cast<const char*>(header.Name), strnlen_s(reinterpret_cast<const char*>(header.Name), IMAGE_SIZEOF_SHORT_NAME));

        AddField(section.fields, "Misc (PhysicalAddress)", header.Misc.PhysicalAddress);
        AddField(section.fields, "Misc (VirtualSize)", header.Misc.VirtualSize);
        ADD_FIELD(section.fields, header, VirtualAddress);
        ADD_FIELD(section.fields, header, SizeOfRawData);
        ADD_FIELD(section.fields, header, PointerToRawData);
        ADD_FIELD(section.fields, header, PointerToRelocations);
        ADD_FIELD(section.fields, header, PointerToLinenumbers);
        ADD_FIELD(section.fields, header, NumberOfRelocations);
        ADD_FIELD(section.fields, header, NumberOfLinenumbers);
        AddField(section.fields, "Characteristics", header.Characteristics, GetSectionProtection(header.Characteristics));
        return section;
    }

    template <class T>
    bool ParseImage(PeImage& image, const size_t ntOffset, const IMAGE_DOS_HEADER& dos, PeInfo& info, std::string& error)
    {
        typename T::NtHeaders nt = {};
        if (!image.Read(ntOffset, nt))
        {
            error = "the NT headers are truncated";
            return false;
        }

        const typename T::OptionalHeader& optional = nt.OptionalHeader;

        const size_t sectionsOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
        std::vector<IMAGE_SECTION_HEADER> sections;
        if (!image.ReadArray(sectionsOffset, nt.FileHeader.NumberOfSections, sections))
        {
            error = "the section headers are truncated";
            return false;
        }

        image.SetLayout(sections, optional.SizeOfHeaders);

        info.is64 = T::Is64;

        info.headers.push_back(ParseDosHeader(dos));

        HeaderGroup ntGroup{ "NT HEADER", {} };
        ADD_FIELD(ntGroup.fields, nt, Signature);
        info.headers.push_back(std::move(ntGroup));

        info.headers.push_back(ParseFileHeader(nt.FileHeader));
        info.headers.push_back(ParseOptionalHeader<T>(optional));

        const DWORD dDirectoryCount = std::min<DWORD>(optional.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (DWORD i = 0; i < dDirectoryCount; ++i)
        {
            const IMAGE_DATA_DIRECTORY& directory = optional.DataDirectory[i];
            if (directory.VirtualAddress != 0)
                info.dataDirectories.push_back({ GetDataDirectoryName(static_cast<int>(i)), directory.VirtualAddress, directory.Size });
        }

        for (const IMAGE_SECTION_HEADER& section : sections)
            info.sections.push_back(ParseSection(section));

        if (dDirectoryCount > IMAGE_DIRECTORY_ENTRY_IMPORT && optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
        {
            info.hasImports = true;
            if (!ParseImports(image, T::Is64, optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, info.imports, error))
                return false;
        }

        if (dDirectoryCount > IMAGE_DIRECTORY_ENTRY_EXPORT && optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
        {
            info.hasExports = true;
            const IMAGE_DATA_DIRECTORY& directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!ParseExports(image, directory.VirtualAddress, directory.Size, info.exports, error))
                return false;
        }

        return true;
    }

#undef ADD_FIELD
}

bool ParsePe(PeImage& image, PeInfo& info, std::string& error)
{
    IMAGE_DOS_HEADER dos = {};
    if (!image.Read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        error = "invalid DOS header, this is not a PE file";
        return false;
    }

    if (dos.e_lfanew < 0)
    {
        error = "invalid NT headers offset";
        return false;
    }

    const size_t ntOffset = static_cast<size_t>(dos.e_lfanew);

    DWORD dSignature = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    WORD wMagic = 0;
    if (!image.Read(ntOffset, dSignature) || dSignature != IMAGE_NT_SIGNATURE ||
        !image.Read(ntOffset + sizeof(DWORD), fileHeader) ||
        !image.Read(ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), wMagic))
    {
        error = "invalid NT headers, this is not a PE file";
        return false;
    }

    // Identify x86 and x64 PE files.
    switch (wMagic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        return ParseImage<Pe32>(image, ntOffset, dos, info, error);

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return ParseImage<Pe64>(image, ntOffset, dos, info, error);

    default:
        error = "unsupported optional header (neither x86 nor x64)";
        return false;
    }
}
