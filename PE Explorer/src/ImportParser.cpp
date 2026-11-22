#include "ImportParser.h"
#include "PeTraits.h"

namespace
{
    constexpr size_t MaxImportedDlls = 4096;
    constexpr size_t MaxImportedFunctions = 65536;

    void AddField(std::vector<Field>& fields, const char* lpName, const uint64_t value)
    {
        fields.push_back({ lpName, value, {} });
    }

    template <class T>
    bool ParseFunctions(const PeImage& image, const DWORD dThunkRva, std::vector<ImportedFunction>& functions)
    {
        size_t offset = 0;
        if (!image.RvaToOffset(dThunkRva, offset))
            return false;

        for (size_t i = 0; i < MaxImportedFunctions; ++i, offset += sizeof(typename T::ThunkData))
        {
            typename T::ThunkData thunk = {};
            if (!image.Read(offset, thunk))
                return false;

            const uint64_t value = thunk.u1.Ordinal;
            if (value == 0)
                return true;

            ImportedFunction function;
            if (value & T::OrdinalFlag)
            {
                function.byOrdinal = true;
                function.ordinal = static_cast<WORD>(value & 0xFFFF);
            }
            else
            {
                // IMAGE_IMPORT_BY_NAME : WORD Hint followed by the null terminated name.
                size_t nameOffset = 0;
                if (!image.RvaToOffset(static_cast<DWORD>(value), nameOffset) ||
                    !image.Read(nameOffset, function.hint) ||
                    !image.ReadString(nameOffset + sizeof(WORD), function.name))
                    function.name = "<invalid>";
            }

            functions.push_back(std::move(function));
        }

        return true;
    }

    template <class T>
    bool ParseImportsImpl(const PeImage& image, const DWORD dRva, std::vector<ImportedDll>& imports, std::string& error)
    {
        size_t offset = 0;
        if (!image.RvaToOffset(dRva, offset))
        {
            error = "the import table is not located inside the file";
            return false;
        }

        for (size_t i = 0; i < MaxImportedDlls; ++i, offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor = {};
            if (!image.Read(offset, descriptor))
            {
                error = "the import table is truncated";
                return false;
            }

            if (descriptor.Name == 0)
                return true;

            ImportedDll dll;

            size_t nameOffset = 0;
            if (!image.RvaToOffset(descriptor.Name, nameOffset) || !image.ReadString(nameOffset, dll.name))
                dll.name = "<invalid>";

            AddField(dll.fields, "OriginalFirstThunk", descriptor.OriginalFirstThunk);
            AddField(dll.fields, "TimeDateStamp", descriptor.TimeDateStamp);
            AddField(dll.fields, "ForwarderChain", descriptor.ForwarderChain);
            AddField(dll.fields, "Name", descriptor.Name);
            AddField(dll.fields, "FirstThunk", descriptor.FirstThunk);

            // Without OriginalFirstThunk (unbound import), FirstThunk holds the same information.
            const DWORD dThunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
            const bool bParsed = dThunkRva == 0 || ParseFunctions<T>(image, dThunkRva, dll.functions);

            imports.push_back(std::move(dll));

            if (!bParsed)
            {
                error = "the imported functions of a DLL are truncated or invalid";
                return false;
            }
        }

        return true;
    }
}

bool ParseImports(const PeImage& image, const bool is64, const DWORD dRva, std::vector<ImportedDll>& imports, std::string& error)
{
    return is64 ? ParseImportsImpl<Pe64>(image, dRva, imports, error) : ParseImportsImpl<Pe32>(image, dRva, imports, error);
}
