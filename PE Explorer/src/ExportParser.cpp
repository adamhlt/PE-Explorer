#include "ExportParser.h"
#include <algorithm>

bool ParseExports(const PeImage& image, const DWORD dRva, const DWORD dSize, std::vector<ExportedFunction>& exports, std::string& error)
{
    size_t offset = 0;
    IMAGE_EXPORT_DIRECTORY directory = {};
    if (!image.RvaToOffset(dRva, offset) || !image.Read(offset, directory))
    {
        error = "the export directory is not located inside the file";
        return false;
    }

    std::vector<DWORD> functions;
    std::vector<DWORD> names;
    std::vector<WORD> nameOrdinals;

    size_t functionsOffset = 0, namesOffset = 0, ordinalsOffset = 0;
    if (!image.RvaToOffset(directory.AddressOfFunctions, functionsOffset) || !image.ReadArray(functionsOffset, directory.NumberOfFunctions, functions) ||
        !image.RvaToOffset(directory.AddressOfNames, namesOffset) || !image.ReadArray(namesOffset, directory.NumberOfNames, names) ||
        !image.RvaToOffset(directory.AddressOfNameOrdinals, ordinalsOffset) || !image.ReadArray(ordinalsOffset, directory.NumberOfNames, nameOrdinals))
    {
        // Some DLL have no name table at all, only retry without the names.
        names.clear();
        nameOrdinals.clear();

        if (!image.RvaToOffset(directory.AddressOfFunctions, functionsOffset) || !image.ReadArray(functionsOffset, directory.NumberOfFunctions, functions))
        {
            error = "the export tables are truncated or invalid";
            return false;
        }
    }

    exports.resize(functions.size());
    for (size_t i = 0; i < functions.size(); ++i)
    {
        ExportedFunction& function = exports[i];
        function.ordinal = directory.Base + static_cast<DWORD>(i);
        function.rva = functions[i];

        // The export is forwarded when its address points inside the export directory.
        if (function.rva >= dRva && function.rva - dRva < dSize)
        {
            size_t forwarderOffset = 0;
            if (image.RvaToOffset(function.rva, forwarderOffset))
                image.ReadString(forwarderOffset, function.forwarder);
        }
    }

    for (size_t i = 0; i < names.size(); ++i)
    {
        const size_t index = nameOrdinals[i];
        size_t nameOffset = 0;
        if (index >= exports.size() || !image.RvaToOffset(names[i], nameOffset) || !image.ReadString(nameOffset, exports[index].name))
            continue;

        exports[index].hasName = true;
    }

    // Unused slots in the table have a null address.
    exports.erase(std::remove_if(exports.begin(), exports.end(), [](const ExportedFunction& function) { return function.rva == 0; }), exports.end());
    return true;
}
