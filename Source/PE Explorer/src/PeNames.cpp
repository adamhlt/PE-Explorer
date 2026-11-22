#include "PeNames.h"
#include <iterator>

const char* GetImageCharacteristics(const DWORD dCharacteristics)
{
    if (dCharacteristics & IMAGE_FILE_DLL)
        return "(DLL)";

    if (dCharacteristics & IMAGE_FILE_SYSTEM)
        return "(DRIVER)";

    if (dCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        return "(EXE)";

    return "(UNKNOWN)";
}

const char* GetSubsystemName(const WORD subsystem)
{
    switch (subsystem)
    {
    case IMAGE_SUBSYSTEM_NATIVE:
        return "(NATIVE / DRIVER)";

    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return "(GUI APP)";

    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return "(CONSOLE APP)";

    case IMAGE_SUBSYSTEM_OS2_CUI:
        return "(OS/2 CONSOLE APP)";

    case IMAGE_SUBSYSTEM_POSIX_CUI:
        return "(POSIX CONSOLE APP)";

    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        return "(WINDOWS CE GUI APP)";

    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        return "(EFI APPLICATION)";

    default:
        return "(UNKNOWN)";
    }
}

const char* GetDataDirectoryName(const int directoryNumber)
{
    static const char* const Names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] =
    {
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Entry",
        "Security Entry",
        "Relocation Table",
        "Debug Entry",
        "Copyright Entry",
        "Global PTR Entry",
        "TLS Entry",
        "Configuration Entry",
        "Bound Import Entry",
        "IAT",
        "Delay Import Descriptor",
        "COM Descriptor",
        "Reserved"
    };

    if (directoryNumber < 0 || directoryNumber >= static_cast<int>(std::size(Names)))
        return "Unknown";

    return Names[directoryNumber];
}

std::string GetSectionProtection(const DWORD dCharacteristics)
{
    std::string protection;

    const auto append = [&protection](const char* lpName)
    {
        if (!protection.empty())
            protection += " | ";
        protection += lpName;
    };

    if (dCharacteristics & IMAGE_SCN_MEM_EXECUTE)
        append("EXECUTE");

    if (dCharacteristics & IMAGE_SCN_MEM_READ)
        append("READ");

    if (dCharacteristics & IMAGE_SCN_MEM_WRITE)
        append("WRITE");

    return "(" + protection + ")";
}
