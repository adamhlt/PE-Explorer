#include "FileLoader.h"
#include "Common.h"

namespace
{
    constexpr LONGLONG MaxFileSize = 1024LL * 1024 * 1024; // 1 GiB

    struct HandleCloser
    {
        HANDLE hHandle;
        ~HandleCloser() { CloseHandle(hHandle); }
    };
}

bool LoadFile(const char* lpFilePath, std::vector<uint8_t>& content, std::string& error)
{
    const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        error = "unable to open the PE file (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    const HandleCloser closer{ hFile };

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        error = "unable to get the PE file size (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    if (fileSize.QuadPart > MaxFileSize)
    {
        error = "the file is too large to be a PE file";
        return false;
    }

    content.resize(static_cast<size_t>(fileSize.QuadPart));

    DWORD dBytesRead = 0;
    if (!ReadFile(hFile, content.data(), static_cast<DWORD>(content.size()), &dBytesRead, nullptr) || dBytesRead != content.size())
    {
        error = "unable to read the PE file content (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    return true;
}
