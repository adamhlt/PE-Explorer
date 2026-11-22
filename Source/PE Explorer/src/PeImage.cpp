#include "PeImage.h"
#include <algorithm>

bool PeImage::ReadString(const size_t offset, std::string& out, const size_t maxLength) const
{
    if (offset >= m_Buffer.size())
        return false;

    const size_t available = std::min(maxLength, m_Buffer.size() - offset);
    const char* lpStart = reinterpret_cast<const char*>(m_Buffer.data() + offset);
    const void* lpEnd = std::memchr(lpStart, '\0', available);
    if (lpEnd == nullptr)
        return false;

    out.assign(lpStart, static_cast<const char*>(lpEnd));
    return true;
}

void PeImage::SetLayout(std::vector<IMAGE_SECTION_HEADER> sections, const DWORD dSizeOfHeaders)
{
    m_Sections = std::move(sections);
    m_SizeOfHeaders = dSizeOfHeaders;
}

bool PeImage::RvaToOffset(const DWORD dRva, size_t& offset) const
{
    if (dRva < m_SizeOfHeaders)
    {
        offset = dRva;
        return true;
    }

    for (const IMAGE_SECTION_HEADER& section : m_Sections)
    {
        const DWORD dSpan = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (dRva < section.VirtualAddress || dRva - section.VirtualAddress >= dSpan)
            continue;

        const DWORD dDelta = dRva - section.VirtualAddress;
        if (dDelta >= section.SizeOfRawData)
            return false; // Virtual only (e.g. .bss), nothing in the file.

        offset = static_cast<size_t>(section.PointerToRawData) + dDelta;
        return true;
    }

    return false;
}
