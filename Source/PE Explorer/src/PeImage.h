#pragma once

#include "Common.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

/**
 * Raw content of a PE file with bounds-checked accessors.
 * Every read is validated against the file size, so a malformed PE file can never make the parser read outside of the buffer.
 */
class PeImage
{
public:
    explicit PeImage(std::vector<uint8_t> buffer) : m_Buffer(std::move(buffer)) {}

    size_t Size() const { return m_Buffer.size(); }

    /**
     * Copy a structure from the file.
     * \param offset : file offset of the structure.
     * \param out : receives the structure.
     * \return : false if the structure is not entirely inside the file.
     */
    template <class T>
    bool Read(const size_t offset, T& out) const
    {
        if (offset > m_Buffer.size() || sizeof(T) > m_Buffer.size() - offset)
            return false;

        std::memcpy(&out, m_Buffer.data() + offset, sizeof(T));
        return true;
    }

    /**
     * Copy an array of structures from the file.
     * \param offset : file offset of the first element.
     * \param count : number of elements.
     * \param out : receives the elements.
     * \return : false if the array is not entirely inside the file.
     */
    template <class T>
    bool ReadArray(const size_t offset, const size_t count, std::vector<T>& out) const
    {
        if (offset > m_Buffer.size() || count > (m_Buffer.size() - offset) / sizeof(T))
            return false;

        out.resize(count);
        if (count != 0)
            std::memcpy(out.data(), m_Buffer.data() + offset, count * sizeof(T));

        return true;
    }

    /**
     * Read a null terminated string from the file.
     * \return : false if there is no terminator before the end of the file.
     */
    bool ReadString(size_t offset, std::string& out, size_t maxLength = 4096) const;

    /**
     * Store the headers layout, required to convert RVA to file offsets.
     */
    void SetLayout(std::vector<IMAGE_SECTION_HEADER> sections, DWORD dSizeOfHeaders);

    /**
     * Convert a relative virtual address into a file offset.
     * \return : false if the RVA is not backed by data in the file.
     */
    bool RvaToOffset(DWORD dRva, size_t& offset) const;

private:
    std::vector<uint8_t> m_Buffer;
    std::vector<IMAGE_SECTION_HEADER> m_Sections;
    DWORD m_SizeOfHeaders = 0;
};
