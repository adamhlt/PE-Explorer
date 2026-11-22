#pragma once

#include "Common.h"
#include <cstdint>

/**
 * Types that differ between x86 (PE32) and x64 (PE32+) images.
 * The parsers are templates over these traits, so the logic is written only once.
 */

struct Pe32
{
    using NtHeaders = IMAGE_NT_HEADERS32;
    using OptionalHeader = IMAGE_OPTIONAL_HEADER32;
    using ThunkData = IMAGE_THUNK_DATA32;

    static constexpr bool Is64 = false;
    static constexpr uint64_t OrdinalFlag = IMAGE_ORDINAL_FLAG32;
};

struct Pe64
{
    using NtHeaders = IMAGE_NT_HEADERS64;
    using OptionalHeader = IMAGE_OPTIONAL_HEADER64;
    using ThunkData = IMAGE_THUNK_DATA64;

    static constexpr bool Is64 = true;
    static constexpr uint64_t OrdinalFlag = IMAGE_ORDINAL_FLAG64;
};
