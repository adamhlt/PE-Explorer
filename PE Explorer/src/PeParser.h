#pragma once

#include "PeImage.h"
#include "PeInfo.h"
#include <string>

/**
 * Parse a PE file (x86 or x64).
 * \param image : the PE file content.
 * \param info : receives the result. It can be partially filled when the parsing fails.
 * \param error : receives a description of the failure.
 * \return : true if the parsing is successful.
 */
bool ParsePe(PeImage& image, PeInfo& info, std::string& error);
