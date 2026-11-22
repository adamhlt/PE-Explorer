#pragma once

#include "PeImage.h"
#include "PeInfo.h"
#include <string>
#include <vector>

/**
 * Parse the exported functions.
 * \param image : the PE file (layout must be set).
 * \param dRva : address of the export table found into DataDirectory 0.
 * \param dSize : size of the export table, used to detect forwarded exports.
 * \param exports : receives the exported functions.
 * \param error : receives a description of the failure.
 * \return : true if the parsing is successful.
 */
bool ParseExports(const PeImage& image, DWORD dRva, DWORD dSize, std::vector<ExportedFunction>& exports, std::string& error);
