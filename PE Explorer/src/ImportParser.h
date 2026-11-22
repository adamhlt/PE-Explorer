#pragma once

#include "PeImage.h"
#include "PeInfo.h"
#include <string>
#include <vector>

/**
 * Parse the imported DLL and functions.
 * \param image : the PE file (layout must be set).
 * \param is64 : true for a x64 PE file.
 * \param dRva : address of the import table found into DataDirectory 1.
 * \param imports : receives the imported DLL.
 * \param error : receives a description of the failure.
 * \return : true if the parsing is successful.
 */
bool ParseImports(const PeImage& image, bool is64, DWORD dRva, std::vector<ImportedDll>& imports, std::string& error);
