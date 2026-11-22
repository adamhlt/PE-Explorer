#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * Load the whole content of a file in memory.
 * \param lpFilePath : path of the file.
 * \param content : receives the file content.
 * \param error : receives a description of the failure.
 * \return : true if the file has been loaded.
 */
bool LoadFile(const char* lpFilePath, std::vector<uint8_t>& content, std::string& error);
