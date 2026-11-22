#pragma once

#include "Common.h"
#include <string>

/**
 * Identify the PE file characteristics.
 * \param dCharacteristics : characteristics in the file header.
 * \return : the description of the PE file characteristics.
 */
const char* GetImageCharacteristics(DWORD dCharacteristics);

/**
 * Identify the PE file subsystem.
 * \param subsystem : subsystem in the optional header.
 * \return : the description of the PE file subsystem.
 */
const char* GetSubsystemName(WORD subsystem);

/**
 * Identify the DataDirectory.
 * \param directoryNumber : index of the DataDirectory.
 * \return : the description of the DataDirectory.
 */
const char* GetDataDirectoryName(int directoryNumber);

/**
 * Describe the protection of a section.
 * \param dCharacteristics : characteristics of the section.
 * \return : the description of the protection, e.g. "(EXECUTE | READ)".
 */
std::string GetSectionProtection(DWORD dCharacteristics);
