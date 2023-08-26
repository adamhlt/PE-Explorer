#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <strsafe.h>

/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
HANDLE GetFileContent(const char* lpFilePath)
{
    const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to open the PE file !");
        CloseHandle(hFile);
        return nullptr;
    }

    const DWORD_PTR dFileSize = GetFileSize(hFile, nullptr);
    if (dFileSize == INVALID_FILE_SIZE)
    {
        printf("[-] An error occured when trying to get the PE file size !");
        CloseHandle(hFile);
        return nullptr;
    }

    const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
    if (hFileContent == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to allocate memory for the PE file content !");
        CloseHandle(hFile);
        CloseHandle(hFileContent);
        return nullptr;
    }

    const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
    if (!bFileRead)
    {
        printf("[-] An error occured when trying to read the PE file content !");
        CloseHandle(hFile);
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);

        return nullptr;
    }

    CloseHandle(hFile);
    return hFileContent;
}

/**
 * Function to identify the PE file characteristics.
 * \param dCharacteristics : characteristics in the file header section.
 * \return : the description of the PE file characteristics.
 */
const char* GetImageCharacteristics(const DWORD_PTR dCharacteristics)
{
    if (dCharacteristics & IMAGE_FILE_DLL)
        return "(DLL)";

    if (dCharacteristics & IMAGE_FILE_SYSTEM)
        return "(DRIVER)";

    if (dCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        return "(EXE)";

    return "(UNKNOWN)";
}

/**
 * Function to identify the PE file subsystem.
 * \param Subsystem : subsystem in the optional header.
 * \return : the description of the PE file subsystem.
 */
const char* GetSubsytem(const WORD Subsystem)
{
    if (Subsystem == 1)
        return "(NATIVE / DRIVER)";

    if (Subsystem == 2)
        return "(GUI APP)";

    if (Subsystem == 3)
        return "(CONSOLE APP)";

    return "(UNKNOWN)";
}

/**
 * Function to identify the DataDirectory.
 * \param DirectoryNumber : index of the DataDirectory.
 * \return : the description of the DataDirectory.
 */
const char* GetDataDirectoryName(const int DirectoryNumber)
{
    switch (DirectoryNumber)
    {
    case 0 :
        return "Export Table";

    case 1 :
        return "Import Table";

    case 2 :
        return "Ressource Table";

    case 3 :
        return "Exception Entry";

    case 4 :
        return "Security Entry";

    case 5 :
        return "Relocation Table";

    case 6 :
        return "Debug Entry";

    case 7 :
        return "Copyright Entry";

    case 8 :
        return "Global PTR Entry";

    case 9 :
        return "TLS Entry";

    case 10 :
        return "Configuration Entry";

    case 11 :
        return "Bound Import Entry";

    case 12 :
        return "IAT";

    case 13 :
        return "Delay Import Descriptor";

    case 14 :
        return "COM Descriptor";

    default :
        return nullptr;
    }
}

/**
 * Retrieve and display the DataDirectory informations. 
 * \param pImageDataDirectory : DataDirectory array of the optional header.
 */
void GetDataDirectories(PIMAGE_DATA_DIRECTORY pImageDataDirectory)
{
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i, ++pImageDataDirectory)
    {
        if (pImageDataDirectory->VirtualAddress == 0)
            continue;

        printf("\tDataDirectory (%s) VirtualAddress : 0x%X\n", GetDataDirectoryName(i), (uintptr_t)pImageDataDirectory->VirtualAddress);
        printf("\tDataDirectory (%s) Size : 0x%X\n\n", GetDataDirectoryName(i), (uintptr_t)pImageDataDirectory->Size);
    }
}

/**
 * Retrieve and display the protection of the section.
 * \param dCharacteristics : characteristics of the section.
 * \return : the description of the protection.
 */
const char* GetSectionProtection(DWORD_PTR dCharacteristics)
{
    char lpSectionProtection[1024] = {};
    StringCchCatA(lpSectionProtection, 1024, "(");
    bool bExecute = false, bRead = false;

    if (dCharacteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        bExecute = true;
        StringCchCatA(lpSectionProtection, 1024, "EXECUTE");
    }

    if (dCharacteristics & IMAGE_SCN_MEM_READ)
    {
        bRead = true;
        if (bExecute)
            StringCchCatA(lpSectionProtection, 1024, " | ");
        StringCchCatA(lpSectionProtection, 1024, "READ");
    }

    if (dCharacteristics & IMAGE_SCN_MEM_WRITE)
    {
        if (bExecute || bRead)
            StringCchCatA(lpSectionProtection, 1024, " | ");
        StringCchCatA(lpSectionProtection, 1024, "WRITE");
    }

    StringCchCatA(lpSectionProtection, 1024, ")");
    return lpSectionProtection;
}

/**
 * Function to retrieve sections from the PE file and get the section wich contains imports.
 * \param pImageSectionHeader : section header of the PE file.
 * \param NumberOfSections : number of section in the PE file.
 * \param dImportAddress : address of import found into DataDirectory 1.
 * \return : section which contains imports.
 */
PIMAGE_SECTION_HEADER GetSections(const PIMAGE_SECTION_HEADER pImageSectionHeader, const int NumberOfSections, const DWORD_PTR dImportAddress)
{
    PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;

    printf("\n[+] PE IMAGE SECTIONS\n");

    for (int i = 0; i < NumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));
        printf("\n\tSECTION : %s\n", (char*)pCurrentSectionHeader->Name);
        printf("\t\tMisc (PhysicalAddress) : 0x%X\n", (uintptr_t)pCurrentSectionHeader->Misc.PhysicalAddress);
        printf("\t\tMisc (VirtualSize) : 0x%X\n", (uintptr_t)pCurrentSectionHeader->Misc.VirtualSize);
        printf("\t\tVirtualAddress : 0x%X\n", (uintptr_t)pCurrentSectionHeader->VirtualAddress);
        printf("\t\tSizeOfRawData : 0x%X\n", (uintptr_t)pCurrentSectionHeader->SizeOfRawData);
        printf("\t\tPointerToRawData : 0x%X\n", (uintptr_t)pCurrentSectionHeader->PointerToRawData);
        printf("\t\tPointerToRelocations : 0x%X\n", (uintptr_t)pCurrentSectionHeader->PointerToRelocations);
        printf("\t\tPointerToLinenumbers : 0x%X\n", (uintptr_t)pCurrentSectionHeader->PointerToLinenumbers);
        printf("\t\tNumberOfRelocations : 0x%X\n", (uintptr_t)pCurrentSectionHeader->NumberOfRelocations);
        printf("\t\tNumberOfLinenumbers : 0x%X\n", (uintptr_t)pCurrentSectionHeader->NumberOfLinenumbers);
        printf("\t\tCharacteristics : 0x%X %s\n", (uintptr_t)pCurrentSectionHeader->Characteristics, GetSectionProtection(pCurrentSectionHeader->Characteristics));

        if (dImportAddress >= pCurrentSectionHeader->VirtualAddress && dImportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
            pImageImportHeader = pCurrentSectionHeader;
    }

    return pImageImportHeader;
}

/**
 * Retrieve and display dll and functions imported (for x86 PE file).
 * \param pImageImportDescriptor : import descriptor of the PE file.
 * \param dRawOffset : address of raw data of the import section.
 * \param pImageImportSection : section wich contains imports.
 */
void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, const DWORD_PTR dRawOffset, const PIMAGE_SECTION_HEADER pImageImportSection)
{
    printf("\n[+] IMPORTED DLL\n");

    while (pImageImportDescriptor->Name != 0)
    {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress)));
        printf("\tCharacteristics : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->Characteristics - pImageImportSection->VirtualAddress)));
        printf("\tOriginalFirstThunk : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress)));
        printf("\tTimeDateStamp : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->TimeDateStamp - pImageImportSection->VirtualAddress)));
        printf("\tForwarderChain : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->ForwarderChain - pImageImportSection->VirtualAddress)));
        printf("\tFirstThunk : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->FirstThunk - pImageImportSection->VirtualAddress)));

        if (pImageImportDescriptor->OriginalFirstThunk == 0)
            continue;

        auto pOriginalFirstThrunk = (PIMAGE_THUNK_DATA32)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

        printf("\n\tImported Functions : \n\n");

        while (pOriginalFirstThrunk->u1.AddressOfData != 0)
        {
            if (pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32)
            {
                ++pOriginalFirstThrunk;
                continue;
            }

            const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThrunk->u1.AddressOfData;
            if (pImageImportByName == nullptr)
             continue;

            if (pOriginalFirstThrunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                printf("\t\t0x%X (Ordinal) : %s\n", (uintptr_t)pOriginalFirstThrunk->u1.AddressOfData, dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress));
            else
                printf("\t\t%s\n", dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress));

            ++pOriginalFirstThrunk;
        }

        ++pImageImportDescriptor;
    }
}

/**
 * Retrieve and display dll and functions imported (for x64 PE file).
 * \param pImageImportDescriptor : import descriptor of the PE file.
 * \param dRawOffset : address of raw data of the import section.
 * \param pImageImportSection : section wich contains imports.
 */
void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor, const DWORD_PTR dRawOffset, const PIMAGE_SECTION_HEADER pImageImportSection)
{
    printf("\n[+] IMPORTED DLL\n");

    while (pImageImportDescriptor->Name != 0)
    {
        printf("\n\tDLL NAME : %s\n", (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress)));
        printf("\tCharacteristics : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->Characteristics - pImageImportSection->VirtualAddress)));
        printf("\tOriginalFirstThunk : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress)));
        printf("\tTimeDateStamp : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->TimeDateStamp - pImageImportSection->VirtualAddress)));
        printf("\tForwarderChain : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->ForwarderChain - pImageImportSection->VirtualAddress)));
        printf("\tFirstThunk : 0x%X\n", (uintptr_t)(dRawOffset + (pImageImportDescriptor->FirstThunk - pImageImportSection->VirtualAddress)));

        if (pImageImportDescriptor->OriginalFirstThunk == 0)
            continue;

        auto pOriginalFirstThrunk = (PIMAGE_THUNK_DATA64)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

        printf("\n\tImported Functions : \n\n");

        while (pOriginalFirstThrunk->u1.AddressOfData != 0)
        {
            if (pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64)
            {
                ++pOriginalFirstThrunk;
                continue;
            }

            const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThrunk->u1.AddressOfData;
            if (pImageImportByName == nullptr)
                continue;

            if (pOriginalFirstThrunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                printf("\t\t0x%X (Ordinal) : %s\n", (uintptr_t)pOriginalFirstThrunk->u1.AddressOfData, dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress));
            else
                printf("\t\t%s\n", dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress));

            ++pOriginalFirstThrunk;
        }

        ++pImageImportDescriptor;
    }
}

/**
 * Retrieve the section wich contains exports.
 * \param pImageSectionHeader : section header of the Pe file.
 * \param NumberOfSections : number of sections.
 * \param dExportAddress : export address get from the DataDirectory 0.
 * \return : the section wich conatins exports.
 */
PIMAGE_SECTION_HEADER GetExportSection(const PIMAGE_SECTION_HEADER pImageSectionHeader, const int NumberOfSections, const DWORD_PTR dExportAddress)
{
    PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;

    for (int i = 0; i < NumberOfSections; ++i)
    {
        const auto pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

        if (dExportAddress >= pCurrentSectionHeader->VirtualAddress && dExportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
            pImageImportHeader = pCurrentSectionHeader;
    }

    return pImageImportHeader;
}

/**
 * Retrieve and display exported functions.
 * \param pImageExportDirectory : export directory wich contains every informations on exported functions.
 * \param dRawOffset : address of raw data of the section wich contains exports.
 * \param pImageExportSection : section wich contains exports.
 */
void GetExports(const PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, const DWORD_PTR dRawOffset, const PIMAGE_SECTION_HEADER pImageExportSection)
{
    printf("\n[+] EXPORTED FUNCTIONS\n\n");

    const DWORD_PTR dNumberOfNames = pImageExportDirectory->NumberOfNames;
    const auto pArrayOfFunctionsNames = (DWORD_PTR*)(dRawOffset + (pImageExportDirectory->AddressOfNames - pImageExportSection->VirtualAddress));
    for (int i = 0; i < (int) dNumberOfNames; ++i)
        printf("\t%s\n", (char*)dRawOffset + (pArrayOfFunctionsNames[i] - pImageExportSection->VirtualAddress)); 
}

/**
 * Function wich parse x86 PE file.
 * \param pImageDOSHeader : pointer of the DOS header of the PE file. 
 * \return : 0 if the parsing is succeful else -1.
 */
int ParseImage32(const PIMAGE_DOS_HEADER pImageDOSHeader)
{
    const auto pImageNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
    if (pImageNTHeader32 == nullptr)
        return -1;

    const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader32->FileHeader;
    const IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader32 = pImageNTHeader32->OptionalHeader;

    const auto pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
    if (pImageSectionHeader == nullptr)
        return -1;

    printf("[+] PE IMAGE INFORMATION \n");
    printf("\n[+] Architecture x86 \n");

    printf("\n[+] DOS HEADER \n");
    printf("\te_magic : 0x%X\n", (uintptr_t)pImageDOSHeader->e_magic);
    printf("\te_cblp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cblp);
    printf("\te_cp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cp);
    printf("\te_crlc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_crlc);
    printf("\te_cparhdr : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cparhdr);
    printf("\te_minalloc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_minalloc);
    printf("\te_maxalloc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_maxalloc);
    printf("\te_ss : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ss);
    printf("\te_sp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_sp);
    printf("\te_csum : 0x%X\n", (uintptr_t)pImageDOSHeader->e_csum);
    printf("\te_ip : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ip);
    printf("\te_cs : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cs);
    printf("\te_lfarlc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_lfarlc);
    printf("\te_ovno : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ovno);
    printf("\te_oemid : 0x%X\n", (uintptr_t)pImageDOSHeader->e_oemid);
    printf("\te_oeminfo : 0x%X\n", (uintptr_t)pImageDOSHeader->e_oeminfo);
    printf("\te_lfanew : 0x%X\n", (uintptr_t)pImageDOSHeader->e_lfanew);

    printf("\n[+] NT HEADER\n");
    printf("\tSignature : 0x%X\n", (uintptr_t)pImageNTHeader32->Signature);

    printf("\n[+] FILE HEADER\n");
    printf("\tMachine : 0x%X\n", (uintptr_t)ImageFileHeader.Machine);
    printf("\tNumberOfSections : 0x%X\n", (uintptr_t)ImageFileHeader.NumberOfSections);
    printf("\tTimeDateStamp  : 0x%X\n", (uintptr_t)ImageFileHeader.TimeDateStamp);
    printf("\tPointerToSymbolTable   : 0x%X\n", (uintptr_t)ImageFileHeader.PointerToSymbolTable);
    printf("\tNumberOfSymbols   : 0x%X\n", (uintptr_t)ImageFileHeader.NumberOfSymbols);
    printf("\tSizeOfOptionalHeader   : 0x%X\n", (uintptr_t)ImageFileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics  : 0x%X %s\n", (uintptr_t)ImageFileHeader.Characteristics, GetImageCharacteristics(ImageFileHeader.Characteristics));

    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (uintptr_t)ImageOptionalHeader32.Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (uintptr_t)ImageOptionalHeader32.AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (uintptr_t)ImageOptionalHeader32.BaseOfCode);
    printf("\tBaseOfData : 0x%X\n", (uintptr_t)ImageOptionalHeader32.BaseOfData);
    printf("\tImageBase : 0x%X\n", (uintptr_t)ImageOptionalHeader32.ImageBase);
    printf("\tBSectionAlignment : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (uintptr_t)ImageOptionalHeader32.FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader32.MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (uintptr_t)ImageOptionalHeader32.Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (uintptr_t)ImageOptionalHeader32.CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (uintptr_t)ImageOptionalHeader32.Subsystem, GetSubsytem(ImageOptionalHeader32.Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (uintptr_t)ImageOptionalHeader32.DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (uintptr_t)ImageOptionalHeader32.SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (uintptr_t)ImageOptionalHeader32.LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (uintptr_t)ImageOptionalHeader32.NumberOfRvaAndSizes);
    printf("\tDataDirectory : 0x%X\n\n", (uintptr_t)ImageOptionalHeader32.DataDirectory);
    GetDataDirectories((PIMAGE_DATA_DIRECTORY)ImageOptionalHeader32.DataDirectory);

    const PIMAGE_SECTION_HEADER pImageImportSection = GetSections(pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader32.DataDirectory[1].VirtualAddress);
    if (pImageImportSection == nullptr)
    {
        printf("\n[-] An error when trying to retrieve PE imports !\n");
        return -1;
    }

    DWORD_PTR dRawOffset = (DWORD_PTR)pImageDOSHeader + pImageImportSection->PointerToRawData;
    const auto pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (ImageOptionalHeader32.DataDirectory[1].VirtualAddress - pImageImportSection->VirtualAddress));
    if (pImageImportDescriptor == nullptr)
    {
        printf("\n[-] An error occured when trying to retrieve PE imports descriptor !\n");
        return -1;
    }

    GetImports32(pImageImportDescriptor, dRawOffset, pImageImportSection);

    const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader32.DataDirectory[0].VirtualAddress);
    if (pImageExportSection != nullptr)
    {
        dRawOffset = (DWORD_PTR)pImageDOSHeader + pImageExportSection->PointerToRawData;
        const auto pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (ImageOptionalHeader32.DataDirectory[0].VirtualAddress - pImageExportSection->VirtualAddress));
        GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);
    }

    return 0;
}

/**
 * Function wich parse x64 PE file.
 * \param pImageDOSHeader : pointer of the DOS header of the PE file. 
 * \return : 0 if the parsing is succeful else -1.
 */
int ParseImage64(PIMAGE_DOS_HEADER pImageDOSHeader)
{
    const auto pImageNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
    if (pImageNTHeader64 == nullptr)
        return -1;

    const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader64->FileHeader;
    const IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64 = pImageNTHeader64->OptionalHeader;

    const auto pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
    if (pImageSectionHeader == nullptr)
        return -1;

    printf("[+] PE IMAGE INFORMATION \n");
    printf("\n[+] Architecture x64 \n");

    printf("\n[+] DOS HEADER \n");
    printf("\te_magic : 0x%X\n", (uintptr_t)pImageDOSHeader->e_magic);
    printf("\te_cblp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cblp);
    printf("\te_cp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cp);
    printf("\te_crlc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_crlc);
    printf("\te_cparhdr : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cparhdr);
    printf("\te_minalloc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_minalloc);
    printf("\te_maxalloc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_maxalloc);
    printf("\te_ss : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ss);
    printf("\te_sp : 0x%X\n", (uintptr_t)pImageDOSHeader->e_sp);
    printf("\te_csum : 0x%X\n", (uintptr_t)pImageDOSHeader->e_csum);
    printf("\te_ip : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ip);
    printf("\te_cs : 0x%X\n", (uintptr_t)pImageDOSHeader->e_cs);
    printf("\te_lfarlc : 0x%X\n", (uintptr_t)pImageDOSHeader->e_lfarlc);
    printf("\te_ovno : 0x%X\n", (uintptr_t)pImageDOSHeader->e_ovno);
    printf("\te_oemid : 0x%X\n", (uintptr_t)pImageDOSHeader->e_oemid);
    printf("\te_oeminfo : 0x%X\n", (uintptr_t)pImageDOSHeader->e_oeminfo);
    printf("\te_lfanew : 0x%X\n", (uintptr_t)pImageDOSHeader->e_lfanew);

    printf("\n[+] NT HEADER\n");
    printf("\tSignature : 0x%X\n", (uintptr_t)pImageNTHeader64->Signature);

    printf("\n[+] FILE HEADER\n");
    printf("\tMachine : 0x%X\n", (uintptr_t)ImageFileHeader.Machine);
    printf("\tNumberOfSections : 0x%X\n", (uintptr_t)ImageFileHeader.NumberOfSections);
    printf("\tTimeDateStamp  : 0x%X\n", (uintptr_t)ImageFileHeader.TimeDateStamp);
    printf("\tPointerToSymbolTable   : 0x%X\n", (uintptr_t)ImageFileHeader.PointerToSymbolTable);
    printf("\tNumberOfSymbols   : 0x%X\n", (uintptr_t)ImageFileHeader.NumberOfSymbols);
    printf("\tSizeOfOptionalHeader   : 0x%X\n", (uintptr_t)ImageFileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics  : 0x%X %s\n", (uintptr_t)ImageFileHeader.Characteristics, GetImageCharacteristics(ImageFileHeader.Characteristics));

    printf("\n[+] OPTIONAL HEADER\n");
    printf("\tMagic : 0x%X\n", (uintptr_t)ImageOptionalHeader64.Magic);
    printf("\tMajorLinkerVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MajorLinkerVersion);
    printf("\tMinorLinkerVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MinorLinkerVersion);
    printf("\tSizeOfCode : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfCode);
    printf("\tSizeOfInitializedData : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfInitializedData);
    printf("\tSizeOfUninitializedData : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfUninitializedData);
    printf("\tAddressOfEntryPoint : 0x%X\n", (uintptr_t)ImageOptionalHeader64.AddressOfEntryPoint);
    printf("\tBaseOfCode : 0x%X\n", (uintptr_t)ImageOptionalHeader64.BaseOfCode);
    printf("\tImageBase : 0x%X\n", (uintptr_t)ImageOptionalHeader64.ImageBase);
    printf("\tBSectionAlignment : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SectionAlignment);
    printf("\tFileAlignment : 0x%X\n", (uintptr_t)ImageOptionalHeader64.FileAlignment);
    printf("\tMajorOperatingSystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MajorOperatingSystemVersion);
    printf("\tMinorOperatingSystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MinorOperatingSystemVersion);
    printf("\tMajorImageVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MajorImageVersion);
    printf("\tMinorImageVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MinorImageVersion);
    printf("\tMajorSubsystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MajorSubsystemVersion);
    printf("\tMinorSubsystemVersion : 0x%X\n", (uintptr_t)ImageOptionalHeader64.MinorSubsystemVersion);
    printf("\tWin32VersionValue : 0x%X\n", (uintptr_t)ImageOptionalHeader64.Win32VersionValue);
    printf("\tSizeOfImage : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfImage);
    printf("\tSizeOfHeaders : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfHeaders);
    printf("\tCheckSum : 0x%X\n", (uintptr_t)ImageOptionalHeader64.CheckSum);
    printf("\tSubsystem : 0x%X %s\n", (uintptr_t)ImageOptionalHeader64.Subsystem, GetSubsytem(ImageOptionalHeader64.Subsystem));
    printf("\tDllCharacteristics : 0x%X\n", (uintptr_t)ImageOptionalHeader64.DllCharacteristics);
    printf("\tSizeOfStackReserve : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfStackReserve);
    printf("\tSizeOfStackCommit : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfStackCommit);
    printf("\tSizeOfHeapReserve : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfHeapReserve);
    printf("\tSizeOfHeapCommit : 0x%X\n", (uintptr_t)ImageOptionalHeader64.SizeOfHeapCommit);
    printf("\tLoaderFlags : 0x%X\n", (uintptr_t)ImageOptionalHeader64.LoaderFlags);
    printf("\tNumberOfRvaAndSizes : 0x%X\n", (uintptr_t)ImageOptionalHeader64.NumberOfRvaAndSizes);
    printf("\tDataDirectory : 0x%X\n\n", (uintptr_t)ImageOptionalHeader64.DataDirectory);
    GetDataDirectories((PIMAGE_DATA_DIRECTORY)ImageOptionalHeader64.DataDirectory);

    const PIMAGE_SECTION_HEADER pImageImportSection = GetSections(pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader64.DataDirectory[1].VirtualAddress);
    if (pImageImportSection == nullptr)
    {
        printf("\n[-] An error when trying to retrieve PE imports !\n");
        return -1;
    }

    DWORD_PTR dRawOffset = (DWORD_PTR)pImageDOSHeader + pImageImportSection->PointerToRawData;
    const auto pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (ImageOptionalHeader64.DataDirectory[1].VirtualAddress - pImageImportSection->VirtualAddress));
    if (pImageImportDescriptor == nullptr)
    {
        printf("\n[-] An error occured when trying to retrieve PE imports descriptor !\n");
        return -1;
    }

    GetImports64(pImageImportDescriptor, dRawOffset, pImageImportSection);

    const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader64.DataDirectory[0].VirtualAddress);
    if (pImageExportSection != nullptr)
    {
        dRawOffset = (DWORD_PTR)pImageDOSHeader + pImageExportSection->PointerToRawData;
        const auto pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (ImageOptionalHeader64.DataDirectory[0].VirtualAddress - pImageExportSection->VirtualAddress));
        GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);
    }

    return 0;
}

int main(const int argc, char* argv[])
{
    char* lpFilePath;

    if (argc == 2)
    {
        lpFilePath = argv[1];
    }
    else
    {
        printf("[HELP] explorer.exe <file>");
        return -1;
    }

    const HANDLE hFileContent = GetFileContent(lpFilePath);
    if (hFileContent == INVALID_HANDLE_VALUE)
    {
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);

        return -1;
    }

    const auto pImageDOSHeader = (PIMAGE_DOS_HEADER) hFileContent;
    if (pImageDOSHeader == nullptr)
    {
        if (hFileContent != nullptr)
        {
            HeapFree(hFileContent, 0, nullptr);
            CloseHandle(hFileContent);
        }
        return -1;
    }

    const auto pImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hFileContent + pImageDOSHeader->e_lfanew);
    if (pImageNTHeader == nullptr)
    {
        if (hFileContent != nullptr)
        {
            HeapFree(hFileContent, 0, nullptr);
            CloseHandle(hFileContent);
        }
        return -1;
    }

    //Identify x86 and x64 PE files.
    int ParseResult = 0;
    if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        ParseResult = ParseImage32(pImageDOSHeader);

    if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ParseResult = ParseImage64(pImageDOSHeader);

    if (hFileContent != nullptr)
        HeapFree(hFileContent, 0, nullptr);

    return ParseResult;
}