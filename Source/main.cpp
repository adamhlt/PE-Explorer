#include <windows.h>
#include <iostream>
#include <winternl.h>

LPVOID getFileContent(const std::string& sFileName)
{
    char cPathBuffer[MAX_PATH];
    HANDLE hFile;
    SIZE_T sFileSize;
    ULONG sBytesRead;
    LPVOID lFileData = nullptr;

    //Récupération du chemin complet du fichier, puis ouverture du fichier
    GetFullPathNameA(sFileName.c_str(), MAX_PATH, cPathBuffer, nullptr);
    hFile = CreateFileA(cPathBuffer, GENERIC_ALL, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "An error is occured when trying to open the file !" << std::endl;
        return lFileData;
    }

    //Récupération de la taille du fichier puis récupération du contenu du fichier
    sFileSize = GetFileSize(hFile, nullptr);
    if (sFileSize == INVALID_FILE_SIZE)
    {
        std::cout << "An error is occured when trying to get the size of the file !" << std::endl;
        return lFileData;
    }

    //Allocation de la taille du fichier pour stocker son contenu
    lFileData = HeapAlloc(GetProcessHeap(), 0, sFileSize);
    if (lFileData == nullptr)
    {
        std::cout << "An error is occured when trying to allocate memory !" << std::endl;
    }

    //Copie en mémoire du contenu du fichier
    int iRes = ReadFile(hFile, lFileData, sFileSize, &sBytesRead, nullptr);
    if (iRes == 0)
    {
        std::cout << "An error is occured when trying to read the file !" << std::endl;
        return nullptr;
    }

    //Affichage des informations
    std::cout << "\n[INFORMATION]\n" << std::endl;
    std::cout << "File Path : " << cPathBuffer << std::endl;
    std::cout << "File Size : " << sFileSize << std::endl;
    std::cout << "File Content Memory Address : 0x" << lFileData << "\n" <<std::endl;

    CloseHandle(hFile);
    return lFileData;
}

//Vérification des flags de l'image
std::string getImageCharacteristics(DWORD dCharactaristics)
{
    if (dCharactaristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        return " (EXE)";
    if (dCharactaristics & IMAGE_FILE_SYSTEM)
        return " (DRIVER)";
    if (dCharactaristics & IMAGE_FILE_DLL)
        return " (DLL)";

    return "";
}

//Récupération du sous-système
std::string getSubsystem(WORD dSubsystem)
{
    if (dSubsystem == 1)
        return " (NATIVE / DRIVER)";
    if (dSubsystem == 2)
        return " (GUI APP)";
    if (dSubsystem == 3)
        return " (CONSOLE APP)";

    return "";
}

//Récupération des attributs de chques section
std::string getSectionCharacteristics(DWORD dCharactaristics)
{
    std::string str = " (";
    bool bExecute = false, bRead = false, bWrite = false;
    if (dCharactaristics & IMAGE_SCN_MEM_EXECUTE) {
        bExecute = true;
        str.append("EXECUTE");
    }
    if (dCharactaristics & IMAGE_SCN_MEM_READ) {
        bRead = true;
        if (bExecute)
            str.append(" | ");
        str.append("READ");
    }
    if (dCharactaristics & IMAGE_SCN_MEM_WRITE)
    {
        bWrite = true;
        if (bExecute || bRead)
            str.append(" | ");
        str.append("WRITE");
    }
    str.append(")");

    if (bExecute && bRead && bWrite)
        return "";

    return str;
}

//Récupération de chaque section
PIMAGE_SECTION_HEADER getSection(int iSection, DWORD dSectionAddr, DWORD dImportRVA)
{
    PIMAGE_SECTION_HEADER pimageImportSectionHeader;

    for (int i = 0; i < iSection; ++i)
    {
        auto pimageSectionHeader = (PIMAGE_SECTION_HEADER)(dSectionAddr + (i * sizeof(IMAGE_SECTION_HEADER)));
        std::cout << "Name : " << pimageSectionHeader->Name << std::endl;
        std::cout << "Virtual Address : 0x" << std::hex << pimageSectionHeader->VirtualAddress << std::endl;
        std::cout << "Virtual Size : " << pimageSectionHeader->Misc.VirtualSize << std::endl;
        std::cout << "Pointer To Raw Data : 0x" << std::hex << pimageSectionHeader->PointerToRawData << std::endl;
        std::cout << "Size Of Raw Data : " << pimageSectionHeader->SizeOfRawData << std::endl;
        std::cout << "Characteristics : 0x" << std::hex << pimageSectionHeader->Characteristics << getSectionCharacteristics(pimageSectionHeader->Characteristics) << "\n" << std::endl;
        if (dImportRVA >= pimageSectionHeader->VirtualAddress && dImportRVA < (pimageSectionHeader->VirtualAddress + pimageSectionHeader->Misc.VirtualSize))
        {
            pimageImportSectionHeader = pimageSectionHeader;
        }
    }

    return pimageImportSectionHeader;
}

int parse32Header(LPVOID lFileData)
{
    PIMAGE_DOS_HEADER pimageDosHeader32;
    PIMAGE_NT_HEADERS32 pimageNtHeaders32;
    PIMAGE_SECTION_HEADER pimageImportSectionHeader32;
    PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor32;
    PIMAGE_IMPORT_BY_NAME pimageImportByName32;
    PIMAGE_THUNK_DATA32 pimageThunkData32;
    IMAGE_FILE_HEADER imageFileHeader32;
    IMAGE_OPTIONAL_HEADER32 imageOptionalHeader32;

    DWORD dImportAddress;
    DWORD dSectionAddr;
    DWORD dRawOffset;
    DWORD dThunk;

    pimageDosHeader32 = (PIMAGE_DOS_HEADER)lFileData;
    pimageNtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD)lFileData + pimageDosHeader32->e_lfanew);
    imageFileHeader32 = pimageNtHeaders32->FileHeader;
    imageOptionalHeader32 = pimageNtHeaders32->OptionalHeader;

    std::cout << "\n[INFORMATION PE]\n" << std::endl;
    std::cout << "Architecture x86" << std::endl;
    std::cout << "\n[DOS HEADER]\n" << std::endl;
    std::cout << "e_lfanew : 0x" << std::hex << pimageDosHeader32 << std::endl;

    std::cout << "\n[NT HEADER]\n" << std::endl;
    std::cout << "Signature : 0x" << pimageNtHeaders32->Signature << std::endl;

    std::cout << "\n[FILE HEADER]\n" << std::endl;
    std::cout << "Machine : 0x" << std::hex << imageFileHeader32.Machine << std::endl;
    std::cout << "Number Of Sections : " << imageFileHeader32.NumberOfSections << std::endl;
    std::cout << "Compilation Timestamp : " << imageFileHeader32.TimeDateStamp << std::endl;
    std::cout << "Characteristics : 0x" << std::hex << imageFileHeader32.Characteristics << getImageCharacteristics(imageFileHeader32.Characteristics) << std::endl;

    std::cout << "\n[OPTIONAL HEADER]\n" << std::endl;
    std::cout << "Magic : 0x" << std::hex << imageOptionalHeader32.Magic << std::endl;
    std::cout << "Entry Point Address : 0x" << std::hex << imageOptionalHeader32.AddressOfEntryPoint << std::endl;
    std::cout << "Image Base Address (without Relocation) : 0x" << std::hex << imageOptionalHeader32.ImageBase << std::endl;
    std::cout << "Size Of Image (in Memory) : " << imageOptionalHeader32.SizeOfImage << std::endl;
    std::cout << "Size Of Header : " << imageOptionalHeader32.SizeOfHeaders << std::endl;
    std::cout << "Subsystem : " << imageOptionalHeader32.Subsystem << getSubsystem(imageOptionalHeader32.Subsystem) << std::endl;

    dImportAddress = imageOptionalHeader32.DataDirectory[1].VirtualAddress;
    dSectionAddr = (DWORD)pimageNtHeaders32 + 4 + sizeof(IMAGE_FILE_HEADER) + imageFileHeader32.SizeOfOptionalHeader;

    std::cout << "\n[SECTIONS HEADER]\n" << std::endl;
    pimageImportSectionHeader32 = getSection(imageFileHeader32.NumberOfSections, dSectionAddr, dImportAddress);
    if (pimageImportSectionHeader32 == nullptr)
        return -1;

    dRawOffset = (DWORD)lFileData + pimageImportSectionHeader32->PointerToRawData;
    pimageImportDescriptor32 = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (dImportAddress - pimageImportSectionHeader32->VirtualAddress));

    std::cout << "\n[DLL IMPORTS]\n" << std::endl;
    for (; pimageImportDescriptor32->Name != 0 ; ++pimageImportDescriptor32)
      {
        std::cout << "Name : " << (char*)(dRawOffset + (pimageImportDescriptor32->Name - pimageImportSectionHeader32->VirtualAddress)) << "\n" << std::endl;
        if (pimageImportDescriptor32->OriginalFirstThunk == 0)
          dThunk = pimageImportDescriptor32->FirstThunk;
        else
          dThunk = pimageImportDescriptor32->OriginalFirstThunk;
        pimageThunkData32 = (PIMAGE_THUNK_DATA32)(dRawOffset + (dThunk - pimageImportSectionHeader32->VirtualAddress));

        for (;pimageThunkData32->u1.AddressOfData != 0; ++pimageThunkData32)
          {
            pimageImportByName32 = (PIMAGE_IMPORT_BY_NAME)pimageThunkData32->u1.AddressOfData;
            if (pimageThunkData32->u1.AddressOfData > 0x80000000)
              std::cout << "Ordinal : " << (DWORD)pimageThunkData32->u1.Ordinal << std::endl;
            else
              std::cout << (dRawOffset + (pimageImportByName32->Name - pimageImportSectionHeader32->VirtualAddress)) << std::endl;
          }
        std::cout << "\n" << std::endl;
      }

    return 0;
}

int parse64Header(LPVOID lFileData)
{
    PIMAGE_DOS_HEADER pimageDosHeader64;
    PIMAGE_NT_HEADERS64 pimageNtHeaders64;
    PIMAGE_SECTION_HEADER pimageImportSectionHeader64;
    PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor64;
    PIMAGE_IMPORT_BY_NAME pimageImportByName64;
    PIMAGE_THUNK_DATA64 pimageThunkData64;
    IMAGE_FILE_HEADER imageFileHeader64;
    IMAGE_OPTIONAL_HEADER64 imageOptionalHeader64;

    DWORD dImportAddress;
    DWORD dSectionAddr;
    DWORD dRawOffset;
    DWORD dThunk;

    pimageDosHeader64 = (PIMAGE_DOS_HEADER)lFileData;
    pimageNtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD)lFileData + pimageDosHeader64->e_lfanew);
    imageFileHeader64 = pimageNtHeaders64->FileHeader;
    imageOptionalHeader64 = pimageNtHeaders64->OptionalHeader;

    std::cout << "\n[INFORMATION PE+]\n" << std::endl;
    std::cout << "Architecture x64" << std::endl;
    std::cout << "\n[DOS HEADER]\n" << std::endl;
    std::cout << "e_lfanew : 0x" << std::hex << pimageDosHeader64 << std::endl;

    std::cout << "\n[NT HEADER]\n" << std::endl;
    std::cout << "Signature : 0x" << pimageNtHeaders64->Signature << std::endl;

    std::cout << "\n[FILE HEADER]\n" << std::endl;
    std::cout << "Machine : 0x" << std::hex << imageFileHeader64.Machine << std::endl;
    std::cout << "Number Of Sections : " << imageFileHeader64.NumberOfSections << std::endl;
    std::cout << "Compilation Timestamp : " << imageFileHeader64.TimeDateStamp << std::endl;
    std::cout << "Characteristics : 0x" << std::hex << imageFileHeader64.Characteristics << getImageCharacteristics(imageFileHeader64.Characteristics) << std::endl;

    std::cout << "\n[OPTIONAL HEADER]\n" << std::endl;
    std::cout << "Magic : 0x" << std::hex << imageOptionalHeader64.Magic << std::endl;
    std::cout << "Entry Point Address : 0x" << std::hex << imageOptionalHeader64.AddressOfEntryPoint << std::endl;
    std::cout << "Image Base Address (without Relocation) : 0x" << std::hex << imageOptionalHeader64.ImageBase << std::endl;
    std::cout << "Size Of Image (in Memory) : " << imageOptionalHeader64.SizeOfImage << std::endl;
    std::cout << "Size Of Header : " << imageOptionalHeader64.SizeOfHeaders << std::endl;
    std::cout << "Subsystem : " << imageOptionalHeader64.Subsystem << getSubsystem(imageOptionalHeader64.Subsystem) << std::endl;

    dImportAddress = imageOptionalHeader64.DataDirectory[1].VirtualAddress;
    dSectionAddr = (DWORD)pimageNtHeaders64 + 4 + sizeof(IMAGE_FILE_HEADER) + imageFileHeader64.SizeOfOptionalHeader;

    std::cout << "\n[SECTIONS HEADER]\n" << std::endl;
    pimageImportSectionHeader64 = getSection(imageFileHeader64.NumberOfSections, dSectionAddr, dImportAddress);
    if (pimageImportSectionHeader64 == nullptr)
        return -1;

    dRawOffset = (DWORD)lFileData + pimageImportSectionHeader64->PointerToRawData;
    pimageImportDescriptor64 = (PIMAGE_IMPORT_DESCRIPTOR)(dRawOffset + (dImportAddress - pimageImportSectionHeader64->VirtualAddress));

    std::cout << "\n[DLL IMPORTS]\n" << std::endl;
    for (; pimageImportDescriptor64->Name != 0 ; ++pimageImportDescriptor64)
      {
        std::cout << "Name : " << (char*)(dRawOffset + (pimageImportDescriptor64->Name - pimageImportSectionHeader64->VirtualAddress)) << "\n" << std::endl;
        if (pimageImportDescriptor64->OriginalFirstThunk == 0)
          dThunk = pimageImportDescriptor64->FirstThunk;
        else
          dThunk = pimageImportDescriptor64->OriginalFirstThunk;
        pimageThunkData64 = (PIMAGE_THUNK_DATA64)(dRawOffset + (dThunk - pimageImportSectionHeader64->VirtualAddress));

        for (;pimageThunkData64->u1.AddressOfData != 0; ++pimageThunkData64)
          {
            pimageImportByName64 = (PIMAGE_IMPORT_BY_NAME)pimageThunkData64->u1.AddressOfData;
            if (pimageThunkData64->u1.AddressOfData > 0x80000000)
              std::cout << "Ordinal : " << (DWORD)pimageThunkData64->u1.Ordinal << std::endl;
            else
              std::cout << (dRawOffset + (pimageImportByName64->Name - pimageImportSectionHeader64->VirtualAddress)) << std::endl;
          }
          std::cout << "\n" << std::endl;
      }

    return 0;
}

int main(int argc, char* argv[])
{
    std::string sFileName;
    PIMAGE_DOS_HEADER imageDosHeader;
    PIMAGE_NT_HEADERS imageNtHeaders;

    if (argc != 2)
    {
        std::cout << "[HELP] explorer.exe <pe_file>" << std::endl;
        return -1;
    }
    else sFileName = argv[1];

    //Récupération du contenu du fichier
    LPVOID lFileData = getFileContent(sFileName);
    if(lFileData == nullptr)
    {
        std::cout << "An error is occured when trying to access to the data !" << std::endl;
        return -1;
    }

    //Récupération du DOS Header
    imageDosHeader = (PIMAGE_DOS_HEADER)lFileData;

    //Identification x86/x64
    imageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)lFileData + imageDosHeader->e_lfanew);
    if (imageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        parse64Header(lFileData);
    else
        parse32Header(lFileData);

    system("PAUSE");
    return 0;
}