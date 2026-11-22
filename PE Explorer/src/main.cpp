#include "FileLoader.h"
#include "PeImage.h"
#include "PeInfo.h"
#include "PeParser.h"
#include "PePrinter.h"
#include <cstdio>
#include <string>
#include <vector>

int main(const int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("[HELP] explorer.exe <file>\n");
        return 1;
    }

    std::string error;
    std::vector<uint8_t> content;
    if (!LoadFile(argv[1], content, error))
    {
        fprintf(stderr, "[-] %s\n", error.c_str());
        return 1;
    }

    PeImage image(std::move(content));
    PeInfo info;
    const bool bParsed = ParsePe(image, info, error);

    // Display what has been parsed, even if a later part of the file is invalid.
    PrintPe(info);

    if (!bParsed)
    {
        fprintf(stderr, "\n[-] Parsing failed : %s\n", error.c_str());
        return 1;
    }

    return 0;
}
