#include "pch.h"
#include "Misc.h"

// IDA bitness detection.
const WORD MAGIC_PE_32 = 0x10b;
const WORD MAGIC_PE_64 = 0x20b;
const BYTE MAGIC_ELF_32 = 0x1;
const BYTE MAGIC_ELF_64 = 0x2;
const char x32bit[] = "32";
const char x64bit[] = "64";


const char LoaderFail[] = "Loader failure";
const std::vector < std::string> SigList32 = { "vc32mfc", "vc32mfce", "vc32rtf", "vc32ucrt", "vc32_14" };
const std::vector < std::string> SigList64 = { "vc64atl", "vc64extra", "vc64mfc", "vc64rtf", "vc64seh",
                                              "vc64ucrt", "vc64_14" };

// Loader helpers
const char ShouldLoadAsBin[] = "Could not tell the type of file going to load it as binary. OK ?";
const char DefaultProcessor[] = "MetaPc";
const char CPPCompDefaultName[] = "generic abi";

// Forms
const char ChooseFileFromZip[] = " Chose file from the zip.\n\
                                   <values:b0:0:100:100:> \n\n\n";

// Msg strings
const char LoadedToAddress[] = "Finished loading into memory the file %s from zip.\n";
const char FailedToOpenZipFile[] = "Could not open %s as a zip file.\n";
const char ZipFilesNumber[] = "File %s doesn't contain any files.\n";
const char NoImageBase[] = "Could not find the file's image base address for %s file.\n";
const char YesImageBase[] = "Successfully fixed the image base address for %s file to %p.\n";
const char NoLoadersFound[] = "No loaders were found for %s file.";
const char BadDatabaseLocation[] = "Could not save the database to location %s, please consider changing the database location. (File->Save as...)";

// Questions strings
const char NoBitsLoader[] = "The loader could not tell if the PE is either 32 or 64. Please choose.";
const char bit64[] = "64bit";
const char bit32[] = "32bit";
const char Cancel[] = "Cancel";

// Zip strings
const char EnterZipPass[] = "Please enter zip password:";
const char ZipDefaultPass[] = "infected";
const WCHAR ZipDllName[] = L"7z.dll";

// Exceptions strings
const char ReloadIDADirect[] = "Please reload by selecting the IDB file ";
const char UserCanceled[] = "User canceled.";
const char LoaderFailedBadFileBuffer[] = "IDA could not create a non-binary file from memory.";
const char NoNestedZipping[] = "Nested zipping not supported at this time!";
const char NotSupportedFileFormat[] = "Unrecognized file format.";
const char BadBits[] = "File is not in the right bitness. Please use IDA ";
const char DidNotChooseFile[] = "User did not choose file.";
const char CouldNotTellArch[] = "Could not tell if the file is 64 / 32 bit, but going to load anyway.";
const char NoEmptyUrl[] = "The URL can't be empty.";
const char FileSizeWarning[] = "The file you are downloading is larger than 50 MB. Continue ?";
const char CouldNotTellIfIDA64[] = "Could not tell if IDA process's bitness is 64 or 32 bit.";
const char Unicode2asciiFailed[] = "Converting unicode string to ASCII string has failed.";
const char Ascii2unicodeFailed[] = "Converting ASCII string to unicode string has failed.";

// shell codes segments help
const char SentiSeg[] = "SentiSeg000";
const char CODE_SEG_STR[] = "CODE";


qstring path_append(const qstring& p1, const qstring& p2) {

    char sep = '/';
    qstring tmp = p1;

#ifdef _WIN32
    sep = '\\';
#endif

    if (p1[p1.length()] != sep) { // Need to add a
        tmp += sep;                // path separator
        return(tmp + p2);
    }
    else
        return(p1 + p2);
}

bool check_pe_architecture(const bit7z::byte_t* file_data, const WORD magic, bool& set_arc)
{
    __try
    {
        const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_data;
        const PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(file_data + dos_header->e_lfanew);
        set_arc = true;
        return image_nt_headers->OptionalHeader.Magic == magic;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        warning(CouldNotTellArch);
        set_arc = false;
        return true;
    }
}

bool check_elf_architecture(const bit7z::byte_t* file_data, const BYTE magic, bool & set_arc)
{
    __try {
        const size_t elf_bits_offset = 0x04;
        unsigned char* where_to_read = (unsigned char*)file_data + elf_bits_offset;
        // according to elf format: 2 - 64 bit, 1 - 32 bit
        const int elf_bitness = *where_to_read;
        set_arc = true;
        return elf_bitness == magic;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        warning(CouldNotTellArch);
        set_arc = false;
        return true;
    }
}

bool is_dll(const bit7z::byte_t* file_data)
{
    __try {
        const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_data;
        const PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(file_data + dos_header->e_lfanew);
        if ((image_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL))
            return true;
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        msg("Could not tell if the file is DLL or not (an exception was thrown while parsing PE). Setting IsDll to False by default.\n");
        return false;
    }

}

ULONGLONG get_baseaddress_pe(const bit7z::byte_t* file_data)
{
    __try {
        const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_data;
        const PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(file_data + dos_header->e_lfanew);
        return image_nt_headers->OptionalHeader.ImageBase;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        msg("Could not calculate base address for PE.\n");
        return 0;
    }
}

bool is_ida_64() {
    char ida_name[MAX_PATH]{};
    if (GetModuleBaseNameA(GetCurrentProcess(), NULL, ida_name, MAX_PATH) == 0) {
        throw std::exception(CouldNotTellIfIDA64);
    }
    const std::string ida_name_str = { ida_name };
    if (ida_name_str.find("ida64.exe") != std::string::npos) {
        return true;
    }
    return false;
}

char* unicode2ascii(const wchar_t* wsz_string)
{
    const int outlen = ::WideCharToMultiByte(CP_UTF8, NULL, wsz_string, (int)wcslen(wsz_string), NULL, 0, NULL, NULL);
    char* utf8 = new char[(size_t)outlen + 1];
    ::WideCharToMultiByte(CP_UTF8, NULL, wsz_string, (int)wcslen(wsz_string), utf8, outlen, NULL, NULL);
    utf8[outlen] = '\0';
    return utf8;
}

wchar_t* ascii2unicode(const char* ansi)
{
    const int inlen = ::MultiByteToWideChar(CP_ACP, NULL, ansi, (int)strlen(ansi), NULL, 0);
    wchar_t* wsz_string = new wchar_t[(size_t)inlen + 1];
    ::MultiByteToWideChar(CP_ACP, NULL, ansi, (int)strlen(ansi), wsz_string, inlen);
    wsz_string[inlen] = '\0';
    return wsz_string;
}
