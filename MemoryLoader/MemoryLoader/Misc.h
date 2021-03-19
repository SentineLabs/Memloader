#pragma once
#include "pch.h"

#include <bittypes.hpp>

#ifdef _EXPORTING
#define CLASS_DECLSPEC    __declspec(dllexport)
#else
#define CLASS_DECLSPEC    __declspec(dllimport)
#endif

/// <summary>
/// Join paths.
/// </summary>
/// <param name="p1">first path</param>
/// <param name="p2">second path</param>
/// <returns>New joined path</returns>
CLASS_DECLSPEC
qstring path_append(const qstring& p1,
                    const qstring& p2);

/// <summary>
/// Check if PE in the right architecture for IDA.
/// </summary>
/// <param name="file_data">pointer to file data</param>
/// <param name="magic">PE magic to look for</param>
/// <param name="set_arc">If the function could tell the architecture of the PE</param>
/// <returns>If the PE has the right magic.</returns>
CLASS_DECLSPEC
bool check_pe_architecture(const bit7z::byte_t* file_data,
                      const WORD magic,
                      bool& set_arc);

/// <summary>
/// Check if ELF in the right architecture for IDA.
/// </summary>
/// <param name="file_data">pointer to file data</param>
/// <param name="magic">ELF magic to look for</param>
/// <param name="set_arc">If the function could tell the architecture of the elf</param>
/// <returns>If the ELF has the right magic.</returns>
CLASS_DECLSPEC
bool check_elf_architecture(const bit7z::byte_t* file_data,
                            const BYTE magic,
                            bool & set_arc);

/// <summary>
/// Used to check IDAs bitness.
/// </summary>
/// <returns>If ida64.exe or ida.exe is running.</returns>
CLASS_DECLSPEC
bool is_ida_64();

/// <summary>
/// Check if PE is DLL, used by loader to set IS_DLL property.
/// </summary>
/// <param name="file_data">pointer to file data</param>
/// <returns></returns>
CLASS_DECLSPEC
bool is_dll(const bit7z::byte_t* file_data);

/// <summary>
/// Tries to calculate PEs base address.
/// </summary>
/// <param name="file_data">pointer to file data</param>
/// <returns>Base Address of PE. Or null if there was an exception.</returns>
CLASS_DECLSPEC
ULONGLONG get_baseaddress_pe(const bit7z::byte_t* file_data);

/// <summary>
/// Credit, https://gist.github.com/tfzxyinhao/2818b31a7ce94154a133#file-charsetconvert
/// </summary>
/// <param name="wsz_string">wide char pointer to string</param>
/// <returns></returns>
CLASS_DECLSPEC
char* unicode2ascii(const wchar_t* wsz_string);

/// <summary>
/// Credit, https://gist.github.com/tfzxyinhao/2818b31a7ce94154a133#file-charsetconvert
/// </summary>
/// <param name="ansi">char pointer to string</param>
/// <returns></returns>
CLASS_DECLSPEC
wchar_t* ascii2unicode(const char* ansi);

#define MEMORY_LOADER_FORMAT "MemZipLoader"
#define LOAD_FILE 1
#define SKIP_NOT_RELEVANT 0 

// IDA bitness detection.
CLASS_DECLSPEC extern const WORD MAGIC_PE_32;
CLASS_DECLSPEC extern const WORD MAGIC_PE_64;
CLASS_DECLSPEC extern const BYTE MAGIC_ELF_32;
CLASS_DECLSPEC extern const BYTE MAGIC_ELF_64;
CLASS_DECLSPEC extern const char x32bit[];
CLASS_DECLSPEC extern const char x64bit[];

CLASS_DECLSPEC extern const char LoaderFail[];
CLASS_DECLSPEC extern const std::vector < std::string> SigList32;
CLASS_DECLSPEC extern const std::vector < std::string> SigList64;

// Loader helpers
CLASS_DECLSPEC extern const char ShouldLoadAsBin[];
CLASS_DECLSPEC extern const char DefaultProcessor[];
CLASS_DECLSPEC extern const char CPPCompDefaultName[];
 
// Forms
CLASS_DECLSPEC extern const char ChooseFileFromZip[];
 
// Msg strings
CLASS_DECLSPEC extern const char LoadedToAddress[];
CLASS_DECLSPEC extern const char FailedToOpenZipFile[];
CLASS_DECLSPEC extern const char ZipFilesNumber[];
CLASS_DECLSPEC extern const char NoImageBase[];
CLASS_DECLSPEC extern const char YesImageBase[];
CLASS_DECLSPEC extern const char NoLoadersFound[];
CLASS_DECLSPEC extern const char BadDatabaseLocation[];
 
// Questions strings
CLASS_DECLSPEC extern const char NoBitsLoader[];
CLASS_DECLSPEC extern const char bit64[];
CLASS_DECLSPEC extern const char bit32[];
CLASS_DECLSPEC extern const char Cancel[];
 
// Zip strings
CLASS_DECLSPEC extern const char EnterZipPass[];
CLASS_DECLSPEC extern const char ZipDefaultPass[];
CLASS_DECLSPEC extern const WCHAR ZipDllName[];

// Exceptions strings
CLASS_DECLSPEC extern const char ReloadIDADirect[];
CLASS_DECLSPEC extern const char UserCanceled[];
CLASS_DECLSPEC extern const char LoaderFailedBadFileBuffer[];
CLASS_DECLSPEC extern const char NoNestedZipping[];
CLASS_DECLSPEC extern const char NotSupportedFileFormat[];
CLASS_DECLSPEC extern const char BadBits[];
CLASS_DECLSPEC extern const char DidNotChooseFile[];
CLASS_DECLSPEC extern const char CouldNotTellArch[];
CLASS_DECLSPEC extern const char NoEmptyUrl[];
CLASS_DECLSPEC extern const char FileSizeWarning[];
CLASS_DECLSPEC extern const char CouldNotTellIfIDA64[];
CLASS_DECLSPEC extern const char Unicode2asciiFailed[];
CLASS_DECLSPEC extern const char Ascii2unicodeFailed[];
 
// shell codes segments help
CLASS_DECLSPEC extern const char SentiSeg[];
CLASS_DECLSPEC extern const char CODE_SEG_STR[];
