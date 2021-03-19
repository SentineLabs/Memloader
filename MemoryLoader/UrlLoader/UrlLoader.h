#pragma once
#include "pch.h"

/// <summary>
/// Download file from url.
/// </summary>
/// <param name="dest_url_w">destination url</param>
/// <issues>
///     We actually download the file twice, I have seen code for downloading files that heavily rely on Content-Length
///     filed in the HTTP headers we decided ageist it, we just download the file twice anyway we think that people reverse small files.
/// </issues>
/// <returns>A vector with file download as byte array</returns>
std::vector< bit7z::byte_t > load_file_from_url(const std::wstring & dest_url_w);

/// <summary>
/// Generates sha1 for the file downloaded
/// </summary>
/// <param name="file_buffer">vector of bytes representing the file</param>
/// <param name="file_sha1">out parameter for file sha1</param>
void calc_sha1_for_buffer(std::vector< bit7z::byte_t > file_buffer, std::string& file_sha1);

#define URL_LOADER "UrlLoader"
#define SHA1LEN  20
extern const int WARNING_FILE_SIZE; // 50 MB
extern const char EnterUrl[];
extern const char CouldNotCalcHash[];
extern const char CouldNotOpenUrl[];
extern const char MemAllocationForUrl[];
extern const WCHAR UserAgent[];
