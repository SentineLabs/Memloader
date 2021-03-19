#include "pch.h"
#include "UrlLoader.h"

const char EnterUrl[] = "Enter URL: ";
const char CouldNotCalcHash[] = "Could not calculate sha1 for file downloaded.";
const char CouldNotOpenUrl[] = "Could not open URL ";
const char MemAllocationForUrl[] = "Could not allocate memory for file to be downloaded to.";
// Latest Chrome on Windows User Agent, for 8.3.2021
const WCHAR UserAgent[] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36";
const int WARNING_FILE_SIZE = 50 * 1000000;

void calc_sha1_for_buffer(std::vector< bit7z::byte_t > file_buffer, std::string& file_sha1)
{
    HCRYPTPROV h_prov = 0;
    HCRYPTHASH h_hash = 0;
    BYTE rgb_hash[SHA1LEN];
    DWORD cb_hash = SHA1LEN;
    CHAR rgb_digits[] = "0123456789abcdef";

    // Get handle to the crypt provider
    if (!CryptAcquireContext(&h_prov,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        throw std::exception("CryptAcquireContext failed: %d\n", GetLastError());
    }

    if (!CryptCreateHash(h_prov, CALG_SHA1, 0, 0, &h_hash))
    {
        CryptReleaseContext(h_prov, 0);
        throw std::exception("CryptAcquireContext failed: %d\n", GetLastError());
    }

    if (!CryptHashData(h_hash, file_buffer.data(), (DWORD)file_buffer.size(), 0))
    {
        CryptReleaseContext(h_prov, 0);
        CryptDestroyHash(h_hash);
        throw std::exception("CryptHashData failed: %d\n", GetLastError());
    }

    if (CryptGetHashParam(h_hash, HP_HASHVAL, rgb_hash, &cb_hash, 0))
    {
        // https://www.vbforums.com/showthread.php?371715-Need-Help-Getting-SHA1-value-of-File
        for (DWORD i = 0; i < cb_hash; i++)
        {
            file_sha1 += rgb_digits[rgb_hash[i] >> 4];
            file_sha1 += rgb_digits[rgb_hash[i] & 0xf];
        }
    }

    CryptDestroyHash(h_hash);
    CryptReleaseContext(h_prov, 0);
    msg("SHA1 for file downloaded: %s", file_sha1.c_str());
}

std::vector< bit7z::byte_t > load_file_from_url(const std::wstring & dest_url_w)
{
    unsigned char* file_contents_from_url = nullptr;
    const size_t buf_size = 1024;
    unsigned char tmp_buf[buf_size]{};
    try
    {
        const HINTERNET h_internet_session = InternetOpen(
            UserAgent,                                  // agent
            INTERNET_OPEN_TYPE_PRECONFIG,               // access
            NULL, NULL, 0);   // defaults

        // Make connection to desired page.
        HINTERNET h_url = InternetOpenUrl(
            h_internet_session,                                 // session handle
            (LPWSTR)dest_url_w.c_str(),                         // URL to access
            NULL, 0, 0, 0);           // defaults
        if (!h_url) {
            const std::string dest_url_s = unicode2ascii(dest_url_w.c_str());
            throw std::exception((CouldNotOpenUrl + dest_url_s).c_str());
        }

        // First calculate how much to read.
        DWORD total_read = 0;
        DWORD total_bytes_read = 0;
        bool asked = false;
        while (
            (InternetReadFile(
                h_url,                       // handle to URL
                tmp_buf,                     // pointer to buffer
                buf_size,                    // size of buffer
                &total_bytes_read )
                ) && (total_bytes_read  != 0))
        {
            if ((total_read >= WARNING_FILE_SIZE) && !asked) {
                const int should_continue = ask_yn(ASKBTN_NO, FileSizeWarning);
                if ((should_continue == ASKBTN_NO) || (should_continue == ASKBTN_CANCEL)) {
                    throw std::exception(UserCanceled);
                }
                asked = true;
            }
            total_read += total_bytes_read ;
        }

        msg("Download complete from URL - file size read %d.\n", total_read);

        file_contents_from_url = (unsigned char*)malloc(sizeof(unsigned char) * total_read);
        if (file_contents_from_url == NULL) {
            throw std::exception(MemAllocationForUrl);
        }

        // Make connection to desired page.
        h_url = InternetOpenUrl(
            h_internet_session,                        // session handle
            (LPWSTR)dest_url_w.c_str(),                // URL to access
            NULL, 0, 0, 0);  // defaults
        if (!h_url) {
            const std::string dest_url_s = unicode2ascii(dest_url_w.c_str());
            throw std::exception((CouldNotOpenUrl + dest_url_s).c_str());
        }

        total_bytes_read  = 0;
        while (
            (InternetReadFile(
                h_url,                       // handle to URL
                file_contents_from_url,     // pointer to buffer
                total_read,                 // size of buffer
                &total_bytes_read )
                ) && (total_bytes_read  != 0))
        {
            if (total_read == total_bytes_read ) {
                break;
            }
        }

        InternetCloseHandle(h_internet_session);

        std::vector< bit7z::byte_t > file_buffer(file_contents_from_url, file_contents_from_url + total_read);

        msg("Actual size read %d.\n", file_buffer.size());
        
        free(file_contents_from_url);
        return file_buffer;
    }
    catch (const std::exception&)
    {
        if (file_contents_from_url) {
            free(file_contents_from_url);
        }
        throw;
    }

}
