#include "pch.h"
#include "MemoryLoader.h"
#include "UrlLoader.h"

/// <summary>
/// accept_file* function in called by IDA API each time build_loaders_list is called,
/// if the function return a 1 (LOAD_FILE/TRUE) the loader will be suggested as
/// a loader option for this buffer.
/// </summary>
/// <returns>Boolean value if the loader is relevant</returns>
int idaapi accept_file_url(
    qstring* fileformatname,
    qstring*,
    linput_t*,
    const char* filename)
{
    // If the load_loaders_list is called with no filename (pragmatically) we don't suggest this loader,
    // if the load_loaders_list called with a filename (by loading a file from disk).
    if (strlen(filename) == 0) {
        return SKIP_NOT_RELEVANT;
    }

    *fileformatname = URL_LOADER;
    return LOAD_FILE;

}

//-----------------------------------------------------------------------------
// load a file from a specified URL into IDA.
void idaapi load_from_url(linput_t* li, ushort /*neflag*/, const char* /*fileformatname*/)
{
    UNREFERENCED_PARAMETER(li);
    try
    {
        // file sha1
        std::string file_sha1{};

        // future file name, we will be filled after the file is downloaded and the sha1,
        // of the downloaded file calculated
        std::string file_name_s{};

        // represents the file name that will be displayed in IDA windows, at the top right corner
        qstring new_path{};
        // full path of IDB file
        qstring new_idb_path{};
        // full path of IDB file as wide string
        std::wstring new_path_idb_w{};
        // should override db flag, used to tell if db should be overrider and if the db should be saved immediately to new_idb_path
        int override_db = TRUE;

        // string representation for IDB file name (the architecture part).
        std::string desired_arc_str{};
        // tells if the architecture was already set
        bool set_arc = false;

        qstring url = {};
        const int entered_url = ask_str(&url, 1, EnterUrl);

        if (url.empty()) {
            throw std::exception(NoEmptyUrl);
        }

        if (entered_url == ASKBTN_CANCEL) {
            throw std::exception(UserCanceled);
        }

        const std::wstring url_w = ascii2unicode(url.c_str());

        // file buffer
        std::vector<bit7z::byte_t> file_buffer = load_file_from_url(url_w);

        calc_sha1_for_buffer(file_buffer, file_sha1);
        retrieve_target_architecture(desired_arc_str);
        fix_naming_and_env(file_sha1, desired_arc_str, new_path, new_idb_path, new_path_idb_w);
        check_override_db_file(new_path_idb_w, new_idb_path, file_name_s, override_db);

        const unique_ptr_s1<linput_t, destroy_linput> li2{ create_linput(file_buffer) };
        const unique_ptr_s1<load_info_t, destroy_linfos> linfos{ create_linfos(li2.get()) };

        handle_file_loading(linfos.get(), li2.get(), file_buffer, desired_arc_str, file_name_s, set_arc);
        validate_architecture_set(set_arc, desired_arc_str);
        
        // If the build_loaders_list could no find any suitable loader from IDA loaders list,
        // ask the user if the input should be as a binary (shellcode) buffer.
        if (linfos.get() == nullptr) {
            parse_as_shellcode(file_buffer);
        }

        /*
            Auto-analysis with
            apply type information
            apply signature to address
            load signature file (file name is kept separately)
            find functions chunks
            reanalyze
        */
        set_auto_state(AU_USED | AU_TYPE | AU_LIBF | AU_CHLB | AU_FCHUNK);
        auto_wait();

        // only save the db if we need to, if its new or if the user knows he is going to override it
        if (override_db == ASKBTN_YES) {
            const int success = save_database(new_idb_path.c_str(), 0);
            if (!success) {
                warning(BadDatabaseLocation, new_idb_path.c_str());
            }
        }

        msg(LoadedToAddress, file_name_s.c_str());
    }
    catch (const std::exception& ex)
    {
        loader_failure("Loader failure. Error: %s", ex.what());
    }
}

//-----------------------------------------------------------------------------
// Loader description block
loader_t LDSC =
{
    IDP_INTERFACE_VERSION,
    0,
    accept_file_url,
    load_from_url,
    NULL,
    NULL,
};

