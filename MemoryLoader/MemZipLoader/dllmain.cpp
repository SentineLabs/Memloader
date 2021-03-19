#include "pch.h"
#include "MemoryLoader.h"

/// <summary>
/// accept_file* function in called by IDA API each time build_loaders_list is called,
/// if the function return a 1 (LOAD_FILE/TRUE) the loader will be suggested as
/// a loader option for this buffer.
/// </summary>
/// <returns>Boolean value if the loader is relevant</returns>
int idaapi accept_file_zip_file(
    qstring* fileformatname,
    qstring*,
    linput_t*,
    const char* filename)
{
	const std::wstring archive_name_w = ascii2unicode(filename);
    try {
	    const bit7z::Bit7zLibrary lib{ ZipDllName };
	    const bit7z::BitArchiveInfo arc{ lib, archive_name_w, bit7z::BitFormat::Zip };
        if (arc.items().empty()) {
            info(ZipFilesNumber, archive_name_w.c_str());
            return SKIP_NOT_RELEVANT;
        }
    }
    catch (const std::exception&) {
        return SKIP_NOT_RELEVANT;
    }

    // name of the loader that will be in IDA window
    *fileformatname = MEMORY_LOADER_FORMAT;
    return LOAD_FILE;
};

//-----------------------------------------------------------------------------
// load a file from a ZIP file into IDA.
void idaapi load_from_zip(linput_t* li, ushort /*neflag*/, const char* /*fileformatname*/)
{
    UNREFERENCED_PARAMETER(li);
    try
    {
        // file name, will be filled after zip extracted
        std::string file_name_s{};
        // file buffer
        std::vector< bit7z::byte_t > file_buffer{};

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

        extract_zipped_file_to_buffer(file_name_s, file_buffer);
        retrieve_target_architecture(desired_arc_str);
        fix_naming_and_env(file_name_s, desired_arc_str, new_path, new_idb_path, new_path_idb_w);
        check_override_db_file(new_path_idb_w, new_idb_path, file_name_s, override_db);

        const unique_ptr_s1<linput_t, destroy_linput> li2{ create_linput(file_buffer) };
        const unique_ptr_s1<load_info_t, destroy_linfos> linfos{ create_linfos(li2.get()) };

        // check if build_loader_list returned a not a empty list
        // we don't support nested loading zips of zips
        if ((linfos.get() != nullptr) && (linfos.get()->ftype == f_ZIP)) {
            throw std::exception(NoNestedZipping);
        }

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

        msg(LoadedToAddress, new_path.c_str());
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
    accept_file_zip_file,
    load_from_zip,
    nullptr,
    nullptr,
};
