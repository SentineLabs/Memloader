#include "pch.h"
#include "MemoryLoader.h"

void handle_loaded_pe(const std::vector< bit7z::byte_t >&file_buffer,
              const std::string& file_name_s,
              bool& set_arc)
{
    ULONGLONG cacl_image_base = 0x0;
    // fix image base address, we calculate image base address of PEs in order
    // to make the signature loading read the values in the right address
    const ea_t image_base_old = get_imagebase();
    if (!image_base_old) {
        msg(NoImageBase, file_name_s.c_str());
        cacl_image_base = get_baseaddress_pe(file_buffer.data());
        if (cacl_image_base) {
            msg(YesImageBase, file_name_s.c_str(), cacl_image_base);
            set_imagebase((ea_t)cacl_image_base);
        }
    }

    inf_set_dll(is_dll(file_buffer.data()));

    const WORD desired_arc = is_ida_64() ? MAGIC_PE_64 : MAGIC_PE_32;

    // check if the file is 64 / 32 bits and IDA if its being reversed with the right IDA
    if (!check_pe_architecture(file_buffer.data(), desired_arc, set_arc)) {
        const std::string err = (desired_arc == MAGIC_PE_32) ? x64bit : x32bit;
        throw std::exception((BadBits + err).c_str());
    }

    // check if 32 / 64 bit, load the current til and sig files for PEs in Windows with flirt
    // the list is hard coded
    std::vector <std::string> sig_list = inf_is_64bit() ? SigList64 : SigList32;
    for (const std::string& sig_name : sig_list) {
        plan_to_apply_idasgn(sig_name.c_str());
    }
    
}

void handle_loaded_elf(const std::vector< bit7z::byte_t >& file_buffer,
                       bool& set_arc)
{
    // Handle file as elf
    const BYTE desired_arc = is_ida_64() ? MAGIC_ELF_64 : MAGIC_ELF_32;

    if (!check_elf_architecture(file_buffer.data(), desired_arc, set_arc)) {
        const std::string err = (desired_arc == MAGIC_ELF_32) ? x64bit : x32bit;
        throw std::exception((BadBits + err).c_str());
    }
}

void handle_file_loading(
    load_info_t* linfos,
    linput_t* li2,
    const std::vector< bit7z::byte_t >& file_buffer,
    const std::string& desired_arc_str,
    const std::string& file_name_s,
    bool& set_arc)
{
    if (linfos == nullptr) {
        msg(NoLoadersFound, file_name_s.c_str());
        const int answer = ask_yn(ASKBTN_YES, ShouldLoadAsBin);
        if (answer != ASKBTN_YES) {
            throw std::exception(UserCanceled);
        }
        set_processor_type(DefaultProcessor, SETPROC_LOADER);
        mem2base(file_buffer.data(), 0, (ea_t)file_buffer.size(), (ea_t)0);
        return;
    }
    
    if (!load_nonbinary_file("", li2, "", 0, linfos)) {
        throw std::exception(LoaderFailedBadFileBuffer);
    }

    if (linfos->ftype != f_BIN) {
        compiler_info_t old_cc;
        inf_get_cc(&old_cc);
        // Unknown compiler guess it, try to set it up to the most popular by OS
        if (old_cc.id == COMP_UNK) {
            char file_type[MAX_PATH];
            get_file_type_name(file_type, MAX_PATH);
            msg("Could not tell compiler type. Trying to guess it.", file_type);
            switch (linfos->ftype)
            {
            case f_PE:
                // set compiler type, get the generic one with the good int, long and etc sizes
                // set just the calling convention to be right + Visual C++ compiler for MS files.
                old_cc.id = COMP_MS;
                old_cc.cm = CM_CC_STDCALL;
                // check if pointer size is known, if not guess
                if (desired_arc_str == x32bit) {
                    set_compiler(old_cc, SETCOMP_ONLY_ID, CPPCompDefaultName);
                }
                else {
                    set_compiler(old_cc, SETCOMP_OVERRIDE, CPPCompDefaultName);
                }
                break;
            case f_ELF:
                old_cc.id = COMP_GNU;
                old_cc.cm = CM_CC_CDECL;
                // check if pointer size is known, if not guess
                if (desired_arc_str == x32bit) {
                    set_compiler(old_cc, SETCOMP_ONLY_ID, "");
                }
                else {
                    set_compiler(old_cc, SETCOMP_OVERRIDE, "");
                }
                break;
            default:
                break;
            }
        }
    }

    if (linfos->ftype == f_ELF) {
        handle_loaded_elf(file_buffer, set_arc);
    } else if (linfos->ftype == f_PE) {
        handle_loaded_pe(file_buffer, file_name_s, set_arc);
    }
    
}

void parse_as_shellcode(const std::vector< bit7z::byte_t >& file_buffer)
{
    // If there is no loader for this binary load it a binary blob
    // this means it's a shellcode or a file we did not recognize. We gonna treat
    // as a code block, like a shellcode, Fix sections data to treat loaded binary as code
    del_segm((ea_t)0x0, SEGMOD_KILL);
    add_segm((ea_t)0x0, (ea_t)0x0, (ea_t)file_buffer.size(), SentiSeg, CODE_SEG_STR, ADDSEG_SPARSE);
    segment_t* sentiSeg = getseg(0x0);
    if (inf_is_64bit()) {
        // 2: 64bit segment
        set_segm_addressing(sentiSeg, 2);
    }
    else if (inf_is_32bit()) {
        // 1: 32bit segment
        set_segm_addressing(sentiSeg, 1);
    }
}

void validate_architecture_set(bool& set_arc, std::string& desired_arc_str)
{
    if (set_arc)
        return;
    
    // check if we know what bitness are we dealing with,
    // if IDA did not figure if it's 32 or 64 ask the user.
    if (!inf_is_64bit() && !inf_is_32bit()) {
        // can't tell the bits
        const int answer = ask_buttons(bit64, bit32, Cancel, 0, NoBitsLoader);
        if (answer == ASKBTN_YES) {
            inf_set_64bit(true);
            desired_arc_str = { x64bit };
        }
        else if (answer == ASKBTN_NO) {
            inf_set_32bit(true);
            desired_arc_str = { x32bit };
        }
        else {
            throw std::exception(UserCanceled);
        }
        set_arc = true;
    }
    
}

void retrieve_target_architecture(std::string& desired_arc_str)
{
    desired_arc_str = is_ida_64() ? x64bit : x32bit;
}

void check_override_db_file(std::wstring& new_idb_path_w,
                            qstring& new_idb_path,
                            std::string& file_name_s,
                            int& override_db)
{
    override_db = ASKBTN_YES;
    if (std::filesystem::exists(new_idb_path_w)) {
        // ask the question
        const qstring question = new_idb_path + " Should the loader override the file? (will be overwritten)";
        override_db = ask_yn(ASKBTN_YES, question.c_str());
    }

    // answer == 1, yes-override it
    if (ASKBTN_CANCEL == override_db) {
        throw std::exception(UserCanceled);
    }
    if (ASKBTN_NO == override_db) {
        const std::string tmp1 = { ReloadIDADirect };
        const std::string tmp2 = tmp1 + file_name_s;
        throw std::exception(tmp2.c_str());
    }
}

void fix_naming_and_env(std::string& file_name_s,
                        std::string& desired_arc_str,
                        qstring& new_path,
                        qstring& new_idb_path,
                        std::wstring& new_path_idb_w)
{
    qstring directory;
    const qstring qfile_path = { get_path(PATH_TYPE_CMD) };
    const size_t last_slash_idx = qfile_path.rfind('\\');
    if (std::string::npos != last_slash_idx)
    {
        directory = qfile_path.substr(0, last_slash_idx);
    }

    // for x32 files
    if (desired_arc_str == x32bit) {
        new_path = path_append(directory, file_name_s.c_str());
        new_idb_path = new_path + ".idb";
    }
    // for x64 files
    else {
        new_path = path_append(directory, file_name_s.c_str());
        new_idb_path = new_path + ".i" + desired_arc_str.c_str();
    }

    set_path(PATH_TYPE_CMD, new_path.c_str());
    set_path(PATH_TYPE_IDB, new_idb_path.c_str());
    set_root_filename(new_path.c_str());
    new_path_idb_w = ascii2unicode(new_idb_path.c_str());
}

void extract_zipped_file_to_buffer(std::string& file_name_s, std::vector< bit7z::byte_t >& file_buffer)
{
    std::wstring archive_name_w = ascii2unicode(get_path(PATH_TYPE_CMD));

    bit7z::Bit7zLibrary lib{ ZipDllName };
    bit7z::BitArchiveInfo arc{ lib, archive_name_w, bit7z::BitFormat::Zip };
    bit7z::BitExtractor extractor{ lib, bit7z::BitFormat::Zip };

    qstring password = { ZipDefaultPass };
    std::wstring password_w;
    if (!arc.isPasswordDefined()) {
        // ask the user for a password with "infected" being the default one.
        int entered_pass = ask_str(&password, 1, EnterZipPass);
        password_w = ascii2unicode(password.c_str());
        // if the user pressed cancel, exit
        if (entered_pass != ASKBTN_YES)
        {
            throw std::exception(UserCanceled);
        }
        extractor.setPassword(password_w);
    }

    auto arc_items = arc.items();
    qstrvec_t file_names;
    std::wstring file_name;
    for (auto& item : arc_items) {
        if (!item.isDir()) {
            // Format a nice string here, add index + size + x64 + format (user loader) ?
            file_name = std::to_wstring(item.index() + 1) + L". " + item.name() + L" - " + std::to_wstring(item.size()) + L" - " + item.extension();
            qstring qstring_tmp = { unicode2ascii(file_name.c_str()) };
            file_names.add(qstring_tmp);
        }
    }

    // display options to the user with file info
    uval_t ret_val = 0;
    uval_t form_answer = 0;
    bool choose_file_ans = ask_form(ChooseFileFromZip, &file_names, &form_answer, &ret_val);

    if (choose_file_ans != ASKBTN_YES) {
        throw std::exception(UserCanceled);
    }

    if (form_answer < 0 || form_answer >= file_names.size()) {
        throw std::exception(DidNotChooseFile);
    }

    try {
        extractor.extract(archive_name_w, file_buffer, (unsigned int)form_answer);
    }
    catch (const std::exception&) {
        std::string tmp1 = { password.c_str() };
        std::string tmp2 = {  };
        std::string tmp3 = "Could not open " + tmp2 + " with password: " + tmp1;
        throw std::exception(tmp3.c_str());
    }

    auto selected_item_name = arc_items.at(form_answer).name();
    file_name_s = unicode2ascii(selected_item_name.c_str());
}

void destroy_linput(linput_t* li)
{
    close_linput(li);
}

linput_t* create_linput(std::vector< bit7z::byte_t >& file_buffer)
{
    return create_bytearray_linput(file_buffer.data(), file_buffer.size());
}

void destroy_linfos(load_info_t* linfos)
{
    free_loaders_list(linfos);
}

load_info_t* create_linfos(linput_t* li)
{
    return build_loaders_list(li, "");
}
