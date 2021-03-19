#pragma once
#include "pch.h"

#ifdef _EXPORTING
#define CLASS_DECLSPEC    __declspec(dllexport)
#else
#define CLASS_DECLSPEC    __declspec(dllimport)
#endif

/// <summary>
/// * Setting up base address
/// * Check if PE architecture matches IDA architecture
/// * Loading all til files for windows to get as many symbols as possible with FLIRT.
/// </summary>
/// <param name="file_buffer">file buffer as byte array</param>
/// <param name="file_name_s">file name as string</param>
/// <param name="set_arc">boolean parameter to represent if architecture was set</param>
CLASS_DECLSPEC
void handle_loaded_pe(
    const std::vector< bit7z::byte_t >& file_buffer,
    const std::string& file_name_s,
    bool& set_arc
);

/// <summary>
/// Check if the ELF architecture matches the IDA architecture.
/// </summary>
/// <param name="file_buffer">file buffer as byte array</param>
/// <param name="set_arc">boolean parameter to represent if architecture was set</param>
CLASS_DECLSPEC
void handle_loaded_elf(
    const std::vector< bit7z::byte_t >& file_buffer,
    bool& set_arc
);


/// <summary>
/// Handles loading a file from a buffer, doing a best effort.
/// *. Try to match with the best loader IDA has to offer.
///        *. If no loader is found load the file as binary (user is asked).    
/// *. If a proper loader was found load the file with it into the db. Of course without creating an actual file.
///        *. Fix compiler, id the compiler is not set to try to guess it.
/// *. Extra logic for PE, and ELF.
/// </summary>
/// <param name="linfos">IDA loader information</param>
/// <param name="li2">linput of IDA</param>
/// <param name="file_buffer">file buffer as byte array</param>
/// <param name="desired_arc_str">a string representation of the architecture</param>
/// <param name="file_name_s">file name as string</param>
/// <param name="set_arc">boolean parameter to represent if architecture was set</param>
CLASS_DECLSPEC
void handle_file_loading(
    load_info_t* linfos,
    linput_t* li2,
    const std::vector< bit7z::byte_t >& file_buffer,
    const std::string& desired_arc_str,
    const std::string& file_name_s,
    bool& set_arc
);

/// <summary>
/// Check if the buffer is a shellcode and handle if it is. We thought
/// that many times a researcher would need such functionality.
/// for shellcode reversing.
/// </summary>
/// <param name="file_buffer">file buffer as byte array</param>
CLASS_DECLSPEC
void parse_as_shellcode(const std::vector< bit7z::byte_t >& file_buffer);

/// <summary>
/// Tells if IDA architecture was set already, if its not set it.
/// </summary>
/// <param name="set_arc">boolean parameter to represent if architecture was set</param>
/// <param name="desired_arc_str">a string representation of the architecture</param>
CLASS_DECLSPEC
void validate_architecture_set(bool& set_arc, std::string& desired_arc_str);

/// <summary>
/// Sets IDA to 64 or 32 bit address space
/// </summary>
/// <param name="desired_arc_str">string representation of the architecture</param>
CLASS_DECLSPEC
void retrieve_target_architecture(std::string& desired_arc_str);

/// <summary>
/// Check in the directory we started the IDA process if a db filename with the same name as the we extracted
/// already exists. If it does, ask we should override it.
/// </summary>
/// <param name="new_idb_path_w">wide string representation of the IDB path</param>
/// <param name="new_idb_path">path to the new IDB path as qstring</param>
/// <param name="file_name_s">file name as string</param>
/// <param name="override_db">should override db flag</param>
CLASS_DECLSPEC
void check_override_db_file(
                        std::wstring& new_idb_path_w,
                        qstring& new_idb_path,
                        std::string& file_name_s,
                        int& override_db);

/// <summary>
/// Handle all the changes to the IDA environment. This produces: IDB files and temporary files with
/// corresponding names to the file you are reversing. Try to mimic the same behavior.
/// </summary>
/// <param name="file_name_s">file name as string</param>
/// <param name="desired_arc_str">string representation of the architecture</param>
/// <param name="new_path">New path for the file</param>
/// <param name="new_idb_path">New IDB path of the reversed file</param>
/// <param name="new_path_idb_w">wide string representation of the path of the file</param>
CLASS_DECLSPEC
void fix_naming_and_env(std::string& file_name_s,
                        std::string& desired_arc_str,
                        qstring& new_path,
                        qstring& new_idb_path,
                        std::wstring& new_path_idb_w);

/// <summary>
/// Extracts file from Zip into a buffer. Will display a drop-box with files in zips. 
/// </summary>
/// <param name="file_name_s">file name as string</param>
/// <param name="file_buffer">file buffer to fill</param>
CLASS_DECLSPEC
void extract_zipped_file_to_buffer(std::string& file_name_s,
                            std::vector< bit7z::byte_t >& file_buffer);

/// <summary>
/// Using unique pointers syntax in order to make sure we free the resource used in allocating
/// input object for IDA db and its possible loaders list.
/// https://en.cppreference.com/w/cpp/memory/unique_ptr
/// </summary>
template <auto fn>
using deleter_from_fn = std::integral_constant<decltype(fn), fn>;
template <typename T, auto fn>
using unique_ptr_s1 = std::unique_ptr<T, deleter_from_fn<fn>>;

/// <summary>
/// Wrapper for freeing li memory.
/// </summary>
/// <param name="li">loader input source</param>
CLASS_DECLSPEC
void destroy_linput(linput_t* li);

/// <summary>
/// Wrapper for creating a linput object that represents loader input source.
/// </summary>
/// <param name="file_buffer">vector of bytes</param>
/// <returns>loader input source pointer</returns>
CLASS_DECLSPEC
linput_t* create_linput(std::vector< bit7z::byte_t >& file_buffer);

/// <summary>
/// Free the list of loaders.
/// </summary>
/// <param name="linfos"></param>
CLASS_DECLSPEC
void destroy_linfos(load_info_t* linfos);

/// <summary>
/// Generate a list a list of loaders for loader input source.
/// </summary>
/// <param name="li">loader input source pointer</param>
/// <returns>List of loaders</returns>
CLASS_DECLSPEC
load_info_t* create_linfos(linput_t* li);
