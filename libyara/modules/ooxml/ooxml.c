/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <string.h>
#include <yara/modules.h>
#include <yara/endian.h>
#include <yara/ooxml.h>

#define MODULE_NAME ooxml

// Helper functions 
static uint32_t read_le32(const uint8_t* data, size_t offset, size_t max_size) {
    if (offset + sizeof(uint32_t) > max_size) return 0;
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    return yr_le32toh(value);
}

static uint16_t read_le16(const uint8_t* data, size_t offset, size_t max_size) {
    if (offset + sizeof(uint16_t) > max_size) return 0;
    uint16_t value;
    memcpy(&value, data + offset, sizeof(uint16_t));
    return yr_le16toh(value);
}

static const char* lookup_compression(uint16_t id) {
    for (int i = 0; COMPRESSION_METHODS[i].name != NULL; i++) {
        if (COMPRESSION_METHODS[i].id == id) {
            return COMPRESSION_METHODS[i].name;
        }
    }
    return "Unknown";
}

static const char* lookup_os(uint8_t id) {
    for (int i = 0; HOST_OS_SYSTEMS[i].name != NULL; i++) {
        if (HOST_OS_SYSTEMS[i].id == id) {
            return HOST_OS_SYSTEMS[i].name;
        }
    }
    return "Unknown";
}

begin_declarations;
    begin_struct_array("entries");
        declare_string("name_string");
        declare_integer("name_length");
        declare_integer("compressed_size");
        declare_integer("uncompressed_size");
        declare_integer("crc32_checksum");
        declare_integer("compression_method_value");
        declare_string("compression_method_name");
        declare_integer("mod_time_raw");
        declare_integer("mod_date_raw");
        declare_integer("flags");
        declare_integer("version_needed");

        declare_integer("version_made_by");
        declare_string("os_name");
        declare_integer("spec_version");
    end_struct_array("entries");

    declare_integer("is_ooxml");
    declare_integer("number_of_on_disk_entries");
    declare_integer("number_of_total_entries");
    declare_integer("central_dir_size");
    declare_integer("central_dir_offset");
    declare_integer("zip_comment_len");
    declare_string("zip_comment_str");
end_declarations;

int module_initialize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module) {
    return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context, 
    YR_OBJECT* module_object, 
    void* module_data, 
    size_t module_data_size) 
  {
    
    YR_MEMORY_BLOCK* block = first_memory_block(context);
    if (block == NULL) return ERROR_SUCCESS;

    const uint8_t* data = block->fetch_data(block);
    if (data == NULL) return ERROR_SUCCESS;
    
    size_t data_size = block->size;
    if (data_size < 22) return ERROR_SUCCESS; // Smallest PKZIP File Check

    uint32_t signature = read_le32(data, 0, data_size);
    if (signature != SIG_LOCAL_FILE_HEADER) {
        return ERROR_SUCCESS; // PKZIP File Header Check
    }

    size_t eocd_offset = 0;
    int found_eocd = 0;

    size_t max_comment_size = 65535;
    size_t scanable_space = data_size - 22;
    
    // Only scan the smaller of the max comment size or the available file space
    size_t scan_len = (scanable_space > max_comment_size) ? max_comment_size : scanable_space;

    for (size_t i = 0; i < scan_len; i++) {
        size_t current_idx = data_size - 22 - i;
        // PKZIP File Trailer Check from end of file
        if (data[current_idx] == 0x50 && 
            data[current_idx + 1] == 0x4b && 
            data[current_idx + 2] == 0x05 && 
            data[current_idx + 3] == 0x06) {
            
            uint16_t comment_len = read_le16(data, current_idx + 20, data_size);
            if (current_idx + 22 + comment_len == data_size) {
                eocd_offset = current_idx;
                found_eocd = 1;
                break;
            }
        }
    }

    if (!found_eocd) return ERROR_SUCCESS;

    // EOCD (End of Central Directory) data
    uint16_t on_dsk_cd_num = read_le16(data, eocd_offset + 8, data_size);
    uint16_t total_entries = read_le16(data, eocd_offset + 10, data_size);
    uint32_t cd_size = read_le32(data, eocd_offset + 12, data_size);
    uint32_t cd_offset = read_le32(data, eocd_offset + 16, data_size);
    uint16_t comment_len = read_le16(data, eocd_offset + 20, data_size);

    yr_set_integer(on_dsk_cd_num, module_object, "number_of_on_disk_entries");
    yr_set_integer(total_entries, module_object, "number_of_total_entries");
    yr_set_integer(cd_size, module_object, "central_dir_size");
    yr_set_integer(cd_offset, module_object, "central_dir_offset");
    yr_set_integer(comment_len, module_object, "zip_comment_len");


    if (comment_len > 0 && (eocd_offset + 22 + comment_len <= data_size)) {
        yr_set_sized_string((const char*)(data + eocd_offset + 22), comment_len, module_object, "zip_comment_str");
    }

    if (cd_offset + cd_size > data_size) return ERROR_SUCCESS;


    size_t current_offset = cd_offset;
    int found_content_types = 0;

    for (int i = 0; i < total_entries; i++) {
        if (current_offset + 46 > data_size) break; 

        if (read_le32(data, current_offset, data_size) != SIG_CENTRAL_DIR) break;

        // Below 3 are required to dynamically calculate and update the offset to next entry
        uint16_t fname_len = read_le16(data, current_offset + 28, data_size);
        uint16_t extra_len = read_le16(data, current_offset + 30, data_size);
        uint16_t file_comment_len = read_le16(data, current_offset + 32, data_size);
        
        if (fname_len == 19) {
            if (current_offset + 46 + 19 <= data_size) {
            const char* name_ptr = (const char*)(data + current_offset + 46);
            if (memcmp(name_ptr, "[Content_Types].xml", 19) == 0) {
                found_content_types = 1; // Check for [Content_Types].xml in first few entries to qualify as ooxml
            }
          }  
        }

        // CD (Central Directory) Entry Data
        uint16_t version_made = read_le16(data, current_offset + 4, data_size);
        uint8_t spec_ver_raw = (version_made & 0xFF);

        uint16_t version_need = read_le16(data, current_offset + 6, data_size);
        uint16_t flag = read_le16(data, current_offset + 8, data_size);
        uint16_t compress_method = read_le16(data, current_offset + 10, data_size);
        uint16_t dos_time_raw = read_le16(data, current_offset + 12, data_size);
        uint16_t dos_date_raw = read_le16(data, current_offset + 14, data_size);
        uint32_t crc32 = read_le32(data, current_offset + 16, data_size);
        uint32_t comp_size = read_le32(data, current_offset + 20, data_size);
        uint32_t uncomp_size = read_le32(data, current_offset + 24, data_size);
        

        if (current_offset + 46 + fname_len > data_size) break;

        yr_set_integer(found_content_types, module_object, "is_ooxml");
        yr_set_integer(version_made, module_object, "entries[%i].version_made_by", i);
        yr_set_integer(version_need, module_object, "entries[%i].version_needed", i);
        yr_set_integer(flag, module_object, "entries[%i].flags", i);
        yr_set_integer(compress_method, module_object, "entries[%i].compression_method_value", i);
        yr_set_integer(crc32, module_object, "entries[%i].crc32_checksum", i);
        yr_set_integer(comp_size, module_object, "entries%i].compressed_size", i);
        yr_set_integer(uncomp_size, module_object, "entries[%i].uncompressed_size", i);
        yr_set_integer(dos_time_raw, module_object, "entries[%i].mod_time_raw", i);
        yr_set_integer(dos_date_raw, module_object, "entries[%i].mod_date_raw", i);
        
        yr_set_string(lookup_compression(compress_method), module_object, "entries[%i].compression_method_name", i);
        yr_set_string(lookup_os(version_made >> 8), module_object, "entries[%i].os_name", i);
        yr_set_integer(spec_ver_raw, module_object, "entries[%i].spec_version", i);

        if (fname_len > 0) {
            yr_set_sized_string((const char*)(data + current_offset + 46), fname_len, module_object, "entries[%i].name_string", i);
            yr_set_integer(fname_len, module_object, "entries[%i].name_length", i);
        }

        current_offset += 46 + fname_len + extra_len + file_comment_len;

    }

    return ERROR_SUCCESS;
}  

int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME


