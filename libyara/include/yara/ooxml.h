/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#ifndef _OOXML_H
#define _OOXML_H

#include <yara/integers.h>

#define SIG_LOCAL_FILE_HEADER 0x04034b50
#define SIG_CENTRAL_DIR 0x02014b50
#define SIG_END_OF_CENTRAL_DIR 0x06054b50

typedef struct {
    uint16_t id;
    const char* name;
} CompressionMethod;

static const CompressionMethod COMPRESSION_METHODS[] = {
    {8, "Deflate"},
    {0, "Store"},    
    {9, "Deflate64"},
    {14, "LZMA"},
    {12, "BZIP2"},
    {1, "Shrink"},
    {2, "Reduce1"},
    {3, "Reduce2"},
    {4, "Reduce3"},
    {5, "Reduce4"},
    {6, "Implode"},
    {98, "PPMd"},
    {19, "LZ77"},
    {0, NULL}
};

typedef struct {
    uint8_t id;
    const char* name;
} HostOS;

static const HostOS HOST_OS_SYSTEMS[] = {
    {0, "FAT"},
    {1, "Amiga"},
    {2, "VMS"},
    {3, "Unix"},
    {4, "VM/CMS"},
    {5, "Atari ST"},
    {6, "HPFS"},
    {7, "Macintosh"},
    {10, "NTFS"},
    {11, "MVS"},
    {14, "VFAT"},
    {18, "IBM OS/2"},
    {19, "Macintosh OSX"},
    {0, NULL}
};

#define FLAG_ENCRYPTED      0x0001 // Bit 0
#define FLAG_COMP_OPT1      0x0002 // Bit 1
#define FLAG_COMP_OPT2      0x0004 // Bit 2
#define FLAG_DATA_DESC      0x0008 // Bit 3
#define FLAG_ENHANCED_DEF   0x0010 // Bit 4
#define FLAG_PATCHED        0x0020 // Bit 5
#define FLAG_STRONG_ENC     0x0040 // Bit 6
#define FLAG_UTF8           0x0800 // Bit 11
#define FLAG_MASK_HEADER    0x2000 // Bit 13

#pragma pack(push, 1)

typedef struct 
{
    uint32_t signature;
    uint16_t disk_number; //Not Used
    uint16_t start_disk_position;  //Not Used
    uint16_t total_entries_on_disk;
    uint16_t total_entries;
    uint32_t size_central_dir;
    uint32_t offset_central_dir;
    uint16_t zip_comment_len;
} ooxml_end_of_central_directory_record;

typedef struct 
{
    uint32_t signature;          
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t flags;              
    uint16_t compression_method;
    uint16_t last_mod_time;      
    uint16_t last_mod_date;    
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
    uint16_t file_comment_len;
    uint16_t disk_number_start;
    uint16_t internal_attrs;
    uint32_t external_attrs;
    uint32_t relative_offset; 
} ooxml_central_directory_file_header;

#pragma pack(pop)

#endif
