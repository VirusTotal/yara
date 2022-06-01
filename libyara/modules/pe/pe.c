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

#include <ctype.h>
#include <stdio.h>
#include <time.h>

#include "../crypto.h"
#if defined(HAVE_LIBCRYPTO)
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_get_signature_nid(o) OBJ_obj2nid((o)->sig_alg->algorithm)
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter  X509_get_notAfter
#endif
#endif

#include <yara/dotnet.h>
#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/pe.h>
#include <yara/pe_utils.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#define MODULE_NAME pe

#define IMPORT_STANDARD 1
#define IMPORT_DELAYED  2
#define IMPORT_ANY      (~0)

// http://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
#define RESOURCE_TYPE_CURSOR       1
#define RESOURCE_TYPE_BITMAP       2
#define RESOURCE_TYPE_ICON         3
#define RESOURCE_TYPE_MENU         4
#define RESOURCE_TYPE_DIALOG       5
#define RESOURCE_TYPE_STRING       6
#define RESOURCE_TYPE_FONTDIR      7
#define RESOURCE_TYPE_FONT         8
#define RESOURCE_TYPE_ACCELERATOR  9
#define RESOURCE_TYPE_RCDATA       10
#define RESOURCE_TYPE_MESSAGETABLE 11
#define RESOURCE_TYPE_GROUP_CURSOR \
  12  // MAKEINTRESOURCE((ULONG_PTR)(RT_CURSOR) + 11)
#define RESOURCE_TYPE_GROUP_ICON \
  14  // MAKEINTRESOURCE((ULONG_PTR)(RT_ICON) + 11)
#define RESOURCE_TYPE_VERSION    16
#define RESOURCE_TYPE_DLGINCLUDE 17
#define RESOURCE_TYPE_PLUGPLAY   19
#define RESOURCE_TYPE_VXD        20
#define RESOURCE_TYPE_ANICURSOR  21
#define RESOURCE_TYPE_ANIICON    22
#define RESOURCE_TYPE_HTML       23
#define RESOURCE_TYPE_MANIFEST   24

#define RESOURCE_CALLBACK_CONTINUE 0
#define RESOURCE_CALLBACK_ABORT    1

#define RESOURCE_ITERATOR_FINISHED 0
#define RESOURCE_ITERATOR_ABORTED  1

#define MAX_PE_IMPORTS         16384
#define MAX_PE_EXPORTS         8192
#define MAX_EXPORT_NAME_LENGTH 512
#define MAX_RESOURCES          65536

#define IS_RESOURCE_SUBDIRECTORY(entry) \
  (yr_le32toh((entry)->OffsetToData) & 0x80000000)

#define RESOURCE_OFFSET(entry) (yr_le32toh((entry)->OffsetToData) & 0x7FFFFFFF)

typedef int (*RESOURCE_CALLBACK_FUNC)(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    const IMAGE_RESOURCE_DIR_STRING_U* type_string,
    const IMAGE_RESOURCE_DIR_STRING_U* name_string,
    const IMAGE_RESOURCE_DIR_STRING_U* lang_string,
    void* cb_data);

static size_t available_space(PE* pe, void* pointer)
{
  if ((uint8_t*) pointer < pe->data)
    return 0;

  if ((uint8_t*) pointer >= pe->data + pe->data_size)
    return 0;

  return pe->data + pe->data_size - (uint8_t*) pointer;
}

static int wide_string_fits_in_pe(PE* pe, char* data)
{
  size_t i = 0;
  size_t space_left = available_space(pe, data);

  while (space_left >= 2)
  {
    if (data[i] == 0 && data[i + 1] == 0)
      return 1;
    space_left -= 2;
    i += 2;
  }

  return 0;
}

// Parse the rich signature.
// http://www.ntcore.com/files/richsign.htm

static void pe_parse_rich_signature(PE* pe, uint64_t base_address)
{
  PIMAGE_DOS_HEADER mz_header;
  PRICH_SIGNATURE rich_signature = NULL;

  DWORD* rich_ptr = NULL;
  BYTE* raw_data = NULL;
  BYTE* clear_data = NULL;
  DWORD* p = NULL;
  uint32_t nthdr_offset = 0;
  uint32_t key = 0;
  size_t rich_len = 0;

  if (pe->data_size < sizeof(IMAGE_DOS_HEADER))
    return;

  mz_header = (PIMAGE_DOS_HEADER) pe->data;

  if (yr_le16toh(mz_header->e_magic) != IMAGE_DOS_SIGNATURE)
    return;

  // To find the Rich marker we start at the NT header and work backwards, so
  // make sure we have at least enough data to get to the NT header.
  nthdr_offset = yr_le32toh(mz_header->e_lfanew);
  if (nthdr_offset > pe->data_size + sizeof(uint32_t) || nthdr_offset < 4)
    return;

  // Most files have the Rich header at offset 0x80, but that is not always
  // true. 582ce3eea9c97d5e89f7d83953a6d518b16770e635a19a456c0225449c6967a4 is
  // one sample which has a Rich header starting at offset 0x200. To properly
  // find the Rich header we need to start at the NT header and work backwards.
  p = (DWORD*) (pe->data + nthdr_offset - 4);

  while (p >= (DWORD*) (pe->data + sizeof(IMAGE_DOS_HEADER)))
  {
    if (yr_le32toh(*p) == RICH_RICH)
    {
      // The XOR key is the dword following the Rich value. We  use this to find
      // DanS header only.
      key = *(p + 1);
      rich_ptr = p;
      --p;
      break;
    }

    // The NT header is 8 byte aligned so we can move back in 4 byte increments.
    --p;
  }

  // If we haven't found a key we can skip processing the rest.
  if (key == 0)
    return;

  // If we have found the key we need to now find the start (DanS).
  while (p >= (DWORD*) (pe->data + sizeof(IMAGE_DOS_HEADER)))
  {
    if (yr_le32toh((*(p) ^ key)) == RICH_DANS)
    {
      rich_signature = (PRICH_SIGNATURE) p;
      break;
    }

    --p;
  }

  if (rich_signature == NULL)
    return;

  // The three key values must all be equal and the first dword
  // XORs to "DanS". Then walk the buffer looking for "Rich" which marks the
  // end. Technically the XOR key should be right after "Rich" but it's not
  // important.

  if (yr_le32toh(rich_signature->key1) != yr_le32toh(rich_signature->key2) ||
      yr_le32toh(rich_signature->key2) != yr_le32toh(rich_signature->key3) ||
      (yr_le32toh(rich_signature->dans) ^ yr_le32toh(rich_signature->key1)) !=
          RICH_DANS)
  {
    return;
  }

  // Multiple by 4 because we are counting in DWORDs.
  rich_len = (rich_ptr - (DWORD*) rich_signature) * 4;
  raw_data = (BYTE*) yr_malloc(rich_len);

  if (!raw_data)
    return;

  memcpy(raw_data, rich_signature, rich_len);

  set_integer(
      base_address + ((uint8_t*) rich_signature - pe->data),
      pe->object,
      "rich_signature.offset");

  set_integer(rich_len, pe->object, "rich_signature.length");

  set_integer(
      yr_le32toh(rich_signature->key1), pe->object, "rich_signature.key");

  clear_data = (BYTE*) yr_malloc(rich_len);

  if (!clear_data)
  {
    yr_free(raw_data);
    return;
  }

  // Copy the entire block here to be XORed.
  memcpy(clear_data, raw_data, rich_len);

  for (rich_ptr = (DWORD*) clear_data;
       rich_ptr < (DWORD*) (clear_data + rich_len);
       rich_ptr++)
  {
    *rich_ptr ^= rich_signature->key1;
  }

  set_sized_string(
      (char*) raw_data, rich_len, pe->object, "rich_signature.raw_data");

  set_sized_string(
      (char*) clear_data, rich_len, pe->object, "rich_signature.clear_data");

  yr_free(raw_data);
  yr_free(clear_data);
}

static void pe_parse_debug_directory(PE* pe)
{
  PIMAGE_DATA_DIRECTORY data_dir;
  PIMAGE_DEBUG_DIRECTORY debug_dir;
  int64_t debug_dir_offset;
  int i, dcount;
  size_t pdb_path_len;
  char* pdb_path = NULL;

  data_dir = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_DEBUG);

  if (data_dir == NULL)
    return;

  if (yr_le32toh(data_dir->Size) == 0)
    return;

  if (yr_le32toh(data_dir->Size) % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
    return;

  if (yr_le32toh(data_dir->VirtualAddress) == 0)
    return;

  debug_dir_offset = pe_rva_to_offset(pe, yr_le32toh(data_dir->VirtualAddress));

  if (debug_dir_offset < 0)
    return;

  dcount = yr_le32toh(data_dir->Size) / sizeof(IMAGE_DEBUG_DIRECTORY);

  for (i = 0; i < dcount; i++)
  {
    int64_t pcv_hdr_offset = 0;

    debug_dir =
        (PIMAGE_DEBUG_DIRECTORY) (pe->data + debug_dir_offset + i * sizeof(IMAGE_DEBUG_DIRECTORY));

    if (!struct_fits_in_pe(pe, debug_dir, IMAGE_DEBUG_DIRECTORY))
      break;

    if (yr_le32toh(debug_dir->Type) != IMAGE_DEBUG_TYPE_CODEVIEW)
      continue;

    // The debug info offset may be present either as RVA or as raw offset
    // Sample: 0249e00b6d46bee5a17096559f18e671cd0ceee36373e8708f614a9a6c7c079e
    if (debug_dir->AddressOfRawData != 0)
    {
      pcv_hdr_offset = pe_rva_to_offset(
          pe, yr_le32toh(debug_dir->AddressOfRawData));
    }

    // Give it chance to read it from the RAW offset
    // Sample: 735f72b3fcd72789f01e923c9de2a9ab5b5ffbece23633da81d976ad0ad159e3
    if (pcv_hdr_offset <= 0 && debug_dir->PointerToRawData != 0)
    {
      pcv_hdr_offset = yr_le32toh(debug_dir->PointerToRawData);
    }

    if (pcv_hdr_offset <= 0)
      continue;

    PCV_HEADER cv_hdr = (PCV_HEADER) (pe->data + pcv_hdr_offset);

    if (!struct_fits_in_pe(pe, cv_hdr, CV_HEADER))
      continue;

    if (yr_le32toh(cv_hdr->dwSignature) == CVINFO_PDB20_CVSIGNATURE)
    {
      PCV_INFO_PDB20 pdb20 = (PCV_INFO_PDB20) cv_hdr;

      if (struct_fits_in_pe(pe, pdb20, CV_INFO_PDB20))
        pdb_path = (char*) (pdb20->PdbFileName);
    }
    else if (yr_le32toh(cv_hdr->dwSignature) == CVINFO_PDB70_CVSIGNATURE)
    {
      PCV_INFO_PDB70 pdb70 = (PCV_INFO_PDB70) cv_hdr;

      if (struct_fits_in_pe(pe, pdb70, CV_INFO_PDB70))
        pdb_path = (char*) (pdb70->PdbFileName);
    }
    else if (yr_le32toh(cv_hdr->dwSignature) == CODEVIEW_SIGNATURE_MTOC)
    {
      PMTOC_ENTRY mtoc = (PMTOC_ENTRY) cv_hdr;

      if (struct_fits_in_pe(pe, mtoc, MTOC_ENTRY))
        pdb_path = (char*) (mtoc->PdbFileName);
    }

    if (pdb_path != NULL)
    {
      pdb_path_len = strnlen(
          pdb_path, yr_min(available_space(pe, pdb_path), MAX_PATH));

      if (pdb_path_len > 0 && pdb_path_len < MAX_PATH)
      {
        set_sized_string(pdb_path, pdb_path_len, pe->object, "pdb_path");
        break;
      }
    }
  }
}

// Return a pointer to the resource directory string or NULL.
// The callback function will parse this and call set_sized_string().
// The pointer is guaranteed to have enough space to contain the entire string.

static const PIMAGE_RESOURCE_DIR_STRING_U parse_resource_name(
    PE* pe,
    const uint8_t* rsrc_data,
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry)
{
  // If high bit is set it is an offset relative to rsrc_data, which contains
  // a resource directory string.

  if (yr_le32toh(entry->Name) & 0x80000000)
  {
    const PIMAGE_RESOURCE_DIR_STRING_U pNameString =
        (PIMAGE_RESOURCE_DIR_STRING_U) (rsrc_data + (yr_le32toh(entry->Name) & 0x7FFFFFFF));

    // A resource directory string is 2 bytes for the length and then a variable
    // length Unicode string. Make sure we have at least 2 bytes.

    if (!fits_in_pe(pe, pNameString, 2))
      return NULL;

    // Move past the length and make sure we have enough bytes for the string.
    if (!fits_in_pe(
            pe, pNameString, sizeof(uint16_t) + pNameString->Length * 2))
      return NULL;

    return pNameString;
  }

  return NULL;
}

static int _pe_iterate_resources(
    PE* pe,
    PIMAGE_RESOURCE_DIRECTORY resource_dir,
    const uint8_t* rsrc_data,
    int rsrc_tree_level,
    int* type,
    int* id,
    int* language,
    const IMAGE_RESOURCE_DIR_STRING_U* type_string,
    const IMAGE_RESOURCE_DIR_STRING_U* name_string,
    const IMAGE_RESOURCE_DIR_STRING_U* lang_string,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int i, result = RESOURCE_ITERATOR_FINISHED;
  int total_entries;

  PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;

  // A few sanity checks to avoid corrupt files

  if (yr_le32toh(resource_dir->Characteristics) != 0 ||
      yr_le16toh(resource_dir->NumberOfNamedEntries) > 32768 ||
      yr_le16toh(resource_dir->NumberOfIdEntries) > 32768)
  {
    return result;
  }

  total_entries = yr_le16toh(resource_dir->NumberOfNamedEntries) +
                  yr_le16toh(resource_dir->NumberOfIdEntries);

  // The first directory entry is just after the resource directory,
  // by incrementing resource_dir we skip sizeof(resource_dir) bytes
  // and get a pointer to the end of the resource directory.

  entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (resource_dir + 1);

  for (i = 0; i < total_entries; i++)
  {
    if (!struct_fits_in_pe(pe, entry, IMAGE_RESOURCE_DIRECTORY_ENTRY))
    {
      result = RESOURCE_ITERATOR_ABORTED;
      break;
    }

    switch (rsrc_tree_level)
    {
    case 0:
      *type = yr_le32toh(entry->Name);
      type_string = parse_resource_name(pe, rsrc_data, entry);
      break;
    case 1:
      *id = yr_le32toh(entry->Name);
      name_string = parse_resource_name(pe, rsrc_data, entry);
      break;
    case 2:
      *language = yr_le32toh(entry->Name);
      lang_string = parse_resource_name(pe, rsrc_data, entry);
      break;
    }

    if (IS_RESOURCE_SUBDIRECTORY(entry) && rsrc_tree_level < 2)
    {
      PIMAGE_RESOURCE_DIRECTORY directory =
          (PIMAGE_RESOURCE_DIRECTORY) (rsrc_data + RESOURCE_OFFSET(entry));

      if (struct_fits_in_pe(pe, directory, IMAGE_RESOURCE_DIRECTORY))
      {
        result = _pe_iterate_resources(
            pe,
            directory,
            rsrc_data,
            rsrc_tree_level + 1,
            type,
            id,
            language,
            type_string,
            name_string,
            lang_string,
            callback,
            callback_data);
      }
      else
      {
        result = RESOURCE_ITERATOR_ABORTED;
      }
    }
    else
    {
      PIMAGE_RESOURCE_DATA_ENTRY data_entry =
          (PIMAGE_RESOURCE_DATA_ENTRY) (rsrc_data + RESOURCE_OFFSET(entry));

      if (struct_fits_in_pe(pe, data_entry, IMAGE_RESOURCE_DATA_ENTRY))
      {
        if (callback(
                data_entry,
                *type,
                *id,
                *language,
                type_string,
                name_string,
                lang_string,
                callback_data) == RESOURCE_CALLBACK_ABORT)
        {
          result = RESOURCE_ITERATOR_ABORTED;
        }
      }
      else
      {
        result = RESOURCE_ITERATOR_ABORTED;
      }
    }

    if (result == RESOURCE_ITERATOR_ABORTED)
      break;

    entry++;
  }

  return result;
}

static int pe_iterate_resources(
    PE* pe,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int64_t offset;

  int type = -1;
  int id = -1;
  int language = -1;

  IMAGE_RESOURCE_DIR_STRING_U* type_string = NULL;
  IMAGE_RESOURCE_DIR_STRING_U* name_string = NULL;
  IMAGE_RESOURCE_DIR_STRING_U* lang_string = NULL;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);

  if (directory == NULL)
    return 0;

  if (yr_le32toh(directory->VirtualAddress) != 0)
  {
    PIMAGE_RESOURCE_DIRECTORY rsrc_dir;

    offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

    if (offset < 0)
      return 0;

    rsrc_dir = (PIMAGE_RESOURCE_DIRECTORY) (pe->data + offset);

    if (struct_fits_in_pe(pe, rsrc_dir, IMAGE_RESOURCE_DIRECTORY))
    {
      set_integer(
          yr_le32toh(rsrc_dir->TimeDateStamp),
          pe->object,
          "resource_timestamp");

      set_integer(
          yr_le16toh(rsrc_dir->MajorVersion),
          pe->object,
          "resource_version.major");

      set_integer(
          yr_le16toh(rsrc_dir->MinorVersion),
          pe->object,
          "resource_version.minor");

      _pe_iterate_resources(
          pe,
          rsrc_dir,
          pe->data + offset,
          0,
          &type,
          &id,
          &language,
          type_string,
          name_string,
          lang_string,
          callback,
          callback_data);

      return 1;
    }
  }

  return 0;
}

// Align offset to a 32-bit boundary and add it to a pointer

#define ADD_OFFSET(ptr, offset) \
  (PVERSION_INFO)((uint8_t*) (ptr) + ((offset + 3) & ~3))

static void pe_parse_version_info(PIMAGE_RESOURCE_DATA_ENTRY rsrc_data, PE* pe)
{
  PVERSION_INFO version_info;

  int64_t version_info_offset = pe_rva_to_offset(
      pe, yr_le32toh(rsrc_data->OffsetToData));

  if (version_info_offset < 0)
    return;

  version_info = (PVERSION_INFO) (pe->data + version_info_offset);

  if (!struct_fits_in_pe(pe, version_info, VERSION_INFO))
    return;

  if (!fits_in_pe(pe, version_info->Key, sizeof("VS_VERSION_INFO") * 2))
    return;

  if (strcmp_w(version_info->Key, "VS_VERSION_INFO") != 0)
    return;

  version_info = ADD_OFFSET(version_info, sizeof(VERSION_INFO) + 86);

  while (fits_in_pe(pe, version_info->Key, sizeof("VarFileInfo") * 2) &&
         strcmp_w(version_info->Key, "VarFileInfo") == 0 &&
         yr_le16toh(version_info->Length) != 0)
  {
    version_info = ADD_OFFSET(version_info, yr_le16toh(version_info->Length));
  }

  while (fits_in_pe(pe, version_info->Key, sizeof("StringFileInfo") * 2) &&
         strcmp_w(version_info->Key, "StringFileInfo") == 0 &&
         yr_le16toh(version_info->Length) != 0)
  {
    PVERSION_INFO string_table = ADD_OFFSET(
        version_info, sizeof(VERSION_INFO) + 30);

    version_info = ADD_OFFSET(version_info, yr_le16toh(version_info->Length));

    while (struct_fits_in_pe(pe, string_table, VERSION_INFO) &&
           wide_string_fits_in_pe(pe, string_table->Key) &&
           yr_le16toh(string_table->Length) != 0 && string_table < version_info)
    {
      PVERSION_INFO string = ADD_OFFSET(
          string_table,
          sizeof(VERSION_INFO) + 2 * (strnlen_w(string_table->Key) + 1));

      string_table = ADD_OFFSET(string_table, yr_le16toh(string_table->Length));

      while (struct_fits_in_pe(pe, string, VERSION_INFO) &&
             wide_string_fits_in_pe(pe, string->Key) &&
             yr_le16toh(string->Length) != 0 && string < string_table)
      {
        char* string_value = (char*) ADD_OFFSET(
            string, sizeof(VERSION_INFO) + 2 * (strnlen_w(string->Key) + 1));

        if (wide_string_fits_in_pe(pe, string_value))
        {
          char key[64];
          char value[256];

          strlcpy_w(key, string->Key, sizeof(key));
          strlcpy_w(value, string_value, sizeof(value));

          // null terminator of string is not included in version value when
          // ValueLength is zero
          if (yr_le16toh(string->ValueLength) == 0)
            value[yr_le16toh(string->ValueLength)] = '\0';

          set_string(value, pe->object, "version_info[%s]", key);

          set_string(
              key, pe->object, "version_info_list[%i].key", pe->version_infos);

          set_string(
              value,
              pe->object,
              "version_info_list[%i].value",
              pe->version_infos);

          pe->version_infos += 1;
        }

        string = ADD_OFFSET(string, yr_le16toh(string->Length));
      }
    }
  }
}

static void pe_set_resource_string_or_id(
    IMAGE_RESOURCE_DIR_STRING_U* rsrc_string,
    int rsrc_int,
    const char* string_description,
    const char* int_description,
    PE* pe)
{
  if (rsrc_string)
  {
    // Multiply by 2 because it is a Unicode string.
    size_t length = rsrc_string->Length * 2;

    // Check if the whole string fits in the PE image.
    // If not, the name becomes UNDEFINED by default.
    if (fits_in_pe(pe, rsrc_string->NameString, length))
    {
      set_sized_string(
          (char*) rsrc_string->NameString,
          length,
          pe->object,
          string_description,
          pe->resources);
    }
  }
  else
  {
    set_integer(rsrc_int, pe->object, int_description, pe->resources);
  }
}

static int pe_collect_resources(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    IMAGE_RESOURCE_DIR_STRING_U* type_string,
    IMAGE_RESOURCE_DIR_STRING_U* name_string,
    IMAGE_RESOURCE_DIR_STRING_U* lang_string,
    PE* pe)
{
  // Don't collect too many resources.
  if (pe->resources > MAX_RESOURCES)
    return RESOURCE_CALLBACK_CONTINUE;

  set_integer(
      yr_le32toh(rsrc_data->OffsetToData),
      pe->object,
      "resources[%i].rva",
      pe->resources);

  int64_t offset = pe_rva_to_offset(pe, yr_le32toh(rsrc_data->OffsetToData));

  if (offset < 0)
    offset = YR_UNDEFINED;

  set_integer(offset, pe->object, "resources[%i].offset", pe->resources);

  set_integer(
      yr_le32toh(rsrc_data->Size),
      pe->object,
      "resources[%i].length",
      pe->resources);

  pe_set_resource_string_or_id(
      type_string,
      rsrc_type,
      "resources[%i].type_string",
      "resources[%i].type",
      pe);

  pe_set_resource_string_or_id(
      name_string,
      rsrc_id,
      "resources[%i].name_string",
      "resources[%i].id",
      pe);

  pe_set_resource_string_or_id(
      lang_string,
      rsrc_language,
      "resources[%i].language_string",
      "resources[%i].language",
      pe);

  // Resources we do extra parsing on
  if (rsrc_type == RESOURCE_TYPE_VERSION)
    pe_parse_version_info(rsrc_data, pe);

  pe->resources += 1;
  return RESOURCE_CALLBACK_CONTINUE;
}

static IMPORT_FUNCTION* pe_parse_import_descriptor(
    PE* pe,
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor,
    char* dll_name,
    int* num_function_imports)
{
  IMPORT_FUNCTION* head = NULL;
  IMPORT_FUNCTION* tail = NULL;

  int64_t offset = pe_rva_to_offset(
      pe, yr_le32toh(import_descriptor->OriginalFirstThunk));

  // I've seen binaries where OriginalFirstThunk is zero. In this case
  // use FirstThunk.

  if (offset <= 0)
    offset = pe_rva_to_offset(pe, yr_le32toh(import_descriptor->FirstThunk));

  if (offset < 0)
    return NULL;

  if (IS_64BITS_PE(pe))
  {
    PIMAGE_THUNK_DATA64 thunks64 = (PIMAGE_THUNK_DATA64) (pe->data + offset);

    while (struct_fits_in_pe(pe, thunks64, IMAGE_THUNK_DATA64) &&
           yr_le64toh(thunks64->u1.Ordinal) != 0 &&
           *num_function_imports < MAX_PE_IMPORTS)
    {
      char* name = NULL;
      uint16_t ordinal = 0;
      uint8_t has_ordinal = 0;

      if (!(yr_le64toh(thunks64->u1.Ordinal) & IMAGE_ORDINAL_FLAG64))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, yr_le64toh(thunks64->u1.Function));

        if (offset >= 0)
        {
          PIMAGE_IMPORT_BY_NAME import =
              (PIMAGE_IMPORT_BY_NAME) (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char*) yr_strndup(
                (char*) import->Name,
                yr_min(available_space(pe, import->Name), 512));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, yr_le64toh(thunks64->u1.Ordinal) & 0xFFFF);
        // Also store the ordinal.
        ordinal = yr_le64toh(thunks64->u1.Ordinal) & 0xFFFF;
        has_ordinal = 1;
      }

      if (name != NULL || has_ordinal == 1)
      {
        IMPORT_FUNCTION* imported_func = (IMPORT_FUNCTION*) yr_calloc(
            1, sizeof(IMPORT_FUNCTION));

        if (imported_func == NULL)
        {
          yr_free(name);
          continue;
        }

        imported_func->name = name;
        imported_func->ordinal = ordinal;
        imported_func->has_ordinal = has_ordinal;
        imported_func->next = NULL;

        if (head == NULL)
          head = imported_func;

        if (tail != NULL)
          tail->next = imported_func;

        tail = imported_func;
      }

      (*num_function_imports)++;
      thunks64++;
    }
  }
  else
  {
    PIMAGE_THUNK_DATA32 thunks32 = (PIMAGE_THUNK_DATA32) (pe->data + offset);

    while (struct_fits_in_pe(pe, thunks32, IMAGE_THUNK_DATA32) &&
           yr_le32toh(thunks32->u1.Ordinal) != 0 &&
           *num_function_imports < MAX_PE_IMPORTS)
    {
      char* name = NULL;
      uint16_t ordinal = 0;
      uint8_t has_ordinal = 0;

      if (!(yr_le32toh(thunks32->u1.Ordinal) & IMAGE_ORDINAL_FLAG32))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, yr_le32toh(thunks32->u1.Function));

        if (offset >= 0)
        {
          PIMAGE_IMPORT_BY_NAME import =
              (PIMAGE_IMPORT_BY_NAME) (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char*) yr_strndup(
                (char*) import->Name,
                yr_min(available_space(pe, import->Name), 512));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, yr_le32toh(thunks32->u1.Ordinal) & 0xFFFF);
        // Also store the ordinal.
        ordinal = yr_le32toh(thunks32->u1.Ordinal) & 0xFFFF;
        has_ordinal = 1;
      }

      if (name != NULL || has_ordinal == 1)
      {
        IMPORT_FUNCTION* imported_func = (IMPORT_FUNCTION*) yr_calloc(
            1, sizeof(IMPORT_FUNCTION));

        if (imported_func == NULL)
        {
          yr_free(name);
          continue;
        }

        imported_func->name = name;
        imported_func->ordinal = ordinal;
        imported_func->has_ordinal = has_ordinal;
        imported_func->next = NULL;

        if (head == NULL)
          head = imported_func;

        if (tail != NULL)
          tail->next = imported_func;

        tail = imported_func;
      }

      (*num_function_imports)++;
      thunks32++;
    }
  }

  return head;
}

//
// In Windows PE files, any character including 0x20 and above is allowed.
// The only exceptions are characters that are invalid for file names in
// Windows, which are "*<>?|. While they still can be present in the import
// directory, such module can never be present in Windows, so we can treat them
// as invalid.
//
// Explicit: The above also applies to slash, backslash (these form a relative
// path in a subdirectory, which is allowed in the import directory) and colon
// (which forms a file name with an Alternate Data Stream "test:file.dll" - also
// allowed).
//
// Proof of concept: https://github.com/ladislav-zezula/ImportTest
//
// Samples
// -------
// f561d60bff4342e529b2c793e216b73a72e6256f90ab24c3cc460646371130ca (imports
// "test/file.dll")
// b7f7b8a001769eb0f9c36cb27626b62cabdca9a716a222066028fcd206244b40 (imports
// "test\file.dll")
// 94cfb8223132da0a76f9dfbd35a29ab78e5806651758650292ab9c7baf2c0bc2 (imports
// "test:file.dll")
// eb2e2c443840276afe095fff05a3a24c00e610ac0e020233d6cd7a0b0b340fb1 (the
// imported DLL)
//

static int pe_valid_dll_name(const char* dll_name, size_t n)
{
  const unsigned char* c = (const unsigned char*) dll_name;
  size_t l = 0;

  while (l < n && *c != '\0')
  {
    if (*c < ' ' || *c == '\"' || *c == '*' || *c == '<' || *c == '>' ||
        *c == '?' || *c == '|')
    {
      return false;
    }

    c++;
    l++;
  }

  return (l > 0 && l < n);
}

void pe_set_imports(
    PE* pe,
    IMPORTED_DLL* dll,
    const char* dll_name,
    const char* dll_number_of_functions,
    const char* fun_name,
    const char* fun_ordinal)
{
  int dll_cnt = 0;
  int fun_cnt = 0;

  for (; dll != NULL; dll = dll->next, dll_cnt++)
  {
    for (IMPORT_FUNCTION* func = dll->functions; func != NULL;
         func = func->next, fun_cnt++)
    {
      set_string(func->name, pe->object, fun_name, dll_cnt, fun_cnt);
      if (func->has_ordinal)
        set_integer(func->ordinal, pe->object, fun_ordinal, dll_cnt, fun_cnt);
      else
        set_integer(YR_UNDEFINED, pe->object, fun_ordinal, dll_cnt, fun_cnt);
    }
    set_string(dll->name, pe->object, dll_name, dll_cnt);
    set_integer(fun_cnt, pe->object, dll_number_of_functions, dll_cnt);
  }
}

//
// Walk the imports and collect relevant information. It is used in the
// "imports" function for comparison and in the "imphash" function for
// calculation.
//

static IMPORTED_DLL* pe_parse_imports(PE* pe)
{
  int64_t offset;
  int num_imports = 0;           // Number of imported DLLs
  int num_function_imports = 0;  // Total number of functions imported

  IMPORTED_DLL* head = NULL;
  IMPORTED_DLL* tail = NULL;

  PIMAGE_IMPORT_DESCRIPTOR imports;
  PIMAGE_DATA_DIRECTORY directory;

  // Default to 0 imports until we know there are any
  set_integer(0, pe->object, "number_of_imports");
  set_integer(0, pe->object, "number_of_imported_functions");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

  if (directory == NULL)
    return NULL;

  if (yr_le32toh(directory->VirtualAddress) == 0)
    return NULL;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0)
    return NULL;

  imports = (PIMAGE_IMPORT_DESCRIPTOR) (pe->data + offset);

  while (struct_fits_in_pe(pe, imports, IMAGE_IMPORT_DESCRIPTOR) &&
         yr_le32toh(imports->Name) != 0 && num_imports < MAX_PE_IMPORTS)
  {
    int64_t offset = pe_rva_to_offset(pe, yr_le32toh(imports->Name));

    if (offset >= 0)
    {
      IMPORTED_DLL* imported_dll;

      char* dll_name = (char*) (pe->data + offset);

      if (!pe_valid_dll_name(dll_name, pe->data_size - (size_t) offset))
      {
        imports++;
        continue;
      }

      imported_dll = (IMPORTED_DLL*) yr_calloc(1, sizeof(IMPORTED_DLL));

      if (imported_dll != NULL)
      {
        IMPORT_FUNCTION* functions = pe_parse_import_descriptor(
            pe, imports, dll_name, &num_function_imports);

        if (functions != NULL)
        {
          imported_dll->name = yr_strdup(dll_name);
          ;
          imported_dll->functions = functions;
          imported_dll->next = NULL;

          if (head == NULL)
            head = imported_dll;

          if (tail != NULL)
            tail->next = imported_dll;

          tail = imported_dll;
        }
        else
        {
          yr_free(imported_dll);
        }
      }
    }

    num_imports++;
    imports++;
  }

  set_integer(num_imports, pe->object, "number_of_imports");
  set_integer(num_function_imports, pe->object, "number_of_imported_functions");
  pe_set_imports(
      pe,
      head,
      "import_details[%i].library_name",
      "import_details[%i].number_of_functions",
      "import_details[%i].functions[%i].name",
      "import_details[%i].functions[%i].ordinal");

  return head;
}

// Delay-import descriptors made by MS Visual C++ 6.0 have old format
// of delay import directory, where all entries are VAs (as opposite to RVAs
// from newer MS compilers). We convert the delay-import directory entries to
// RVAs by checking the lowest bit in the delay-import descriptor's Attributes
// value
uint64_t pe_normalize_delay_import_value(
    uint64_t image_base,
    uint64_t virtual_address)
{
  // Ignore zero items
  if (virtual_address != 0)
  {
    // Sample: 0fc4cb0620f95bdd624f2c78eea4d2b59594244c6671cf249526adf2f2cb71ec
    // Contains artificially created delay import directory with incorrect
    // values:
    //
    //  Attributes                      0x00000000 <-- Old MS delay import
    //  record, contains VAs NameRva                         0x004010e6
    //  ModuleHandleRva                 0x00000000
    //  DelayImportAddressTableRva      0x00001140 <-- WRONG! This is an RVA
    //  DelayImportNameTableRva         0x004010c0
    //  BoundDelayImportTableRva        0x00000000
    //  ...

    if (virtual_address > image_base)
    {
      virtual_address = virtual_address - image_base;
    }
  }

  return virtual_address;
}

int pe_is_termination_delay_import_entry(
    PIMAGE_DELAYLOAD_DESCRIPTOR importDescriptor)
{
  return (
      importDescriptor->Attributes.AllAttributes == 0 &&
      importDescriptor->DllNameRVA == 0 &&
      importDescriptor->ModuleHandleRVA == 0 &&
      importDescriptor->ImportAddressTableRVA == 0 &&
      importDescriptor->ImportNameTableRVA == 0 &&
      importDescriptor->BoundImportAddressTableRVA == 0 &&
      importDescriptor->UnloadInformationTableRVA == 0 &&
      importDescriptor->TimeDateStamp == 0);
}

char* pe_parse_delay_import_dll_name(PE* pe, uint64_t rva)
{
  const int64_t offset = pe_rva_to_offset(pe, rva);

  if (offset < 0)
    return NULL;

  char* dll_name = (char*) (pe->data + offset);

  if (!pe_valid_dll_name(dll_name, pe->data_size - (size_t) offset))
    return NULL;

  return yr_strdup(dll_name);
}

uint64_t pe_parse_delay_import_pointer(
    PE* pe,
    uint64_t pointerSize,
    uint64_t rva)
{
  const int64_t offset = pe_rva_to_offset(pe, rva);
  const uint8_t* data = pe->data + offset;

  if (!fits_in_pe(pe, data, pointerSize))
    return YR_UNDEFINED;

  if (IS_64BITS_PE(pe))
    return yr_le64toh(*(uint64_t*) data);
  else
    return yr_le32toh(*(uint32_t*) data);
}

static void* pe_parse_delayed_imports(PE* pe)
{
  int64_t offset;
  uint64_t num_imports = 0;           // Number of imported DLLs
  uint64_t num_function_imports = 0;  // Total number of functions imported
  uint64_t image_base = OptionalHeader(pe, ImageBase);
  uint64_t size_of_image = OptionalHeader(pe, SizeOfImage);
  uint64_t pointer_size = (IS_64BITS_PE(pe)) ? 8 : 4;
  uint64_t ordinal_mask = (IS_64BITS_PE(pe)) ? IMAGE_ORDINAL_FLAG64
                                             : IMAGE_ORDINAL_FLAG32;

  IMPORTED_DLL* head_dll = NULL;
  IMPORTED_DLL* tail_dll = NULL;

  IMPORT_FUNCTION* head_fun = NULL;
  IMPORT_FUNCTION* tail_fun = NULL;

  PIMAGE_DELAYLOAD_DESCRIPTOR import_descriptor = NULL;
  PIMAGE_DATA_DIRECTORY directory = NULL;

  // Default to 0 imports until we know there are any
  set_integer(0, pe->object, "number_of_delayed_imports");
  set_integer(0, pe->object, "number_of_delayed_imported_functions");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

  if (directory == NULL)
    return NULL;

  if (yr_le32toh(directory->VirtualAddress) == 0)
    return NULL;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0)
    return NULL;

  import_descriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR) (pe->data + offset);

  for (; struct_fits_in_pe(pe, import_descriptor, IMAGE_DELAYLOAD_DESCRIPTOR);
       import_descriptor++)
  {
    // Check for the termination entry
    if (pe_is_termination_delay_import_entry(import_descriptor))
      break;

    DWORD Attributes = yr_le32toh(import_descriptor->Attributes.AllAttributes);
    DWORD DllNameRVA = yr_le32toh(import_descriptor->DllNameRVA);
    DWORD ModuleHandleRVA = yr_le32toh(import_descriptor->ModuleHandleRVA);
    DWORD ImportAddressTableRVA = yr_le32toh(
        import_descriptor->ImportAddressTableRVA);
    DWORD ImportNameTableRVA = yr_le32toh(
        import_descriptor->ImportNameTableRVA);
    DWORD BoundImportAddressTableRVA = yr_le32toh(
        import_descriptor->BoundImportAddressTableRVA);
    DWORD UnloadInformationTableRVA = yr_le32toh(
        import_descriptor->UnloadInformationTableRVA);

    // Valid delayed import entry starts either with 0 or 0x01.
    // We strict require one of the valid values here
    if (Attributes > 0x1)
      break;

    // Convert older (MS Visual C++ 6.0) delay-import descriptor to newer one.
    // These delay-import descriptors are distinguishable by lowest bit in
    // rec.Attributes to be zero. Sample:
    // 2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4
    if (!IS_64BITS_PE(pe) && !Attributes)
    {
      DllNameRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, DllNameRVA);
      ModuleHandleRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, ModuleHandleRVA);
      ImportAddressTableRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, ImportAddressTableRVA);
      ImportNameTableRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, ImportNameTableRVA);
      BoundImportAddressTableRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, BoundImportAddressTableRVA);
      UnloadInformationTableRVA = (DWORD) pe_normalize_delay_import_value(
          image_base, UnloadInformationTableRVA);
    }

    // Stop on blatantly invalid delay import entries (old PELIB behavior)
    if (ImportNameTableRVA >= size_of_image ||
        ImportAddressTableRVA >= size_of_image ||
        DllNameRVA < sizeof(IMAGE_DOS_HEADER) ||
        ImportNameTableRVA < sizeof(IMAGE_DOS_HEADER))
      break;

    char* dll_name = pe_parse_delay_import_dll_name(pe, DllNameRVA);

    if (dll_name == NULL)
      continue;

    IMPORTED_DLL* imported_dll = (IMPORTED_DLL*) yr_calloc(
        1, sizeof(IMPORTED_DLL));

    if (imported_dll == NULL)
    {
      yr_free(dll_name);
      continue;
    }

    imported_dll->name = dll_name;
    imported_dll->next = NULL;
    imported_dll->functions = NULL;

    head_fun = tail_fun = NULL;

    uint64_t name_rva = ImportNameTableRVA;
    uint64_t func_rva = ImportAddressTableRVA;

    for (;;)
    {
      uint64_t nameAddress = pe_parse_delay_import_pointer(
          pe, pointer_size, name_rva);
      uint64_t funcAddress = pe_parse_delay_import_pointer(
          pe, pointer_size, func_rva);

      // Value of YR_UNDEFINED means that value is outside of pe->data
      if (nameAddress == YR_UNDEFINED || funcAddress == YR_UNDEFINED)
        break;

      // Value of zero means that this is the end of the bound import name table
      if (nameAddress == 0 || funcAddress == 0)
        break;

      IMPORT_FUNCTION* imported_func = (IMPORT_FUNCTION*) yr_malloc(
          sizeof(IMPORT_FUNCTION));

      if (imported_func == NULL)
        continue;

      imported_func->name = NULL;
      imported_func->has_ordinal = 0;
      imported_func->ordinal = 0;
      imported_func->next = NULL;

      // Check name address. It could be ordinal, VA or RVA
      if (!(nameAddress & ordinal_mask))
      {
        // Convert name address to RVA, if needed
        if (!Attributes)
          nameAddress = pe_normalize_delay_import_value(
              image_base, nameAddress);

        offset = pe_rva_to_offset(pe, nameAddress + sizeof(uint16_t));
        imported_func->name = (char*) yr_strndup(
            (char*) (pe->data + offset),
            yr_min(available_space(pe, (char*) (pe->data + offset)), 512));
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        imported_func->name = ord_lookup(
            dll_name, yr_le64toh(nameAddress) & 0xFFFF);
        // Also store the ordinal.
        imported_func->ordinal = yr_le64toh(nameAddress) & 0xFFFF;
        imported_func->has_ordinal = 1;
      }

      num_function_imports++;
      name_rva += pointer_size;
      func_rva += pointer_size;

      if (head_fun == NULL)
        head_fun = imported_func;

      if (tail_fun != NULL)
        tail_fun->next = imported_func;

      tail_fun = imported_func;
    }

    num_imports++;

    imported_dll->functions = head_fun;

    if (head_dll == NULL)
      head_dll = imported_dll;

    if (tail_dll != NULL)
      tail_dll->next = imported_dll;

    tail_dll = imported_dll;
  }

  set_integer(num_imports, pe->object, "number_of_delayed_imports");
  set_integer(
      num_function_imports, pe->object, "number_of_delayed_imported_functions");

  pe_set_imports(
      pe,
      head_dll,
      "delayed_import_details[%i].library_name",
      "delayed_import_details[%i].number_of_functions",
      "delayed_import_details[%i].functions[%i].name",
      "delayed_import_details[%i].functions[%i].ordinal");

  return head_dll;
}

//
// Walk the exports and collect relevant information. It is used in the
// "exports" function for comparison.
//

static void pe_parse_exports(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_EXPORT_DIRECTORY exports;

  int64_t offset;
  int64_t export_start;

  uint32_t i, j;
  uint32_t number_of_exports;
  uint32_t number_of_names;
  uint32_t ordinal_base;

  size_t export_size;
  size_t remaining;
  size_t name_len;

  uint32_t exp_sz = 0;
  DWORD* names = NULL;
  WORD* ordinals = NULL;
  DWORD* function_addrs = NULL;

  // If not a PE file, return YR_UNDEFINED

  if (pe == NULL)
    return;

  // Default to 0 exports until we know there are any
  set_integer(0, pe->object, "number_of_exports");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

  if (directory == NULL)
    return;

  if (yr_le32toh(directory->VirtualAddress) == 0)
    return;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0)
    return;

  export_start = offset;
  export_size = yr_le32toh(directory->Size);

  exports = (PIMAGE_EXPORT_DIRECTORY) (pe->data + offset);

  if (!struct_fits_in_pe(pe, exports, IMAGE_EXPORT_DIRECTORY))
    return;

  number_of_exports = yr_min(
      yr_le32toh(exports->NumberOfFunctions), MAX_PE_EXPORTS);

  ordinal_base = yr_le32toh(exports->Base);

  set_integer(
      yr_le32toh(exports->TimeDateStamp), pe->object, "export_timestamp");

  offset = pe_rva_to_offset(pe, yr_le32toh(exports->Name));

  if (offset > 0)
  {
    remaining = pe->data_size - (size_t) offset;
    name_len = strnlen((char*) (pe->data + offset), remaining);
    set_sized_string(
        (char*) (pe->data + offset), name_len, pe->object, "dll_name");
  }

  if (number_of_exports * sizeof(DWORD) > pe->data_size - offset)
    return;

  if (yr_le32toh(exports->NumberOfNames) > 0)
  {
    offset = pe_rva_to_offset(pe, yr_le32toh(exports->AddressOfNames));

    if (offset < 0)
      return;

    if (yr_le32toh(exports->NumberOfNames) * sizeof(DWORD) >
        pe->data_size - offset)
      return;

    names = (DWORD*) (pe->data + offset);
  }

  offset = pe_rva_to_offset(pe, yr_le32toh(exports->AddressOfNameOrdinals));

  if (offset < 0)
    return;

  ordinals = (WORD*) (pe->data + offset);

  if (available_space(pe, ordinals) < sizeof(WORD) * number_of_exports)
    return;

  offset = pe_rva_to_offset(pe, yr_le32toh(exports->AddressOfFunctions));

  if (offset < 0)
    return;

  function_addrs = (DWORD*) (pe->data + offset);

  if (available_space(pe, function_addrs) < sizeof(DWORD) * number_of_exports)
    return;

  number_of_names = yr_min(
      yr_le32toh(yr_le32toh(exports->NumberOfNames)), number_of_exports);

  // Mapping out the exports is a bit janky. We start with the export address
  // array. The index from that array plus the ordinal base is the ordinal for
  // that export. To find the name we walk the ordinal array looking for a value
  // that matches our index. If one exists we look up the corresponding RVA from
  // the names array and follow it to get the name. If one does not exist then
  // the export has no name.
  //
  // Ordinal base: 5
  //                       0            1            2
  // Address array: [ 0x00000011 | 0x00000022 | 0x00000033 ]
  //                     0        1        2
  // Ordinal array: [ 0x0000 | 0x0002 | 0x0001 ]
  //                       0            1
  // Names array:   [ 0x00000044 | 0x00000055 ]
  //
  // The function at RVA 0x00000011 (index 0) has ordinal 5 (base + index). The
  // index can be found in position 0 in the ordinal array. Using 0 to index
  // into the name array gives us an RVA (0x00000044) which we can follow to get
  // the name.
  //
  // The function at RVA 0x00000022 (index 1) has ordinal 6 (base + index). The
  // index can be found in position 2 in the ordinal array. 2 is out of bounds
  // for the names array so this function is exported without a name.
  //
  // The function at RVA 0x00000033 (index 2) has ordinal 7 (base + index). The
  // index can be found in position 1 in the ordinal array. Using 1 to index
  // into the name array gives us an RVA (0x00000055) which we can follow to get
  // the name.
  //
  // If the RVA from the address array is within the export directory it is a
  // forwarder RVA and points to a NULL terminated ASCII string.

  for (i = 0; i < number_of_exports; i++)
  {
    set_integer(
        ordinal_base + i, pe->object, "export_details[%i].ordinal", exp_sz);

    // Don't check for a failure here since some packers make this an invalid
    // value.
    offset = pe_rva_to_offset(pe, yr_le32toh(function_addrs[i]));

    if (offset > export_start && offset < export_start + export_size)
    {
      remaining = pe->data_size - (size_t) offset;
      name_len = strnlen((char*) (pe->data + offset), remaining);

      set_sized_string(
          (char*) (pe->data + offset),
          yr_min(name_len, MAX_EXPORT_NAME_LENGTH),
          pe->object,
          "export_details[%i].forward_name",
          exp_sz);
    }
    else
    {
      set_integer(offset, pe->object, "export_details[%i].offset", exp_sz);
    }

    if (names != NULL)
    {
      for (j = 0; j < number_of_exports; j++)
      {
        if (yr_le16toh(ordinals[j]) == i && j < number_of_names)
        {
          offset = pe_rva_to_offset(pe, yr_le32toh(names[j]));

          if (offset > 0)
          {
            remaining = pe->data_size - (size_t) offset;
            name_len = strnlen((char*) (pe->data + offset), remaining);

            set_sized_string(
                (char*) (pe->data + offset),
                yr_min(name_len, MAX_EXPORT_NAME_LENGTH),
                pe->object,
                "export_details[%i].name",
                exp_sz);
          }
          break;
        }
      }
    }
    exp_sz++;
  }

  set_integer(exp_sz, pe->object, "number_of_exports");
}

// BoringSSL (https://boringssl.googlesource.com/boringssl/) doesn't support
// some features used in pe_parse_certificates, if you are using BoringSSL
// instead of OpenSSL you should define BORINGSSL for YARA to compile properly,
// but you won't have signature-related features in the PE module.
#if defined(HAVE_LIBCRYPTO) && !defined(BORINGSSL)

//
// Parse a PKCS7 blob, looking for certs and nested PKCS7 blobs.
//

void _parse_pkcs7(PE* pe, PKCS7* pkcs7, int* counter)
{
  int i, j;
  time_t date_time;
  int sig_nid;
  char buffer[256];
  int bytes;
  int idx;
  const EVP_MD* sha1_digest = EVP_sha1();
  const unsigned char* p;
  unsigned char thumbprint[YR_SHA1_LEN];
  char thumbprint_ascii[YR_SHA1_LEN * 2 + 1];

  PKCS7_SIGNER_INFO* signer_info = NULL;
  PKCS7* nested_pkcs7 = NULL;
  ASN1_INTEGER* serial = NULL;
  ASN1_TYPE* nested = NULL;
  ASN1_STRING* value = NULL;
  X509* cert = NULL;
  STACK_OF(X509)* certs = NULL;
  X509_ATTRIBUTE* xa = NULL;
  STACK_OF(X509_ATTRIBUTE)* attrs = NULL;

  if (*counter >= MAX_PE_CERTS)
    return;

  certs = PKCS7_get0_signers(pkcs7, NULL, 0);

  if (!certs)
    return;

  for (i = 0; i < sk_X509_num(certs) && *counter < MAX_PE_CERTS; i++)
  {
    cert = sk_X509_value(certs, i);

    X509_digest(cert, sha1_digest, thumbprint, NULL);

    for (j = 0; j < YR_SHA1_LEN; j++)
      sprintf(thumbprint_ascii + (j * 2), "%02x", thumbprint[j]);

    set_string(
        (char*) thumbprint_ascii,
        pe->object,
        "signatures[%i].thumbprint",
        *counter);

    X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));

    set_string(buffer, pe->object, "signatures[%i].issuer", *counter);

    X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));

    set_string(buffer, pe->object, "signatures[%i].subject", *counter);

    set_integer(
        X509_get_version(cert) + 1,  // Versions are zero based, so add one.
        pe->object,
        "signatures[%i].version",
        *counter);

    sig_nid = X509_get_signature_nid(cert);
    set_string(
        OBJ_nid2ln(sig_nid), pe->object, "signatures[%i].algorithm", *counter);
    OBJ_obj2txt(buffer, sizeof(buffer), OBJ_nid2obj(sig_nid), 1);
    set_string(buffer, pe->object, "signatures[%i].algorithm_oid", *counter);

    serial = X509_get_serialNumber(cert);

    if (serial)
    {
      // ASN1_INTEGER can be negative (serial->type & V_ASN1_NEG_INTEGER),
      // in which case the serial number will be stored in 2's complement.
      //
      // Handle negative serial numbers, which are technically not allowed
      // by RFC5280, but do exist. An example binary which has a negative
      // serial number is: 4bfe05f182aa273e113db6ed7dae4bb8.
      //
      // Negative serial numbers are handled by calling i2d_ASN1_INTEGER()
      // with a NULL second parameter. This will return the size of the
      // buffer necessary to store the proper serial number.
      //
      // Do this even for positive serial numbers because it makes the code
      // cleaner and easier to read.

      bytes = i2d_ASN1_INTEGER(serial, NULL);

      // According to X.509 specification the maximum length for the
      // serial number is 20 octets. Add two bytes to account for
      // DER type and length information.

      if (bytes > 2 && bytes <= 22)
      {
        // Now that we know the size of the serial number allocate enough
        // space to hold it, and use i2d_ASN1_INTEGER() one last time to
        // hold it in the allocated buffer.

        unsigned char* serial_der = (unsigned char*) yr_malloc(bytes);

        if (serial_der != NULL)
        {
          unsigned char* serial_bytes;
          char* serial_ascii;

          bytes = i2d_ASN1_INTEGER(serial, &serial_der);

          // i2d_ASN1_INTEGER() moves the pointer as it writes into
          // serial_bytes. Move it back.

          serial_der -= bytes;

          // Skip over DER type, length information
          serial_bytes = serial_der + 2;
          bytes -= 2;

          // Also allocate space to hold the "common" string format:
          // 00:01:02:03:04...
          //
          // For each byte in the serial to convert to hexlified format we
          // need three bytes, two for the byte itself and one for colon.
          // The last one doesn't have the colon, but the extra byte is used
          // for the NULL terminator.

          serial_ascii = (char*) yr_malloc(bytes * 3);

          if (serial_ascii)
          {
            for (j = 0; j < bytes; j++)
            {
              // Don't put the colon on the last one.
              if (j < bytes - 1)
                snprintf(serial_ascii + 3 * j, 4, "%02x:", serial_bytes[j]);
              else
                snprintf(serial_ascii + 3 * j, 3, "%02x", serial_bytes[j]);
            }

            set_string(
                serial_ascii, pe->object, "signatures[%i].serial", *counter);

            yr_free(serial_ascii);
          }

          yr_free(serial_der);
        }
      }
    }

    date_time = ASN1_get_time_t(X509_get0_notBefore(cert));
    set_integer(date_time, pe->object, "signatures[%i].not_before", *counter);

    date_time = ASN1_get_time_t(X509_get0_notAfter(cert));
    set_integer(date_time, pe->object, "signatures[%i].not_after", *counter);

    (*counter)++;
  }

  // See if there is a nested signature, which is apparently an authenticode
  // specific feature. See https://github.com/VirusTotal/yara/issues/515.
  signer_info = sk_PKCS7_SIGNER_INFO_value(pkcs7->d.sign->signer_info, 0);

  if (signer_info != NULL)
  {
    attrs = PKCS7_get_attributes(signer_info);

    idx = X509at_get_attr_by_NID(
        attrs, OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID), -1);

    xa = X509at_get_attr(attrs, idx);

    for (j = 0; j < MAX_PE_CERTS; j++)
    {
      nested = X509_ATTRIBUTE_get0_type(xa, j);
      if (nested == NULL)
        break;
      value = nested->value.sequence;
      p = value->data;
      nested_pkcs7 = d2i_PKCS7(NULL, &p, value->length);
      if (nested_pkcs7 != NULL)
      {
        _parse_pkcs7(pe, nested_pkcs7, counter);
        PKCS7_free(nested_pkcs7);
      }
    }
  }

  sk_X509_free(certs);
}

static void pe_parse_certificates(PE* pe)
{
  int counter = 0;

  const uint8_t* eod;
  const unsigned char* cert_p;
  uintptr_t end;

  PWIN_CERTIFICATE win_cert;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_SECURITY);

  if (directory == NULL)
    return;

  // Default to 0 signatures until we know otherwise.
  set_integer(0, pe->object, "number_of_signatures");

  // directory->VirtualAddress is a file offset. Don't call pe_rva_to_offset().
  if (yr_le32toh(directory->VirtualAddress) == 0 ||
      yr_le32toh(directory->VirtualAddress) > pe->data_size ||
      yr_le32toh(directory->Size) > pe->data_size ||
      yr_le32toh(directory->VirtualAddress) + yr_le32toh(directory->Size) >
          pe->data_size)
  {
    return;
  }

  // Store the end of directory, making comparisons easier.
  eod = pe->data + yr_le32toh(directory->VirtualAddress) +
        yr_le32toh(directory->Size);

  win_cert =
      (PWIN_CERTIFICATE) (pe->data + yr_le32toh(directory->VirtualAddress));

  //
  // Walk the directory, pulling out certificates.
  //
  // Make sure WIN_CERTIFICATE fits within the directory.
  // Make sure the Length specified fits within directory too.
  //
  // The docs say that the length is only for the Certificate, but the next
  // paragraph contradicts that. All the binaries I've seen have the Length
  // being the entire structure (Certificate included).
  //

  while (struct_fits_in_pe(pe, win_cert, WIN_CERTIFICATE) &&
         yr_le32toh(win_cert->Length) > sizeof(WIN_CERTIFICATE) &&
         fits_in_pe(pe, win_cert, yr_le32toh(win_cert->Length)) &&
         (uint8_t*) win_cert + sizeof(WIN_CERTIFICATE) < eod &&
         (uint8_t*) win_cert + yr_le32toh(win_cert->Length) <= eod)
  {
    PKCS7* pkcs7;

    // Some sanity checks

    if (yr_le32toh(win_cert->Length) == 0 ||
        (yr_le16toh(win_cert->Revision) != WIN_CERT_REVISION_1_0 &&
         yr_le16toh(win_cert->Revision) != WIN_CERT_REVISION_2_0))
    {
      break;
    }

    // Don't support legacy revision for now.
    // Make sure type is PKCS#7 too.

    if (yr_le16toh(win_cert->Revision) != WIN_CERT_REVISION_2_0 ||
        yr_le16toh(win_cert->CertificateType) != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    {
      end = (uintptr_t) ((uint8_t*) win_cert) + yr_le32toh(win_cert->Length);

      // Next certificate is aligned to the next 8-bytes boundary.
      win_cert = (PWIN_CERTIFICATE) ((end + 7) & -8);
      continue;
    }

    cert_p = win_cert->Certificate;
    end = (uintptr_t) ((uint8_t*) win_cert) + yr_le32toh(win_cert->Length);

    while ((uintptr_t) cert_p < end && counter < MAX_PE_CERTS)
    {
      pkcs7 = d2i_PKCS7(NULL, &cert_p, (uint32_t) (end - (uintptr_t) cert_p));

      if (pkcs7 == NULL)
        break;

      _parse_pkcs7(pe, pkcs7, &counter);
      PKCS7_free(pkcs7);
      pkcs7 = NULL;
    }

    // Next certificate is aligned to the next 8-bytes boundary.
    win_cert = (PWIN_CERTIFICATE) ((end + 7) & -8);
  }

  set_integer(counter, pe->object, "number_of_signatures");
}

#endif  // defined(HAVE_LIBCRYPTO)

const char* pe_get_section_full_name(
    PE* pe,
    const char* section_name,
    uint64_t section_name_length,
    uint64_t* section_full_name_length)
{
  // section_name is an 8-byte, null-padded UTF-8 encoded string. If the string
  // is exactly 8 characters long, there is no terminating null. For longer
  // names, this field contains a slash (/) that is followed by an ASCII
  // representation of a decimal number that is an offset into the string table.

  // Sample: 2e9c671b8a0411f2b397544b368c44d7f095eb395779de0ad1ac946914dfa34c

  // Check if any param is NULL
  if (pe == NULL || section_name == NULL || section_full_name_length == NULL)
    return NULL;

  // Set length to zero
  *section_full_name_length = 0;

  // Offset and number of records in coff table
  uint64_t coff_offset = yr_le32toh(
      pe->header->FileHeader.PointerToSymbolTable);
  uint64_t coff_number = yr_le32toh(pe->header->FileHeader.NumberOfSymbols);

  // If section name start with '/' and file contain coff table then section
  // name is stored in string table
  if (coff_offset == 0 || section_name[0] != '/')
  {
    *section_full_name_length = section_name_length;
    return section_name;
  }

  // Calculate offset of string table (String table is immediately after coff
  // table)
  uint64_t string_offset = coff_offset + coff_number * sizeof(IMAGE_SYMBOL);
  uint64_t string_index = 0;

  // Calculate string index/offset in string table
  for (int i = 1; i < IMAGE_SIZEOF_SHORT_NAME && isdigit(section_name[i]); i++)
    string_index = (string_index * 10) + (section_name[i] - '0');

  // Calculate string pointer
  const char* string = (char*) (pe->data + string_offset + string_index);

  // Check string
  for (uint64_t len = 0; fits_in_pe(pe, string, len + 1); len++)
  {
    // Valid string
    if (string[len] == 0)
    {
      *section_full_name_length = len;
      return string;
    }

    // string contain unprintable character
    if (!isprint(string[len]))
      return NULL;
  }

  // String do not fit into pe file
  return NULL;
}

static void pe_parse_header(PE* pe, uint64_t base_address, int flags)
{
  PIMAGE_SECTION_HEADER section;
  PIMAGE_DATA_DIRECTORY data_dir;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
  int sect_name_length, scount, ddcount;

  uint64_t highest_sec_siz = 0;
  uint64_t highest_sec_ofs = 0;
  uint64_t section_end;
  uint64_t last_section_end;

  set_integer(1, pe->object, "is_pe");

  set_integer(
      yr_le16toh(pe->header->FileHeader.Machine), pe->object, "machine");

  set_integer(
      yr_le16toh(pe->header->FileHeader.NumberOfSections),
      pe->object,
      "number_of_sections");

  set_integer(
      yr_le32toh(pe->header->FileHeader.TimeDateStamp),
      pe->object,
      "timestamp");

  set_integer(
      yr_le32toh(pe->header->FileHeader.PointerToSymbolTable),
      pe->object,
      "pointer_to_symbol_table");

  set_integer(
      yr_le32toh(pe->header->FileHeader.NumberOfSymbols),
      pe->object,
      "number_of_symbols");

  set_integer(
      yr_le32toh(pe->header->FileHeader.SizeOfOptionalHeader),
      pe->object,
      "size_of_optional_header");

  set_integer(
      yr_le16toh(pe->header->FileHeader.Characteristics),
      pe->object,
      "characteristics");

  set_integer(
      flags & SCAN_FLAGS_PROCESS_MEMORY
          ? base_address + yr_le32toh(OptionalHeader(pe, AddressOfEntryPoint))
          : pe_rva_to_offset(
                pe, yr_le32toh(OptionalHeader(pe, AddressOfEntryPoint))),
      pe->object,
      "entry_point");

  set_integer(
      yr_le32toh(OptionalHeader(pe, AddressOfEntryPoint)),
      pe->object,
      "entry_point_raw");

  set_integer(
      IS_64BITS_PE(pe) ? yr_le64toh(OptionalHeader(pe, ImageBase))
                       : yr_le32toh(OptionalHeader(pe, ImageBase)),
      pe->object,
      "image_base");

  set_integer(
      yr_le32toh(OptionalHeader(pe, NumberOfRvaAndSizes)),
      pe->object,
      "number_of_rva_and_sizes");

  set_integer(
      yr_le32toh(OptionalHeader(pe, Magic)), pe->object, "opthdr_magic");

  set_integer(
      OptionalHeader(pe, MajorLinkerVersion),
      pe->object,
      "linker_version.major");

  set_integer(
      OptionalHeader(pe, MinorLinkerVersion),
      pe->object,
      "linker_version.minor");

  set_integer(
      yr_le32toh(OptionalHeader(pe, SizeOfCode)), pe->object, "size_of_code");

  set_integer(
      yr_le32toh(OptionalHeader(pe, SizeOfInitializedData)),
      pe->object,
      "size_of_initialized_data");

  set_integer(
      yr_le32toh(OptionalHeader(pe, SizeOfUninitializedData)),
      pe->object,
      "size_of_uninitialized_data");

  set_integer(
      yr_le32toh(OptionalHeader(pe, BaseOfCode)), pe->object, "base_of_code");

  if (!IS_64BITS_PE(pe))
  {
    set_integer(
        yr_le32toh(pe->header->OptionalHeader.BaseOfData),
        pe->object,
        "base_of_data");
  }

  set_integer(
      yr_le32toh(OptionalHeader(pe, SectionAlignment)),
      pe->object,
      "section_alignment");

  set_integer(
      yr_le32toh(OptionalHeader(pe, FileAlignment)),
      pe->object,
      "file_alignment");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MajorOperatingSystemVersion)),
      pe->object,
      "os_version.major");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MinorOperatingSystemVersion)),
      pe->object,
      "os_version.minor");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MajorImageVersion)),
      pe->object,
      "image_version.major");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MinorImageVersion)),
      pe->object,
      "image_version.minor");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MajorSubsystemVersion)),
      pe->object,
      "subsystem_version.major");

  set_integer(
      yr_le16toh(OptionalHeader(pe, MinorSubsystemVersion)),
      pe->object,
      "subsystem_version.minor");

  set_integer(
      yr_le32toh(OptionalHeader(pe, Win32VersionValue)),
      pe->object,
      "win32_version_value");

  set_integer(
      yr_le32toh(OptionalHeader(pe, SizeOfImage)), pe->object, "size_of_image");

  set_integer(
      yr_le32toh(OptionalHeader(pe, SizeOfHeaders)),
      pe->object,
      "size_of_headers");

  set_integer(yr_le32toh(OptionalHeader(pe, CheckSum)), pe->object, "checksum");

  set_integer(
      yr_le16toh(OptionalHeader(pe, Subsystem)), pe->object, "subsystem");

  set_integer(
      OptionalHeader(pe, DllCharacteristics),
      pe->object,
      "dll_characteristics");

  set_integer(
      IS_64BITS_PE(pe) ? yr_le64toh(OptionalHeader(pe, SizeOfStackReserve))
                       : yr_le32toh(OptionalHeader(pe, SizeOfStackReserve)),
      pe->object,
      "size_of_stack_reserve");

  set_integer(
      IS_64BITS_PE(pe) ? yr_le64toh(OptionalHeader(pe, SizeOfStackCommit))
                       : yr_le32toh(OptionalHeader(pe, SizeOfStackCommit)),
      pe->object,
      "size_of_stack_commit");

  set_integer(
      IS_64BITS_PE(pe) ? yr_le64toh(OptionalHeader(pe, SizeOfHeapReserve))
                       : yr_le32toh(OptionalHeader(pe, SizeOfHeapReserve)),
      pe->object,
      "size_of_heap_reserve");

  set_integer(
      IS_64BITS_PE(pe) ? yr_le64toh(OptionalHeader(pe, SizeOfHeapCommit))
                       : yr_le32toh(OptionalHeader(pe, SizeOfHeapCommit)),
      pe->object,
      "size_of_heap_commit");

  set_integer(
      yr_le32toh(OptionalHeader(pe, LoaderFlags)), pe->object, "loader_flags");

  data_dir = IS_64BITS_PE(pe) ? pe->header64->OptionalHeader.DataDirectory
                              : pe->header->OptionalHeader.DataDirectory;

  ddcount = yr_le16toh(OptionalHeader(pe, NumberOfRvaAndSizes));
  ddcount = yr_min(ddcount, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

  for (int i = 0; i < ddcount; i++)
  {
    if (!struct_fits_in_pe(pe, data_dir, IMAGE_DATA_DIRECTORY))
      break;

    set_integer(
        yr_le32toh(data_dir->VirtualAddress),
        pe->object,
        "data_directories[%i].virtual_address",
        i);

    set_integer(
        yr_le32toh(data_dir->Size), pe->object, "data_directories[%i].size", i);

    data_dir++;
  }

  pe_iterate_resources(
      pe, (RESOURCE_CALLBACK_FUNC) pe_collect_resources, (void*) pe);

  set_integer(pe->resources, pe->object, "number_of_resources");
  set_integer(pe->version_infos, pe->object, "number_of_version_infos");

  section = IMAGE_FIRST_SECTION(pe->header);

  scount = yr_min(
      yr_le16toh(pe->header->FileHeader.NumberOfSections), MAX_PE_SECTIONS);

  for (int i = 0; i < scount; i++)
  {
    if (!struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
      break;

    memcpy(section_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
    section_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

    // Basically do rstrip('\0'), find the rightmost non-null character.
    // Samples like
    // 0043812838495a45449a0ac61a81b9c16eddca1ad249fb4f7fdb1c4505e9bb34 contain
    // sections with additional characters after the first null.
    for (sect_name_length = IMAGE_SIZEOF_SHORT_NAME - 1; sect_name_length >= 0;
         --sect_name_length)
    {
      if (section_name[sect_name_length] != '\0')
        break;
    }

    uint64_t sect_full_name_length = 0;
    const char* full_section_name = pe_get_section_full_name(
        pe, section_name, sect_name_length + 1, &sect_full_name_length);

    set_sized_string(
        (char*) section_name,
        sect_name_length + 1,
        pe->object,
        "sections[%i].name",
        i);

    set_sized_string(
        full_section_name,
        sect_full_name_length,
        pe->object,
        "sections[%i].full_name",
        i);

    set_integer(
        yr_le32toh(section->Characteristics),
        pe->object,
        "sections[%i].characteristics",
        i);

    set_integer(
        yr_le32toh(section->SizeOfRawData),
        pe->object,
        "sections[%i].raw_data_size",
        i);

    set_integer(
        yr_le32toh(section->PointerToRawData),
        pe->object,
        "sections[%i].raw_data_offset",
        i);

    set_integer(
        yr_le32toh(section->VirtualAddress),
        pe->object,
        "sections[%i].virtual_address",
        i);

    set_integer(
        yr_le32toh(section->Misc.VirtualSize),
        pe->object,
        "sections[%i].virtual_size",
        i);

    set_integer(
        yr_le32toh(section->PointerToRelocations),
        pe->object,
        "sections[%i].pointer_to_relocations",
        i);

    set_integer(
        yr_le32toh(section->PointerToLinenumbers),
        pe->object,
        "sections[%i].pointer_to_line_numbers",
        i);

    set_integer(
        yr_le32toh(section->NumberOfRelocations),
        pe->object,
        "sections[%i].number_of_relocations",
        i);

    set_integer(
        yr_le32toh(section->NumberOfLinenumbers),
        pe->object,
        "sections[%i].number_of_line_numbers",
        i);

    // This will catch the section with the highest raw offset to help checking
    // if overlay data is present. If two sections have the same raw pointer
    // but different raw sizes the largest one is used. An example of this case
    // is file: cf62bf1815a93e68e6c5189f689286b66c4088b9507cf3ecf835e4ac3f9ededa

    section_end = yr_le32toh(section->PointerToRawData) +
                  yr_le32toh(section->SizeOfRawData);

    if (section_end > highest_sec_ofs + highest_sec_siz)
    {
      highest_sec_ofs = yr_le32toh(section->PointerToRawData);
      highest_sec_siz = yr_le32toh(section->SizeOfRawData);
    }

    section++;
  }

  // An overlay is data appended to a PE file. Its location is at
  // RawData + RawOffset of the last section on the physical file
  last_section_end = highest_sec_siz + highest_sec_ofs;

  // For PE files that have overlaid data overlay.offset contains the offset
  // within the file where the overlay starts and overlay.size contains the
  // size. If the PE file doesn't have an overlay both fields are 0, if the
  // file is not a PE file (or is a malformed PE) both fields are YR_UNDEFINED.
  if (last_section_end && (pe->data_size > last_section_end))
  {
    set_integer(last_section_end, pe->object, "overlay.offset");
    set_integer(pe->data_size - last_section_end, pe->object, "overlay.size");
  }
  else
  {
    set_integer(0, pe->object, "overlay.offset");
    set_integer(0, pe->object, "overlay.size");
  }
}

//
// Given a posix timestamp argument, make sure not_before <= arg <= not_after
//

define_function(valid_on)
{
  int64_t timestamp;
  int64_t not_before;
  int64_t not_after;

  if (is_undefined(parent(), "not_before") ||
      is_undefined(parent(), "not_after"))
  {
    return_integer(YR_UNDEFINED);
  }

  timestamp = integer_argument(1);

  not_before = get_integer(parent(), "not_before");
  not_after = get_integer(parent(), "not_after");

  return_integer(timestamp >= not_before && timestamp <= not_after);
}

define_function(section_index_addr)
{
  YR_OBJECT* module = module();
  YR_SCAN_CONTEXT* context = scan_context();

  int64_t offset;
  int64_t size;

  int64_t addr = integer_argument(1);
  int64_t n = get_integer(module, "number_of_sections");

  if (is_undefined(module, "number_of_sections"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < yr_min(n, MAX_PE_SECTIONS); i++)
  {
    if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    {
      offset = get_integer(module, "sections[%i].virtual_address", i);
      size = get_integer(module, "sections[%i].virtual_size", i);
    }
    else
    {
      offset = get_integer(module, "sections[%i].raw_data_offset", i);
      size = get_integer(module, "sections[%i].raw_data_size", i);
    }

    if (addr >= offset && addr < offset + size)
      return_integer(i);
  }

  return_integer(YR_UNDEFINED);
}

define_function(section_index_name)
{
  YR_OBJECT* module = module();

  char* name = string_argument(1);

  int64_t n = get_integer(module, "number_of_sections");

  if (is_undefined(module, "number_of_sections"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < yr_min(n, MAX_PE_SECTIONS); i++)
  {
    SIZED_STRING* sect = get_string(module, "sections[%i].name", i);

    if (sect != NULL && strcmp(name, sect->c_string) == 0)
      return_integer(i);
  }

  return_integer(YR_UNDEFINED);
}

define_function(exports)
{
  SIZED_STRING* search_name = sized_string_argument(1);

  SIZED_STRING* function_name = NULL;
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(0);

  for (int i = 0; i < n; i++)
  {
    function_name = get_string(module, "export_details[%i].name", i);

    if (function_name == NULL)
      continue;

    if (ss_icompare(function_name, search_name) == 0)
      return_integer(1);
  }

  return_integer(0);
}

define_function(exports_regexp)
{
  RE* regex = regexp_argument(1);

  SIZED_STRING* function_name = NULL;
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(0);

  for (int i = 0; i < n; i++)
  {
    function_name = get_string(module, "export_details[%i].name", i);
    if (function_name == NULL)
      continue;

    if (yr_re_match(scan_context(), regex, function_name->c_string) != -1)
      return_integer(1);
  }

  return_integer(0);
}

define_function(exports_ordinal)
{
  int64_t ordinal = integer_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(0);

  if (ordinal == 0 || ordinal > n)
    return_integer(0);

  for (int i = 0; i < n; i++)
  {
    int64_t exported_ordinal = yr_object_get_integer(
        module, "export_details[%i].ordinal", i);

    if (exported_ordinal == ordinal)
      return_integer(1);
  }

  return_integer(0);
}

define_function(exports_index_name)
{
  SIZED_STRING* search_name = sized_string_argument(1);

  SIZED_STRING* function_name = NULL;
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < n; i++)
  {
    function_name = get_string(module, "export_details[%i].name", i);

    if (function_name == NULL)
      continue;

    if (ss_icompare(function_name, search_name) == 0)
      return_integer(i);
  }

  return_integer(YR_UNDEFINED);
}

define_function(exports_index_ordinal)
{
  int64_t ordinal = integer_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(YR_UNDEFINED);

  if (ordinal == 0 || ordinal > n)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < n; i++)
  {
    int64_t exported_ordinal = yr_object_get_integer(
        module, "export_details[%i].ordinal", i);

    if (exported_ordinal == ordinal)
      return_integer(i);
  }

  return_integer(YR_UNDEFINED);
}

define_function(exports_index_regex)
{
  RE* regex = regexp_argument(1);

  SIZED_STRING* function_name = NULL;
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.
  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  // If PE, but no exported functions, return false.
  int n = (int) get_integer(module, "number_of_exports");

  if (n == 0)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < n; i++)
  {
    function_name = get_string(module, "export_details[%i].name", i);
    if (function_name == NULL)
      continue;

    if (yr_re_match(scan_context(), regex, function_name->c_string) != -1)
    {
      return_integer(i);
    }
  }

  return_integer(YR_UNDEFINED);
}

#if defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H) || \
    defined(HAVE_COMMONCRYPTO_COMMONCRYPTO_H)

//
// Generate an import hash:
// https://www.mandiant.com/blog/tracking-malware-import-hashing/
// It is important to make duplicates of the strings as we don't want
// to alter the contents of the parsed import structures.
//

define_function(imphash)
{
  YR_OBJECT* module = module();

  IMPORTED_DLL* dll;
  yr_md5_ctx ctx;

  unsigned char digest[YR_MD5_LEN];
  char* digest_ascii;

  size_t i;
  bool first = true;

  PE* pe = (PE*) module->data;

  // If not a PE, return YR_UNDEFINED.

  if (!pe)
    return_string(YR_UNDEFINED);

  // Lookup in cache first.
  digest_ascii = (char*) yr_hash_table_lookup(pe->hash_table, "imphash", NULL);

  if (digest_ascii != NULL)
    return_string(digest_ascii);

  yr_md5_init(&ctx);

  dll = pe->imported_dlls;

  while (dll)
  {
    IMPORT_FUNCTION* func;

    size_t dll_name_len;
    char* dll_name;

    // If extension is 'ocx', 'sys' or 'dll', chop it.

    char* ext = strstr(dll->name, ".");

    if (ext &&
        (strncasecmp(ext, ".ocx", 4) == 0 || strncasecmp(ext, ".sys", 4) == 0 ||
         strncasecmp(ext, ".dll", 4) == 0))
    {
      dll_name_len = (ext - dll->name);
    }
    else
    {
      dll_name_len = strlen(dll->name);
    }

    // Allocate a new string to hold the dll name.

    dll_name = (char*) yr_malloc(dll_name_len + 1);

    if (!dll_name)
      return ERROR_INSUFFICIENT_MEMORY;

    strlcpy(dll_name, dll->name, dll_name_len + 1);

    func = dll->functions;

    while (func)
    {
      char* final_name;
      size_t final_name_len = dll_name_len + strlen(func->name) + 1;

      if (!first)
        final_name_len++;  // Additional byte to accommodate the extra comma

      final_name = (char*) yr_malloc(final_name_len + 1);

      if (final_name == NULL)
        break;

      sprintf(final_name, first ? "%s.%s" : ",%s.%s", dll_name, func->name);

      // Lowercase the whole thing.

      for (i = 0; i < final_name_len; i++)
        final_name[i] = tolower(final_name[i]);

      yr_md5_update(&ctx, final_name, final_name_len);

      yr_free(final_name);

      func = func->next;
      first = false;
    }

    yr_free(dll_name);

    dll = dll->next;
  }

  yr_md5_final(digest, &ctx);

  digest_ascii = (char*) yr_malloc(YR_MD5_LEN * 2 + 1);

  if (digest_ascii == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  // Transform the binary digest to ascii

  for (i = 0; i < YR_MD5_LEN; i++)
  {
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
  }

  digest_ascii[YR_MD5_LEN * 2] = '\0';

  yr_hash_table_add(pe->hash_table, "imphash", NULL, digest_ascii);

  return_string(digest_ascii);
}

#endif  // defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H)

int64_t pe_imports_dll(IMPORTED_DLL* dll, char* dll_name)
{
  if (dll == NULL)
    return 0;

  int64_t result = 0;

  for (; dll != NULL; dll = dll->next)
  {
    if (strcasecmp(dll->name, dll_name) == 0)
    {
      IMPORT_FUNCTION* fun = dll->functions;
      for (; fun != NULL; fun = fun->next)
      {
        result++;
      }
    }
  }

  return result;
}

int64_t pe_imports(IMPORTED_DLL* dll, char* dll_name, char* fun_name)
{
  if (dll == NULL)
    return 0;

  for (; dll != NULL; dll = dll->next)
  {
    if (strcasecmp(dll->name, dll_name) == 0)
    {
      IMPORT_FUNCTION* fun = dll->functions;
      for (; fun != NULL; fun = fun->next)
      {
        if (strcasecmp(fun->name, fun_name) == 0)
          return 1;
      }
    }
  }

  return 0;
}

int64_t pe_imports_regexp(
    YR_SCAN_CONTEXT* context,
    IMPORTED_DLL* dll,
    RE* dll_name,
    RE* fun_name)
{
  if (dll == NULL)
    return 0;

  int64_t result = 0;

  for (; dll != NULL; dll = dll->next)
  {
    if (yr_re_match(context, dll_name, dll->name) > 0)
    {
      IMPORT_FUNCTION* fun = dll->functions;
      for (; fun != NULL; fun = fun->next)
      {
        if (yr_re_match(context, fun_name, fun->name) > 0)
          result++;
      }
    }
  }

  return result;
}

int64_t pe_imports_ordinal(IMPORTED_DLL* dll, char* dll_name, uint64_t ordinal)
{
  if (dll == NULL)
    return 0;

  for (; dll != NULL; dll = dll->next)
  {
    if (strcasecmp(dll->name, dll_name) == 0)
    {
      IMPORT_FUNCTION* fun = dll->functions;
      for (; fun != NULL; fun = fun->next)
      {
        if (fun->has_ordinal && fun->ordinal == ordinal)
          return 1;
      }
    }
  }

  return 0;
}

define_function(imports_standard)
{
  char* dll_name = string_argument(1);
  char* function_name = string_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  return_integer(pe_imports(pe->imported_dlls, dll_name, function_name));
}

define_function(imports)
{
  int64_t flags = integer_argument(1);
  char* dll_name = string_argument(2);
  char* function_name = string_argument(3);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  if (flags & IMPORT_STANDARD &&
      pe_imports(pe->imported_dlls, dll_name, function_name))
  {
    return_integer(1);
  }

  if (flags & IMPORT_DELAYED &&
      pe_imports(pe->delay_imported_dlls, dll_name, function_name))
  {
    return_integer(1);
  }

  return_integer(0);
}

define_function(imports_standard_ordinal)
{
  char* dll_name = string_argument(1);
  int64_t ordinal = integer_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  return_integer(pe_imports_ordinal(pe->imported_dlls, dll_name, ordinal))
}

define_function(imports_ordinal)
{
  int64_t flags = integer_argument(1);
  char* dll_name = string_argument(2);
  int64_t ordinal = integer_argument(3);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  if (flags & IMPORT_STANDARD &&
      pe_imports_ordinal(pe->imported_dlls, dll_name, ordinal))
  {
    return_integer(1);
  }

  if (flags & IMPORT_DELAYED &&
      pe_imports_ordinal(pe->delay_imported_dlls, dll_name, ordinal))
  {
    return_integer(1);
  }

  return_integer(0);
}

define_function(imports_standard_regex)
{
  RE* dll_name = regexp_argument(1);
  RE* function_name = regexp_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  return_integer(pe_imports_regexp(
      scan_context(), pe->imported_dlls, dll_name, function_name))
}

define_function(imports_regex)
{
  int64_t flags = integer_argument(1);
  RE* dll_name = regexp_argument(2);
  RE* function_name = regexp_argument(3);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  int64_t result = 0;

  if (flags & IMPORT_STANDARD)
    result += pe_imports_regexp(
        scan_context(), pe->imported_dlls, dll_name, function_name);

  if (flags & IMPORT_DELAYED)
    result += pe_imports_regexp(
        scan_context(), pe->delay_imported_dlls, dll_name, function_name);

  return_integer(result);
}

define_function(imports_standard_dll)
{
  char* dll_name = string_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  return_integer(pe_imports_dll(pe->imported_dlls, dll_name));
}

define_function(imports_dll)
{
  int64_t flags = integer_argument(1);
  char* dll_name = string_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (!pe)
    return_integer(YR_UNDEFINED);

  int64_t result = 0;

  if (flags & IMPORT_STANDARD)
    result += pe_imports_dll(pe->imported_dlls, dll_name);

  if (flags & IMPORT_DELAYED)
    result += pe_imports_dll(pe->delay_imported_dlls, dll_name);

  return_integer(result);
}

define_function(locale)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  uint64_t locale = integer_argument(1);

  if (is_undefined(module, "number_of_resources"))
    return_integer(YR_UNDEFINED);

  // If not a PE file, return YR_UNDEFINED

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  int n = (int) get_integer(module, "number_of_resources");

  for (int i = 0; i < n; i++)
  {
    uint64_t rsrc_language = get_integer(module, "resources[%i].language", i);

    if ((rsrc_language & 0xFFFF) == locale)
      return_integer(1);
  }

  return_integer(0);
}

define_function(language)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  uint64_t language = integer_argument(1);

  if (is_undefined(module, "number_of_resources"))
    return_integer(YR_UNDEFINED);

  // If not a PE file, return YR_UNDEFINED

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  int n = (int) get_integer(module, "number_of_resources");

  for (int i = 0; i < n; i++)
  {
    uint64_t rsrc_language = get_integer(module, "resources[%i].language", i);

    if ((rsrc_language & 0xFF) == language)
      return_integer(1);
  }

  return_integer(0);
}

define_function(is_dll)
{
  int64_t characteristics;
  YR_OBJECT* module = module();

  if (is_undefined(module, "characteristics"))
    return_integer(YR_UNDEFINED);

  characteristics = get_integer(module, "characteristics");
  return_integer(characteristics & IMAGE_FILE_DLL);
}

define_function(is_32bit)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  return_integer(IS_64BITS_PE(pe) ? 0 : 1);
}

define_function(is_64bit)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  return_integer(IS_64BITS_PE(pe) ? 1 : 0);
}

// _rich_version
//
// Returns the number of rich signatures that match the specified version and
// toolid numbers.
//
static uint64_t _rich_version(
    YR_OBJECT* module,
    uint64_t version,
    uint64_t toolid)
{
  int64_t rich_length;
  int64_t rich_count;

  PRICH_SIGNATURE clear_rich_signature;
  SIZED_STRING* rich_string;

  uint64_t result = 0;

  // Check if the required fields are set
  if (is_undefined(module, "rich_signature.length"))
    return YR_UNDEFINED;

  rich_length = get_integer(module, "rich_signature.length");
  rich_string = get_string(module, "rich_signature.clear_data");

  // If the clear_data was not set, return YR_UNDEFINED
  if (rich_string == NULL)
    return YR_UNDEFINED;

  if (version == YR_UNDEFINED && toolid == YR_UNDEFINED)
    return false;

  clear_rich_signature = (PRICH_SIGNATURE) rich_string->c_string;

  // Loop over the versions in the rich signature

  rich_count = (rich_length - sizeof(RICH_SIGNATURE)) /
               sizeof(RICH_VERSION_INFO);

  for (int i = 0; i < rich_count; i++)
  {
    DWORD id_version = yr_le32toh(clear_rich_signature->versions[i].id_version);

    int match_version = (version == RICH_VERSION_VERSION(id_version));
    int match_toolid = (toolid == RICH_VERSION_ID(id_version));

    if ((version == YR_UNDEFINED || match_version) &&
        (toolid == YR_UNDEFINED || match_toolid))
    {
      result += yr_le32toh(clear_rich_signature->versions[i].times);
    }
  }

  return result;
}

define_function(rich_version)
{
  return_integer(_rich_version(module(), integer_argument(1), YR_UNDEFINED));
}

define_function(rich_version_toolid)
{
  return_integer(
      _rich_version(module(), integer_argument(1), integer_argument(2)));
}

define_function(rich_toolid)
{
  return_integer(_rich_version(module(), YR_UNDEFINED, integer_argument(1)));
}

define_function(rich_toolid_version)
{
  return_integer(
      _rich_version(module(), integer_argument(2), integer_argument(1)));
}

define_function(calculate_checksum)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  uint64_t csum = 0;
  size_t csum_offset;

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  csum_offset = ((uint8_t*) &(pe->header->OptionalHeader) +
                 offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum)) -
                pe->data;

  for (size_t i = 0; i <= pe->data_size / 4; i++)
  {
    // Treat the CheckSum field as 0 -- the offset is the same for
    // PE32 and PE64.

    if (4 * i == csum_offset)
      continue;

    if (4 * i + 4 <= pe->data_size)
    {
      csum +=
          ((uint64_t) pe->data[4 * i] + ((uint64_t) pe->data[4 * i + 1] << 8) +
           ((uint64_t) pe->data[4 * i + 2] << 16) +
           ((uint64_t) pe->data[4 * i + 3] << 24));
    }
    else
    {
      for (size_t j = 0; j < pe->data_size % 4; j++)
        csum += (uint64_t) pe->data[4 * i + j] << (8 * j);
    }

    if (csum > 0xffffffff)
      csum = (csum & 0xffffffff) + (csum >> 32);
  }

  csum = (csum & 0xffff) + (csum >> 16);
  csum += (csum >> 16);
  csum &= 0xffff;
  csum += pe->data_size;

  return_integer(csum);
}

define_function(rva_to_offset)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  uint64_t rva;
  int64_t offset;

  if (pe == NULL)
    return_integer(YR_UNDEFINED);

  rva = integer_argument(1);
  offset = pe_rva_to_offset(pe, rva);

  if (offset == -1)
    return_integer(YR_UNDEFINED);

  return_integer(offset);
}

begin_declarations
  declare_integer("MACHINE_UNKNOWN");
  declare_integer("MACHINE_AM33");
  declare_integer("MACHINE_AMD64");
  declare_integer("MACHINE_ARM");
  declare_integer("MACHINE_ARMNT");
  declare_integer("MACHINE_ARM64");
  declare_integer("MACHINE_EBC");
  declare_integer("MACHINE_I386");
  declare_integer("MACHINE_IA64");
  declare_integer("MACHINE_M32R");
  declare_integer("MACHINE_MIPS16");
  declare_integer("MACHINE_MIPSFPU");
  declare_integer("MACHINE_MIPSFPU16");
  declare_integer("MACHINE_POWERPC");
  declare_integer("MACHINE_POWERPCFP");
  declare_integer("MACHINE_R4000");
  declare_integer("MACHINE_SH3");
  declare_integer("MACHINE_SH3DSP");
  declare_integer("MACHINE_SH4");
  declare_integer("MACHINE_SH5");
  declare_integer("MACHINE_THUMB");
  declare_integer("MACHINE_WCEMIPSV2");
  declare_integer("MACHINE_TARGET_HOST");
  declare_integer("MACHINE_R3000");
  declare_integer("MACHINE_R10000");
  declare_integer("MACHINE_ALPHA");
  declare_integer("MACHINE_SH3E");
  declare_integer("MACHINE_ALPHA64");
  declare_integer("MACHINE_AXP64");
  declare_integer("MACHINE_TRICORE");
  declare_integer("MACHINE_CEF");
  declare_integer("MACHINE_CEE");

  declare_integer("SUBSYSTEM_UNKNOWN");
  declare_integer("SUBSYSTEM_NATIVE");
  declare_integer("SUBSYSTEM_WINDOWS_GUI");
  declare_integer("SUBSYSTEM_WINDOWS_CUI");
  declare_integer("SUBSYSTEM_OS2_CUI");
  declare_integer("SUBSYSTEM_POSIX_CUI");
  declare_integer("SUBSYSTEM_NATIVE_WINDOWS");
  declare_integer("SUBSYSTEM_WINDOWS_CE_GUI");
  declare_integer("SUBSYSTEM_EFI_APPLICATION");
  declare_integer("SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER");
  declare_integer("SUBSYSTEM_EFI_RUNTIME_DRIVER");
  declare_integer("SUBSYSTEM_EFI_ROM_IMAGE");
  declare_integer("SUBSYSTEM_XBOX");
  declare_integer("SUBSYSTEM_WINDOWS_BOOT_APPLICATION");

  declare_integer("HIGH_ENTROPY_VA");
  declare_integer("DYNAMIC_BASE");
  declare_integer("FORCE_INTEGRITY");
  declare_integer("NX_COMPAT");
  declare_integer("NO_ISOLATION");
  declare_integer("NO_SEH");
  declare_integer("NO_BIND");
  declare_integer("APPCONTAINER");
  declare_integer("WDM_DRIVER");
  declare_integer("GUARD_CF");
  declare_integer("TERMINAL_SERVER_AWARE");

  declare_integer("RELOCS_STRIPPED");
  declare_integer("EXECUTABLE_IMAGE");
  declare_integer("LINE_NUMS_STRIPPED");
  declare_integer("LOCAL_SYMS_STRIPPED");
  declare_integer("AGGRESIVE_WS_TRIM");
  declare_integer("LARGE_ADDRESS_AWARE");
  declare_integer("BYTES_REVERSED_LO");
  declare_integer("MACHINE_32BIT");
  declare_integer("DEBUG_STRIPPED");
  declare_integer("REMOVABLE_RUN_FROM_SWAP");
  declare_integer("NET_RUN_FROM_SWAP");
  declare_integer("SYSTEM");
  declare_integer("DLL");
  declare_integer("UP_SYSTEM_ONLY");
  declare_integer("BYTES_REVERSED_HI");

  declare_integer("IMAGE_DIRECTORY_ENTRY_EXPORT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_IMPORT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_RESOURCE");
  declare_integer("IMAGE_DIRECTORY_ENTRY_EXCEPTION");
  declare_integer("IMAGE_DIRECTORY_ENTRY_SECURITY");
  declare_integer("IMAGE_DIRECTORY_ENTRY_BASERELOC");
  declare_integer("IMAGE_DIRECTORY_ENTRY_DEBUG");
  declare_integer("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE");
  declare_integer("IMAGE_DIRECTORY_ENTRY_COPYRIGHT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_GLOBALPTR");
  declare_integer("IMAGE_DIRECTORY_ENTRY_TLS");
  declare_integer("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG");
  declare_integer("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_IAT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT");
  declare_integer("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR");

  declare_integer("IMAGE_NT_OPTIONAL_HDR32_MAGIC");
  declare_integer("IMAGE_NT_OPTIONAL_HDR64_MAGIC");
  declare_integer("IMAGE_ROM_OPTIONAL_HDR_MAGIC");

  declare_integer("SECTION_NO_PAD");
  declare_integer("SECTION_CNT_CODE");
  declare_integer("SECTION_CNT_INITIALIZED_DATA");
  declare_integer("SECTION_CNT_UNINITIALIZED_DATA");
  declare_integer("SECTION_LNK_OTHER");
  declare_integer("SECTION_LNK_INFO");
  declare_integer("SECTION_LNK_REMOVE");
  declare_integer("SECTION_LNK_COMDAT");
  declare_integer("SECTION_NO_DEFER_SPEC_EXC");
  declare_integer("SECTION_GPREL");
  declare_integer("SECTION_MEM_FARDATA");
  declare_integer("SECTION_MEM_PURGEABLE");
  declare_integer("SECTION_MEM_16BIT");
  declare_integer("SECTION_MEM_LOCKED");
  declare_integer("SECTION_MEM_PRELOAD");
  declare_integer("SECTION_ALIGN_1BYTES");
  declare_integer("SECTION_ALIGN_2BYTES");
  declare_integer("SECTION_ALIGN_4BYTES");
  declare_integer("SECTION_ALIGN_8BYTES");
  declare_integer("SECTION_ALIGN_16BYTES");
  declare_integer("SECTION_ALIGN_32BYTES");
  declare_integer("SECTION_ALIGN_64BYTES");
  declare_integer("SECTION_ALIGN_128BYTES");
  declare_integer("SECTION_ALIGN_256BYTES");
  declare_integer("SECTION_ALIGN_512BYTES");
  declare_integer("SECTION_ALIGN_1024BYTES");
  declare_integer("SECTION_ALIGN_2048BYTES");
  declare_integer("SECTION_ALIGN_4096BYTES");
  declare_integer("SECTION_ALIGN_8192BYTES");
  declare_integer("SECTION_ALIGN_MASK");
  declare_integer("SECTION_LNK_NRELOC_OVFL");
  declare_integer("SECTION_MEM_DISCARDABLE");
  declare_integer("SECTION_MEM_NOT_CACHED");
  declare_integer("SECTION_MEM_NOT_PAGED");
  declare_integer("SECTION_MEM_SHARED");
  declare_integer("SECTION_MEM_EXECUTE");
  declare_integer("SECTION_MEM_READ");
  declare_integer("SECTION_MEM_WRITE");
  declare_integer("SECTION_SCALE_INDEX");

  declare_integer("RESOURCE_TYPE_CURSOR");
  declare_integer("RESOURCE_TYPE_BITMAP");
  declare_integer("RESOURCE_TYPE_ICON");
  declare_integer("RESOURCE_TYPE_MENU");
  declare_integer("RESOURCE_TYPE_DIALOG");
  declare_integer("RESOURCE_TYPE_STRING");
  declare_integer("RESOURCE_TYPE_FONTDIR");
  declare_integer("RESOURCE_TYPE_FONT");
  declare_integer("RESOURCE_TYPE_ACCELERATOR");
  declare_integer("RESOURCE_TYPE_RCDATA");
  declare_integer("RESOURCE_TYPE_MESSAGETABLE");
  declare_integer("RESOURCE_TYPE_GROUP_CURSOR");
  declare_integer("RESOURCE_TYPE_GROUP_ICON");
  declare_integer("RESOURCE_TYPE_VERSION");
  declare_integer("RESOURCE_TYPE_DLGINCLUDE");
  declare_integer("RESOURCE_TYPE_PLUGPLAY");
  declare_integer("RESOURCE_TYPE_VXD");
  declare_integer("RESOURCE_TYPE_ANICURSOR");
  declare_integer("RESOURCE_TYPE_ANIICON");
  declare_integer("RESOURCE_TYPE_HTML");
  declare_integer("RESOURCE_TYPE_MANIFEST");

  declare_integer("IMAGE_DEBUG_TYPE_UNKNOWN");
  declare_integer("IMAGE_DEBUG_TYPE_COFF");
  declare_integer("IMAGE_DEBUG_TYPE_CODEVIEW");
  declare_integer("IMAGE_DEBUG_TYPE_FPO");
  declare_integer("IMAGE_DEBUG_TYPE_MISC");
  declare_integer("IMAGE_DEBUG_TYPE_EXCEPTION");
  declare_integer("IMAGE_DEBUG_TYPE_FIXUP");
  declare_integer("IMAGE_DEBUG_TYPE_OMAP_TO_SRC");
  declare_integer("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC");
  declare_integer("IMAGE_DEBUG_TYPE_BORLAND");
  declare_integer("IMAGE_DEBUG_TYPE_RESERVED10");
  declare_integer("IMAGE_DEBUG_TYPE_CLSID");
  declare_integer("IMAGE_DEBUG_TYPE_VC_FEATURE");
  declare_integer("IMAGE_DEBUG_TYPE_POGO");
  declare_integer("IMAGE_DEBUG_TYPE_ILTCG");
  declare_integer("IMAGE_DEBUG_TYPE_MPX");
  declare_integer("IMAGE_DEBUG_TYPE_REPRO");

  declare_integer("is_pe");
  declare_integer("machine");
  declare_integer("number_of_sections");
  declare_integer("timestamp");
  declare_integer("pointer_to_symbol_table");
  declare_integer("number_of_symbols");
  declare_integer("size_of_optional_header");
  declare_integer("characteristics");

  declare_integer("entry_point");
  declare_integer("entry_point_raw");
  declare_integer("image_base");
  declare_integer("number_of_rva_and_sizes");
  declare_integer("number_of_version_infos");

  declare_string_dictionary("version_info");

  begin_struct_array("version_info_list")
    declare_string("key");
    declare_string("value");
  end_struct_array("version_info_list");

  declare_integer("opthdr_magic");
  declare_integer("size_of_code");
  declare_integer("size_of_initialized_data");
  declare_integer("size_of_uninitialized_data");
  declare_integer("base_of_code");
  declare_integer("base_of_data");
  declare_integer("section_alignment");
  declare_integer("file_alignment");

  begin_struct("linker_version")
    declare_integer("major");
    declare_integer("minor");
  end_struct("linker_version");

  begin_struct("os_version")
    declare_integer("major");
    declare_integer("minor");
  end_struct("os_version");

  begin_struct("image_version")
    declare_integer("major");
    declare_integer("minor");
  end_struct("image_version");

  begin_struct("subsystem_version")
    declare_integer("major");
    declare_integer("minor");
  end_struct("subsystem_version");

  declare_integer("win32_version_value");
  declare_integer("size_of_image");
  declare_integer("size_of_headers");

  declare_integer("checksum");
  declare_function("calculate_checksum", "", "i", calculate_checksum);
  declare_integer("subsystem");

  declare_integer("dll_characteristics");
  declare_integer("size_of_stack_reserve");
  declare_integer("size_of_stack_commit");
  declare_integer("size_of_heap_reserve");
  declare_integer("size_of_heap_commit");
  declare_integer("loader_flags");

  begin_struct_array("data_directories")
    declare_integer("virtual_address");
    declare_integer("size");
  end_struct_array("data_directories");

  begin_struct_array("sections")
    declare_string("name");
    declare_string("full_name");
    declare_integer("characteristics");
    declare_integer("virtual_address");
    declare_integer("virtual_size");
    declare_integer("raw_data_offset");
    declare_integer("raw_data_size");
    declare_integer("pointer_to_relocations");
    declare_integer("pointer_to_line_numbers");
    declare_integer("number_of_relocations");
    declare_integer("number_of_line_numbers");
  end_struct_array("sections");

  begin_struct("overlay")
    declare_integer("offset");
    declare_integer("size");
  end_struct("overlay");

  begin_struct("rich_signature")
    declare_integer("offset");
    declare_integer("length");
    declare_integer("key");
    declare_string("raw_data");
    declare_string("clear_data");
    declare_function("version", "i", "i", rich_version);
    declare_function("version", "ii", "i", rich_version_toolid);
    declare_function("toolid", "i", "i", rich_toolid);
    declare_function("toolid", "ii", "i", rich_toolid_version);
  end_struct("rich_signature");

#if defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H) || \
    defined(HAVE_COMMONCRYPTO_COMMONCRYPTO_H)
  declare_function("imphash", "", "s", imphash);
#endif

  declare_integer("IMPORT_DELAYED");
  declare_integer("IMPORT_STANDARD");
  declare_integer("IMPORT_ANY");

  declare_function("section_index", "s", "i", section_index_name);
  declare_function("section_index", "i", "i", section_index_addr);
  declare_function("exports", "s", "i", exports);
  declare_function("exports", "r", "i", exports_regexp);
  declare_function("exports", "i", "i", exports_ordinal);
  declare_function("exports_index", "s", "i", exports_index_name);
  declare_function("exports_index", "i", "i", exports_index_ordinal);
  declare_function("exports_index", "r", "i", exports_index_regex);
  declare_function("imports", "ss", "i", imports_standard);
  declare_function("imports", "si", "i", imports_standard_ordinal);
  declare_function("imports", "s", "i", imports_standard_dll);
  declare_function("imports", "rr", "i", imports_standard_regex);
  declare_function("imports", "iss", "i", imports);
  declare_function("imports", "isi", "i", imports_ordinal);
  declare_function("imports", "is", "i", imports_dll);
  declare_function("imports", "irr", "i", imports_regex);
  declare_function("locale", "i", "i", locale);
  declare_function("language", "i", "i", language);
  declare_function("is_dll", "", "i", is_dll);
  declare_function("is_32bit", "", "i", is_32bit);
  declare_function("is_64bit", "", "i", is_64bit);

  declare_integer("number_of_imports");
  declare_integer("number_of_imported_functions");
  declare_integer("number_of_delayed_imports");
  declare_integer("number_of_delayed_imported_functions");
  declare_integer("number_of_exports");

  declare_string("dll_name");
  declare_integer("export_timestamp");
  begin_struct_array("export_details")
    declare_integer("offset");
    declare_string("name");
    declare_string("forward_name");
    declare_integer("ordinal");
  end_struct_array("export_details")

  begin_struct_array("import_details")
    declare_string("library_name");
    declare_integer("number_of_functions");
    begin_struct_array("functions")
      declare_string("name");
      declare_integer("ordinal");
    end_struct_array("functions");
  end_struct_array("import_details");

  begin_struct_array("delayed_import_details")
    declare_string("library_name");
    declare_integer("number_of_functions");
    begin_struct_array("functions")
      declare_string("name");
      declare_integer("ordinal");
    end_struct_array("functions");
  end_struct_array("delayed_import_details");

  declare_integer("resource_timestamp");

  begin_struct("resource_version")
    declare_integer("major");
    declare_integer("minor");
  end_struct("resource_version")

  begin_struct_array("resources")
    declare_integer("rva");
    declare_integer("offset");
    declare_integer("length");
    declare_integer("type");
    declare_integer("id");
    declare_integer("language");
    declare_string("type_string");
    declare_string("name_string");
    declare_string("language_string");
  end_struct_array("resources")

  declare_integer("number_of_resources");
  declare_string("pdb_path");

#if defined(HAVE_LIBCRYPTO) && !defined(BORINGSSL)
  begin_struct_array("signatures")
    declare_string("thumbprint");
    declare_string("issuer");
    declare_string("subject");
    declare_integer("version");
    declare_string("algorithm");
    declare_string("algorithm_oid");
    declare_string("serial");
    declare_integer("not_before");
    declare_integer("not_after");
    declare_function("valid_on", "i", "i", valid_on);
  end_struct_array("signatures")

  declare_integer("number_of_signatures");
#endif

  declare_function("rva_to_offset", "i", "i", rva_to_offset);
end_declarations

int module_initialize(YR_MODULE* module)
{
#if defined(HAVE_LIBCRYPTO)
  // Not checking return value here because if it fails we will not parse the
  // nested signature silently.
  OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL);
#endif
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  PIMAGE_NT_HEADERS32 pe_header;
  const uint8_t* block_data = NULL;
  PE* pe = NULL;

  set_integer(IMPORT_DELAYED, module_object, "IMPORT_DELAYED");
  set_integer(IMPORT_STANDARD, module_object, "IMPORT_STANDARD");
  set_integer(IMPORT_ANY, module_object, "IMPORT_ANY");

  set_integer(IMAGE_FILE_MACHINE_UNKNOWN, module_object, "MACHINE_UNKNOWN");
  set_integer(IMAGE_FILE_MACHINE_AM33, module_object, "MACHINE_AM33");
  set_integer(IMAGE_FILE_MACHINE_AMD64, module_object, "MACHINE_AMD64");
  set_integer(IMAGE_FILE_MACHINE_ARM, module_object, "MACHINE_ARM");
  set_integer(IMAGE_FILE_MACHINE_ARMNT, module_object, "MACHINE_ARMNT");
  set_integer(IMAGE_FILE_MACHINE_ARM64, module_object, "MACHINE_ARM64");
  set_integer(IMAGE_FILE_MACHINE_EBC, module_object, "MACHINE_EBC");
  set_integer(IMAGE_FILE_MACHINE_I386, module_object, "MACHINE_I386");
  set_integer(IMAGE_FILE_MACHINE_IA64, module_object, "MACHINE_IA64");
  set_integer(IMAGE_FILE_MACHINE_M32R, module_object, "MACHINE_M32R");
  set_integer(IMAGE_FILE_MACHINE_MIPS16, module_object, "MACHINE_MIPS16");
  set_integer(IMAGE_FILE_MACHINE_MIPSFPU, module_object, "MACHINE_MIPSFPU");
  set_integer(IMAGE_FILE_MACHINE_MIPSFPU16, module_object, "MACHINE_MIPSFPU16");
  set_integer(IMAGE_FILE_MACHINE_POWERPC, module_object, "MACHINE_POWERPC");
  set_integer(IMAGE_FILE_MACHINE_POWERPCFP, module_object, "MACHINE_POWERPCFP");
  set_integer(IMAGE_FILE_MACHINE_R4000, module_object, "MACHINE_R4000");
  set_integer(IMAGE_FILE_MACHINE_SH3, module_object, "MACHINE_SH3");
  set_integer(IMAGE_FILE_MACHINE_SH3DSP, module_object, "MACHINE_SH3DSP");
  set_integer(IMAGE_FILE_MACHINE_SH4, module_object, "MACHINE_SH4");
  set_integer(IMAGE_FILE_MACHINE_SH5, module_object, "MACHINE_SH5");
  set_integer(IMAGE_FILE_MACHINE_THUMB, module_object, "MACHINE_THUMB");
  set_integer(IMAGE_FILE_MACHINE_WCEMIPSV2, module_object, "MACHINE_WCEMIPSV2");
  set_integer(
      IMAGE_FILE_MACHINE_TARGET_HOST, module_object, "MACHINE_TARGET_HOST");
  set_integer(IMAGE_FILE_MACHINE_R3000, module_object, "MACHINE_R3000");
  set_integer(IMAGE_FILE_MACHINE_R10000, module_object, "MACHINE_R10000");
  set_integer(IMAGE_FILE_MACHINE_ALPHA, module_object, "MACHINE_ALPHA");
  set_integer(IMAGE_FILE_MACHINE_SH3E, module_object, "MACHINE_SH3E");
  set_integer(IMAGE_FILE_MACHINE_ALPHA64, module_object, "MACHINE_ALPHA64");
  set_integer(IMAGE_FILE_MACHINE_AXP64, module_object, "MACHINE_AXP64");
  set_integer(IMAGE_FILE_MACHINE_TRICORE, module_object, "MACHINE_TRICORE");
  set_integer(IMAGE_FILE_MACHINE_CEF, module_object, "MACHINE_CEF");
  set_integer(IMAGE_FILE_MACHINE_CEE, module_object, "MACHINE_CEE");

  set_integer(IMAGE_SUBSYSTEM_UNKNOWN, module_object, "SUBSYSTEM_UNKNOWN");
  set_integer(IMAGE_SUBSYSTEM_NATIVE, module_object, "SUBSYSTEM_NATIVE");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_GUI, module_object, "SUBSYSTEM_WINDOWS_GUI");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_CUI, module_object, "SUBSYSTEM_WINDOWS_CUI");
  set_integer(IMAGE_SUBSYSTEM_OS2_CUI, module_object, "SUBSYSTEM_OS2_CUI");
  set_integer(IMAGE_SUBSYSTEM_POSIX_CUI, module_object, "SUBSYSTEM_POSIX_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
      module_object,
      "SUBSYSTEM_NATIVE_WINDOWS");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
      module_object,
      "SUBSYSTEM_WINDOWS_CE_GUI");
  set_integer(
      IMAGE_SUBSYSTEM_EFI_APPLICATION,
      module_object,
      "SUBSYSTEM_EFI_APPLICATION");
  set_integer(
      IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
      module_object,
      "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER");
  set_integer(
      IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
      module_object,
      "SUBSYSTEM_EFI_RUNTIME_DRIVER");
  set_integer(
      IMAGE_SUBSYSTEM_EFI_ROM_IMAGE, module_object, "SUBSYSTEM_EFI_ROM_IMAGE");
  set_integer(IMAGE_SUBSYSTEM_XBOX, module_object, "SUBSYSTEM_XBOX");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
      module_object,
      "SUBSYSTEM_WINDOWS_BOOT_APPLICATION");

  set_integer(
      IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
      module_object,
      "HIGH_ENTROPY_VA");
  set_integer(
      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, module_object, "DYNAMIC_BASE");
  set_integer(
      IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
      module_object,
      "FORCE_INTEGRITY");
  set_integer(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, module_object, "NX_COMPAT");
  set_integer(
      IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, module_object, "NO_ISOLATION");
  set_integer(IMAGE_DLLCHARACTERISTICS_NO_SEH, module_object, "NO_SEH");
  set_integer(IMAGE_DLLCHARACTERISTICS_NO_BIND, module_object, "NO_BIND");
  set_integer(
      IMAGE_DLLCHARACTERISTICS_APPCONTAINER, module_object, "APPCONTAINER");
  set_integer(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, module_object, "WDM_DRIVER");
  set_integer(IMAGE_DLLCHARACTERISTICS_GUARD_CF, module_object, "GUARD_CF");
  set_integer(
      IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
      module_object,
      "TERMINAL_SERVER_AWARE");

  set_integer(IMAGE_FILE_RELOCS_STRIPPED, module_object, "RELOCS_STRIPPED");
  set_integer(IMAGE_FILE_EXECUTABLE_IMAGE, module_object, "EXECUTABLE_IMAGE");
  set_integer(
      IMAGE_FILE_LINE_NUMS_STRIPPED, module_object, "LINE_NUMS_STRIPPED");
  set_integer(
      IMAGE_FILE_LOCAL_SYMS_STRIPPED, module_object, "LOCAL_SYMS_STRIPPED");
  set_integer(IMAGE_FILE_AGGRESIVE_WS_TRIM, module_object, "AGGRESIVE_WS_TRIM");
  set_integer(
      IMAGE_FILE_LARGE_ADDRESS_AWARE, module_object, "LARGE_ADDRESS_AWARE");
  set_integer(IMAGE_FILE_BYTES_REVERSED_LO, module_object, "BYTES_REVERSED_LO");
  set_integer(IMAGE_FILE_32BIT_MACHINE, module_object, "MACHINE_32BIT");
  set_integer(IMAGE_FILE_DEBUG_STRIPPED, module_object, "DEBUG_STRIPPED");
  set_integer(
      IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
      module_object,
      "REMOVABLE_RUN_FROM_SWAP");
  set_integer(IMAGE_FILE_NET_RUN_FROM_SWAP, module_object, "NET_RUN_FROM_SWAP");
  set_integer(IMAGE_FILE_SYSTEM, module_object, "SYSTEM");
  set_integer(IMAGE_FILE_DLL, module_object, "DLL");
  set_integer(IMAGE_FILE_UP_SYSTEM_ONLY, module_object, "UP_SYSTEM_ONLY");
  set_integer(IMAGE_FILE_BYTES_REVERSED_HI, module_object, "BYTES_REVERSED_HI");

  set_integer(
      IMAGE_DIRECTORY_ENTRY_EXPORT,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_EXPORT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_IMPORT,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_IMPORT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_RESOURCE,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_RESOURCE");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_EXCEPTION,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_EXCEPTION");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_SECURITY,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_SECURITY");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_BASERELOC,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_BASERELOC");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_DEBUG,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_DEBUG");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_COPYRIGHT,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_COPYRIGHT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_GLOBALPTR");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_TLS, module_object, "IMAGE_DIRECTORY_ENTRY_TLS");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_IAT, module_object, "IMAGE_DIRECTORY_ENTRY_IAT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT");
  set_integer(
      IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
      module_object,
      "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR");

  set_integer(
      IMAGE_NT_OPTIONAL_HDR32_MAGIC,
      module_object,
      "IMAGE_NT_OPTIONAL_HDR32_MAGIC");
  set_integer(
      IMAGE_NT_OPTIONAL_HDR64_MAGIC,
      module_object,
      "IMAGE_NT_OPTIONAL_HDR64_MAGIC");
  set_integer(
      IMAGE_ROM_OPTIONAL_HDR_MAGIC,
      module_object,
      "IMAGE_ROM_OPTIONAL_HDR_MAGIC");

  set_integer(IMAGE_SCN_TYPE_NO_PAD, module_object, "SECTION_NO_PAD");
  set_integer(IMAGE_SCN_CNT_CODE, module_object, "SECTION_CNT_CODE");
  set_integer(
      IMAGE_SCN_CNT_INITIALIZED_DATA,
      module_object,
      "SECTION_CNT_INITIALIZED_DATA");
  set_integer(
      IMAGE_SCN_CNT_UNINITIALIZED_DATA,
      module_object,
      "SECTION_CNT_UNINITIALIZED_DATA");
  set_integer(IMAGE_SCN_LNK_OTHER, module_object, "SECTION_LNK_OTHER");
  set_integer(IMAGE_SCN_LNK_INFO, module_object, "SECTION_LNK_INFO");
  set_integer(IMAGE_SCN_LNK_REMOVE, module_object, "SECTION_LNK_REMOVE");
  set_integer(IMAGE_SCN_LNK_COMDAT, module_object, "SECTION_LNK_COMDAT");
  set_integer(
      IMAGE_SCN_NO_DEFER_SPEC_EXC, module_object, "SECTION_NO_DEFER_SPEC_EXC");
  set_integer(IMAGE_SCN_GPREL, module_object, "SECTION_GPREL");
  set_integer(IMAGE_SCN_MEM_FARDATA, module_object, "SECTION_MEM_FARDATA");
  set_integer(IMAGE_SCN_MEM_PURGEABLE, module_object, "SECTION_MEM_PURGEABLE");
  set_integer(IMAGE_SCN_MEM_16BIT, module_object, "SECTION_MEM_16BIT");
  set_integer(IMAGE_SCN_MEM_LOCKED, module_object, "SECTION_MEM_LOCKED");
  set_integer(IMAGE_SCN_MEM_PRELOAD, module_object, "SECTION_MEM_PRELOAD");
  set_integer(IMAGE_SCN_ALIGN_1BYTES, module_object, "SECTION_ALIGN_1BYTES");
  set_integer(IMAGE_SCN_ALIGN_2BYTES, module_object, "SECTION_ALIGN_2BYTES");
  set_integer(IMAGE_SCN_ALIGN_4BYTES, module_object, "SECTION_ALIGN_4BYTES");
  set_integer(IMAGE_SCN_ALIGN_8BYTES, module_object, "SECTION_ALIGN_8BYTES");
  set_integer(IMAGE_SCN_ALIGN_16BYTES, module_object, "SECTION_ALIGN_16BYTES");
  set_integer(IMAGE_SCN_ALIGN_32BYTES, module_object, "SECTION_ALIGN_32BYTES");
  set_integer(IMAGE_SCN_ALIGN_64BYTES, module_object, "SECTION_ALIGN_64BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_128BYTES, module_object, "SECTION_ALIGN_128BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_256BYTES, module_object, "SECTION_ALIGN_256BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_512BYTES, module_object, "SECTION_ALIGN_512BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_1024BYTES, module_object, "SECTION_ALIGN_1024BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_2048BYTES, module_object, "SECTION_ALIGN_2048BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_4096BYTES, module_object, "SECTION_ALIGN_4096BYTES");
  set_integer(
      IMAGE_SCN_ALIGN_8192BYTES, module_object, "SECTION_ALIGN_8192BYTES");
  set_integer(IMAGE_SCN_ALIGN_MASK, module_object, "SECTION_ALIGN_MASK");
  set_integer(
      IMAGE_SCN_LNK_NRELOC_OVFL, module_object, "SECTION_LNK_NRELOC_OVFL");
  set_integer(
      IMAGE_SCN_MEM_DISCARDABLE, module_object, "SECTION_MEM_DISCARDABLE");
  set_integer(
      IMAGE_SCN_MEM_NOT_CACHED, module_object, "SECTION_MEM_NOT_CACHED");
  set_integer(IMAGE_SCN_MEM_NOT_PAGED, module_object, "SECTION_MEM_NOT_PAGED");
  set_integer(IMAGE_SCN_MEM_SHARED, module_object, "SECTION_MEM_SHARED");
  set_integer(IMAGE_SCN_MEM_EXECUTE, module_object, "SECTION_MEM_EXECUTE");
  set_integer(IMAGE_SCN_MEM_READ, module_object, "SECTION_MEM_READ");
  set_integer(IMAGE_SCN_MEM_WRITE, module_object, "SECTION_MEM_WRITE");
  set_integer(IMAGE_SCN_SCALE_INDEX, module_object, "SECTION_SCALE_INDEX");

  set_integer(RESOURCE_TYPE_CURSOR, module_object, "RESOURCE_TYPE_CURSOR");
  set_integer(RESOURCE_TYPE_BITMAP, module_object, "RESOURCE_TYPE_BITMAP");
  set_integer(RESOURCE_TYPE_ICON, module_object, "RESOURCE_TYPE_ICON");
  set_integer(RESOURCE_TYPE_MENU, module_object, "RESOURCE_TYPE_MENU");
  set_integer(RESOURCE_TYPE_DIALOG, module_object, "RESOURCE_TYPE_DIALOG");
  set_integer(RESOURCE_TYPE_STRING, module_object, "RESOURCE_TYPE_STRING");
  set_integer(RESOURCE_TYPE_FONTDIR, module_object, "RESOURCE_TYPE_FONTDIR");
  set_integer(RESOURCE_TYPE_FONT, module_object, "RESOURCE_TYPE_FONT");
  set_integer(
      RESOURCE_TYPE_ACCELERATOR, module_object, "RESOURCE_TYPE_ACCELERATOR");
  set_integer(RESOURCE_TYPE_RCDATA, module_object, "RESOURCE_TYPE_RCDATA");
  set_integer(
      RESOURCE_TYPE_MESSAGETABLE, module_object, "RESOURCE_TYPE_MESSAGETABLE");
  set_integer(
      RESOURCE_TYPE_GROUP_CURSOR, module_object, "RESOURCE_TYPE_GROUP_CURSOR");
  set_integer(
      RESOURCE_TYPE_GROUP_ICON, module_object, "RESOURCE_TYPE_GROUP_ICON");
  set_integer(RESOURCE_TYPE_VERSION, module_object, "RESOURCE_TYPE_VERSION");
  set_integer(
      RESOURCE_TYPE_DLGINCLUDE, module_object, "RESOURCE_TYPE_DLGINCLUDE");
  set_integer(RESOURCE_TYPE_PLUGPLAY, module_object, "RESOURCE_TYPE_PLUGPLAY");
  set_integer(RESOURCE_TYPE_VXD, module_object, "RESOURCE_TYPE_VXD");
  set_integer(
      RESOURCE_TYPE_ANICURSOR, module_object, "RESOURCE_TYPE_ANICURSOR");
  set_integer(RESOURCE_TYPE_ANIICON, module_object, "RESOURCE_TYPE_ANIICON");
  set_integer(RESOURCE_TYPE_HTML, module_object, "RESOURCE_TYPE_HTML");
  set_integer(RESOURCE_TYPE_MANIFEST, module_object, "RESOURCE_TYPE_MANIFEST");

  set_integer(
      IMAGE_DEBUG_TYPE_UNKNOWN, module_object, "IMAGE_DEBUG_TYPE_UNKNOWN");
  set_integer(IMAGE_DEBUG_TYPE_COFF, module_object, "IMAGE_DEBUG_TYPE_COFF");
  set_integer(
      IMAGE_DEBUG_TYPE_CODEVIEW, module_object, "IMAGE_DEBUG_TYPE_CODEVIEW");
  set_integer(IMAGE_DEBUG_TYPE_FPO, module_object, "IMAGE_DEBUG_TYPE_FPO");
  set_integer(IMAGE_DEBUG_TYPE_MISC, module_object, "IMAGE_DEBUG_TYPE_MISC");
  set_integer(
      IMAGE_DEBUG_TYPE_EXCEPTION, module_object, "IMAGE_DEBUG_TYPE_EXCEPTION");
  set_integer(IMAGE_DEBUG_TYPE_FIXUP, module_object, "IMAGE_DEBUG_TYPE_FIXUP");
  set_integer(
      IMAGE_DEBUG_TYPE_OMAP_TO_SRC,
      module_object,
      "IMAGE_DEBUG_TYPE_OMAP_TO_SRC");
  set_integer(
      IMAGE_DEBUG_TYPE_OMAP_FROM_SRC,
      module_object,
      "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC");
  set_integer(
      IMAGE_DEBUG_TYPE_BORLAND, module_object, "IMAGE_DEBUG_TYPE_BORLAND");
  set_integer(
      IMAGE_DEBUG_TYPE_RESERVED10,
      module_object,
      "IMAGE_DEBUG_TYPE_RESERVED10");
  set_integer(IMAGE_DEBUG_TYPE_CLSID, module_object, "IMAGE_DEBUG_TYPE_CLSID");
  set_integer(
      IMAGE_DEBUG_TYPE_VC_FEATURE,
      module_object,
      "IMAGE_DEBUG_TYPE_VC_FEATURE");
  set_integer(IMAGE_DEBUG_TYPE_POGO, module_object, "IMAGE_DEBUG_TYPE_POGO");
  set_integer(IMAGE_DEBUG_TYPE_ILTCG, module_object, "IMAGE_DEBUG_TYPE_ILTCG");
  set_integer(IMAGE_DEBUG_TYPE_MPX, module_object, "IMAGE_DEBUG_TYPE_MPX");
  set_integer(IMAGE_DEBUG_TYPE_REPRO, module_object, "IMAGE_DEBUG_TYPE_REPRO");

  set_integer(0, module_object, "is_pe");

  foreach_memory_block(iterator, block)
  {
    block_data = block->fetch_data(block);

    if (block_data == NULL)
      continue;

    pe_header = pe_get_header(block_data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(yr_le16toh(pe_header->FileHeader.Characteristics) & IMAGE_FILE_DLL))
      {
        pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_hash_table_create(17, &pe->hash_table), yr_free(pe));

        pe->data = block_data;
        pe->data_size = block->size;
        pe->header = pe_header;
        pe->object = module_object;
        pe->resources = 0;
        pe->version_infos = 0;

        module_object->data = pe;

        pe_parse_header(pe, block->base, context->flags);
        pe_parse_rich_signature(pe, block->base);
        pe_parse_debug_directory(pe);

#if defined(HAVE_LIBCRYPTO) && !defined(BORINGSSL)
        pe_parse_certificates(pe);
#endif

        pe->imported_dlls = pe_parse_imports(pe);
        pe->delay_imported_dlls = pe_parse_delayed_imports(pe);
        pe_parse_exports(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}

void free_dlls(IMPORTED_DLL* dll)
{
  IMPORTED_DLL* next_dll = NULL;
  IMPORT_FUNCTION* func = NULL;
  IMPORT_FUNCTION* next_func = NULL;

  while (dll)
  {
    if (dll->name)
      yr_free(dll->name);

    func = dll->functions;

    while (func)
    {
      if (func->name)
        yr_free(func->name);

      next_func = func->next;
      yr_free(func);
      func = next_func;
    }

    next_dll = dll->next;
    yr_free(dll);
    dll = next_dll;
  }
}

int module_unload(YR_OBJECT* module_object)
{
  PE* pe = (PE*) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  if (pe->hash_table != NULL)
    yr_hash_table_destroy(
        pe->hash_table, (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_free);

  free_dlls(pe->imported_dlls);
  free_dlls(pe->delay_imported_dlls);

  yr_free(pe);

  return ERROR_SUCCESS;
}
