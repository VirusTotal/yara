/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <config.h>

#if defined(HAVE_LIBCRYPTO)
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/safestack.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#endif

#include <yara/pe.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/strutils.h>

#include "pe_utils.c"

#define MODULE_NAME pe

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
#define RESOURCE_TYPE_GROUP_CURSOR 12 // MAKEINTRESOURCE((ULONG_PTR)(RT_CURSOR) + 11)
#define RESOURCE_TYPE_GROUP_ICON   14 // MAKEINTRESOURCE((ULONG_PTR)(RT_ICON) + 11)
#define RESOURCE_TYPE_VERSION      16
#define RESOURCE_TYPE_DLGINCLUDE   17
#define RESOURCE_TYPE_PLUGPLAY     19
#define RESOURCE_TYPE_VXD          20
#define RESOURCE_TYPE_ANICURSOR    21
#define RESOURCE_TYPE_ANIICON      22
#define RESOURCE_TYPE_HTML         23
#define RESOURCE_TYPE_MANIFEST     24


#define RESOURCE_CALLBACK_CONTINUE   0
#define RESOURCE_CALLBACK_ABORT      1


#define RESOURCE_ITERATOR_FINISHED   0
#define RESOURCE_ITERATOR_ABORTED    1


#define MAX_PE_SECTIONS              96
#define MAX_PE_IMPORTS               16384
#define MAX_PE_EXPORTS               65535


#define IS_RESOURCE_SUBDIRECTORY(entry) \
    ((entry)->OffsetToData & 0x80000000)


#define RESOURCE_OFFSET(entry) \
    ((entry)->OffsetToData & 0x7FFFFFFF)


#define IS_64BITS_PE(pe) \
    (pe->header64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)


#define available_space(pe, pointer) \
    (pe->data + pe->data_size - (uint8_t*)(pointer))


#define fits_in_pe(pe, pointer, size) \
    ((size_t) size <= pe->data_size && \
     (uint8_t*) (pointer) >= pe->data && \
     (uint8_t*) (pointer) <= pe->data + pe->data_size - size)


#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof(struct_type))


typedef int (*RESOURCE_CALLBACK_FUNC) ( \
     PIMAGE_RESOURCE_DATA_ENTRY rsrc_data, \
     int rsrc_type, \
     int rsrc_id, \
     int rsrc_language, \
     uint8_t* type_string, \
     uint8_t* name_string, \
     uint8_t* lang_string, \
     void* cb_data);


//
// Imports are stored in a linked list. Each node (IMPORTED_DLL) contains the
// name of the DLL and a pointer to another linked list of IMPORTED_FUNCTION
// structures containing the names of imported functions.
//

typedef struct _IMPORTED_DLL
{
  char *name;

  struct _IMPORTED_FUNCTION *functions;
  struct _IMPORTED_DLL *next;

} IMPORTED_DLL, *PIMPORTED_DLL;


typedef struct _IMPORTED_FUNCTION
{
  char *name;
  uint8_t has_ordinal;
  uint16_t ordinal;

  struct _IMPORTED_FUNCTION *next;

} IMPORTED_FUNCTION, *PIMPORTED_FUNCTION;


typedef struct _PE
{
  uint8_t* data;
  size_t data_size;

  union {
    PIMAGE_NT_HEADERS32 header;
    PIMAGE_NT_HEADERS64 header64;
  };

  YR_OBJECT* object;
  IMPORTED_DLL* imported_dlls;
  uint32_t resources;

} PE;


int wide_string_fits_in_pe(
    PE* pe,
    char* data)
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


PIMAGE_NT_HEADERS32 pe_get_header(
    uint8_t* data,
    size_t data_size)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;

  size_t headers_size = 0;

  if (data_size < sizeof(IMAGE_DOS_HEADER))
    return NULL;

  mz_header = (PIMAGE_DOS_HEADER) data;

  if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  if (mz_header->e_lfanew < 0)
    return NULL;

  headers_size = mz_header->e_lfanew + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (data_size < headers_size)
    return NULL;

  pe_header = (PIMAGE_NT_HEADERS32) (data + mz_header->e_lfanew);

  headers_size += pe_header->FileHeader.SizeOfOptionalHeader;

  if (pe_header->Signature == IMAGE_NT_SIGNATURE &&
      (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_UNKNOWN ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AM33 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARMNT ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_EBC ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_M32R ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_MIPS16 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_MIPSFPU ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_MIPSFPU16 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_POWERPC ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_POWERPCFP ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_R4000 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_SH3 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_SH3DSP ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_SH4 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_SH5 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_THUMB ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_WCEMIPSV2) &&
      data_size > headers_size)
  {
    return pe_header;
  }
  else
  {
    return NULL;
  }
}


// Parse the rich signature.
// http://www.ntcore.com/files/richsign.htm

void pe_parse_rich_signature(
    PE* pe,
    size_t base_address)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;
  PRICH_SIGNATURE rich_signature;
  DWORD* rich_ptr;

  BYTE* raw_data = NULL;
  BYTE* clear_data = NULL;
  size_t headers_size = 0;
  size_t rich_len = 0;

  if (pe->data_size < sizeof(IMAGE_DOS_HEADER))
    return;

  mz_header = (PIMAGE_DOS_HEADER) pe->data;

  if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  if (mz_header->e_lfanew < 0)
    return;

  headers_size = mz_header->e_lfanew + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (pe->data_size < headers_size)
    return;

  // From offset 0x80 until the start of the PE header should be the Rich
  // signature. The three key values must all be equal and the first dword
  // XORs to "DanS". Then walk the buffer looking for "Rich" which marks the
  // end. Technically the XOR key should be right after "Rich" but it's not
  // important.

  rich_signature = (PRICH_SIGNATURE) (pe->data + 0x80);

  if (rich_signature->key1 != rich_signature->key2 ||
      rich_signature->key2 != rich_signature->key3 ||
      (rich_signature->dans ^ rich_signature->key1) != RICH_DANS)
  {
    return;
  }

  for (rich_ptr = (DWORD*) rich_signature;
       rich_ptr <= (DWORD*) (pe->data + headers_size);
       rich_ptr++)
  {
    if (*rich_ptr == RICH_RICH)
    {
      // Multiple by 4 because we are counting in DWORDs.
      rich_len = (rich_ptr - (DWORD*) rich_signature) * 4;
      raw_data = (BYTE*) yr_malloc(rich_len);

      if (!raw_data)
        return;

      memcpy(raw_data, rich_signature, rich_len);

      set_integer(
          base_address + 0x80, pe->object, "rich_signature.offset");

      set_integer(
          rich_len, pe->object, "rich_signature.length");

      set_integer(
          rich_signature->key1, pe->object, "rich_signature.key");

      break;
    }
  }

  // Walk the entire block and apply the XOR key.
  if (raw_data)
  {
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
    return;
  }

  return;
}


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry)
{
  PIMAGE_DATA_DIRECTORY result;

  if (IS_64BITS_PE(pe))
    result = &pe->header64->OptionalHeader.DataDirectory[entry];
  else
    result = &pe->header->OptionalHeader.DataDirectory[entry];

  return result;
}


int64_t pe_rva_to_offset(
    PE* pe,
    uint64_t rva)
{
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe->header);

  DWORD section_rva = 0;
  DWORD section_offset = 0;
  DWORD section_raw_size = 0;

  int64_t result;

  int i = 0;

  while(i < yr_min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS))
  {
    if (struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
    {
      if (rva >= section->VirtualAddress &&
          section_rva <= section->VirtualAddress)
      {
        section_rva = section->VirtualAddress;
        section_offset = section->PointerToRawData;
        section_raw_size = section->SizeOfRawData;
      }

      section++;
      i++;
    }
    else
    {
      return -1;
    }
  }

  // Many sections, have a raw (on disk) size smaller than their in-memory size.
  // Check for rva's that map to this sparse space, and therefore have no valid
  // associated file offset.

  if ((rva - section_rva) >= section_raw_size)
    return -1;

  result = section_offset + (rva - section_rva);

  // Check that the offset fits within the file.
  if (result >= pe->data_size)
    return -1;

  return result;
}


// Return a pointer to the resource directory string or NULL.
// The callback function will parse this and call set_sized_string().
// The pointer is guranteed to have enough space to contain the entire string.

uint8_t* parse_resource_name(
    PE* pe,
    uint8_t* rsrc_data,
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry)
{

  // If high bit is set it is an offset relative to rsrc_data, which contains
  // a resource directory string.

  if (entry->Name & 0x80000000)
  {
    DWORD length;

    uint8_t* rsrc_str_ptr = rsrc_data + (entry->Name & 0x7FFFFFFF);

    // A resource directory string is 2 bytes for a string and then a variable
    // length Unicode string. Make sure we at least have two bytes.

    if (!fits_in_pe(pe, rsrc_str_ptr, 2))
      return NULL;

    length = *rsrc_str_ptr;

    // Move past the length and make sure we have enough bytes for the string.
    if (!fits_in_pe(pe, rsrc_str_ptr + 2, length * 2))
      return NULL;

    return rsrc_str_ptr;
  }

  return NULL;
}


int _pe_iterate_resources(
    PE* pe,
    PIMAGE_RESOURCE_DIRECTORY resource_dir,
    uint8_t* rsrc_data,
    int rsrc_tree_level,
    int* type,
    int* id,
    int* language,
    uint8_t* type_string,
    uint8_t* name_string,
    uint8_t* lang_string,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int i, result = RESOURCE_ITERATOR_FINISHED;
  int total_entries;

  PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;

  // A few sanity checks to avoid corrupt files

  if (resource_dir->Characteristics != 0 ||
      resource_dir->NumberOfNamedEntries > 32768 ||
      resource_dir->NumberOfIdEntries > 32768)
  {
    return result;
  }

  total_entries = resource_dir->NumberOfNamedEntries +
                  resource_dir->NumberOfIdEntries;

  // The first directory entry is just after the resource directory,
  // by incrementing resource_dir we skip sizeof(resource_dir) bytes
  // and get a pointer to the end of the resource directory.

  entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (resource_dir + 1);

  for (i = 0; i < total_entries; i++)
  {
    if (!struct_fits_in_pe(pe, entry, IMAGE_RESOURCE_DIRECTORY_ENTRY))
    {
      return RESOURCE_ITERATOR_ABORTED;
    }

    switch(rsrc_tree_level)
    {
      case 0:
        *type = entry->Name;
        type_string = parse_resource_name(pe, rsrc_data, entry);
        break;
      case 1:
        *id = entry->Name;
        name_string = parse_resource_name(pe, rsrc_data, entry);
        break;
      case 2:
        *language = entry->Name;
        lang_string = parse_resource_name(pe, rsrc_data, entry);
        break;
    }

    if (IS_RESOURCE_SUBDIRECTORY(entry) && rsrc_tree_level < 2)
    {
      PIMAGE_RESOURCE_DIRECTORY directory = (PIMAGE_RESOURCE_DIRECTORY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

      if (!struct_fits_in_pe(pe, directory, IMAGE_RESOURCE_DIRECTORY))
      {
        return RESOURCE_ITERATOR_ABORTED;
      }

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

      if (result == RESOURCE_ITERATOR_ABORTED)
        return RESOURCE_ITERATOR_ABORTED;
    }
    else
    {
      PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

      if (!struct_fits_in_pe(pe, data_entry, IMAGE_RESOURCE_DATA_ENTRY))
      {
        return RESOURCE_ITERATOR_ABORTED;
      }

      result = callback(
          data_entry,
          *type,
          *id,
          *language,
          type_string,
          name_string,
          lang_string,
          callback_data);

      if (result == RESOURCE_CALLBACK_ABORT)
        return RESOURCE_ITERATOR_ABORTED;
    }

    if (result == RESOURCE_ITERATOR_ABORTED)
      return result;

    entry++;
  }

  return RESOURCE_ITERATOR_FINISHED;
}


int pe_iterate_resources(
    PE* pe,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int64_t offset;

  int type = -1;
  int id = -1;
  int language = -1;

  uint8_t* type_string = NULL;
  uint8_t* name_string = NULL;
  uint8_t* lang_string = NULL;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);

  if (directory->VirtualAddress != 0)
  {
    PIMAGE_RESOURCE_DIRECTORY rsrc_dir;

    offset = pe_rva_to_offset(pe, directory->VirtualAddress);

    if (offset < 0)
      return 0;

    rsrc_dir = (PIMAGE_RESOURCE_DIRECTORY) (pe->data + offset);

    if (struct_fits_in_pe(pe, rsrc_dir, IMAGE_RESOURCE_DIRECTORY))
    {
      set_integer(rsrc_dir->TimeDateStamp,
          pe->object,
          "resource_timestamp");

      set_integer(rsrc_dir->MajorVersion,
                  pe->object,
                  "resource_version.major");
      set_integer(rsrc_dir->MinorVersion,
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
    (PVERSION_INFO) ((uint8_t*) (ptr) + ((offset + 3) & ~3))


void pe_parse_version_info(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    PE* pe)
{
  PVERSION_INFO version_info;

  int64_t version_info_offset = pe_rva_to_offset(pe, rsrc_data->OffsetToData);

  if (version_info_offset < 0)
    return;

  version_info = (PVERSION_INFO) (pe->data + version_info_offset);

  if (!struct_fits_in_pe(pe, version_info, VERSION_INFO))
    return;

  if (!fits_in_pe(pe, version_info->Key, sizeof("VS_VERSION_INFO") * 2))
    return;

  if (strcmp_w(version_info->Key, "VS_VERSION_INFO") != 0)
    return;

  version_info = ADD_OFFSET(
      version_info, sizeof(VERSION_INFO) + 86);

  while(fits_in_pe(pe, version_info->Key, sizeof("VarFileInfo") * 2) &&
        strcmp_w(version_info->Key, "VarFileInfo") == 0 &&
        version_info->Length != 0)
  {
    version_info = ADD_OFFSET(
        version_info,
        version_info->Length);
  }

  while(fits_in_pe(pe, version_info->Key, sizeof("StringFileInfo") * 2) &&
        strcmp_w(version_info->Key, "StringFileInfo") == 0 &&
        version_info->Length != 0)
  {
    PVERSION_INFO string_table = ADD_OFFSET(
        version_info,
        sizeof(VERSION_INFO) + 30);

    version_info = ADD_OFFSET(
        version_info,
        version_info->Length);

    while (struct_fits_in_pe(pe, string_table, VERSION_INFO) &&
           wide_string_fits_in_pe(pe, string_table->Key) &&
           string_table->Length != 0 &&
           string_table < version_info)
    {
      PVERSION_INFO string = ADD_OFFSET(
          string_table,
          sizeof(VERSION_INFO) + 2 * (strnlen_w(string_table->Key) + 1));

      string_table = ADD_OFFSET(
          string_table,
          string_table->Length);

      while (struct_fits_in_pe(pe, string, VERSION_INFO) &&
             wide_string_fits_in_pe(pe, string->Key) &&
             string->Length != 0 &&
             string < string_table)
      {
        if (string->ValueLength > 0)
        {
          char* string_value = (char*) ADD_OFFSET(string,
              sizeof(VERSION_INFO) + 2 * (strnlen_w(string->Key) + 1));

          if (wide_string_fits_in_pe(pe, string_value))
          {
            char key[64];
            char value[256];

            strlcpy_w(key, string->Key, sizeof(key));
            strlcpy_w(value, string_value, sizeof(value));

            set_string(value, pe->object, "version_info[%s]", key);
          }
        }

        string = ADD_OFFSET(string, string->Length);
      }
    }
  }
}


int pe_collect_resources(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    uint8_t* type_string,
    uint8_t* name_string,
    uint8_t* lang_string,
    PE* pe)
{
  DWORD length;

  int64_t offset = pe_rva_to_offset(pe, rsrc_data->OffsetToData);

  if (offset < 0 || !fits_in_pe(pe, pe->data + offset, rsrc_data->Size))
    return RESOURCE_CALLBACK_CONTINUE;

  set_integer(
        offset,
        pe->object,
        "resources[%i].offset",
        pe->resources);

  set_integer(
        rsrc_data->Size,
        pe->object,
        "resources[%i].length",
        pe->resources);

  if (type_string)
  {
    // Multiply by 2 because it is a Unicode string.
    length = ((DWORD) *type_string) * 2;
    type_string += 2;

    set_sized_string(
        (char*) type_string, length, pe->object,
        "resources[%i].type_string", pe->resources);
  }
  else
  {
    set_integer(
          rsrc_type,
          pe->object,
          "resources[%i].type",
          pe->resources);
  }

  if (name_string)
  {
    // Multiply by 2 because it is a Unicode string.
    length = ((DWORD) *name_string) * 2;
    name_string += 2;
    set_sized_string(
        (char*) name_string, length, pe->object,
        "resources[%i].name_string", pe->resources);
  }
  else
  {
    set_integer(
        rsrc_id,
        pe->object,
        "resources[%i].id",
        pe->resources);
  }

  if (lang_string)
  {
    // Multiply by 2 because it is a Unicode string.
    length = ((DWORD) *lang_string) * 2;
    lang_string += 2;
    set_sized_string(
        (char*) lang_string, length, pe->object,
        "resources[%i].language_string", pe->resources);
  }
  else
  {
    set_integer(
        rsrc_language,
        pe->object,
        "resources[%i].language",
        pe->resources);
  }

  // Resources we do extra parsing on
  if (rsrc_type == RESOURCE_TYPE_VERSION)
    pe_parse_version_info(rsrc_data, pe);

  pe->resources += 1;
  return RESOURCE_CALLBACK_CONTINUE;
}


IMPORTED_FUNCTION* pe_parse_import_descriptor(
    PE* pe,
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor,
    char* dll_name)
{
  IMPORTED_FUNCTION* head = NULL;
  IMPORTED_FUNCTION* tail = NULL;

  int num_functions = 0;

  int64_t offset = pe_rva_to_offset(
      pe, import_descriptor->OriginalFirstThunk);

  // I've seen binaries where OriginalFirstThunk is zero. In this case
  // use FirstThunk.

  if (offset < 0)
    offset = pe_rva_to_offset(pe, import_descriptor->FirstThunk);

  if (offset < 0)
    return NULL;

  if (IS_64BITS_PE(pe))
  {
    PIMAGE_THUNK_DATA64 thunks64 = (PIMAGE_THUNK_DATA64)(pe->data + offset);

    while (struct_fits_in_pe(pe, thunks64, IMAGE_THUNK_DATA64) &&
           thunks64->u1.Ordinal != 0 && num_functions < MAX_PE_IMPORTS)
    {
      char* name = NULL;
      uint16_t ordinal = 0;
      uint8_t has_ordinal = 0;

      if (!(thunks64->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, thunks64->u1.Function);

        if (offset >= 0)
        {
          PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME) \
              (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char *) yr_strndup(
                (char*) import->Name,
                yr_min(available_space(pe, import->Name), 512));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, thunks64->u1.Ordinal & 0xFFFF);
        // Also store the ordinal.
        ordinal = thunks64->u1.Ordinal & 0xFFFF;
        has_ordinal = 1;
      }

      if (name != NULL || has_ordinal == 1)
      {
        IMPORTED_FUNCTION* imported_func = (IMPORTED_FUNCTION*)
            yr_calloc(1, sizeof(IMPORTED_FUNCTION));

        if (imported_func == NULL)
          continue;

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

      num_functions++;
      thunks64++;
    }
  }
  else
  {
    PIMAGE_THUNK_DATA32 thunks32 = (PIMAGE_THUNK_DATA32)(pe->data + offset);

    while (struct_fits_in_pe(pe, thunks32, IMAGE_THUNK_DATA32) &&
           thunks32->u1.Ordinal != 0 && num_functions < MAX_PE_IMPORTS)
    {
      char* name = NULL;
      uint16_t ordinal = 0;
      uint8_t has_ordinal = 0;

      if (!(thunks32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, thunks32->u1.Function);

        if (offset >= 0)
        {
          PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME) \
              (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char *) yr_strndup(
                (char*) import->Name,
                yr_min(available_space(pe, import->Name), 512));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, thunks32->u1.Ordinal & 0xFFFF);
        // Also store the ordinal.
        ordinal = thunks32->u1.Ordinal & 0xFFFF;
        has_ordinal = 1;
      }

      if (name != NULL || has_ordinal == 1)
      {
        IMPORTED_FUNCTION* imported_func = (IMPORTED_FUNCTION*)
            yr_calloc(1, sizeof(IMPORTED_FUNCTION));

        if (imported_func == NULL)
          continue;

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

      num_functions++;
      thunks32++;
    }
  }

  return head;
}


int pe_valid_dll_name(
    const char* dll_name, size_t n)
{
  const char* c = dll_name;
  size_t l = 0;

  while (l < n && *c != '\0')
  {
    if ((*c >= 'a' && *c <= 'z') ||
        (*c >= 'A' && *c <= 'Z') ||
        (*c >= '0' && *c <= '9') ||
        (*c == '_' || *c == '.'))
    {
      c++;
      l++;
    }
    else
    {
      return FALSE;
    }
  }

  return (l > 0 && l < n);
}


//
// Walk the imports and collect relevant information. It is used in the
// "imports" function for comparison and in the "imphash" function for
// calculation.
//

IMPORTED_DLL* pe_parse_imports(
    PE* pe)
{
  int64_t offset;
  int num_imports = 0;

  IMPORTED_DLL* head = NULL;
  IMPORTED_DLL* tail = NULL;

  PIMAGE_IMPORT_DESCRIPTOR imports;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

  if (directory->VirtualAddress == 0)
    return NULL;

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset < 0)
    return NULL;

  imports = (PIMAGE_IMPORT_DESCRIPTOR) \
      (pe->data + offset);

  while (struct_fits_in_pe(pe, imports, IMAGE_IMPORT_DESCRIPTOR) &&
         imports->Name != 0 && num_imports < MAX_PE_IMPORTS)
  {
    int64_t offset = pe_rva_to_offset(pe, imports->Name);

    if (offset >= 0)
    {
      IMPORTED_FUNCTION* functions;

      char* dll_name = (char *) (pe->data + offset);

      if (!pe_valid_dll_name(dll_name, pe->data_size - (size_t) offset))
        break;

      functions = pe_parse_import_descriptor(
          pe, imports, dll_name);

      if (functions != NULL)
      {
        IMPORTED_DLL* imported_dll = (IMPORTED_DLL*) yr_calloc(
            1, sizeof(IMPORTED_DLL));

        if (imported_dll != NULL)
        {
          imported_dll->name = yr_strdup(dll_name);;
          imported_dll->functions = functions;
          imported_dll->next = NULL;

          if (head == NULL)
            head = imported_dll;

          if (tail != NULL)
            tail->next = imported_dll;

          tail = imported_dll;
        }
      }
    }

    num_imports++;
    imports++;
  }

  return head;
}


#if defined(HAVE_LIBCRYPTO)

void pe_parse_certificates(
    PE* pe)
{
  int i, counter = 0;
  uint8_t* eod;

  PWIN_CERTIFICATE win_cert;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_SECURITY);

  // directory->VirtualAddress is a file offset. Don't call pe_rva_to_offset().

  if (directory->VirtualAddress == 0 ||
      directory->VirtualAddress > pe->data_size ||
      directory->Size > pe->data_size ||
      directory->VirtualAddress + directory->Size > pe->data_size)
  {
    return;
  }

  // Store the end of directory, making comparisons easier.
  eod = pe->data + directory->VirtualAddress + directory->Size;

  win_cert = (PWIN_CERTIFICATE) \
      (pe->data + directory->VirtualAddress);

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
         win_cert->Length > sizeof(WIN_CERTIFICATE) &&
         fits_in_pe(pe, win_cert, win_cert->Length) &&
         (uint8_t*) win_cert + sizeof(WIN_CERTIFICATE) < eod &&
         (uint8_t*) win_cert + win_cert->Length <= eod)
  {
    BIO* cert_bio;
    PKCS7* pkcs7;
    STACK_OF(X509)* certs;

    // Some sanity checks

    if (win_cert->Length == 0 ||
        (win_cert->Revision != WIN_CERT_REVISION_1_0 &&
         win_cert->Revision != WIN_CERT_REVISION_2_0))
    {
      break;
    }

    // Don't support legacy revision for now.
    // Make sure type is PKCS#7 too.

    if (win_cert->Revision != WIN_CERT_REVISION_2_0 ||
        win_cert->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    {
      uintptr_t end = (uintptr_t) ((uint8_t *) win_cert) + win_cert->Length;
      win_cert = (PWIN_CERTIFICATE) (end + (end % 8));

      continue;
    }

    cert_bio = BIO_new_mem_buf(win_cert->Certificate, win_cert->Length);

    if (!cert_bio)
      break;

    pkcs7 = d2i_PKCS7_bio(cert_bio, NULL);
    certs = PKCS7_get0_signers(pkcs7, NULL, 0);

    if (!certs)
    {
      BIO_free(cert_bio);
      PKCS7_free(pkcs7);
      break;
    }

    for (i = 0; i < sk_X509_num(certs); i++)
    {
      const char* sig_alg;
      char buffer[256];
      int bytes;

      ASN1_INTEGER* serial;

      X509* cert = sk_X509_value(certs, i);

      X509_NAME_oneline(
          X509_get_issuer_name(cert), buffer, sizeof(buffer));

      set_string(buffer, pe->object, "signatures[%i].issuer", counter);

      X509_NAME_oneline(
          X509_get_subject_name(cert), buffer, sizeof(buffer));

      set_string(buffer, pe->object, "signatures[%i].subject", counter);

      set_integer(
          X509_get_version(cert) + 1, // Versions are zero based, so add one.
          pe->object,
          "signatures[%i].version", counter);

      sig_alg = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));

      set_string(sig_alg, pe->object, "signatures[%i].algorithm", counter);

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
        // Negative serial numbers are handled by calling i2c_ASN1_INTEGER()
        // with a NULL second parameter. This will return the size of the
        // buffer necessary to store the proper serial number.
        //
        // Do this even for positive serial numbers because it makes the code
        // cleaner and easier to read.

        bytes = i2c_ASN1_INTEGER(serial, NULL);

        // According to X.509 specification the maximum length for the serial
        // number is 20 octets.

        if (bytes > 0 && bytes <= 20)
        {
          // Now that we know the size of the serial number allocate enough
          // space to hold it, and use i2c_ASN1_INTEGER() one last time to
          // hold it in the allocated buffer.

          unsigned char* serial_bytes = (unsigned char*)  yr_malloc(bytes);

          if (serial_bytes != NULL)
          {
            bytes = i2c_ASN1_INTEGER(serial, &serial_bytes);

            // i2c_ASN1_INTEGER() moves the pointer as it writes into
            // serial_bytes. Move it back.

            serial_bytes -= bytes;

            // Also allocate space to hold the "common" string format:
            // 00:01:02:03:04...
            //
            // For each byte in the serial to convert to hexlified format we
            // need three bytes, two for the byte itself and one for colon.
            // The last one doesn't have the colon, but the extra byte is used
            // for the NULL terminator.

            char *serial_ascii = (char*) yr_malloc(bytes * 3);

            if (serial_ascii)
            {
              int j;

              for (j = 0; j < bytes; j++)
              {
                // Don't put the colon on the last one.
                if (j < bytes - 1)
                  snprintf(
                    (char*) serial_ascii + 3 * j, 4, "%02x:", serial_bytes[j]);
                else
                  snprintf(
                    (char*) serial_ascii + 3 * j, 3, "%02x", serial_bytes[j]);
              }

              set_string(
                  (char*) serial_ascii,
                  pe->object,
                  "signatures[%i].serial",
                  counter);

              yr_free(serial_ascii);
            }

            yr_free(serial_bytes);
          }
        }
      }

      time_t date_time = ASN1_get_time_t(X509_get_notBefore(cert));
      set_integer(date_time, pe->object, "signatures[%i].not_before", counter);

      date_time = ASN1_get_time_t(X509_get_notAfter(cert));
      set_integer(date_time, pe->object, "signatures[%i].not_after", counter);

      counter++;
    }

    uintptr_t end = (uintptr_t)((uint8_t *) win_cert) + win_cert->Length;
    win_cert = (PWIN_CERTIFICATE)(end + (end % 8));

    BIO_free(cert_bio);
    PKCS7_free(pkcs7);
    sk_X509_free(certs);
  }

  set_integer(counter, pe->object, "number_of_signatures");
}

#endif  // defined(HAVE_LIBCRYPTO)


void pe_parse_header(
    PE* pe,
    size_t base_address,
    int flags)
{
  PIMAGE_SECTION_HEADER section;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
  int i, scount;

#define OptionalHeader(field) \
    (IS_64BITS_PE(pe) ? \
        pe->header64->OptionalHeader.field : \
        pe->header->OptionalHeader.field)

  set_integer(
      pe->header->FileHeader.Machine,
      pe->object, "machine");

  set_integer(
      pe->header->FileHeader.NumberOfSections,
      pe->object, "number_of_sections");

  set_integer(
      pe->header->FileHeader.TimeDateStamp,
      pe->object, "timestamp");

  set_integer(
      pe->header->FileHeader.Characteristics,
      pe->object, "characteristics");

  set_integer(
      flags & SCAN_FLAGS_PROCESS_MEMORY ?
        base_address + OptionalHeader(AddressOfEntryPoint) :
        pe_rva_to_offset(pe, OptionalHeader(AddressOfEntryPoint)),
      pe->object, "entry_point");

  set_integer(
      OptionalHeader(ImageBase),
      pe->object, "image_base");

  set_integer(
      OptionalHeader(MajorLinkerVersion),
      pe->object, "linker_version.major");

  set_integer(
      OptionalHeader(MinorLinkerVersion),
      pe->object, "linker_version.minor");

  set_integer(
      OptionalHeader(MajorOperatingSystemVersion),
      pe->object, "os_version.major");

  set_integer(
      OptionalHeader(MinorOperatingSystemVersion),
      pe->object, "os_version.minor");

  set_integer(
      OptionalHeader(MajorImageVersion),
      pe->object, "image_version.major");

  set_integer(
      OptionalHeader(MinorImageVersion),
      pe->object, "image_version.minor");

  set_integer(
      OptionalHeader(MajorSubsystemVersion),
      pe->object, "subsystem_version.major");

  set_integer(
      OptionalHeader(MinorSubsystemVersion),
      pe->object, "subsystem_version.minor");

  set_integer(
      OptionalHeader(Subsystem),
      pe->object, "subsystem");

  pe_iterate_resources(
      pe,
      (RESOURCE_CALLBACK_FUNC) pe_collect_resources,
      (void*) pe);

  set_integer(pe->resources, pe->object, "number_of_resources");

  section = IMAGE_FIRST_SECTION(pe->header);

  scount = yr_min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS);

  for (i = 0; i < scount; i++)
  {
    if (!struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
      break;

    strncpy(section_name, (char*) section->Name, IMAGE_SIZEOF_SHORT_NAME);
    section_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

    set_string(
        section_name,
        pe->object, "sections[%i].name", i);

    set_integer(
        section->Characteristics,
        pe->object, "sections[%i].characteristics", i);

    set_integer(section->SizeOfRawData,
        pe->object, "sections[%i].raw_data_size", i);

    set_integer(section->PointerToRawData,
        pe->object, "sections[%i].raw_data_offset", i);

    set_integer(section->VirtualAddress,
        pe->object, "sections[%i].virtual_address", i);

    set_integer(
        section->Misc.VirtualSize,
        pe->object, "sections[%i].virtual_size", i);

    section++;
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
    return_integer(UNDEFINED);
  }

  timestamp = integer_argument(1);

  not_before = get_integer(parent(), "not_before");
  not_after = get_integer(parent(), "not_after");

  return_integer(timestamp >= not_before  && timestamp <= not_after);
}


define_function(section_index_addr)
{
  YR_OBJECT* module = module();
  YR_SCAN_CONTEXT* context = scan_context();

  int64_t i;
  int64_t offset;
  int64_t size;

  int64_t addr = integer_argument(1);
  int64_t n = get_integer(module, "number_of_sections");

  if (is_undefined(module, "number_of_sections"))
    return_integer(UNDEFINED);

  for (i = 0; i < yr_min(n, MAX_PE_SECTIONS); i++)
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

  return_integer(UNDEFINED);
}


define_function(section_index_name)
{
  YR_OBJECT* module = module();

  char* name = string_argument(1);

  int64_t n = get_integer(module, "number_of_sections");
  int64_t i;

  if (is_undefined(module, "number_of_sections"))
    return_integer(UNDEFINED);

  for (i = 0; i < yr_min(n, MAX_PE_SECTIONS); i++)
  {
    SIZED_STRING* sect = get_string(module, "sections[%i].name", i);

    if (sect != NULL && strcmp(name, sect->c_string) == 0)
      return_integer(i);
  }

  return_integer(UNDEFINED);
}


define_function(exports)
{
  SIZED_STRING* function_name = sized_string_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_EXPORT_DIRECTORY exports;
  DWORD* names;

  int64_t offset;
  uint32_t i;
  size_t remaining;

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

  // If the PE doesn't export any functions, return FALSE

  if (directory->VirtualAddress == 0)
    return_integer(0);

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset < 0)
    return_integer(0);

  exports = (PIMAGE_EXPORT_DIRECTORY) \
      (pe->data + offset);

  if (!struct_fits_in_pe(pe, exports, IMAGE_EXPORT_DIRECTORY))
    return_integer(0);

  offset = pe_rva_to_offset(pe, exports->AddressOfNames);

  if (offset < 0)
    return_integer(0);

  if (exports->NumberOfNames > MAX_PE_EXPORTS ||
      exports->NumberOfNames * sizeof(DWORD) > pe->data_size - offset)
    return_integer(0);

  names = (DWORD*)(pe->data + offset);

  for (i = 0; i < exports->NumberOfNames; i++)
  {
    char* name;
    offset = pe_rva_to_offset(pe, names[i]);

    if (offset < 0)
      return_integer(0);

    remaining = pe->data_size - (size_t) offset;
    name = (char*)(pe->data + offset);

    if (remaining >= function_name->length &&
        strncmp(name, function_name->c_string, remaining) == 0)
    {
      return_integer(1);
    }
  }

  return_integer(0);
}


#if defined(HAVE_LIBCRYPTO)

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
  MD5_CTX ctx;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];
  int i, first = TRUE;

  PE* pe = (PE*) module->data;

  // If not a PE, return UNDEFINED.

  if (!pe)
    return_string(UNDEFINED);

  MD5_Init(&ctx);

  dll = pe->imported_dlls;

  while (dll)
  {
    IMPORTED_FUNCTION* func;

    size_t dll_name_len;
    char* dll_name;

    // If extension is 'ocx', 'sys' or 'dll', chop it.

    char* ext = strstr(dll->name, ".");

    if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||
                strncasecmp(ext, ".sys", 4) == 0 ||
                strncasecmp(ext, ".dll", 4) == 0))
    {
      dll_name_len = (ext - dll->name);
    }
    else
    {
      dll_name_len = strlen(dll->name);
    }

    // Allocate a new string to hold the dll name.

    dll_name = (char *) yr_malloc(dll_name_len + 1);

    if (!dll_name)
      return ERROR_INSUFICIENT_MEMORY;

    strlcpy(dll_name, dll->name, dll_name_len + 1);

    func = dll->functions;

    while (func)
    {
      char* final_name;
      size_t final_name_len = dll_name_len + strlen(func->name) + 1;

      if (!first)
        final_name_len++;   // Additional byte to accommodate the extra comma

      final_name = (char*) yr_malloc(final_name_len + 1);

      if (final_name == NULL)
      {
        yr_free(dll_name);
        break;
      }

      sprintf(final_name, first ? "%s.%s": ",%s.%s", dll_name, func->name);

      // Lowercase the whole thing.

      for (i = 0; i < final_name_len; i++)
        final_name[i] = tolower(final_name[i]);

      MD5_Update(&ctx, final_name, final_name_len);

      yr_free(final_name);

      func = func->next;
      first = FALSE;
    }

    yr_free(dll_name);

    dll = dll->next;
  }

  MD5_Final(digest, &ctx);

  // Transform the binary digest to ascii

  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
  }

  digest_ascii[MD5_DIGEST_LENGTH * 2] = '\0';

  return_string(digest_ascii);
}

#endif  // defined(HAVE_LIBCRYPTO)


define_function(imports)
{
  char* dll_name = string_argument(1);
  char* function_name = string_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  IMPORTED_DLL* imported_dll;

  if (!pe)
    return_integer(UNDEFINED);

  imported_dll = pe->imported_dlls;

  while (imported_dll != NULL)
  {
    if (strcasecmp(imported_dll->name, dll_name) == 0)
    {
      IMPORTED_FUNCTION* imported_func = imported_dll->functions;

      while (imported_func != NULL)
      {
        if (imported_func->name &&
            strcasecmp(imported_func->name, function_name) == 0)
          return_integer(1);

        imported_func = imported_func->next;
      }
    }

    imported_dll = imported_dll->next;
  }

  return_integer(0);
}

define_function(imports_ordinal)
{
  char* dll_name = string_argument(1);
  uint64_t ordinal = integer_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  IMPORTED_DLL* imported_dll;

  if (!pe)
    return_integer(UNDEFINED);

  imported_dll = pe->imported_dlls;

  while (imported_dll != NULL)
  {
    if (strcasecmp(imported_dll->name, dll_name) == 0)
    {
      IMPORTED_FUNCTION* imported_func = imported_dll->functions;

      while (imported_func != NULL)
      {
        if (imported_func->has_ordinal && imported_func->ordinal == ordinal)
          return_integer(1);

        imported_func = imported_func->next;
      }
    }

    imported_dll = imported_dll->next;
  }

  return_integer(0);
}

define_function(imports_dll)
{
  char* dll_name = string_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  IMPORTED_DLL* imported_dll;

  if (!pe)
    return_integer(UNDEFINED);

  imported_dll = pe->imported_dlls;

  while (imported_dll != NULL)
  {
    if (strcasecmp(imported_dll->name, dll_name) == 0)
    {
      return_integer(1);
    }

    imported_dll = imported_dll->next;
  }

  return_integer(0);
}

define_function(locale)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  uint64_t locale = integer_argument(1);
  int64_t n, i;

  if (is_undefined(module, "number_of_resources"))
    return_integer(UNDEFINED);

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  n = get_integer(module, "number_of_resources");

  for (i = 0; i < n; i++)
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
  int64_t n, i;

  if (is_undefined(module, "number_of_resources"))
    return_integer(UNDEFINED);

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  n = get_integer(module, "number_of_resources");

  for (i = 0; i < n; i++)
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
    return_integer(UNDEFINED);

  characteristics = get_integer(module, "characteristics");
  return_integer(characteristics & IMAGE_FILE_DLL);
}


define_function(is_32bit)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (pe == NULL)
    return_integer(UNDEFINED);

  return_integer(IS_64BITS_PE(pe) ? 0 : 1);
}


define_function(is_64bit)
{
  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  if (pe == NULL)
    return_integer(UNDEFINED);

  return_integer(IS_64BITS_PE(pe) ? 1 : 0);
}


static uint64_t rich_internal(
    YR_OBJECT* module,
    uint64_t version,
    uint64_t toolid)
{
    size_t rich_len;

    PRICH_SIGNATURE clear_rich_signature;
    SIZED_STRING* rich_string;

    int rich_signature_count;
    int i;

    // Check if the required fields are set
    if (is_undefined(module, "rich_signature.length"))
        return UNDEFINED;

    rich_len = get_integer(module, "rich_signature.length");
    rich_string = get_string(module, "rich_signature.clear_data");

    // If the clear_data was not set, return UNDEFINED
    if (rich_string == NULL)
        return UNDEFINED;

    if (version == UNDEFINED && toolid == UNDEFINED)
        return FALSE;

    clear_rich_signature = (PRICH_SIGNATURE) rich_string->c_string;

    // Loop over the versions in the rich signature

    rich_signature_count = \
        (rich_len - sizeof(RICH_SIGNATURE)) / sizeof(RICH_VERSION_INFO);

    for (i = 0; i < rich_signature_count; i++)
    {
        DWORD id_version = clear_rich_signature->versions[i].id_version;

        int match_version = version == RICH_VERSION_VERSION(id_version);
        int match_toolid = toolid == RICH_VERSION_ID(id_version);

        if (version != UNDEFINED && toolid != UNDEFINED)
        {
          // check version and toolid
          if (match_version && match_toolid)
            return TRUE;
        }
        else if (version != UNDEFINED)
        {
          // check only version
          if (match_version)
            return TRUE;
        }
        else if (toolid != UNDEFINED)
        {
          // check only toolid
          if (match_toolid)
            return TRUE;
        }
    }

    return FALSE;
}


define_function(rich_version)
{
  return_integer(
      rich_internal(module(), integer_argument(1), UNDEFINED));
}


define_function(rich_version_toolid)
{
  return_integer(
      rich_internal(module(), integer_argument(1), integer_argument(2)));
}


define_function(rich_toolid)
{
    return_integer(
       rich_internal(module(), UNDEFINED, integer_argument(1)));
}


define_function(rich_toolid_version)
{
  return_integer(
      rich_internal(module(), integer_argument(2), integer_argument(1)));
}

begin_declarations;

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

  declare_integer("SUBSYSTEM_UNKNOWN");
  declare_integer("SUBSYSTEM_NATIVE");
  declare_integer("SUBSYSTEM_WINDOWS_GUI");
  declare_integer("SUBSYSTEM_WINDOWS_CUI");
  declare_integer("SUBSYSTEM_OS2_CUI");
  declare_integer("SUBSYSTEM_POSIX_CUI");
  declare_integer("SUBSYSTEM_NATIVE_WINDOWS");

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

  declare_integer("SECTION_CNT_CODE");
  declare_integer("SECTION_CNT_INITIALIZED_DATA");
  declare_integer("SECTION_CNT_UNINITIALIZED_DATA");
  declare_integer("SECTION_GPREL");
  declare_integer("SECTION_MEM_16BIT");
  declare_integer("SECTION_LNK_NRELOC_OVFL");
  declare_integer("SECTION_MEM_DISCARDABLE");
  declare_integer("SECTION_MEM_NOT_CACHED");
  declare_integer("SECTION_MEM_NOT_PAGED");
  declare_integer("SECTION_MEM_SHARED");
  declare_integer("SECTION_MEM_EXECUTE");
  declare_integer("SECTION_MEM_READ");
  declare_integer("SECTION_MEM_WRITE");

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

  declare_integer("machine");
  declare_integer("number_of_sections");
  declare_integer("timestamp");
  declare_integer("characteristics");

  declare_integer("entry_point");
  declare_integer("image_base");

  declare_string_dictionary("version_info");

  begin_struct("linker_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("linker_version");

  begin_struct("os_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("os_version");

  begin_struct("image_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("image_version");

  begin_struct("subsystem_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("subsystem_version");

  declare_integer("subsystem");

  begin_struct_array("sections");
    declare_string("name");
    declare_integer("characteristics");
    declare_integer("virtual_address");
    declare_integer("virtual_size");
    declare_integer("raw_data_offset");
    declare_integer("raw_data_size");
  end_struct_array("sections");

  begin_struct("rich_signature");
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

  #if defined(HAVE_LIBCRYPTO)
  declare_function("imphash", "", "s", imphash);
  #endif

  declare_function("section_index", "s", "i", section_index_name);
  declare_function("section_index", "i", "i", section_index_addr);
  declare_function("exports", "s", "i", exports);
  declare_function("imports", "ss", "i", imports);
  declare_function("imports", "si", "i", imports_ordinal);
  declare_function("imports", "s", "i", imports_dll);
  declare_function("locale", "i", "i", locale);
  declare_function("language", "i", "i", language);
  declare_function("is_dll", "", "i", is_dll);
  declare_function("is_32bit", "", "i", is_32bit);
  declare_function("is_64bit", "", "i", is_64bit);

  declare_integer("resource_timestamp");

  begin_struct("resource_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("resource_version");

  begin_struct_array("resources");
    declare_integer("offset");
    declare_integer("length");
    declare_integer("type");
    declare_integer("id");
    declare_integer("language");
    declare_string("type_string");
    declare_string("name_string");
    declare_string("language_string");
  end_struct_array("resources");

  declare_integer("number_of_resources");

  #if defined(HAVE_LIBCRYPTO)
  begin_struct_array("signatures");
    declare_string("issuer");
    declare_string("subject");
    declare_integer("version");
    declare_string("algorithm");
    declare_string("serial");
    declare_integer("not_before");
    declare_integer("not_after");
    declare_function("valid_on", "i", "i", valid_on);
  end_struct_array("signatures");

  declare_integer("number_of_signatures");
  #endif

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
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

  set_integer(
      IMAGE_FILE_MACHINE_UNKNOWN, module_object,
      "MACHINE_UNKNOWN");
  set_integer(
      IMAGE_FILE_MACHINE_AM33, module_object,
      "MACHINE_AM33");
  set_integer(
      IMAGE_FILE_MACHINE_AMD64, module_object,
      "MACHINE_AMD64");
  set_integer(
      IMAGE_FILE_MACHINE_ARM, module_object,
      "MACHINE_ARM");
  set_integer(
      IMAGE_FILE_MACHINE_ARMNT, module_object,
      "MACHINE_ARMNT");
  set_integer(
      IMAGE_FILE_MACHINE_ARM64, module_object,
      "MACHINE_ARM64");
  set_integer(
      IMAGE_FILE_MACHINE_EBC, module_object,
      "MACHINE_EBC");
  set_integer(
      IMAGE_FILE_MACHINE_I386, module_object,
      "MACHINE_I386");
  set_integer(
      IMAGE_FILE_MACHINE_IA64, module_object,
      "MACHINE_IA64");
  set_integer(
      IMAGE_FILE_MACHINE_M32R, module_object,
      "MACHINE_M32R");
  set_integer(
      IMAGE_FILE_MACHINE_MIPS16, module_object,
      "MACHINE_MIPS16");
  set_integer(
      IMAGE_FILE_MACHINE_MIPSFPU, module_object,
      "MACHINE_MIPSFPU");
  set_integer(
      IMAGE_FILE_MACHINE_MIPSFPU16, module_object,
      "MACHINE_MIPSFPU16");
  set_integer(
      IMAGE_FILE_MACHINE_POWERPC, module_object,
      "MACHINE_POWERPC");
  set_integer(
      IMAGE_FILE_MACHINE_POWERPCFP, module_object,
      "MACHINE_POWERPCFP");
  set_integer(
      IMAGE_FILE_MACHINE_R4000, module_object,
      "MACHINE_R4000");
  set_integer(
      IMAGE_FILE_MACHINE_SH3, module_object,
      "MACHINE_SH3");
  set_integer(
      IMAGE_FILE_MACHINE_SH3DSP, module_object,
      "MACHINE_SH3DSP");
  set_integer(
      IMAGE_FILE_MACHINE_SH4, module_object,
      "MACHINE_SH4");
  set_integer(
      IMAGE_FILE_MACHINE_SH5, module_object,
      "MACHINE_SH5");
  set_integer(
      IMAGE_FILE_MACHINE_THUMB, module_object,
      "MACHINE_THUMB");
  set_integer(
      IMAGE_FILE_MACHINE_WCEMIPSV2, module_object,
      "MACHINE_WCEMIPSV2");

  set_integer(
      IMAGE_SUBSYSTEM_UNKNOWN, module_object,
      "SUBSYSTEM_UNKNOWN");
  set_integer(
      IMAGE_SUBSYSTEM_NATIVE, module_object,
      "SUBSYSTEM_NATIVE");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_GUI, module_object,
      "SUBSYSTEM_WINDOWS_GUI");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_CUI, module_object,
      "SUBSYSTEM_WINDOWS_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_OS2_CUI, module_object,
      "SUBSYSTEM_OS2_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_POSIX_CUI, module_object,
      "SUBSYSTEM_POSIX_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_NATIVE_WINDOWS, module_object,
      "SUBSYSTEM_NATIVE_WINDOWS");

  set_integer(
      IMAGE_FILE_RELOCS_STRIPPED, module_object,
      "RELOCS_STRIPPED");
  set_integer(
      IMAGE_FILE_EXECUTABLE_IMAGE, module_object,
      "EXECUTABLE_IMAGE");
  set_integer(
      IMAGE_FILE_LINE_NUMS_STRIPPED, module_object,
      "LINE_NUMS_STRIPPED");
  set_integer(
      IMAGE_FILE_LOCAL_SYMS_STRIPPED, module_object,
      "LOCAL_SYMS_STRIPPED");
  set_integer(
      IMAGE_FILE_AGGRESIVE_WS_TRIM, module_object,
      "AGGRESIVE_WS_TRIM");
  set_integer(
      IMAGE_FILE_LARGE_ADDRESS_AWARE, module_object,
      "LARGE_ADDRESS_AWARE");
  set_integer(
      IMAGE_FILE_BYTES_REVERSED_LO, module_object,
      "BYTES_REVERSED_LO");
  set_integer(
      IMAGE_FILE_32BIT_MACHINE, module_object,
      "MACHINE_32BIT");
  set_integer(
      IMAGE_FILE_DEBUG_STRIPPED, module_object,
      "DEBUG_STRIPPED");
  set_integer(
      IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, module_object,
      "REMOVABLE_RUN_FROM_SWAP");
  set_integer(
      IMAGE_FILE_NET_RUN_FROM_SWAP, module_object,
      "NET_RUN_FROM_SWAP");
  set_integer(
      IMAGE_FILE_SYSTEM, module_object,
      "SYSTEM");
  set_integer(
      IMAGE_FILE_DLL, module_object,
      "DLL");
  set_integer(
      IMAGE_FILE_UP_SYSTEM_ONLY, module_object,
      "UP_SYSTEM_ONLY");
  set_integer(
      IMAGE_FILE_BYTES_REVERSED_HI, module_object,
      "BYTES_REVERSED_HI");

  set_integer(
      IMAGE_SCN_CNT_CODE, module_object,
      "SECTION_CNT_CODE");
  set_integer(
      IMAGE_SCN_CNT_INITIALIZED_DATA, module_object,
      "SECTION_CNT_INITIALIZED_DATA");
  set_integer(
      IMAGE_SCN_CNT_UNINITIALIZED_DATA, module_object,
      "SECTION_CNT_UNINITIALIZED_DATA");
  set_integer(
      IMAGE_SCN_GPREL, module_object,
      "SECTION_GPREL");
  set_integer(
      IMAGE_SCN_MEM_16BIT, module_object,
      "SECTION_MEM_16BIT");
  set_integer(
      IMAGE_SCN_LNK_NRELOC_OVFL, module_object,
      "SECTION_LNK_NRELOC_OVFL");
  set_integer(
      IMAGE_SCN_MEM_DISCARDABLE, module_object,
      "SECTION_MEM_DISCARDABLE");
  set_integer(
      IMAGE_SCN_MEM_NOT_CACHED, module_object,
      "SECTION_MEM_NOT_CACHED");
  set_integer(
      IMAGE_SCN_MEM_NOT_PAGED, module_object,
      "SECTION_MEM_NOT_PAGED");
  set_integer(
      IMAGE_SCN_MEM_SHARED, module_object,
      "SECTION_MEM_SHARED");
  set_integer(
      IMAGE_SCN_MEM_EXECUTE, module_object,
      "SECTION_MEM_EXECUTE");
  set_integer(
      IMAGE_SCN_MEM_READ, module_object,
      "SECTION_MEM_READ");
  set_integer(
      IMAGE_SCN_MEM_WRITE, module_object,
      "SECTION_MEM_WRITE");

  set_integer(
      RESOURCE_TYPE_CURSOR, module_object,
      "RESOURCE_TYPE_CURSOR");
  set_integer(
      RESOURCE_TYPE_BITMAP, module_object,
      "RESOURCE_TYPE_BITMAP");
  set_integer(
      RESOURCE_TYPE_ICON, module_object,
      "RESOURCE_TYPE_ICON");
  set_integer(
      RESOURCE_TYPE_MENU, module_object,
      "RESOURCE_TYPE_MENU");
  set_integer(
      RESOURCE_TYPE_DIALOG, module_object,
      "RESOURCE_TYPE_DIALOG");
  set_integer(
      RESOURCE_TYPE_STRING, module_object,
      "RESOURCE_TYPE_STRING");
  set_integer(
      RESOURCE_TYPE_FONTDIR, module_object,
      "RESOURCE_TYPE_FONTDIR");
  set_integer(
      RESOURCE_TYPE_FONT, module_object,
      "RESOURCE_TYPE_FONT");
  set_integer(
      RESOURCE_TYPE_ACCELERATOR, module_object,
      "RESOURCE_TYPE_ACCELERATOR");
  set_integer(
      RESOURCE_TYPE_RCDATA, module_object,
      "RESOURCE_TYPE_RCDATA");
  set_integer(
      RESOURCE_TYPE_MESSAGETABLE, module_object,
      "RESOURCE_TYPE_MESSAGETABLE");
  set_integer(
      RESOURCE_TYPE_GROUP_CURSOR, module_object,
      "RESOURCE_TYPE_GROUP_CURSOR");
  set_integer(
      RESOURCE_TYPE_GROUP_ICON, module_object,
      "RESOURCE_TYPE_GROUP_ICON");
  set_integer(
      RESOURCE_TYPE_VERSION, module_object,
      "RESOURCE_TYPE_VERSION");
  set_integer(
      RESOURCE_TYPE_DLGINCLUDE, module_object,
      "RESOURCE_TYPE_DLGINCLUDE");
  set_integer(
      RESOURCE_TYPE_PLUGPLAY, module_object,
      "RESOURCE_TYPE_PLUGPLAY");
  set_integer(
      RESOURCE_TYPE_VXD, module_object,
      "RESOURCE_TYPE_VXD");
  set_integer(
      RESOURCE_TYPE_ANICURSOR, module_object,
      "RESOURCE_TYPE_ANICURSOR");
  set_integer(
      RESOURCE_TYPE_ANIICON, module_object,
      "RESOURCE_TYPE_ANIICON");
  set_integer(
      RESOURCE_TYPE_HTML, module_object,
      "RESOURCE_TYPE_HTML");
  set_integer(
      RESOURCE_TYPE_MANIFEST, module_object,
      "RESOURCE_TYPE_MANIFEST");

  foreach_memory_block(context, block)
  {
    PIMAGE_NT_HEADERS32 pe_header = pe_get_header(block->data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        PE* pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        pe->data = block->data;
        pe->data_size = block->size;
        pe->header = pe_header;
        pe->object = module_object;
        pe->resources = 0;

        module_object->data = pe;

        pe_parse_header(pe, block->base, context->flags);
        pe_parse_rich_signature(pe, block->base);

        #if defined(HAVE_LIBCRYPTO)
        pe_parse_certificates(pe);
        #endif

        pe->imported_dlls = pe_parse_imports(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  IMPORTED_DLL* dll = NULL;
  IMPORTED_DLL* next_dll = NULL;
  IMPORTED_FUNCTION* func = NULL;
  IMPORTED_FUNCTION* next_func = NULL;

  PE* pe = (PE *) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  dll = pe->imported_dlls;

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

  yr_free(pe);

  return ERROR_SUCCESS;
}
