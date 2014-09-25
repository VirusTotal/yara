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

#ifdef _WIN32
#include <windows.h>
#else
#include <yara/pe.h>
#endif

#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/strutils.h>

#define MODULE_NAME pe

#define RESOURCE_TYPE_CURSOR         1
#define RESOURCE_TYPE_BITMAP         2
#define RESOURCE_TYPE_ICON           3
#define RESOURCE_TYPE_MENU           4
#define RESOURCE_TYPE_DIALOG         5
#define RESOURCE_TYPE_STRING         6
#define RESOURCE_TYPE_FONTDIR        7
#define RESOURCE_TYPE_FONT           8
#define RESOURCE_TYPE_ACCELERATOR    9
#define RESOURCE_TYPE_RCDATA         10
#define RESOURCE_TYPE_MESSAGETABLE   11
#define RESOURCE_TYPE_VERSION        16
#define RESOURCE_TYPE_MANIFEST       24


#define RESOURCE_CALLBACK_CONTINUE   0
#define RESOURCE_CALLBACK_ABORT      1


#define RESOURCE_ITERATOR_FINISHED   0
#define RESOURCE_ITERATOR_ABORTED    1


#define MAX_PE_SECTIONS              96


#define IS_RESOURCE_SUBDIRECTORY(entry) \
    ((entry)->OffsetToData & 0x80000000)


#define RESOURCE_OFFSET(entry) \
    ((entry)->OffsetToData & 0x7FFFFFFF)


#define fits_in_pe(pe, pointer, size) \
    ((uint8_t*)(pointer) + size <= pe->data + pe->data_size)


#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof(struct_type))


typedef int (*RESOURCE_CALLBACK_FUNC) ( \
     PIMAGE_RESOURCE_DATA_ENTRY rsrc_data, \
     int rsrc_type, \
     int rsrc_id, \
     int rsrc_language, \
     void* cb_data);


typedef struct _PE
{
  uint8_t* data;
  size_t data_size;

  PIMAGE_NT_HEADERS32 header;
  YR_OBJECT* object;

} PE;


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
      (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
      data_size > headers_size)
  {
    return pe_header;
  }
  else
  {
    return NULL;
  }
}


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry)
{
  PIMAGE_DATA_DIRECTORY result;

  if (pe->header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    result = &((PIMAGE_NT_HEADERS64) pe->header)->
        OptionalHeader.DataDirectory[entry];
  else
    result = &pe->header->OptionalHeader.DataDirectory[entry];

  return result;
}


uint64_t pe_rva_to_offset(
    PE* pe,
    uint64_t rva)
{
  PIMAGE_SECTION_HEADER section;
  DWORD section_rva;
  DWORD section_offset;

  int i = 0;

  section = IMAGE_FIRST_SECTION(pe->header);
  section_rva = 0;
  section_offset = 0;

  while(i < min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS))
  {
    if ((uint8_t*) section - \
        (uint8_t*) pe->data + sizeof(IMAGE_SECTION_HEADER) < pe->data_size)
    {
      if (rva >= section->VirtualAddress &&
          section_rva <= section->VirtualAddress)
      {
        section_rva = section->VirtualAddress;
        section_offset = section->PointerToRawData;
      }

      section++;
      i++;
    }
    else
    {
      return 0;
    }
  }

  return section_offset + (rva - section_rva);
}


int _pe_iterate_resources(
    PE* pe,
    PIMAGE_RESOURCE_DIRECTORY resource_dir,
    uint8_t* rsrc_data,
    int rsrc_tree_level,
    int* type,
    int* id,
    int* language,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int result = RESOURCE_ITERATOR_FINISHED;
  int total_entries = resource_dir->NumberOfNamedEntries +
                      resource_dir->NumberOfIdEntries;

  PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = &resource_dir->DirectoryEntries[0];

  for (int i = 0; i < total_entries; i++)
  {
    if (!struct_fits_in_pe(pe, entry, IMAGE_RESOURCE_DIRECTORY_ENTRY))
      break;

    switch(rsrc_tree_level)
    {
      case 0:
        *type = entry->Name;
        break;
      case 1:
        *id = entry->Name;
        break;
      case 2:
        *language = entry->Name;
        break;
    }

    if (IS_RESOURCE_SUBDIRECTORY(entry))
    {
      PIMAGE_RESOURCE_DIRECTORY directory = (PIMAGE_RESOURCE_DIRECTORY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

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
            callback,
            callback_data);

        if (result == RESOURCE_ITERATOR_ABORTED)
          return RESOURCE_ITERATOR_ABORTED;
      }
    }
    else
    {
      PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

      if (struct_fits_in_pe(pe, data_entry, IMAGE_RESOURCE_DATA_ENTRY))
      {
        result = callback(
            data_entry,
            *type,
            *id,
            *language,
            callback_data);
      }

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
  uint64_t offset;

  int type = -1;
  int id = -1;
  int language = -1;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);

  if (directory->VirtualAddress != 0)
  {
    offset = pe_rva_to_offset(pe, directory->VirtualAddress);

    if (offset != 0 &&
        offset < pe->data_size)
    {
      _pe_iterate_resources(
          pe,
          (PIMAGE_RESOURCE_DIRECTORY) (pe->data + offset),
          pe->data + offset,
          0,
          &type,
          &id,
          &language,
          callback,
          callback_data);

      return 1;
    }
  }

  return 0;
}


// Align offset to a 32-bit boundary and add it to a pointer

#define ADD_OFFSET(ptr, offset) \
    (typeof(ptr)) ((uint8_t*) (ptr) + ((offset + 3) & ~3))


int pe_find_version_info_cb(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    PE* pe)
{
  PVERSION_INFO version_info;
  PVERSION_INFO string_file_info;

  char key[64];
  char value[256];

  size_t version_info_offset;

  if (rsrc_type == RESOURCE_TYPE_VERSION)
  {
    version_info_offset = pe_rva_to_offset(pe, rsrc_data->OffsetToData);

    if (version_info_offset == 0)
      return RESOURCE_CALLBACK_CONTINUE;

    version_info = (PVERSION_INFO) (pe->data + version_info_offset);

    if (!struct_fits_in_pe(pe, version_info, VERSION_INFO))
      return RESOURCE_CALLBACK_CONTINUE;

    if (!fits_in_pe(pe, version_info, sizeof("VS_VERSION_INFO")))
      return RESOURCE_CALLBACK_CONTINUE;

    if (strcmp_w(version_info->Key, "VS_VERSION_INFO") != 0)
      return RESOURCE_CALLBACK_CONTINUE;

    string_file_info = ADD_OFFSET(version_info, sizeof(VERSION_INFO) + 86);

    if (!struct_fits_in_pe(pe, string_file_info, VERSION_INFO))
      return RESOURCE_CALLBACK_CONTINUE;

    if (!fits_in_pe(pe, string_file_info, sizeof("StringFileInfo")))
      return RESOURCE_CALLBACK_CONTINUE;

    while(strcmp_w(string_file_info->Key, "StringFileInfo") == 0)
    {
      PVERSION_INFO string_table = ADD_OFFSET(
          string_file_info,
          sizeof(VERSION_INFO) + 30);

      string_file_info = ADD_OFFSET(
          string_file_info,
          string_file_info->Length);

      while (string_table < string_file_info)
      {
        PVERSION_INFO string = ADD_OFFSET(
            string_table,
            sizeof(VERSION_INFO) + 2 * (strlen_w(string_table->Key) + 1));

        string_table = ADD_OFFSET(
            string_table,
            string_table->Length);

        while (string < string_table)
        {
          char* string_value = (char*) ADD_OFFSET(
              string,
              sizeof(VERSION_INFO) + 2 * (strlen_w(string->Key) + 1));

          strlcpy_w(key, string->Key, sizeof(key));
          strlcpy_w(value, string_value, sizeof(value));

          set_string(value, pe->object, "version_info[%s]", key);

          if (string->Length == 0)
            break;

          string = ADD_OFFSET(string, string->Length);
        }

        if (string_table->Length == 0)
          break;
      }
    }

    return RESOURCE_CALLBACK_ABORT;
  }

  return RESOURCE_CALLBACK_CONTINUE;
}


void pe_parse(
    PE* pe,
    size_t base_address,
    int flags)
{
  PIMAGE_SECTION_HEADER section;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];

#define OptionalHeader(field) \
  (pe->header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? \
   ((PIMAGE_NT_HEADERS64) pe->header)->OptionalHeader.field : \
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
      (RESOURCE_CALLBACK_FUNC) pe_find_version_info_cb,
      (void*) pe);

  section = IMAGE_FIRST_SECTION(pe->header);

  int scount = min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS);

  for (int i = 0; i < scount; i++)
  {
    if (!struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
      break;

    strlcpy(section_name, (char*) section->Name, IMAGE_SIZEOF_SHORT_NAME + 1);

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


define_function(section_index)
{
  YR_OBJECT* module = module();
  char* name = string_argument(1);

  int64_t n = get_integer(module, "number_of_sections");
  int64_t i;

  if (n == UNDEFINED)
    return_integer(UNDEFINED);

  for (i = 0; i < n; i++)
  {
    if (strcmp(name, get_string(module, "sections[%i].name", i)) == 0)
      return_integer(i);
  }

  return_integer(UNDEFINED);
}


define_function(exports)
{
  char* function_name = string_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_EXPORT_DIRECTORY exports;
  DWORD* names;

  char* name;
  int i;
  uint64_t offset;

  // if not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

  // if the PE doesn't export any functions, return FALSE

  if (directory->VirtualAddress == 0)
    return_integer(0);

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset == 0 ||
      offset >= pe->data_size)
    return_integer(0);

  exports = (PIMAGE_EXPORT_DIRECTORY)(pe->data + offset);

  offset = pe_rva_to_offset(pe, exports->AddressOfNames);

  if (offset == 0 ||
      offset + exports->NumberOfNames * sizeof(DWORD) > pe->data_size)
    return_integer(0);

  names = (DWORD*)(pe->data + offset);

  for (i = 0; i < exports->NumberOfNames; i++)
  {
    offset = pe_rva_to_offset(pe, names[i]);

    if (offset == 0 || offset >= pe->data_size)
      return_integer(0);

    name = (char*)(pe->data + offset);

    if (strncmp(name, function_name, pe->data_size - offset) == 0)
      return_integer(1);
  }

  return_integer(0);
}


define_function(imports)
{
  char* dll_name = string_argument(1);
  char* function_name = string_argument(2);
  int function_name_len = strlen(function_name);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_IMPORT_DESCRIPTOR imports;
  PIMAGE_IMPORT_BY_NAME import;
  PIMAGE_THUNK_DATA32 thunks32;
  PIMAGE_THUNK_DATA64 thunks64;

  uint64_t offset;

  // if not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

  if (directory->VirtualAddress == 0)
    return_integer(0);

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset == 0 ||
      offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->data_size)
    return_integer(0);

  imports = (PIMAGE_IMPORT_DESCRIPTOR)(pe->data + offset);

  while (struct_fits_in_pe(pe, imports, IMAGE_IMPORT_DESCRIPTOR) &&
         imports->Name != 0)
  {
    offset = pe_rva_to_offset(pe, imports->Name);

    if (offset > 0 &&
        offset <= pe->data_size &&
        strncasecmp(
            dll_name,
            (char*)(pe->data + offset),
            pe->data_size - offset) == 0)
    {
      offset = pe_rva_to_offset(pe, imports->OriginalFirstThunk);

      if (offset > 0)
      {
        if (pe->header->FileHeader.Machine == 0x8664)
        {
          thunks64 = (PIMAGE_THUNK_DATA64)(pe->data + offset);

          while (struct_fits_in_pe(pe, thunks64, IMAGE_THUNK_DATA64) &&
                 thunks64->u1.Ordinal != 0)
          {
            if (!(thunks64->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
            {
              // if not exported by ordinal
              offset = pe_rva_to_offset(pe, thunks64->u1.Function);

              if (offset != 0 &&
                  offset <= pe->data_size - sizeof(IMAGE_IMPORT_BY_NAME))
              {
                import = (PIMAGE_IMPORT_BY_NAME)(pe->data + offset);

                if (fits_in_pe(pe, import->Name, function_name_len))
                {
                  if (strncmp((char*) import->Name,
                              function_name,
                              function_name_len) == 0)
                  {
                    return_integer(1);
                  }
                }
              }
            }

            thunks64++;
          }
        }
        else
        {
          thunks32 = (PIMAGE_THUNK_DATA32)(pe->data + offset);

          while (struct_fits_in_pe(pe, thunks32, sizeof(IMAGE_THUNK_DATA32)) &&
                 thunks32->u1.Ordinal != 0)
          {
            if (!(thunks32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
            {
              // if not exported by ordinal
              offset = pe_rva_to_offset(pe, thunks32->u1.Function);

              if (offset != 0 &&
                  offset <= pe->data_size - sizeof(IMAGE_IMPORT_BY_NAME))
              {
                import = (PIMAGE_IMPORT_BY_NAME)(pe->data + offset);

                if (fits_in_pe(pe, import->Name, function_name_len))
                {
                  if (strncmp((char*) import->Name,
                              function_name,
                              function_name_len) == 0)
                  {
                    return_integer(1);
                  }
                }
              }
            }

            thunks32++;
          }
        }
      }
    }

    imports++;
  }

  return_integer(0);
}


typedef struct _FIND_LANGUAGE_CB_DATA
{
  uint64_t locale;
  uint64_t mask;

  int found;

} FIND_LANGUAGE_CB_DATA;


int pe_find_language_cb(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    FIND_LANGUAGE_CB_DATA* cb_data)
{
  if ((rsrc_language & cb_data->mask) == cb_data->locale)
  {
    cb_data->found = TRUE;
    return RESOURCE_CALLBACK_ABORT;
  }

  return RESOURCE_CALLBACK_CONTINUE;
}


define_function(locale)
{
  FIND_LANGUAGE_CB_DATA cb_data;

  cb_data.locale = integer_argument(1);
  cb_data.mask = 0xFFFF;
  cb_data.found = FALSE;

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // if not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  if (pe_iterate_resources(pe,
          (RESOURCE_CALLBACK_FUNC) pe_find_language_cb,
          (void*) &cb_data))
  {
    return_integer(cb_data.found);
  }
  else
  {
    return_integer(UNDEFINED);
  }
}


define_function(language)
{
  FIND_LANGUAGE_CB_DATA cb_data;

  cb_data.locale = integer_argument(1);
  cb_data.mask = 0xFF;
  cb_data.found = FALSE;

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // if not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  if (pe_iterate_resources(pe,
          (RESOURCE_CALLBACK_FUNC) pe_find_language_cb,
          (void*) &cb_data))
  {
    return_integer(cb_data.found);
  }
  else
  {
    return_integer(UNDEFINED);
  }
}

begin_declarations;

  declare_integer("MACHINE_I386");
  declare_integer("MACHINE_AMD64");

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
  declare_integer("32BIT_MACHINE");
  declare_integer("DEBUG_STRIPPED");
  declare_integer("REMOVABLE_RUN_FROM_SWAP");
  declare_integer("NET_RUN_FROM_SWAP");
  declare_integer("SYSTEM");
  declare_integer("DLL");
  declare_integer("UP_SYSTEM_ONLY");
  declare_integer("BYTES_REVERSED_HI");

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

  declare_function("section_index", "s", "i", section_index);
  declare_function("exports", "s", "i", exports);
  declare_function("imports", "ss", "i", imports);
  declare_function("locale", "i", "i", locale);
  declare_function("language", "i", "i", language);

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
  set_integer(
      IMAGE_FILE_MACHINE_I386, module_object,
      "MACHINE_I386");
  set_integer(
      IMAGE_FILE_MACHINE_AMD64, module_object,
      "MACHINE_AMD64");

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
      "32BIT_MACHINE");
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

  YR_MEMORY_BLOCK* block;

  foreach_memory_block(context, block)
  {
    PIMAGE_NT_HEADERS32 pe_header = pe_get_header(block->data, block->size);

    if (pe_header != NULL)
    {
      // ignore DLLs while scanning a process

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

        module_object->data = pe;

        pe_parse(
            pe,
            block->base,
            context->flags);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  if (module_object->data != NULL)
    yr_free(module_object->data);

  return ERROR_SUCCESS;
}
