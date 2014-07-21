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

#ifdef WIN32
#include <windows.h>
#else
#include <yara/pe.h>
#endif

#include <yara/modules.h>
#include <yara/mem.h>


#define MODULE_NAME pe


typedef struct _DATA
{
  uint8_t* data;
  size_t size;
  PIMAGE_NT_HEADERS32 pe_header;
  size_t pe_size;

} DATA;


#ifndef MIN
#define MIN(x,y) ((x < y)?(x):(y))
#endif


PIMAGE_NT_HEADERS32 get_pe_header(
    uint8_t* buffer,
    size_t buffer_length)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;

  size_t headers_size = 0;

  if (buffer_length < sizeof(IMAGE_DOS_HEADER))
    return NULL;

  mz_header = (PIMAGE_DOS_HEADER) buffer;

  if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  if (mz_header->e_lfanew < 0)
    return NULL;

  headers_size = mz_header->e_lfanew + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (buffer_length < headers_size)
    return NULL;

  pe_header = (PIMAGE_NT_HEADERS32) (buffer + mz_header->e_lfanew);

  headers_size += pe_header->FileHeader.SizeOfOptionalHeader;

  if (pe_header->Signature == IMAGE_NT_SIGNATURE &&
      (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
      buffer_length > headers_size)
  {
    return pe_header;
  }
  else
  {
    return NULL;
  }
}


uint64_t rva_to_offset(
    PIMAGE_NT_HEADERS32 pe_header,
    size_t pe_size,
    uint64_t rva)
{
  PIMAGE_SECTION_HEADER section;
  DWORD section_rva;
  DWORD section_offset;

  int i = 0;

  section = IMAGE_FIRST_SECTION(pe_header);
  section_rva = 0;
  section_offset = 0;

  while(i < MIN(pe_header->FileHeader.NumberOfSections, 60))
  {
    if ((uint8_t*) section - \
        (uint8_t*) pe_header + sizeof(IMAGE_SECTION_HEADER) < pe_size)
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

void parse_pe_header(
    PIMAGE_NT_HEADERS32 pe,
    size_t base_address,
    size_t pe_size,
    int flags,
    YR_OBJECT* pe_obj)
{
  PIMAGE_SECTION_HEADER section;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
  int i;

#define OptionalHeader(field) \
  (pe->FileHeader.Machine == 0x8664 ? \
   ((PIMAGE_NT_HEADERS64) pe)->OptionalHeader.field: pe->OptionalHeader.field)

  set_integer(
      pe->FileHeader.Machine,
      pe_obj, "machine");

  set_integer(
      pe->FileHeader.NumberOfSections,
      pe_obj, "number_of_sections");

  set_integer(
      pe->FileHeader.TimeDateStamp,
      pe_obj, "timestamp");

  set_integer(
      pe->FileHeader.Characteristics,
      pe_obj, "characteristics");

  set_integer(
      flags & SCAN_FLAGS_PROCESS_MEMORY ?
        base_address + OptionalHeader(AddressOfEntryPoint) :
        rva_to_offset(
            pe, pe_size, OptionalHeader(AddressOfEntryPoint)),
      pe_obj, "entry_point");

  set_integer(
      OptionalHeader(ImageBase),
      pe_obj, "image_base");

  set_integer(
      OptionalHeader(MajorLinkerVersion),
      pe_obj, "linker_version.major");

  set_integer(
      OptionalHeader(MinorLinkerVersion),
      pe_obj, "linker_version.minor");

  set_integer(
      OptionalHeader(MajorOperatingSystemVersion),
      pe_obj, "os_version.major");

  set_integer(
      OptionalHeader(MinorOperatingSystemVersion),
      pe_obj, "os_version.minor");

  set_integer(
      OptionalHeader(MajorImageVersion),
      pe_obj, "image_version.major");

  set_integer(
      OptionalHeader(MinorImageVersion),
      pe_obj, "image_version.minor");

  set_integer(
      OptionalHeader(MajorSubsystemVersion),
      pe_obj, "subsystem_version.major");

  set_integer(
      OptionalHeader(MinorSubsystemVersion),
      pe_obj, "subsystem_version.minor");

  set_integer(
      OptionalHeader(Subsystem),
      pe_obj, "subsystem");

  section = IMAGE_FIRST_SECTION(pe);

  for (i = 0; i < min(pe->FileHeader.NumberOfSections, 60); i++)
  {
    if ((uint8_t*) section -
        (uint8_t*) pe + sizeof(IMAGE_SECTION_HEADER) >= pe_size)
    {
      break;
    }

    strncpy(section_name, (char*) section->Name, IMAGE_SIZEOF_SHORT_NAME);
    section_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

    set_string(
        section_name,
        pe_obj, "sections[%i].name", i);

    set_integer(
        section->Characteristics,
        pe_obj, "sections[%i].characteristics", i);

    set_integer(section->SizeOfRawData,
        pe_obj, "sections[%i].raw_data_size", i);

    set_integer(section->PointerToRawData,
        pe_obj, "sections[%i].raw_data_offset", i);

    set_integer(section->VirtualAddress,
        pe_obj, "sections[%i].virtual_address", i);

    set_integer(
        section->Misc.VirtualSize,
        pe_obj, "sections[%i].virtual_size", i);

    section++;
  }
}


define_function(section_index)
{
  YR_OBJECT* self = self();

  char* name = string_argument(1);

  int64_t n = get_integer(self, "number_of_sections");
  int64_t i;

  if (n == UNDEFINED)
    return_integer(UNDEFINED);

  for (i = 0; i < n; i++)
  {
    if (strcmp(name, get_string(self, "sections[%i].name", i)) == 0)
      return_integer(i);
  }

  return_integer(UNDEFINED);
}

define_function(exports)
{
  YR_OBJECT* self = self();

  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_EXPORT_DIRECTORY exports;

  DWORD* names;
  DATA* data;

  char* function_name = string_argument(1);
  char* name;

  uint64_t offset;
  int i;

  data = (DATA*) self->data;

  // if not a PE file, return UNDEFINED

  if (data == NULL)
    return_integer(UNDEFINED);

  if (data->pe_header->FileHeader.Machine == 0x8664)  // is a 64-bit PE ?
  {
    directory = &((PIMAGE_NT_HEADERS64)
                    (data->pe_header))->OptionalHeader.DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_EXPORT];
  }
  else
  {
    directory = &data->pe_header->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT];
  }

  // if the PE doesn't export any functions, return FALSE

  if (directory->VirtualAddress == 0)
    return_integer(0);

  offset = rva_to_offset(
      data->pe_header,
      data->pe_size,
      directory->VirtualAddress);

  if (offset == 0 ||
      offset >= data->size)
    return_integer(0);

  exports = (PIMAGE_EXPORT_DIRECTORY)(data->data + offset);

  offset = rva_to_offset(
      data->pe_header,
      data->pe_size,
      exports->AddressOfNames);

  if (offset == 0 ||
      offset >= data->size - exports->NumberOfNames * sizeof(DWORD))
    return_integer(0);

  names = (DWORD*)(data->data + offset);

  for (i = 0; i < exports->NumberOfNames; i++)
  {
    offset = rva_to_offset(
        data->pe_header,
        data->pe_size,
        names[i]);

    if (offset == 0 || offset >= data->size)
      return_integer(0);

    name = (char*)(data->data + offset);

    if (strncmp(name, function_name, data->size - offset) == 0)
      return_integer(1);
  }

  return_integer(0);
}


begin_declarations;

  integer("MACHINE_I386");
  integer("MACHINE_AMD64");

  integer("SUBSYSTEM_UNKNOWN");
  integer("SUBSYSTEM_NATIVE");
  integer("SUBSYSTEM_WINDOWS_GUI");
  integer("SUBSYSTEM_WINDOWS_CUI");
  integer("SUBSYSTEM_OS2_CUI");
  integer("SUBSYSTEM_POSIX_CUI");
  integer("SUBSYSTEM_NATIVE_WINDOWS");

  integer("RELOCS_STRIPPED");
  integer("EXECUTABLE_IMAGE");
  integer("LINE_NUMS_STRIPPED");
  integer("LOCAL_SYMS_STRIPPED");
  integer("AGGRESIVE_WS_TRIM");
  integer("LARGE_ADDRESS_AWARE");
  integer("BYTES_REVERSED_LO");
  integer("32BIT_MACHINE");
  integer("DEBUG_STRIPPED");
  integer("REMOVABLE_RUN_FROM_SWAP");
  integer("NET_RUN_FROM_SWAP");
  integer("SYSTEM");
  integer("DLL");
  integer("UP_SYSTEM_ONLY");
  integer("BYTES_REVERSED_HI");

  integer("machine");
  integer("number_of_sections");
  integer("timestamp");
  integer("characteristics");

  integer("entry_point");
  integer("image_base");

  begin_struct("linker_version");
    integer("major");
    integer("minor");
  end_struct("linker_version");

  begin_struct("os_version");
    integer("major");
    integer("minor");
  end_struct("os_version");

  begin_struct("image_version");
    integer("major");
    integer("minor");
  end_struct("image_version");

  begin_struct("subsystem_version");
    integer("major");
    integer("minor");
  end_struct("subsystem_version");

  integer("subsystem");

  begin_struct_array("sections");
    string("name");
    integer("characteristics");
    integer("virtual_address");
    integer("virtual_size");
    integer("raw_data_offset");
    integer("raw_data_size");
  end_struct_array("sections");

  function("section_index", "s", "i", section_index);

  function("exports", "s", "i", exports);

end_declarations;


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;

  PIMAGE_NT_HEADERS32 pe_header;
  DATA* data;

  size_t pe_size;

  set_integer(IMAGE_FILE_MACHINE_I386, module, "MACHINE_I386");
  set_integer(IMAGE_FILE_MACHINE_AMD64, module, "MACHINE_AMD64");

  set_integer(IMAGE_SUBSYSTEM_UNKNOWN, module, "SUBSYSTEM_UNKNOWN");
  set_integer(IMAGE_SUBSYSTEM_NATIVE, module, "SUBSYSTEM_NATIVE");
  set_integer(IMAGE_SUBSYSTEM_WINDOWS_GUI, module, "SUBSYSTEM_WINDOWS_GUI");
  set_integer(IMAGE_SUBSYSTEM_WINDOWS_CUI, module, "SUBSYSTEM_WINDOWS_CUI");
  set_integer(IMAGE_SUBSYSTEM_OS2_CUI, module, "SUBSYSTEM_OS2_CUI");
  set_integer(IMAGE_SUBSYSTEM_POSIX_CUI, module, "SUBSYSTEM_POSIX_CUI");
  set_integer(IMAGE_SUBSYSTEM_NATIVE_WINDOWS, module, "SUBSYSTEM_NATIVE_WINDOWS");

  set_integer(IMAGE_FILE_RELOCS_STRIPPED, module, "RELOCS_STRIPPED");
  set_integer(IMAGE_FILE_EXECUTABLE_IMAGE, module, "EXECUTABLE_IMAGE");
  set_integer(IMAGE_FILE_LINE_NUMS_STRIPPED, module, "LINE_NUMS_STRIPPED");
  set_integer(IMAGE_FILE_LOCAL_SYMS_STRIPPED, module, "LOCAL_SYMS_STRIPPED");
  set_integer(IMAGE_FILE_AGGRESIVE_WS_TRIM, module, "AGGRESIVE_WS_TRIM");
  set_integer(IMAGE_FILE_LARGE_ADDRESS_AWARE, module, "LARGE_ADDRESS_AWARE");
  set_integer(IMAGE_FILE_BYTES_REVERSED_LO, module, "BYTES_REVERSED_LO");
  set_integer(IMAGE_FILE_32BIT_MACHINE, module, "32BIT_MACHINE");
  set_integer(IMAGE_FILE_DEBUG_STRIPPED, module, "DEBUG_STRIPPED");
  set_integer(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, module, "REMOVABLE_RUN_FROM_SWAP");
  set_integer(IMAGE_FILE_NET_RUN_FROM_SWAP, module, "NET_RUN_FROM_SWAP");
  set_integer(IMAGE_FILE_SYSTEM, module, "SYSTEM");
  set_integer(IMAGE_FILE_DLL, module, "DLL");
  set_integer(IMAGE_FILE_UP_SYSTEM_ONLY, module, "UP_SYSTEM_ONLY");
  set_integer(IMAGE_FILE_BYTES_REVERSED_HI, module, "BYTES_REVERSED_HI");

  foreach_memory_block(context, block)
  {
    pe_header = get_pe_header(block->data, block->size);

    if (pe_header != NULL)
    {
      // ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        pe_size = block->size - ((uint8_t*) pe_header - block->data);

        parse_pe_header(
            pe_header,
            block->base,
            pe_size,
            context->flags,
            module);

        data = (DATA*) yr_malloc(sizeof(DATA));

        if (data == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        data->data = block->data;
        data->size = block->size;
        data->pe_header = pe_header;
        data->pe_size = pe_size;

        module->data = data;
        break;
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  if (module->data != NULL)
    yr_free(module->data);

  return ERROR_SUCCESS;
}
