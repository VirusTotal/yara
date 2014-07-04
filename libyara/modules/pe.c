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

#include <yara/pe.h>
#include <yara/modules.h>


#define MODULE_NAME pe


#ifndef MIN
#define MIN(x,y) ((x < y)?(x):(y))
#endif


PIMAGE_NT_HEADERS get_pe_header(
    uint8_t* buffer,
    size_t buffer_length)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS pe_header;

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

  pe_header = (PIMAGE_NT_HEADERS) (buffer + mz_header->e_lfanew);

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
    PIMAGE_NT_HEADERS pe_header,
    uint64_t rva,
    size_t buffer_length)
{
  PIMAGE_SECTION_HEADER section;
  DWORD section_rva;
  DWORD section_offset;

  section = IMAGE_FIRST_SECTION(pe_header);
  section_rva = 0;
  section_offset = 0;

  int i = 0;

  while(i < MIN(pe_header->FileHeader.NumberOfSections, 60))
  {
    if ((uint8_t*) section - \
        (uint8_t*) pe_header + sizeof(IMAGE_SECTION_HEADER) < buffer_length)
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
    PIMAGE_NT_HEADERS pe,
    size_t buffer_length,
    int flags,
    YR_OBJECT* pe_obj)
{
  PIMAGE_SECTION_HEADER section;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
  int i;

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
        pe->OptionalHeader.AddressOfEntryPoint :
        rva_to_offset(
            pe, pe->OptionalHeader.AddressOfEntryPoint, buffer_length),
      pe_obj, "entry_point");

  set_integer(
      pe->OptionalHeader.ImageBase,
      pe_obj, "image_base");

  set_integer(
      pe->OptionalHeader.MajorLinkerVersion,
      pe_obj, "linker_version.major");

  set_integer(
      pe->OptionalHeader.MinorLinkerVersion,
      pe_obj, "linker_version.minor");

  set_integer(
      pe->OptionalHeader.MajorOperatingSystemVersion,
      pe_obj, "os_version.major");

  set_integer(pe->OptionalHeader.MinorOperatingSystemVersion,
      pe_obj, "os_version.minor");

  set_integer(pe->OptionalHeader.MajorImageVersion,
      pe_obj, "image_version.major");

  set_integer(pe->OptionalHeader.MinorImageVersion,
      pe_obj, "image_version.minor");

  set_integer(
      pe->OptionalHeader.MajorSubsystemVersion,
      pe_obj, "subsystem_version.major");

  set_integer(pe->OptionalHeader.MinorSubsystemVersion,
      pe_obj, "subsystem_version.minor");

  set_integer(pe->OptionalHeader.Subsystem,
      pe_obj, "subsystem");

  section = IMAGE_FIRST_SECTION(pe);

  for (i = 0; i < min(pe->FileHeader.NumberOfSections, 60); i++)
  {
    if ((uint8_t*) section -
        (uint8_t*) pe + sizeof(IMAGE_SECTION_HEADER) >= buffer_length)
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


begin_declarations;

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

end_declarations;


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  PIMAGE_NT_HEADERS header;

  foreach_memory_block(context, block)
  {
    header = get_pe_header(block->data, block->size);

    if (header != NULL)
    {
      // ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        parse_pe_header(header, block->size, context->flags, module);
        break;
      }

      break;
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME