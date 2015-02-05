/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#include <limits.h>

#include <yara/pe.h>
#include <yara/elf.h>
#include <yara/exec.h>

#ifndef NULL
#define NULL 0
#endif

#ifndef MIN
#define MIN(x,y) ((x < y)?(x):(y))
#endif


PIMAGE_NT_HEADERS32 yr_get_pe_header(
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


uint64_t yr_pe_rva_to_offset(
    PIMAGE_NT_HEADERS32 pe_header,
    uint64_t rva,
    size_t buffer_length)
{
  int i = 0;
  PIMAGE_SECTION_HEADER section;
  DWORD section_rva;
  DWORD section_offset;

  section = IMAGE_FIRST_SECTION(pe_header);
  section_rva = 0;
  section_offset = 0;

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


int yr_get_elf_type(
    uint8_t* buffer,
    size_t buffer_length)
{
  elf_ident_t* elf_ident;

  if (buffer_length < sizeof(elf_ident_t))
    return 0;

  elf_ident = (elf_ident_t*) buffer;

  if (elf_ident->magic == ELF_MAGIC)
  {
    return elf_ident->_class;
  }
  else
  {
    return 0;
  }
}


uint64_t yr_elf_rva_to_offset_32(
    elf32_header_t* elf_header,
    uint64_t rva,
    size_t buffer_length)
{
  int i;
  elf32_section_header_t* section;

  if (elf_header->sh_offset == 0 || elf_header->sh_entry_count == 0)
    return 0;

  // check to prevent integer wraps

  if (ULONG_MAX - elf_header->sh_entry_count <
      sizeof(elf32_section_header_t) * elf_header->sh_entry_count)
    return 0;

  // check that 'sh_offset' doesn't wrap when added to the
  // size of entries.

  if (ULONG_MAX - elf_header->sh_offset <
      sizeof(elf32_section_header_t) * elf_header->sh_entry_count)
    return 0;

  if (elf_header->sh_offset + \
      sizeof(elf32_section_header_t) * \
      elf_header->sh_entry_count > buffer_length)
    return 0;

  section = (elf32_section_header_t*) \
      ((unsigned char*) elf_header + elf_header->sh_offset);

  for (i = 0; i < elf_header->sh_entry_count; i++)
  {
    if (section->type != ELF_SHT_NULL &&
        section->type != ELF_SHT_NOBITS &&
        rva >= section->addr &&
        rva <  section->addr + section->size)
    {
      // prevent integer wrapping with the return value

      if (ULONG_MAX - section->offset < (rva - section->addr))
        return 0;
      else
        return section->offset + (rva - section->addr);
    }

    section++;
  }

  return 0;

}


uint64_t yr_elf_rva_to_offset_64(
    elf64_header_t* elf_header,
    uint64_t rva,
    size_t buffer_length)
{
  int i;
  elf64_section_header_t* section;

  if (elf_header->sh_offset == 0 || elf_header->sh_entry_count == 0)
    return 0;

  // check that 'sh_offset' doesn't wrap when added to the
  // size of entries.
  if(ULONG_MAX - elf_header->sh_offset <
     sizeof(elf64_section_header_t) * elf_header->sh_entry_count)
    return 0;

  if (elf_header->sh_offset + \
      sizeof(elf64_section_header_t) * \
      elf_header->sh_entry_count > buffer_length)
    return 0;

  section = (elf64_section_header_t*) \
      ((uint8_t*) elf_header + elf_header->sh_offset);

  for (i = 0; i < elf_header->sh_entry_count; i++)
  {
    if (section->type != ELF_SHT_NULL &&
        section->type != ELF_SHT_NOBITS &&
        rva >= section->addr &&
        rva <  section->addr + section->size)
    {
      return section->offset + (rva - section->addr);
    }

    section++;
  }

  return 0;
}


uint64_t yr_get_entry_point_offset(
    uint8_t* buffer,
    size_t buffer_length)
{
  PIMAGE_NT_HEADERS32 pe_header;
  elf32_header_t* elf_header32;
  elf64_header_t* elf_header64;

  pe_header = yr_get_pe_header(buffer, buffer_length);

  if (pe_header != NULL)
  {
    return yr_pe_rva_to_offset(
        pe_header,
        pe_header->OptionalHeader.AddressOfEntryPoint,
        buffer_length - ((uint8_t*) pe_header - buffer));
  }

  switch(yr_get_elf_type(buffer, buffer_length))
  {
    case ELF_CLASS_32:
      elf_header32 = (elf32_header_t*) buffer;
      return yr_elf_rva_to_offset_32(
          elf_header32,
          elf_header32->entry,
          buffer_length);

    case ELF_CLASS_64:
      elf_header64 = (elf64_header_t*) buffer;
      return yr_elf_rva_to_offset_64(
          elf_header64,
          elf_header64->entry,
          buffer_length);
  }

  return UNDEFINED;
}


uint64_t yr_get_entry_point_address(
    uint8_t* buffer,
    size_t buffer_length,
    size_t base_address)
{
  PIMAGE_NT_HEADERS32 pe_header;

  elf32_header_t* elf_header32;
  elf64_header_t* elf_header64;

  pe_header = yr_get_pe_header(buffer, buffer_length);

  // If file is PE but not a DLL.

  if (pe_header != NULL &&
      !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
    return base_address + pe_header->OptionalHeader.AddressOfEntryPoint;

  // If file is executable ELF, not shared library.

  switch(yr_get_elf_type(buffer, buffer_length))
  {
    case ELF_CLASS_32:
      elf_header32 = (elf32_header_t*) buffer;

      if (elf_header32->type == ELF_ET_EXEC)
        return elf_header32->entry;

      break;

    case ELF_CLASS_64:
      elf_header64 = (elf64_header_t*) buffer;

      if (elf_header64->type == ELF_ET_EXEC)
        return elf_header64->entry;

      break;
  }

  return UNDEFINED;
}
