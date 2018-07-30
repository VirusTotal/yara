/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#include <limits.h>

#include <yara/endian.h>
#include <yara/pe.h>
#include <yara/elf.h>
#include <yara/exec.h>
#include <yara/utils.h>

#ifndef NULL
#define NULL 0
#endif

#ifndef MIN
#define MIN(x,y) ((x < y)?(x):(y))
#endif


PIMAGE_NT_HEADERS32 yr_get_pe_header(
    const uint8_t* buffer,
    size_t buffer_length)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;

  size_t headers_size = 0;

  if (buffer_length < sizeof(IMAGE_DOS_HEADER))
    return NULL;

  mz_header = (PIMAGE_DOS_HEADER) buffer;

  if (yr_le16toh(mz_header->e_magic) != IMAGE_DOS_SIGNATURE)
    return NULL;

  if ((int32_t) yr_le32toh(mz_header->e_lfanew) < 0)
    return NULL;

  headers_size = yr_le32toh(mz_header->e_lfanew) + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (buffer_length < headers_size)
    return NULL;

  pe_header = (PIMAGE_NT_HEADERS32) (buffer + yr_le32toh(mz_header->e_lfanew));

  headers_size += sizeof(IMAGE_OPTIONAL_HEADER32);

  if (yr_le32toh(pe_header->Signature) == IMAGE_NT_SIGNATURE &&
      (yr_le16toh(pe_header->FileHeader.Machine) == IMAGE_FILE_MACHINE_I386 ||
       yr_le16toh(pe_header->FileHeader.Machine) == IMAGE_FILE_MACHINE_AMD64) &&
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

  while(i < MIN(yr_le16toh(pe_header->FileHeader.NumberOfSections), 60))
  {
    if ((uint8_t*) section - \
        (uint8_t*) pe_header + sizeof(IMAGE_SECTION_HEADER) < buffer_length)
    {
      if (rva >= section->VirtualAddress &&
          section_rva <= yr_le32toh(section->VirtualAddress))
      {
        section_rva = yr_le32toh(section->VirtualAddress);
        section_offset = yr_le32toh(section->PointerToRawData);
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
    const uint8_t* buffer,
    size_t buffer_length)
{
  elf_ident_t* elf_ident;

  if (buffer_length < sizeof(elf_ident_t))
    return 0;

  elf_ident = (elf_ident_t*) buffer;

  if (yr_le32toh(elf_ident->magic) != ELF_MAGIC)
  {
    return 0;
  }

  switch (elf_ident->_class) {
    case ELF_CLASS_32:
      if (buffer_length < sizeof(elf32_header_t))
      {
        return 0;
      }
      break;
    case ELF_CLASS_64:
      if (buffer_length < sizeof(elf64_header_t))
      {
        return 0;
      }
      break;
    default:
      /* Unexpected class */
      return 0;
  }

  return elf_ident->_class;
}


static uint64_t yr_elf_rva_to_offset_32(
    elf32_header_t* elf_header,
    uint64_t rva,
    size_t buffer_length)
{
  // if the binary is an executable then prefer the program headers to resolve
  // the offset
  if (yr_le16toh(elf_header->type) == ELF_ET_EXEC)
  {
    int i;
    elf32_program_header_t* program;
    if (yr_le32toh(elf_header->ph_offset) == 0 ||
        yr_le16toh(elf_header->ph_entry_count == 0))
      return 0;

    // check to prevent integer wraps
    if (ULONG_MAX - yr_le16toh(elf_header->ph_entry_count) <
     sizeof(elf32_program_header_t) * yr_le16toh(elf_header->ph_entry_count))
      return 0;

    // check that 'ph_offset' doesn't wrap when added to the
    // size of entries.
    if(ULONG_MAX - yr_le32toh(elf_header->ph_offset) <
     sizeof(elf32_program_header_t) * yr_le16toh(elf_header->ph_entry_count))
      return 0;

    // ensure we don't exceed the buffer size
    if (yr_le32toh(elf_header->ph_offset) + sizeof(elf32_program_header_t) *
        yr_le16toh(elf_header->ph_entry_count) > buffer_length)
      return 0;

    program = (elf32_program_header_t*)
      ((uint8_t*) elf_header + yr_le32toh(elf_header->ph_offset));

    for (i = 0; i < yr_le16toh(elf_header->ph_entry_count); i++)
    {
      if (rva >= yr_le32toh(program->virt_addr) &&
          rva <  yr_le32toh(program->virt_addr) + yr_le32toh(program->mem_size))
      {
        return yr_le32toh(program->offset) + (rva - yr_le32toh(program->virt_addr));
      }

      program++;
    }
  }
  else
  {
    int i;
    elf32_section_header_t* section;

    if (yr_le32toh(elf_header->sh_offset) == 0 ||
        yr_le16toh(elf_header->sh_entry_count == 0))
      return 0;

    // check to prevent integer wraps

    if (ULONG_MAX - yr_le16toh(elf_header->sh_entry_count) <
     sizeof(elf32_section_header_t) * yr_le16toh(elf_header->sh_entry_count))
      return 0;

    // check that 'sh_offset' doesn't wrap when added to the
    // size of entries.

    if (ULONG_MAX - yr_le32toh(elf_header->sh_offset) <
     sizeof(elf32_section_header_t) * yr_le16toh(elf_header->sh_entry_count))
      return 0;

    if (yr_le32toh(elf_header->sh_offset) + sizeof(elf32_section_header_t) *
     yr_le16toh(elf_header->sh_entry_count) > buffer_length)
      return 0;

    section = (elf32_section_header_t*)
      ((unsigned char*) elf_header + yr_le32toh(elf_header->sh_offset));

    for (i = 0; i < yr_le16toh(elf_header->sh_entry_count); i++)
    {
      if (yr_le32toh(section->type) != ELF_SHT_NULL &&
          yr_le32toh(section->type) != ELF_SHT_NOBITS &&
          rva >= yr_le32toh(section->addr) &&
          rva <  yr_le32toh(section->addr) + yr_le32toh(section->size))
      {
        // prevent integer wrapping with the return value

        if (ULONG_MAX - yr_le32toh(section->offset) < (rva - yr_le32toh(section->addr)))
          return 0;
        else
          return yr_le32toh(section->offset) + (rva - yr_le32toh(section->addr));
      }

      section++;
    }
  }

  return 0;

}


static uint64_t yr_elf_rva_to_offset_64(
    elf64_header_t* elf_header,
    uint64_t rva,
    size_t buffer_length)
{
  // if the binary is an executable then prefer the program headers to resolve
  // the offset
  if (yr_le16toh(elf_header->type) == ELF_ET_EXEC)
  {
    int i;
    elf64_program_header_t* program;
    if (yr_le64toh(elf_header->ph_offset) == 0 ||
        yr_le16toh(elf_header->ph_entry_count == 0))
      return 0;

    // check that 'ph_offset' doesn't wrap when added to the
    // size of entries.
    if(ULONG_MAX - yr_le64toh(elf_header->ph_offset) <
     sizeof(elf64_program_header_t) * yr_le16toh(elf_header->ph_entry_count))
      return 0;

    // ensure we don't exceed the buffer size
    if (yr_le64toh(elf_header->ph_offset) + sizeof(elf64_program_header_t) *
        yr_le16toh(elf_header->ph_entry_count) > buffer_length)
      return 0;

    program = (elf64_program_header_t*)
      ((uint8_t*) elf_header + yr_le64toh(elf_header->ph_offset));

    for (i = 0; i < yr_le16toh(elf_header->ph_entry_count); i++)
    {
      if (rva >= yr_le64toh(program->virt_addr) &&
          rva <  yr_le64toh(program->virt_addr) + yr_le64toh(program->mem_size))
      {
        return yr_le64toh(program->offset) + (rva - yr_le64toh(program->virt_addr));
      }

      program++;
    }
  }
  else
  {
    int i;
    elf64_section_header_t* section;

    if (yr_le64toh(elf_header->sh_offset) == 0 ||
        yr_le16toh(elf_header->sh_entry_count) == 0)
      return 0;

    // check that 'sh_offset' doesn't wrap when added to the
    // size of entries.
    if(ULONG_MAX - yr_le64toh(elf_header->sh_offset) <
     sizeof(elf64_section_header_t) * yr_le16toh(elf_header->sh_entry_count))
      return 0;

    if (yr_le64toh(elf_header->sh_offset) + sizeof(elf64_section_header_t) *
        yr_le16toh(elf_header->sh_entry_count) > buffer_length)
      return 0;

    section = (elf64_section_header_t*)
      ((uint8_t*) elf_header + yr_le64toh(elf_header->sh_offset));

    for (i = 0; i < yr_le16toh(elf_header->sh_entry_count); i++)
    {
      if (yr_le32toh(section->type) != ELF_SHT_NULL &&
          yr_le32toh(section->type) != ELF_SHT_NOBITS &&
          rva >= yr_le64toh(section->addr) &&
          rva <  yr_le64toh(section->addr) + yr_le64toh(section->size))
      {
        return yr_le64toh(section->offset) + (rva - yr_le64toh(section->addr));
      }

      section++;
    }
  }

  return 0;
}


uint64_t yr_get_entry_point_offset(
    const uint8_t* buffer,
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
        yr_le32toh(pe_header->OptionalHeader.AddressOfEntryPoint),
        buffer_length - ((uint8_t*) pe_header - buffer));
  }

  switch(yr_get_elf_type(buffer, buffer_length))
  {
    case ELF_CLASS_32:
      elf_header32 = (elf32_header_t*) buffer;
      return yr_elf_rva_to_offset_32(
          elf_header32,
          yr_le32toh(elf_header32->entry),
          buffer_length);

    case ELF_CLASS_64:
      elf_header64 = (elf64_header_t*) buffer;
      return yr_elf_rva_to_offset_64(
          elf_header64,
          yr_le64toh(elf_header64->entry),
          buffer_length);
  }

  return UNDEFINED;
}


uint64_t yr_get_entry_point_address(
    const uint8_t* buffer,
    size_t buffer_length,
    uint64_t base_address)
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
