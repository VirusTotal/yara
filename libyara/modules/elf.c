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

#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <yara/elf.h>
#endif

#include <yara/modules.h>
#include <yara/mem.h>


#define MODULE_NAME elf


int get_elf_type(
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

#define SIZE_OF_SECTION_TABLE_32 \
    (sizeof(elf32_section_header_t) * elf_header->sh_entry_count)

#define SIZE_OF_SECTION_TABLE_64 \
    (sizeof(elf64_section_header_t) * elf_header->sh_entry_count)


#define ELF_RVA_TO_OFFSET(bits)                                               \
uint64_t elf_rva_to_offset_##bits(                                            \
    elf##bits##_header_t* elf_header,                                         \
    uint64_t rva,                                                             \
    size_t elf_size)                                                          \
{                                                                             \
  elf##bits##_section_header_t* section;                                      \
                                                                              \
  /* check that sh_offset doesn't wrap when added to SIZE_OF_SECTION_TABLE */ \
                                                                              \
  if(ULONG_MAX - elf_header->sh_offset < SIZE_OF_SECTION_TABLE_##bits)        \
  {                                                                           \
    return UNDEFINED;                                                         \
  }                                                                           \
                                                                              \
  if (elf_header->sh_offset == 0 ||                                           \
      elf_header->sh_offset > elf_size ||                                     \
      elf_header->sh_offset + SIZE_OF_SECTION_TABLE_##bits > elf_size ||      \
      elf_header->sh_entry_count == 0)                                        \
  {                                                                           \
    return UNDEFINED;                                                         \
  }                                                                           \
                                                                              \
  section = (elf##bits##_section_header_t*)                                   \
      ((uint8_t*) elf_header + elf_header->sh_offset);                        \
                                                                              \
  for (int i = 0; i < elf_header->sh_entry_count; i++)                        \
  {                                                                           \
    if (section->type != ELF_SHT_NULL &&                                      \
        section->type != ELF_SHT_NOBITS &&                                    \
        rva >= section->addr &&                                               \
        rva <  section->addr + section->size)                                 \
    {                                                                         \
      return section->offset + (rva - section->addr);                         \
    }                                                                         \
                                                                              \
    section++;                                                                \
  }                                                                           \
                                                                              \
  return UNDEFINED;                                                           \
}

#define PARSE_ELF_HEADER(bits)                                                \
void parse_elf_header_##bits(                                                 \
  elf##bits##_header_t* elf,                                                  \
  size_t base_address,                                                        \
  size_t elf_size,                                                            \
  int flags,                                                                  \
  YR_OBJECT* elf_obj)                                                         \
{                                                                             \
  char* str_table;                                                            \
  elf##bits##_section_header_t* section;                                      \
                                                                              \
  set_integer(elf->type, elf_obj, "type");                                    \
  set_integer(elf->machine, elf_obj, "machine");                              \
  set_integer(elf->sh_entry_count, elf_obj, "number_of_sections");            \
                                                                              \
  if (elf->entry != 0)                                                        \
  {                                                                           \
    set_integer(                                                              \
        flags & SCAN_FLAGS_PROCESS_MEMORY ?                                   \
          base_address + elf->entry :                                         \
          elf_rva_to_offset_##bits(elf, elf->entry, elf_size),                \
        elf_obj, "entry_point");                                              \
  }                                                                           \
                                                                              \
  if (elf->sh_offset < elf_size &&                                            \
      elf->sh_offset + elf->sh_entry_count *                                  \
         sizeof(elf##bits##_section_header_t) < elf_size)                     \
  {                                                                           \
    section = (elf##bits##_section_header_t*)                                 \
                  ((uint8_t*) elf + elf->sh_offset);                          \
                                                                              \
    str_table = (char*) elf + section[elf->sh_str_table_index].offset;        \
                                                                              \
    for (int i = 0; i < elf->sh_entry_count; i++)                             \
    {                                                                         \
      set_integer(section->type, elf_obj, "sections[%i].type", i);            \
      set_integer(section->flags, elf_obj, "sections[%i].flags", i);          \
      set_integer(section->size, elf_obj, "sections[%i].size", i);            \
      set_integer(section->offset, elf_obj, "sections[%i].offset", i);        \
      set_string(str_table + section->name, elf_obj, "sections[%i].name", i); \
                                                                              \
      section++;                                                              \
    }                                                                         \
  }                                                                           \
}


ELF_RVA_TO_OFFSET(32);
ELF_RVA_TO_OFFSET(64);


PARSE_ELF_HEADER(32);
PARSE_ELF_HEADER(64);


begin_declarations;

  declare_integer("ET_NONE");
  declare_integer("ET_REL");
  declare_integer("ET_EXEC");
  declare_integer("ET_DYN");
  declare_integer("ET_CORE");

  declare_integer("EM_NONE");
  declare_integer("EM_M32");
  declare_integer("EM_SPARC");
  declare_integer("EM_386");
  declare_integer("EM_68K");
  declare_integer("EM_88K");
  declare_integer("EM_860");
  declare_integer("EM_ARM");
  declare_integer("EM_MIPS");
  declare_integer("EM_X86_64");

  declare_integer("SHT_NULL");
  declare_integer("SHT_PROGBITS");
  declare_integer("SHT_SYMTAB");
  declare_integer("SHT_STRTAB");
  declare_integer("SHT_RELA");
  declare_integer("SHT_HASH");
  declare_integer("SHT_DYNAMIC");
  declare_integer("SHT_NOTE");
  declare_integer("SHT_NOBITS");
  declare_integer("SHT_REL");
  declare_integer("SHT_SHLIB");
  declare_integer("SHT_DYNSYM");

  declare_integer("SHF_WRITE");
  declare_integer("SHF_ALLOC");
  declare_integer("SHF_EXECINSTR");

  declare_integer("type");
  declare_integer("machine");
  declare_integer("entry_point");
  declare_integer("number_of_sections");

  begin_struct_array("sections");
    declare_integer("type");
    declare_integer("flags");
    declare_string("name");
    declare_integer("size");
    declare_integer("offset");
  end_struct_array("sections");

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

  elf32_header_t* elf_header32;
  elf64_header_t* elf_header64;

  set_integer(ELF_ET_NONE, module_object, "ET_NONE");
  set_integer(ELF_ET_REL, module_object, "ET_REL");
  set_integer(ELF_ET_EXEC, module_object, "ET_EXEC");
  set_integer(ELF_ET_DYN, module_object, "ET_DYN");
  set_integer(ELF_ET_CORE, module_object, "ET_CORE");

  set_integer(ELF_EM_NONE, module_object, "EM_NONE");
  set_integer(ELF_EM_M32, module_object, "EM_M32");
  set_integer(ELF_EM_SPARC, module_object, "EM_SPARC");
  set_integer(ELF_EM_386, module_object, "EM_386");
  set_integer(ELF_EM_68K, module_object, "EM_68K");
  set_integer(ELF_EM_88K, module_object, "EM_88K");
  set_integer(ELF_EM_860, module_object, "EM_860");
  set_integer(ELF_EM_ARM, module_object, "EM_ARM");
  set_integer(ELF_EM_MIPS, module_object, "EM_MIPS");
  set_integer(ELF_EM_X86_64, module_object, "EM_X86_64");

  set_integer(ELF_SHT_NULL, module_object, "SHT_NULL");
  set_integer(ELF_SHT_PROGBITS, module_object, "SHT_PROGBITS");
  set_integer(ELF_SHT_SYMTAB, module_object, "SHT_SYMTAB");
  set_integer(ELF_SHT_STRTAB, module_object, "SHT_STRTAB");
  set_integer(ELF_SHT_RELA, module_object, "SHT_RELA");
  set_integer(ELF_SHT_HASH, module_object, "SHT_HASH");
  set_integer(ELF_SHT_DYNAMIC, module_object, "SHT_DYNAMIC");
  set_integer(ELF_SHT_NOTE, module_object, "SHT_NOTE");
  set_integer(ELF_SHT_NOBITS, module_object, "SHT_NOBITS");
  set_integer(ELF_SHT_REL, module_object, "SHT_REL");
  set_integer(ELF_SHT_SHLIB, module_object, "SHT_SHLIB");
  set_integer(ELF_SHT_DYNSYM, module_object, "SHT_DYNSYM");

  set_integer(ELF_SHF_WRITE, module_object, "SHF_WRITE");
  set_integer(ELF_SHF_ALLOC, module_object, "SHF_ALLOC");
  set_integer(ELF_SHF_EXECINSTR, module_object, "SHF_EXECINSTR");

  foreach_memory_block(context, block)
  {
    switch(get_elf_type(block->data, block->size))
    {
      case ELF_CLASS_32:

        if (block->size > sizeof(elf32_header_t))
        {
          elf_header32 = (elf32_header_t*) block->data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              elf_header32->type == ELF_ET_EXEC)
          {
            parse_elf_header_32(
                elf_header32,
                block->base,
                block->size,
                context->flags,
                module_object);
          }
        }

        break;

      case ELF_CLASS_64:

        if (block->size > sizeof(elf64_header_t))
        {
          elf_header64 = (elf64_header_t*) block->data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              elf_header64->type == ELF_ET_EXEC)
          {
            parse_elf_header_64(
                elf_header64,
                block->base,
                block->size,
                context->flags,
                module_object);
          }
        }

        break;
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
