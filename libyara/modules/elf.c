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

#define _GNU_SOURCE

#include <limits.h>
#include <string.h>

#include <yara/elf.h>
#include <yara/endian.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/utils.h>


#define MODULE_NAME elf

#define CLASS_DATA(c,d) ((c << 8) | d)

int get_elf_class_data(
    const uint8_t* buffer,
    size_t buffer_length)
{
  elf_ident_t* elf_ident;

  if (buffer_length < sizeof(elf_ident_t))
    return 0;

  elf_ident = (elf_ident_t*) buffer;

  if (yr_le32toh(elf_ident->magic) == ELF_MAGIC)
  {
    return CLASS_DATA(elf_ident->_class, elf_ident->data);
  }
  else
  {
    return 0;
  }
}

static bool is_valid_ptr(
    const void* base,
    size_t size,
    const void* ptr,
    uint64_t ptr_size)  // ptr_size can be 64bit even in 32bit systems.
{
  return ptr >= base && ptr_size <= size &&
      ((char*) ptr) + ptr_size <= ((char*) base) + size;
}

#define IS_VALID_PTR(base, size, ptr) \
    is_valid_ptr(base, size, ptr, sizeof(*ptr))

/*
 * Returns a string table entry for the index or NULL if the entry is out
 * of bounds. A non-null return value will be a null-terminated C string.
 */
static const char* str_table_entry(const char* str_table_base,
                                   const char* str_table_limit,
                                   int index) {
  size_t len;
  const char* str_entry = str_table_base + index;

  if (index < 0)
  {
    return NULL;
  }

  if (str_entry >= str_table_limit)
  {
    return NULL;
  }

  len = strnlen(str_entry, str_table_limit - str_entry);

  if (str_entry + len == str_table_limit)
  {
    /* Entry is clamped by extent of string table, not null-terminated. */
    return NULL;
  }

  return str_entry;
}

#define ELF_SIZE_OF_SECTION_TABLE(bits,bo,h)       \
  (sizeof(elf##bits##_section_header_t) * yr_##bo##16toh(h->sh_entry_count))

#define ELF_SIZE_OF_PROGRAM_TABLE(bits,bo,h)       \
  (sizeof(elf##bits##_program_header_t) * yr_##bo##16toh(h->ph_entry_count))

#define ELF_RVA_TO_OFFSET(bits,bo)                                             \
uint64_t elf_rva_to_offset_##bits##_##bo(                                      \
    elf##bits##_header_t* elf_header,                                          \
    uint64_t rva,                                                              \
    size_t elf_size)                                                           \
{                                                                              \
  if (yr_##bo##16toh(elf_header->type) == ELF_ET_EXEC)                         \
  {                                                                            \
    int i;                                                                     \
                                                                               \
    elf##bits##_program_header_t* program;                                     \
                                                                               \
    /* check that ph_offset doesn't wrap when added to SIZE_OF_PROGRAM_TABLE */\
                                                                               \
    if(ULONG_MAX - yr_##bo##bits##toh(elf_header->ph_offset) <                 \
       ELF_SIZE_OF_PROGRAM_TABLE(bits,bo,elf_header))                          \
    {                                                                          \
      return UNDEFINED;                                                        \
    }                                                                          \
                                                                               \
    if (yr_##bo##bits##toh(elf_header->ph_offset) == 0 ||                      \
        yr_##bo##bits##toh(elf_header->ph_offset) > elf_size ||                \
        yr_##bo##bits##toh(elf_header->ph_offset) +                            \
         ELF_SIZE_OF_PROGRAM_TABLE(bits,bo,elf_header) > elf_size ||           \
        yr_##bo##16toh(elf_header->ph_entry_count) == 0)                       \
    {                                                                          \
      return UNDEFINED;                                                        \
    }                                                                          \
                                                                               \
    program = (elf##bits##_program_header_t*)                                  \
        ((uint8_t*) elf_header + yr_##bo##bits##toh(elf_header->ph_offset));   \
                                                                               \
    for (i = 0; i < yr_##bo##16toh(elf_header->ph_entry_count); i++)           \
    {                                                                          \
      if (rva >= yr_##bo##bits##toh(program->virt_addr) &&                     \
          rva < yr_##bo##bits##toh(program->virt_addr) +                       \
          yr_##bo##bits##toh(program->mem_size))                               \
      {                                                                        \
        return yr_##bo##bits##toh(program->offset) +                           \
          (rva - yr_##bo##bits##toh(program->virt_addr));                      \
      }                                                                        \
                                                                               \
      program++;                                                               \
    }                                                                          \
  }                                                                            \
  else                                                                         \
  {                                                                            \
    int i;                                                                     \
                                                                               \
    elf##bits##_section_header_t* section;                                     \
                                                                               \
    /* check that sh_offset doesn't wrap when added to SIZE_OF_SECTION_TABLE */\
                                                                               \
    if(ULONG_MAX - yr_##bo##bits##toh(elf_header->sh_offset) <                 \
       ELF_SIZE_OF_SECTION_TABLE(bits,bo,elf_header))                          \
    {                                                                          \
      return UNDEFINED;                                                        \
    }                                                                          \
                                                                               \
    if (yr_##bo##bits##toh(elf_header->sh_offset) == 0 ||                      \
        yr_##bo##bits##toh(elf_header->sh_offset) > elf_size ||                \
        yr_##bo##bits##toh(elf_header->sh_offset) +                            \
         ELF_SIZE_OF_SECTION_TABLE(bits,bo,elf_header) > elf_size ||           \
        yr_##bo##16toh(elf_header->sh_entry_count) == 0)                       \
    {                                                                          \
      return UNDEFINED;                                                        \
    }                                                                          \
                                                                               \
    section = (elf##bits##_section_header_t*)                                  \
        ((uint8_t*) elf_header + yr_##bo##bits##toh(elf_header->sh_offset));   \
                                                                               \
    for (i = 0; i < yr_##bo##16toh(elf_header->sh_entry_count); i++)           \
    {                                                                          \
      if (yr_##bo##32toh(section->type) != ELF_SHT_NULL &&                     \
          yr_##bo##32toh(section->type) != ELF_SHT_NOBITS &&                   \
          rva >= yr_##bo##bits##toh(section->addr) &&                          \
          rva < yr_##bo##bits##toh(section->addr) +                            \
          yr_##bo##bits##toh(section->size))                                   \
      {                                                                        \
        return yr_##bo##bits##toh(section->offset) +                           \
          (rva - yr_##bo##bits##toh(section->addr));                           \
      }                                                                        \
                                                                               \
      section++;                                                               \
    }                                                                          \
  }                                                                            \
  return UNDEFINED;                                                            \
}

#define PARSE_ELF_HEADER(bits,bo)                                              \
void parse_elf_header_##bits##_##bo(                                           \
  elf##bits##_header_t* elf,                                                   \
  uint64_t base_address,                                                       \
  size_t elf_size,                                                             \
  int flags,                                                                   \
  YR_OBJECT* elf_obj)                                                          \
{                                                                              \
  unsigned int i, j;                                                           \
  const char* elf_raw = (const char*) elf;                                     \
  uint16_t str_table_index = yr_##bo##16toh(elf->sh_str_table_index);          \
                                                                               \
  const char* sym_table = NULL;                                                \
  const char* sym_str_table = NULL;                                            \
                                                                               \
  uint##bits##_t sym_table_size = 0;                                           \
  uint##bits##_t sym_str_table_size = 0;                                       \
                                                                               \
  elf##bits##_section_header_t* section_table;                                 \
  elf##bits##_section_header_t* section;                                       \
  elf##bits##_program_header_t* segment;                                       \
                                                                               \
  set_integer(yr_##bo##16toh(elf->type), elf_obj, "type");                     \
  set_integer(yr_##bo##16toh(elf->machine), elf_obj, "machine");               \
  set_integer(yr_##bo##bits##toh(elf->sh_offset), elf_obj,                     \
              "sh_offset");                                                    \
  set_integer(yr_##bo##16toh(elf->sh_entry_size), elf_obj,                     \
              "sh_entry_size");                                                \
  set_integer(yr_##bo##16toh(elf->sh_entry_count), elf_obj,                    \
              "number_of_sections");                                           \
  set_integer(yr_##bo##bits##toh(elf->ph_offset), elf_obj,                     \
              "ph_offset");                                                    \
  set_integer(yr_##bo##16toh(elf->ph_entry_size), elf_obj,                     \
              "ph_entry_size");                                                \
  set_integer(yr_##bo##16toh(elf->ph_entry_count), elf_obj,                    \
              "number_of_segments");                                           \
                                                                               \
  if (yr_##bo##bits##toh(elf->entry) != 0)                                     \
  {                                                                            \
    set_integer(                                                               \
        flags & SCAN_FLAGS_PROCESS_MEMORY ?                                    \
        base_address + yr_##bo##bits##toh(elf->entry) :                        \
        elf_rva_to_offset_##bits##_##bo(                                       \
            elf, yr_##bo##bits##toh(elf->entry), elf_size),                    \
        elf_obj, "entry_point");                                               \
  }                                                                            \
                                                                               \
  if (yr_##bo##16toh(elf->sh_entry_count) < ELF_SHN_LORESERVE &&               \
      str_table_index < yr_##bo##16toh(elf->sh_entry_count) &&                 \
      yr_##bo##bits##toh(elf->sh_offset) < elf_size &&                         \
      yr_##bo##bits##toh(elf->sh_offset) +                                     \
        yr_##bo##16toh(elf->sh_entry_count) *                                  \
        sizeof(elf##bits##_section_header_t) <= elf_size)                      \
  {                                                                            \
    const char* str_table = NULL;                                              \
                                                                               \
    section_table = (elf##bits##_section_header_t*)                            \
        (elf_raw + yr_##bo##bits##toh(elf->sh_offset));                        \
                                                                               \
    if (yr_##bo##bits##toh(section_table[str_table_index].offset) < elf_size)  \
    {                                                                          \
      str_table = elf_raw + yr_##bo##bits##toh(                                \
          section_table[str_table_index].offset);                              \
    }                                                                          \
                                                                               \
    section = section_table;                                                   \
                                                                               \
    for (i = 0; i < yr_##bo##16toh(elf->sh_entry_count); i++, section++)       \
    {                                                                          \
      set_integer(yr_##bo##32toh(section->type), elf_obj,                      \
                  "sections[%i].type", i);                                     \
      set_integer(yr_##bo##bits##toh(section->flags), elf_obj,                 \
                  "sections[%i].flags", i);                                    \
      set_integer(yr_##bo##bits##toh(section->addr), elf_obj,                  \
                  "sections[%i].address", i);                                  \
      set_integer(yr_##bo##bits##toh(section->size), elf_obj,                  \
                  "sections[%i].size", i);                                     \
      set_integer(yr_##bo##bits##toh(section->offset), elf_obj,                \
                  "sections[%i].offset", i);                                   \
                                                                               \
      if (yr_##bo##32toh(section->name) < elf_size &&                          \
          str_table > elf_raw &&                                               \
          str_table + yr_##bo##32toh(section->name) < elf_raw + elf_size)      \
      {                                                                        \
        const char* str_entry = str_table_entry(                               \
            str_table,                                                         \
            elf_raw + elf_size,                                                \
            yr_##bo##32toh(section->name));                                    \
                                                                               \
        if (str_entry)                                                         \
          set_string(str_entry, elf_obj, "sections[%i].name", i);              \
      }                                                                        \
                                                                               \
      if (yr_##bo##32toh(section->type) == ELF_SHT_SYMTAB &&                   \
          yr_##bo##32toh(section->link) < elf->sh_entry_count)                 \
      {                                                                        \
        elf##bits##_section_header_t* string_section =                         \
            section_table + yr_##bo##32toh(section->link);                     \
                                                                               \
        if (IS_VALID_PTR(elf, elf_size, string_section) &&                     \
            yr_##bo##32toh(string_section->type) == ELF_SHT_STRTAB)            \
        {                                                                      \
          sym_table = elf_raw + yr_##bo##bits##toh(section->offset);           \
          sym_str_table = elf_raw + yr_##bo##bits##toh(string_section->offset);\
          sym_table_size = yr_##bo##bits##toh(section->size);                  \
          sym_str_table_size = yr_##bo##bits##toh(string_section->size);       \
        }                                                                      \
      }                                                                        \
    }                                                                          \
                                                                               \
    if (is_valid_ptr(elf, elf_size, sym_str_table, sym_str_table_size) &&      \
        is_valid_ptr(elf, elf_size, sym_table, sym_table_size))                \
    {                                                                          \
      elf##bits##_sym_t* sym = (elf##bits##_sym_t*) sym_table;                 \
                                                                               \
      for (j = 0; j < sym_table_size / sizeof(elf##bits##_sym_t); j++, sym++)  \
      {                                                                        \
        uint32_t sym_name_offset = yr_##bo##32toh(sym->name);                  \
                                                                               \
        if (sym_name_offset < sym_str_table_size)                              \
        {                                                                      \
          const char* sym_name = sym_str_table + sym_name_offset;              \
                                                                               \
          set_sized_string(                                                    \
              sym_name,                                                        \
              strnlen(                                                         \
                  sym_name, (size_t) (sym_str_table_size - sym_name_offset)),  \
              elf_obj,                                                         \
              "symtab[%i].name",                                               \
              j);                                                              \
        }                                                                      \
                                                                               \
        set_integer(sym->info >> 4, elf_obj,                                   \
            "symtab[%i].bind", j);                                             \
        set_integer(sym->info & 0xf, elf_obj,                                  \
            "symtab[%i].type", j);                                             \
        set_integer(yr_##bo##16toh(sym->shndx), elf_obj,                       \
           "symtab[%i].shndx", j);                                             \
        set_integer(yr_##bo##bits##toh(sym->value), elf_obj,                   \
           "symtab[%i].value", j);                                             \
        set_integer(yr_##bo##bits##toh(sym->size), elf_obj,                    \
           "symtab[%i].size", j);                                              \
      }                                                                        \
                                                                               \
      set_integer(j, elf_obj, "symtab_entries");                               \
    }                                                                          \
  }                                                                            \
                                                                               \
  if (yr_##bo##16toh(elf->ph_entry_count) > 0 &&                               \
      yr_##bo##16toh(elf->ph_entry_count) < ELF_PN_XNUM &&                     \
      yr_##bo##bits##toh(elf->ph_offset) < elf_size &&                         \
      yr_##bo##bits##toh(elf->ph_offset) +                                     \
        yr_##bo##16toh(elf->ph_entry_count) *                                  \
        sizeof(elf##bits##_program_header_t) <= elf_size)                      \
  {                                                                            \
    segment = (elf##bits##_program_header_t*)                                  \
        (elf_raw + yr_##bo##bits##toh(elf->ph_offset));                        \
                                                                               \
    for (i = 0; i < yr_##bo##16toh(elf->ph_entry_count); i++, segment++)       \
    {                                                                          \
      set_integer(                                                             \
          yr_##bo##32toh(segment->type), elf_obj, "segments[%i].type", i);     \
      set_integer(                                                             \
          yr_##bo##32toh(segment->flags), elf_obj, "segments[%i].flags", i);   \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->offset), elf_obj,                        \
          "segments[%i].offset", i);                                           \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->virt_addr), elf_obj,                     \
          "segments[%i].virtual_address", i);                                  \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->phys_addr), elf_obj,                     \
          "segments[%i].physical_address", i);                                 \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->file_size), elf_obj,                     \
          "segments[%i].file_size", i);                                        \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->mem_size), elf_obj,                      \
          "segments[%i].memory_size", i);                                      \
      set_integer(                                                             \
          yr_##bo##bits##toh(segment->alignment), elf_obj,                     \
          "segments[%i].alignment", i);                                        \
                                                                               \
      if (yr_##bo##32toh(segment->type) == ELF_PT_DYNAMIC)                     \
      {                                                                        \
        elf##bits##_dyn_t* dyn = (elf##bits##_dyn_t*)                          \
            (elf_raw + yr_##bo##bits##toh(segment->offset));                   \
                                                                               \
        for (j = 0; IS_VALID_PTR(elf, elf_size, dyn); dyn++, j++)              \
        {                                                                      \
          set_integer(                                                         \
              yr_##bo##bits##toh(dyn->tag), elf_obj, "dynamic[%i].type", j);   \
          set_integer(                                                         \
              yr_##bo##bits##toh(dyn->val), elf_obj, "dynamic[%i].val", j);    \
                                                                               \
          if (dyn->tag == ELF_DT_NULL)                                         \
          {                                                                    \
            j++;                                                               \
            break;                                                             \
          }                                                                    \
        }                                                                      \
        set_integer(j, elf_obj, "dynamic_section_entries");                    \
      }                                                                        \
    }                                                                          \
  }                                                                            \
}

ELF_RVA_TO_OFFSET(32,le);
ELF_RVA_TO_OFFSET(64,le);
ELF_RVA_TO_OFFSET(32,be);
ELF_RVA_TO_OFFSET(64,be);

PARSE_ELF_HEADER(32,le);
PARSE_ELF_HEADER(64,le);
PARSE_ELF_HEADER(32,be);
PARSE_ELF_HEADER(64,be);


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
  declare_integer("EM_MIPS");
  declare_integer("EM_MIPS_RS3_LE");
  declare_integer("EM_PPC");
  declare_integer("EM_PPC64");
  declare_integer("EM_ARM");
  declare_integer("EM_X86_64");
  declare_integer("EM_AARCH64");

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
  declare_integer("sh_offset");
  declare_integer("sh_entry_size");

  declare_integer("number_of_segments");
  declare_integer("ph_offset");
  declare_integer("ph_entry_size");

  begin_struct_array("sections");
    declare_integer("type");
    declare_integer("flags");
    declare_integer("address");
    declare_string("name");
    declare_integer("size");
    declare_integer("offset");
  end_struct_array("sections");

  declare_integer("PT_NULL");
  declare_integer("PT_LOAD");
  declare_integer("PT_DYNAMIC");
  declare_integer("PT_INTERP");
  declare_integer("PT_NOTE");
  declare_integer("PT_SHLIB");
  declare_integer("PT_PHDR");
  declare_integer("PT_TLS");
  declare_integer("PT_GNU_EH_FRAME");
  declare_integer("PT_GNU_STACK");

  declare_integer("DT_NULL");
  declare_integer("DT_NEEDED");
  declare_integer("DT_PLTRELSZ");
  declare_integer("DT_PLTGOT");
  declare_integer("DT_HASH");
  declare_integer("DT_STRTAB");
  declare_integer("DT_SYMTAB");
  declare_integer("DT_RELA");
  declare_integer("DT_RELASZ");
  declare_integer("DT_RELAENT");
  declare_integer("DT_STRSZ");
  declare_integer("DT_SYMENT");
  declare_integer("DT_INIT");
  declare_integer("DT_FINI");
  declare_integer("DT_SONAME");
  declare_integer("DT_RPATH");
  declare_integer("DT_SYMBOLIC");
  declare_integer("DT_REL");
  declare_integer("DT_RELSZ");
  declare_integer("DT_RELENT");
  declare_integer("DT_PLTREL");
  declare_integer("DT_DEBUG");
  declare_integer("DT_TEXTREL");
  declare_integer("DT_JMPREL");
  declare_integer("DT_BIND_NOW");
  declare_integer("DT_INIT_ARRAY");
  declare_integer("DT_FINI_ARRAY");
  declare_integer("DT_INIT_ARRAYSZ");
  declare_integer("DT_FINI_ARRAYSZ");
  declare_integer("DT_RUNPATH");
  declare_integer("DT_FLAGS");
  declare_integer("DT_ENCODING");

  declare_integer("STT_NOTYPE");
  declare_integer("STT_OBJECT");
  declare_integer("STT_FUNC");
  declare_integer("STT_SECTION");
  declare_integer("STT_FILE");
  declare_integer("STT_COMMON");
  declare_integer("STT_TLS");

  declare_integer("STB_LOCAL");
  declare_integer("STB_GLOBAL");
  declare_integer("STB_WEAK");

  declare_integer("PF_X");
  declare_integer("PF_W");
  declare_integer("PF_R");

  begin_struct_array("segments");
    declare_integer("type");
    declare_integer("flags");
    declare_integer("offset");
    declare_integer("virtual_address");
    declare_integer("physical_address");
    declare_integer("file_size");
    declare_integer("memory_size");
    declare_integer("alignment");
  end_struct_array("segments");

  declare_integer("dynamic_section_entries");
  begin_struct_array("dynamic");
    declare_integer("type");
    declare_integer("val");
  end_struct_array("dynamic");

  declare_integer("symtab_entries");
  begin_struct_array("symtab");
    declare_string("name");
    declare_integer("value");
    declare_integer("size");
    declare_integer("type");
    declare_integer("bind");
    declare_integer("shndx");
  end_struct_array("symtab");

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
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

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
  set_integer(ELF_EM_MIPS, module_object, "EM_MIPS");
  set_integer(ELF_EM_MIPS_RS3_LE, module_object, "EM_MIPS_RS3_LE");
  set_integer(ELF_EM_PPC, module_object, "EM_PPC");
  set_integer(ELF_EM_PPC64, module_object, "EM_PPC64");
  set_integer(ELF_EM_ARM, module_object, "EM_ARM");
  set_integer(ELF_EM_X86_64, module_object, "EM_X86_64");
  set_integer(ELF_EM_AARCH64, module_object, "EM_AARCH64");

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

  set_integer(ELF_PT_NULL, module_object, "PT_NULL");
  set_integer(ELF_PT_LOAD, module_object, "PT_LOAD");
  set_integer(ELF_PT_DYNAMIC, module_object, "PT_DYNAMIC");
  set_integer(ELF_PT_INTERP, module_object, "PT_INTERP");
  set_integer(ELF_PT_NOTE, module_object, "PT_NOTE");
  set_integer(ELF_PT_SHLIB, module_object, "PT_SHLIB");
  set_integer(ELF_PT_PHDR, module_object, "PT_PHDR");
  set_integer(ELF_PT_TLS, module_object, "PT_TLS");
  set_integer(ELF_PT_GNU_EH_FRAME, module_object, "PT_GNU_EH_FRAME");
  set_integer(ELF_PT_GNU_STACK, module_object, "PT_GNU_STACK");

  set_integer(ELF_DT_NULL, module_object, "DT_NULL");
  set_integer(ELF_DT_NEEDED, module_object, "DT_NEEDED");
  set_integer(ELF_DT_PLTRELSZ, module_object, "DT_PLTRELSZ");
  set_integer(ELF_DT_PLTGOT, module_object, "DT_PLTGOT");
  set_integer(ELF_DT_HASH, module_object, "DT_HASH");
  set_integer(ELF_DT_STRTAB, module_object, "DT_STRTAB");
  set_integer(ELF_DT_SYMTAB, module_object, "DT_SYMTAB");
  set_integer(ELF_DT_RELA, module_object, "DT_RELA");
  set_integer(ELF_DT_RELASZ, module_object, "DT_RELASZ");
  set_integer(ELF_DT_RELAENT, module_object, "DT_RELAENT");
  set_integer(ELF_DT_STRSZ, module_object, "DT_STRSZ");
  set_integer(ELF_DT_SYMENT, module_object, "DT_SYMENT");
  set_integer(ELF_DT_INIT, module_object, "DT_INIT");
  set_integer(ELF_DT_FINI, module_object, "DT_FINI");
  set_integer(ELF_DT_SONAME, module_object, "DT_SONAME");
  set_integer(ELF_DT_RPATH, module_object, "DT_RPATH");
  set_integer(ELF_DT_SYMBOLIC, module_object, "DT_SYMBOLIC");
  set_integer(ELF_DT_REL, module_object, "DT_REL");
  set_integer(ELF_DT_RELSZ, module_object, "DT_RELSZ");
  set_integer(ELF_DT_RELENT, module_object, "DT_RELENT");
  set_integer(ELF_DT_PLTREL, module_object, "DT_PLTREL");
  set_integer(ELF_DT_DEBUG, module_object, "DT_DEBUG");
  set_integer(ELF_DT_TEXTREL, module_object, "DT_TEXTREL");
  set_integer(ELF_DT_JMPREL, module_object, "DT_JMPREL");
  set_integer(ELF_DT_BIND_NOW, module_object, "DT_BIND_NOW");
  set_integer(ELF_DT_INIT_ARRAY, module_object, "DT_INIT_ARRAY");
  set_integer(ELF_DT_FINI_ARRAY, module_object, "DT_FINI_ARRAY");
  set_integer(ELF_DT_INIT_ARRAYSZ, module_object, "DT_INIT_ARRAYSZ");
  set_integer(ELF_DT_FINI_ARRAYSZ, module_object, "DT_FINI_ARRAYSZ");
  set_integer(ELF_DT_RUNPATH, module_object, "DT_RUNPATH");
  set_integer(ELF_DT_FLAGS, module_object, "DT_FLAGS");
  set_integer(ELF_DT_ENCODING, module_object, "DT_ENCODING");

  set_integer(ELF_STT_NOTYPE, module_object, "STT_NOTYPE");
  set_integer(ELF_STT_OBJECT, module_object, "STT_OBJECT");
  set_integer(ELF_STT_FUNC, module_object, "STT_FUNC");
  set_integer(ELF_STT_SECTION, module_object, "STT_SECTION");
  set_integer(ELF_STT_FILE, module_object, "STT_FILE");
  set_integer(ELF_STT_COMMON, module_object, "STT_COMMON");
  set_integer(ELF_STT_TLS, module_object, "STT_TLS");

  set_integer(ELF_STB_LOCAL, module_object, "STB_LOCAL");
  set_integer(ELF_STB_GLOBAL, module_object, "STB_GLOBAL");
  set_integer(ELF_STB_WEAK, module_object, "STB_WEAK");

  set_integer(ELF_PF_X, module_object, "PF_X");
  set_integer(ELF_PF_W, module_object, "PF_W");
  set_integer(ELF_PF_R, module_object, "PF_R");

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);

    if (block_data == NULL)
      continue;

    switch(get_elf_class_data(block_data, block->size))
    {
      case CLASS_DATA(ELF_CLASS_32, ELF_DATA_2LSB):

        if (block->size > sizeof(elf32_header_t))
        {
          elf_header32 = (elf32_header_t*) block_data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              yr_le16toh(elf_header32->type) == ELF_ET_EXEC)
          {
            parse_elf_header_32_le(
                elf_header32,
                block->base,
                block->size,
                context->flags,
                module_object);
          }
        }

        break;

      case CLASS_DATA(ELF_CLASS_32, ELF_DATA_2MSB):

        if (block->size > sizeof(elf32_header_t))
        {
          elf_header32 = (elf32_header_t*) block_data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              yr_be16toh(elf_header32->type) == ELF_ET_EXEC)
          {
            parse_elf_header_32_be(
                elf_header32,
                block->base,
                block->size,
                context->flags,
                module_object);
          }
        }

        break;

      case CLASS_DATA(ELF_CLASS_64,ELF_DATA_2LSB):

        if (block->size > sizeof(elf64_header_t))
        {
          elf_header64 = (elf64_header_t*) block_data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              yr_le16toh(elf_header64->type) == ELF_ET_EXEC)
          {
            parse_elf_header_64_le(
                elf_header64,
                block->base,
                block->size,
                context->flags,
                module_object);
          }
        }

        break;

      case CLASS_DATA(ELF_CLASS_64,ELF_DATA_2MSB):

        if (block->size > sizeof(elf64_header_t))
        {
          elf_header64 = (elf64_header_t*) block_data;

          if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
              yr_be16toh(elf_header64->type) == ELF_ET_EXEC)
          {
            parse_elf_header_64_be(
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
