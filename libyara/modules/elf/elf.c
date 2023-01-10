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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <tlshc/tlsh.h>
#include <yara/elf.h>
#include <yara/elf_utils.h>
#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/simple_str.h>
#include <yara/utils.h>
#include "../crypto.h"

#define MODULE_NAME elf

#define CLASS_DATA(c, d) ((c << 8) | d)

static int sort_strcmp(const void* a, const void* b)
{
  return strcmp(*(const char**) a, *(const char**) b);
}

define_function(telfhash)
{
  YR_OBJECT* obj = yr_module();
  ELF* elf = (ELF*) obj->data;
  if (elf == NULL)
    return_string(YR_UNDEFINED);

  if (elf->telfhash)
    return_string(elf->telfhash);

  /* We prefer dynsym if possible */
  ELF_SYMBOL_LIST* list = elf->dynsym ? elf->dynsym : elf->symtab;
  if (!list)
    return_string(YR_UNDEFINED);

  /* exclusions are based on the original implementation
     https://github.com/trendmicro/telfhash/blob/master/telfhash/telfhash.py */
  char* exclude_strings[] = {
      "__libc_start_main",
      "main",
      "abort",
      "cachectl",
      "cacheflush",
      "puts",
      "atol",
      "malloc_trim"};

  SIMPLE_STR* sstr = NULL;
  Tlsh* tlsh = NULL;

  int symbol_count = 0;
  char** clean_names = yr_calloc(list->count, sizeof(*clean_names));

  if (!clean_names)
    return_string(YR_UNDEFINED);

  for (ELF_SYMBOL* i = list->symbols; i != NULL; i = i->next)
  {
    char* name = i->name;

    if (!name)
      continue;

    /* Use only global code symbols */
    if (i->bind != ELF_STB_GLOBAL || i->type != ELF_STT_FUNC ||
        i->visibility != ELF_STV_DEFAULT)
      continue;

    /* ignore:
        x86-64 specific functions
        string functions (str.* and mem.*), gcc changes them depending on arch
        symbols starting with . or _ */
    bool is_bad_prefix = name[0] == '.' || name[0] == '_';
    size_t namelen = strlen(name);
    bool is_x86_64 = namelen >= 2 && strncmp(name + namelen - 2, "64", 2) == 0;
    bool is_mem_or_str = strncmp(name, "str", 3) == 0 ||
                         strncmp(name, "mem", 3) == 0;

    if (is_bad_prefix || is_x86_64 || is_mem_or_str)
      continue;

    /* Exclude any symbols that match the excluded ones */
    bool is_excluded = false;
    for (int i = 0; i < sizeof(exclude_strings) / sizeof(*exclude_strings); i++)
    {
      if (strcmp(name, exclude_strings[i]) == 0)
      {
        is_excluded = true;
        break;
      }
    }

    if (is_excluded)
      continue;

    clean_names[symbol_count] = yr_malloc(strlen(name) + 1);

    if (!clean_names[symbol_count])
      goto cleanup;

    /* Convert it to lowercase */
    int j;
    for (j = 0; name[j]; j++) clean_names[symbol_count][j] = tolower(name[j]);

    clean_names[symbol_count][j] = '\0';

    symbol_count++;
  }

  if (!symbol_count)
    goto cleanup;

  /* Now we have all the valid symbols, sort them, concat them */
  qsort(clean_names, symbol_count, sizeof(*clean_names), &sort_strcmp);

  sstr = sstr_newf("%s", clean_names[0]);
  if (!sstr)
    goto cleanup;

  /* We've already written first symbol, start at 1 */
  for (int i = 1; i < symbol_count; ++i)
  {
    if (!sstr_appendf(sstr, ",%s", clean_names[i]))
      goto cleanup;
  }

  tlsh = tlsh_new();
  if (!tlsh)
    goto cleanup;

  tlsh_final(tlsh, (const unsigned char*) sstr->str, sstr->len, 0);

  const char* telfhash = tlsh_get_hash(tlsh, true);
  elf->telfhash = yr_strdup(telfhash);  // cache it
  if (!elf->telfhash)
    goto cleanup;

  for (int i = 0; i < symbol_count; ++i) yr_free(clean_names[i]);
  yr_free(clean_names);
  sstr_free(sstr);
  tlsh_free(tlsh);

  return_string(elf->telfhash);

cleanup:
  for (int i = 0; i < symbol_count; ++i) yr_free(clean_names[i]);
  yr_free(clean_names);
  sstr_free(sstr);
  tlsh_free(tlsh);

  return_string(YR_UNDEFINED);
}

#if defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H) || \
    defined(HAVE_COMMONCRYPTO_COMMONCRYPTO_H)

define_function(import_md5)
{
  YR_OBJECT* obj = yr_module();
  ELF* elf = (ELF*) obj->data;
  if (elf == NULL)
    return_string(YR_UNDEFINED);

  if (elf->import_hash)
    return_string(elf->import_hash);

  ELF_SYMBOL_LIST* list = elf->dynsym ? elf->dynsym : elf->symtab;
  if (!list)
    return_string(YR_UNDEFINED);

  SIMPLE_STR* sstr = NULL;

  int symbol_count = 0;
  char** clean_names = yr_malloc(list->count * sizeof(*clean_names));
  if (!clean_names)
    return_string(YR_UNDEFINED);

  for (ELF_SYMBOL* i = list->symbols; i != NULL; i = i->next)
  {
    char* name = i->name;

    if (!name)
      continue;

    if (i->shndx != ELF_SHN_UNDEF)
      continue;

    // skip empty names
    if (strlen(i->name) == 0)
      continue;

    clean_names[symbol_count] = yr_malloc(strlen(name) + 1);
    if (!clean_names[symbol_count])
      goto cleanup;

    /* Convert it to lowercase */
    int j;
    for (j = 0; name[j]; j++) clean_names[symbol_count][j] = tolower(name[j]);

    clean_names[symbol_count][j] = '\0';

    symbol_count++;
  }

  if (!symbol_count)
    goto cleanup;

  /* Now we have all the valid symbols, sort them, concat them */
  qsort(clean_names, symbol_count, sizeof(*clean_names), &sort_strcmp);

  sstr = sstr_newf("%s", clean_names[0]);
  if (!sstr)
    goto cleanup;

  /* We've already written first symbol, start at 1 */
  for (int i = 1; i < symbol_count; ++i)
  {
    if (!sstr_appendf(sstr, ",%s", clean_names[i]))
      goto cleanup;
  }

  unsigned char hash[YR_MD5_LEN];

  yr_md5_ctx ctx;
  yr_md5_init(&ctx);
  yr_md5_update(&ctx, sstr->str, sstr->len);
  yr_md5_final(hash, &ctx);

  elf->import_hash = yr_malloc(YR_MD5_LEN * 2 + 1);
  if (!elf->import_hash)
    goto cleanup;

  for (int i = 0; i < YR_MD5_LEN; ++i)
    sprintf(elf->import_hash + (i * 2), "%02x", hash[i]);

  for (int i = 0; i < symbol_count; ++i) yr_free(clean_names[i]);
  yr_free(clean_names);
  sstr_free(sstr);

  return_string(elf->import_hash);

cleanup:
  for (int i = 0; i < symbol_count; ++i) yr_free(clean_names[i]);
  yr_free(clean_names);
  sstr_free(sstr);

  return_string(YR_UNDEFINED);
}

#endif  // defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H)

int get_elf_class_data(const uint8_t* buffer, size_t buffer_length)
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

//
// Returns a string table entry for the index or NULL if the entry is out
// of bounds. A non-null return value will be a null-terminated C string.
//
static const char* str_table_entry(
    const char* str_table_base,
    const char* str_table_limit,
    int index)
{
  size_t len;
  const char* str_entry;

  if (str_table_base >= str_table_limit)
    return NULL;

  // The first entry in the string table must be a null character, if not the
  // string table is probably corrupted.
  if (*str_table_base != '\0')
    return NULL;

  if (index < 0)
    return NULL;

  str_entry = str_table_base + index;

  if (str_entry >= str_table_limit)
    return NULL;

  len = strnlen(str_entry, str_table_limit - str_entry);

  // Entry is clamped by extent of string table, not null-terminated.
  if (str_entry + len == str_table_limit)
    return NULL;

  return str_entry;
}

#define ELF_SIZE_OF_SECTION_TABLE(bits, bo, h) \
  (sizeof(elf##bits##_section_header_t) * yr_##bo##16toh(h->sh_entry_count))

#define ELF_SIZE_OF_PROGRAM_TABLE(bits, bo, h) \
  (sizeof(elf##bits##_program_header_t) * yr_##bo##16toh(h->ph_entry_count))

#define ELF_RVA_TO_OFFSET(bits, bo)                                                \
  uint64_t elf_rva_to_offset_##bits##_##bo(                                        \
      elf##bits##_header_t* elf_header, uint64_t rva, size_t elf_size)             \
  {                                                                                \
    if (yr_##bo##16toh(elf_header->type) == ELF_ET_EXEC)                           \
    {                                                                              \
      int i;                                                                       \
                                                                                   \
      elf##bits##_program_header_t* program;                                       \
                                                                                   \
      /* check that ph_offset doesn't wrap when added to SIZE_OF_PROGRAM_TABLE     \
       */                                                                          \
                                                                                   \
      if (ULONG_MAX - yr_##bo##bits##toh(elf_header->ph_offset) <                  \
          ELF_SIZE_OF_PROGRAM_TABLE(bits, bo, elf_header))                         \
      {                                                                            \
        return YR_UNDEFINED;                                                       \
      }                                                                            \
                                                                                   \
      if (yr_##bo##bits##toh(elf_header->ph_offset) == 0 ||                        \
          yr_##bo##bits##toh(elf_header->ph_offset) > elf_size ||                  \
          yr_##bo##bits##toh(elf_header->ph_offset) +                              \
                  ELF_SIZE_OF_PROGRAM_TABLE(bits, bo, elf_header) >                \
              elf_size ||                                                          \
          yr_##bo##16toh(elf_header->ph_entry_count) == 0)                         \
      {                                                                            \
        return YR_UNDEFINED;                                                       \
      }                                                                            \
                                                                                   \
      program = (elf##bits##_program_header_t*)                                  \
        ((uint8_t*) elf_header + yr_##bo##bits##toh(elf_header->ph_offset)); \
                                                                                   \
      for (i = 0; i < yr_##bo##16toh(elf_header->ph_entry_count); i++)             \
      {                                                                            \
        if (rva >= yr_##bo##bits##toh(program->virt_addr) &&                       \
            rva < yr_##bo##bits##toh(program->virt_addr) +                         \
                      yr_##bo##bits##toh(program->mem_size))                       \
        {                                                                          \
          return yr_##bo##bits##toh(program->offset) +                             \
                 (rva - yr_##bo##bits##toh(program->virt_addr));                   \
        }                                                                          \
                                                                                   \
        program++;                                                                 \
      }                                                                            \
    }                                                                              \
    else                                                                           \
    {                                                                              \
      int i;                                                                       \
                                                                                   \
      elf##bits##_section_header_t* section;                                       \
                                                                                   \
      /* check that sh_offset doesn't wrap when added to SIZE_OF_SECTION_TABLE     \
       */                                                                          \
                                                                                   \
      if (ULONG_MAX - yr_##bo##bits##toh(elf_header->sh_offset) <                  \
          ELF_SIZE_OF_SECTION_TABLE(bits, bo, elf_header))                         \
      {                                                                            \
        return YR_UNDEFINED;                                                       \
      }                                                                            \
                                                                                   \
      if (yr_##bo##bits##toh(elf_header->sh_offset) == 0 ||                        \
          yr_##bo##bits##toh(elf_header->sh_offset) > elf_size ||                  \
          yr_##bo##bits##toh(elf_header->sh_offset) +                              \
                  ELF_SIZE_OF_SECTION_TABLE(bits, bo, elf_header) >                \
              elf_size ||                                                          \
          yr_##bo##16toh(elf_header->sh_entry_count) == 0)                         \
      {                                                                            \
        return YR_UNDEFINED;                                                       \
      }                                                                            \
                                                                                   \
      section = (elf##bits##_section_header_t*)                                  \
        ((uint8_t*) elf_header + yr_##bo##bits##toh(elf_header->sh_offset)); \
                                                                                   \
      for (i = 0; i < yr_##bo##16toh(elf_header->sh_entry_count); i++)             \
      {                                                                            \
        if (yr_##bo##32toh(section->type) != ELF_SHT_NULL &&                       \
            yr_##bo##32toh(section->type) != ELF_SHT_NOBITS &&                     \
            rva >= yr_##bo##bits##toh(section->addr) &&                            \
            rva < yr_##bo##bits##toh(section->addr) +                              \
                      yr_##bo##bits##toh(section->size))                           \
        {                                                                          \
          return yr_##bo##bits##toh(section->offset) +                             \
                 (rva - yr_##bo##bits##toh(section->addr));                        \
        }                                                                          \
                                                                                   \
        section++;                                                                 \
      }                                                                            \
    }                                                                              \
    return YR_UNDEFINED;                                                           \
  }

#define PARSE_ELF_HEADER(bits, bo)                                                        \
  int parse_elf_header_##bits##_##bo(                                                     \
      ELF* elf_data,                                                                      \
      elf##bits##_header_t* elf,                                                          \
      uint64_t base_address,                                                              \
      size_t elf_size,                                                                    \
      int flags,                                                                          \
      YR_OBJECT* elf_obj)                                                                 \
  {                                                                                       \
    unsigned int i, j, m;                                                                 \
    const char* elf_raw = (const char*) elf;                                              \
    uint16_t str_table_index = yr_##bo##16toh(elf->sh_str_table_index);                   \
                                                                                          \
    const char* sym_table = NULL;                                                         \
    const char* sym_str_table = NULL;                                                     \
    const char* dyn_sym_table = NULL;                                                     \
    const char* dyn_sym_str_table = NULL;                                                 \
                                                                                          \
    uint##bits##_t sym_table_size = 0;                                                    \
    uint##bits##_t sym_str_table_size = 0;                                                \
    uint##bits##_t dyn_sym_table_size = 0;                                                \
    uint##bits##_t dyn_sym_str_table_size = 0;                                            \
                                                                                          \
    elf_data->symtab = elf_data->dynsym = NULL;                                           \
                                                                                          \
    elf##bits##_section_header_t* section_table;                                          \
    elf##bits##_section_header_t* section;                                                \
    elf##bits##_program_header_t* segment;                                                \
                                                                                          \
    yr_set_integer(yr_##bo##16toh(elf->type), elf_obj, "type");                              \
    yr_set_integer(yr_##bo##16toh(elf->machine), elf_obj, "machine");                        \
    yr_set_integer(yr_##bo##bits##toh(elf->sh_offset), elf_obj, "sh_offset");                \
    yr_set_integer(yr_##bo##16toh(elf->sh_entry_size), elf_obj, "sh_entry_size");            \
    yr_set_integer(                                                                          \
        yr_##bo##16toh(elf->sh_entry_count), elf_obj, "number_of_sections");              \
    yr_set_integer(yr_##bo##bits##toh(elf->ph_offset), elf_obj, "ph_offset");                \
    yr_set_integer(yr_##bo##16toh(elf->ph_entry_size), elf_obj, "ph_entry_size");            \
    yr_set_integer(                                                                          \
        yr_##bo##16toh(elf->ph_entry_count), elf_obj, "number_of_segments");              \
                                                                                          \
    if (yr_##bo##bits##toh(elf->entry) != 0)                                              \
    {                                                                                     \
      yr_set_integer(                                                                        \
          flags& SCAN_FLAGS_PROCESS_MEMORY                                                \
              ? base_address + yr_##bo##bits##toh(elf->entry)                             \
              : elf_rva_to_offset_##bits##_##bo(                                          \
                    elf, yr_##bo##bits##toh(elf->entry), elf_size),                       \
          elf_obj,                                                                        \
          "entry_point");                                                                 \
    }                                                                                     \
                                                                                          \
    if (yr_##bo##16toh(elf->sh_entry_count) < ELF_SHN_LORESERVE &&                        \
        str_table_index < yr_##bo##16toh(elf->sh_entry_count) &&                          \
        yr_##bo##bits##toh(elf->sh_offset) < elf_size &&                                  \
        yr_##bo##bits##toh(elf->sh_offset) +                                              \
                yr_##bo##16toh(elf->sh_entry_count) *                                     \
                    sizeof(elf##bits##_section_header_t) <=                               \
            elf_size)                                                                     \
    {                                                                                     \
      const char* str_table = NULL;                                                       \
                                                                                          \
      section_table =                                                                     \
          (elf##bits##_section_header_t*) (elf_raw + yr_##bo##bits##toh(elf->sh_offset)); \
                                                                                          \
      if (yr_##bo##bits##toh(section_table[str_table_index].offset) <                     \
          elf_size)                                                                       \
      {                                                                                   \
        str_table = elf_raw +                                                             \
                    yr_##bo##bits##toh(section_table[str_table_index].offset);            \
      }                                                                                   \
                                                                                          \
      section = section_table;                                                            \
                                                                                          \
      for (i = 0; i < yr_##bo##16toh(elf->sh_entry_count); i++, section++)                \
      {                                                                                   \
        yr_set_integer(                                                                      \
            yr_##bo##32toh(section->type), elf_obj, "sections[%i].type", i);              \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(section->flags),                                           \
            elf_obj,                                                                      \
            "sections[%i].flags",                                                         \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(section->addr),                                            \
            elf_obj,                                                                      \
            "sections[%i].address",                                                       \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(section->size),                                            \
            elf_obj,                                                                      \
            "sections[%i].size",                                                          \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(section->offset),                                          \
            elf_obj,                                                                      \
            "sections[%i].offset",                                                        \
            i);                                                                           \
                                                                                          \
        if (yr_##bo##32toh(section->name) < elf_size && str_table > elf_raw)              \
        {                                                                                 \
          const char* section_name = str_table_entry(                                     \
              str_table, elf_raw + elf_size, yr_##bo##32toh(section->name));              \
                                                                                          \
          if (section_name)                                                               \
            yr_set_string(section_name, elf_obj, "sections[%i].name", i);                    \
        }                                                                                 \
                                                                                          \
        if (yr_##bo##32toh(section->type) == ELF_SHT_SYMTAB &&                            \
            yr_##bo##32toh(section->link) < elf->sh_entry_count)                          \
        {                                                                                 \
          elf##bits##_section_header_t* string_section = section_table +                  \
                                                         yr_##bo##32toh(                  \
                                                             section->link);              \
                                                                                          \
          if (IS_VALID_PTR(elf, elf_size, string_section) &&                              \
              yr_##bo##32toh(string_section->type) == ELF_SHT_STRTAB)                     \
          {                                                                               \
            sym_table = elf_raw + yr_##bo##bits##toh(section->offset);                    \
            sym_str_table = elf_raw +                                                     \
                            yr_##bo##bits##toh(string_section->offset);                   \
            sym_table_size = yr_##bo##bits##toh(section->size);                           \
            sym_str_table_size = yr_##bo##bits##toh(string_section->size);                \
          }                                                                               \
        }                                                                                 \
                                                                                          \
        if (yr_##bo##32toh(section->type) == ELF_SHT_DYNSYM &&                            \
            yr_##bo##32toh(section->link) < elf->sh_entry_count)                          \
        {                                                                                 \
          elf##bits##_section_header_t* dynstr_section = section_table +                  \
                                                         yr_##bo##32toh(                  \
                                                             section->link);              \
                                                                                          \
          if (IS_VALID_PTR(elf, elf_size, dynstr_section) &&                              \
              yr_##bo##32toh(dynstr_section->type) == ELF_SHT_STRTAB)                     \
          {                                                                               \
            dyn_sym_table = elf_raw + yr_##bo##bits##toh(section->offset);                \
            dyn_sym_str_table = elf_raw +                                                 \
                                yr_##bo##bits##toh(dynstr_section->offset);               \
            dyn_sym_table_size = yr_##bo##bits##toh(section->size);                       \
            dyn_sym_str_table_size = yr_##bo##bits##toh(dynstr_section->size);            \
          }                                                                               \
        }                                                                                 \
      }                                                                                   \
                                                                                          \
      if (is_valid_ptr(elf, elf_size, sym_str_table, sym_str_table_size) &&               \
          is_valid_ptr(elf, elf_size, sym_table, sym_table_size))                         \
      {                                                                                   \
        elf##bits##_sym_t* sym = (elf##bits##_sym_t*) sym_table;                          \
        elf_data->symtab = (ELF_SYMBOL_LIST*) yr_malloc(                                  \
            sizeof(ELF_SYMBOL_LIST));                                                     \
                                                                                          \
        if (elf_data->symtab == NULL)                                                     \
          return ERROR_INSUFFICIENT_MEMORY;                                               \
                                                                                          \
        ELF_SYMBOL** symbol = &(elf_data->symtab->symbols);                               \
        *symbol = NULL;                                                                   \
                                                                                          \
        for (j = 0; j < sym_table_size / sizeof(elf##bits##_sym_t);                       \
             j++, sym++)                                                                  \
        {                                                                                 \
          *symbol = (ELF_SYMBOL*) yr_malloc(sizeof(ELF_SYMBOL));                          \
          if (*symbol == NULL)                                                            \
            return ERROR_INSUFFICIENT_MEMORY;                                             \
                                                                                          \
          (*symbol)->name = NULL;                                                         \
          (*symbol)->next = NULL;                                                         \
                                                                                          \
          const char* sym_name = str_table_entry(                                         \
              sym_str_table,                                                              \
              sym_str_table + sym_str_table_size,                                         \
              yr_##bo##32toh(sym->name));                                                 \
                                                                                          \
          if (sym_name)                                                                   \
          {                                                                               \
            yr_set_string(sym_name, elf_obj, "symtab[%i].name", j);                          \
            (*symbol)->name = (char*) yr_malloc(strlen(sym_name) + 1);                    \
            if ((*symbol)->name == NULL)                                                  \
              return ERROR_INSUFFICIENT_MEMORY;                                           \
                                                                                          \
            strcpy((*symbol)->name, sym_name);                                            \
          }                                                                               \
                                                                                          \
          int bind = sym->info >> 4;                                                      \
          (*symbol)->bind = bind;                                                         \
          yr_set_integer(bind, elf_obj, "symtab[%i].bind", j);                               \
                                                                                          \
          int type = sym->info & 0xf;                                                     \
          (*symbol)->type = type;                                                         \
          yr_set_integer(type, elf_obj, "symtab[%i].type", j);                               \
                                                                                          \
          int shndx = yr_##bo##16toh(sym->shndx);                                         \
          (*symbol)->shndx = shndx;                                                       \
          yr_set_integer(shndx, elf_obj, "symtab[%i].shndx", j);                             \
                                                                                          \
          int value = yr_##bo##bits##toh(sym->value);                                     \
          (*symbol)->value = value;                                                       \
          yr_set_integer(                                                                    \
              yr_##bo##bits##toh(sym->value), elf_obj, "symtab[%i].value", j);            \
                                                                                          \
          int size = yr_##bo##bits##toh(sym->size);                                       \
          (*symbol)->size = size;                                                         \
          yr_set_integer(                                                                    \
              yr_##bo##bits##toh(sym->size), elf_obj, "symtab[%i].size", j);              \
                                                                                          \
          int other = yr_##bo##bits##toh(sym->other);                                     \
          (*symbol)->visibility = other & 0x3;                                            \
                                                                                          \
          symbol = &((*symbol)->next);                                                    \
        }                                                                                 \
                                                                                          \
        elf_data->symtab->count = j;                                                      \
        yr_set_integer(j, elf_obj, "symtab_entries");                                        \
      }                                                                                   \
                                                                                          \
      if (is_valid_ptr(                                                                   \
              elf, elf_size, dyn_sym_str_table, dyn_sym_str_table_size) &&                \
          is_valid_ptr(elf, elf_size, dyn_sym_table, dyn_sym_table_size))                 \
      {                                                                                   \
        elf##bits##_sym_t* dynsym = (elf##bits##_sym_t*) dyn_sym_table;                   \
                                                                                          \
        elf_data->dynsym = (ELF_SYMBOL_LIST*) yr_malloc(                                  \
            sizeof(ELF_SYMBOL_LIST));                                                     \
                                                                                          \
        if (elf_data->dynsym == NULL)                                                     \
          return ERROR_INSUFFICIENT_MEMORY;                                               \
                                                                                          \
        ELF_SYMBOL** symbol = &(elf_data->dynsym->symbols);                               \
        *symbol = NULL;                                                                   \
                                                                                          \
        for (m = 0; m < dyn_sym_table_size / sizeof(elf##bits##_sym_t);                   \
             m++, dynsym++)                                                               \
        {                                                                                 \
          *symbol = (ELF_SYMBOL*) yr_malloc(sizeof(ELF_SYMBOL));                          \
          if (*symbol == NULL)                                                            \
            return ERROR_INSUFFICIENT_MEMORY;                                             \
                                                                                          \
          (*symbol)->name = NULL;                                                         \
          (*symbol)->next = NULL;                                                         \
                                                                                          \
          const char* dynsym_name = str_table_entry(                                      \
              dyn_sym_str_table,                                                          \
              dyn_sym_str_table + dyn_sym_str_table_size,                                 \
              yr_##bo##32toh(dynsym->name));                                              \
                                                                                          \
          if (dynsym_name)                                                                \
          {                                                                               \
            yr_set_string(dynsym_name, elf_obj, "dynsym[%i].name", m);                       \
            (*symbol)->name = (char*) yr_malloc(strlen(dynsym_name) + 1);                 \
            if ((*symbol)->name == NULL)                                                  \
              return ERROR_INSUFFICIENT_MEMORY;                                           \
                                                                                          \
            strcpy((*symbol)->name, dynsym_name);                                         \
          }                                                                               \
                                                                                          \
          int bind = dynsym->info >> 4;                                                   \
          (*symbol)->bind = bind;                                                         \
          yr_set_integer(dynsym->info >> 4, elf_obj, "dynsym[%i].bind", m);                  \
                                                                                          \
          int type = dynsym->info & 0xf;                                                  \
          (*symbol)->type = type;                                                         \
          yr_set_integer(dynsym->info & 0xf, elf_obj, "dynsym[%i].type", m);                 \
                                                                                          \
          int shndx = yr_##bo##16toh(dynsym->shndx);                                      \
          (*symbol)->shndx = shndx;                                                       \
          yr_set_integer(                                                                    \
              yr_##bo##16toh(dynsym->shndx), elf_obj, "dynsym[%i].shndx", m);             \
                                                                                          \
          int value = yr_##bo##bits##toh(dynsym->value);                                  \
          (*symbol)->value = value;                                                       \
          yr_set_integer(                                                                    \
              yr_##bo##bits##toh(dynsym->value),                                          \
              elf_obj,                                                                    \
              "dynsym[%i].value",                                                         \
              m);                                                                         \
                                                                                          \
          int size = yr_##bo##bits##toh(dynsym->size);                                    \
          (*symbol)->size = size;                                                         \
          yr_set_integer(                                                                    \
              yr_##bo##bits##toh(dynsym->size),                                           \
              elf_obj,                                                                    \
              "dynsym[%i].size",                                                          \
              m);                                                                         \
                                                                                          \
          int other = yr_##bo##bits##toh(dynsym->other);                                  \
          (*symbol)->visibility = other & 0x3;                                            \
                                                                                          \
          symbol = &((*symbol)->next);                                                    \
        }                                                                                 \
                                                                                          \
        elf_data->dynsym->count = m;                                                      \
        yr_set_integer(m, elf_obj, "dynsym_entries");                                        \
      }                                                                                   \
    }                                                                                     \
                                                                                          \
    if (yr_##bo##16toh(elf->ph_entry_count) > 0 &&                                        \
        yr_##bo##16toh(elf->ph_entry_count) < ELF_PN_XNUM &&                              \
        yr_##bo##bits##toh(elf->ph_offset) < elf_size &&                                  \
        yr_##bo##bits##toh(elf->ph_offset) +                                              \
                yr_##bo##16toh(elf->ph_entry_count) *                                     \
                    sizeof(elf##bits##_program_header_t) <=                               \
            elf_size)                                                                     \
    {                                                                                     \
      segment =                                                                           \
          (elf##bits##_program_header_t*) (elf_raw + yr_##bo##bits##toh(elf->ph_offset)); \
                                                                                          \
      for (i = 0; i < yr_##bo##16toh(elf->ph_entry_count); i++, segment++)                \
      {                                                                                   \
        yr_set_integer(                                                                      \
            yr_##bo##32toh(segment->type), elf_obj, "segments[%i].type", i);              \
        yr_set_integer(                                                                      \
            yr_##bo##32toh(segment->flags), elf_obj, "segments[%i].flags", i);            \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->offset),                                          \
            elf_obj,                                                                      \
            "segments[%i].offset",                                                        \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->virt_addr),                                       \
            elf_obj,                                                                      \
            "segments[%i].virtual_address",                                               \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->phys_addr),                                       \
            elf_obj,                                                                      \
            "segments[%i].physical_address",                                              \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->file_size),                                       \
            elf_obj,                                                                      \
            "segments[%i].file_size",                                                     \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->mem_size),                                        \
            elf_obj,                                                                      \
            "segments[%i].memory_size",                                                   \
            i);                                                                           \
        yr_set_integer(                                                                      \
            yr_##bo##bits##toh(segment->alignment),                                       \
            elf_obj,                                                                      \
            "segments[%i].alignment",                                                     \
            i);                                                                           \
                                                                                          \
        if (yr_##bo##32toh(segment->type) == ELF_PT_DYNAMIC)                              \
        {                                                                                 \
          elf##bits##_dyn_t* dyn =                                                        \
              (elf##bits##_dyn_t*) (elf_raw + yr_##bo##bits##toh(segment->offset));       \
                                                                                          \
          for (j = 0; IS_VALID_PTR(elf, elf_size, dyn); dyn++, j++)                       \
          {                                                                               \
            yr_set_integer(                                                                  \
                yr_##bo##bits##toh(dyn->tag), elf_obj, "dynamic[%i].type", j);            \
            yr_set_integer(                                                                  \
                yr_##bo##bits##toh(dyn->val), elf_obj, "dynamic[%i].val", j);             \
                                                                                          \
            if (dyn->tag == ELF_DT_NULL)                                                  \
            {                                                                             \
              j++;                                                                        \
              break;                                                                      \
            }                                                                             \
          }                                                                               \
          yr_set_integer(j, elf_obj, "dynamic_section_entries");                             \
        }                                                                                 \
      }                                                                                   \
    }                                                                                     \
    return ERROR_SUCCESS;                                                                 \
  }

ELF_RVA_TO_OFFSET(32, le);
ELF_RVA_TO_OFFSET(64, le);
ELF_RVA_TO_OFFSET(32, be);
ELF_RVA_TO_OFFSET(64, be);

PARSE_ELF_HEADER(32, le);
PARSE_ELF_HEADER(64, le);
PARSE_ELF_HEADER(32, be);
PARSE_ELF_HEADER(64, be);

begin_declarations
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

  begin_struct_array("sections")
    declare_integer("type");
    declare_integer("flags");
    declare_integer("address");
    declare_string("name");
    declare_integer("size");
    declare_integer("offset");
  end_struct_array("sections")

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

  begin_struct_array("segments")
    declare_integer("type");
    declare_integer("flags");
    declare_integer("offset");
    declare_integer("virtual_address");
    declare_integer("physical_address");
    declare_integer("file_size");
    declare_integer("memory_size");
    declare_integer("alignment");
  end_struct_array("segments")

  declare_integer("dynamic_section_entries");
  begin_struct_array("dynamic")
    declare_integer("type");
    declare_integer("val");
  end_struct_array("dynamic")

  declare_integer("symtab_entries");
  begin_struct_array("symtab")
    declare_string("name");
    declare_integer("value");
    declare_integer("size");
    declare_integer("type");
    declare_integer("bind");
    declare_integer("shndx");
  end_struct_array("symtab")

  declare_integer("dynsym_entries");
  begin_struct_array("dynsym")
    declare_string("name");
    declare_integer("value");
    declare_integer("size");
    declare_integer("type");
    declare_integer("bind");
    declare_integer("shndx");
  end_struct_array("dynsym")

  declare_function("telfhash", "", "s", telfhash);

#if defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H) || \
    defined(HAVE_COMMONCRYPTO_COMMONCRYPTO_H)
  declare_function("import_md5", "", "s", import_md5);
#endif  // defined(HAVE_LIBCRYPTO) || defined(HAVE_WINCRYPT_H)

end_declarations

int module_initialize(YR_MODULE* module)
{
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

  elf32_header_t* elf_header32;
  elf64_header_t* elf_header64;

  yr_set_integer(ELF_ET_NONE, module_object, "ET_NONE");
  yr_set_integer(ELF_ET_REL, module_object, "ET_REL");
  yr_set_integer(ELF_ET_EXEC, module_object, "ET_EXEC");
  yr_set_integer(ELF_ET_DYN, module_object, "ET_DYN");
  yr_set_integer(ELF_ET_CORE, module_object, "ET_CORE");

  yr_set_integer(ELF_EM_NONE, module_object, "EM_NONE");
  yr_set_integer(ELF_EM_M32, module_object, "EM_M32");
  yr_set_integer(ELF_EM_SPARC, module_object, "EM_SPARC");
  yr_set_integer(ELF_EM_386, module_object, "EM_386");
  yr_set_integer(ELF_EM_68K, module_object, "EM_68K");
  yr_set_integer(ELF_EM_88K, module_object, "EM_88K");
  yr_set_integer(ELF_EM_860, module_object, "EM_860");
  yr_set_integer(ELF_EM_MIPS, module_object, "EM_MIPS");
  yr_set_integer(ELF_EM_MIPS_RS3_LE, module_object, "EM_MIPS_RS3_LE");
  yr_set_integer(ELF_EM_PPC, module_object, "EM_PPC");
  yr_set_integer(ELF_EM_PPC64, module_object, "EM_PPC64");
  yr_set_integer(ELF_EM_ARM, module_object, "EM_ARM");
  yr_set_integer(ELF_EM_X86_64, module_object, "EM_X86_64");
  yr_set_integer(ELF_EM_AARCH64, module_object, "EM_AARCH64");

  yr_set_integer(ELF_SHT_NULL, module_object, "SHT_NULL");
  yr_set_integer(ELF_SHT_PROGBITS, module_object, "SHT_PROGBITS");
  yr_set_integer(ELF_SHT_SYMTAB, module_object, "SHT_SYMTAB");
  yr_set_integer(ELF_SHT_STRTAB, module_object, "SHT_STRTAB");
  yr_set_integer(ELF_SHT_RELA, module_object, "SHT_RELA");
  yr_set_integer(ELF_SHT_HASH, module_object, "SHT_HASH");
  yr_set_integer(ELF_SHT_DYNAMIC, module_object, "SHT_DYNAMIC");
  yr_set_integer(ELF_SHT_NOTE, module_object, "SHT_NOTE");
  yr_set_integer(ELF_SHT_NOBITS, module_object, "SHT_NOBITS");
  yr_set_integer(ELF_SHT_REL, module_object, "SHT_REL");
  yr_set_integer(ELF_SHT_SHLIB, module_object, "SHT_SHLIB");
  yr_set_integer(ELF_SHT_DYNSYM, module_object, "SHT_DYNSYM");

  yr_set_integer(ELF_SHF_WRITE, module_object, "SHF_WRITE");
  yr_set_integer(ELF_SHF_ALLOC, module_object, "SHF_ALLOC");
  yr_set_integer(ELF_SHF_EXECINSTR, module_object, "SHF_EXECINSTR");

  yr_set_integer(ELF_PT_NULL, module_object, "PT_NULL");
  yr_set_integer(ELF_PT_LOAD, module_object, "PT_LOAD");
  yr_set_integer(ELF_PT_DYNAMIC, module_object, "PT_DYNAMIC");
  yr_set_integer(ELF_PT_INTERP, module_object, "PT_INTERP");
  yr_set_integer(ELF_PT_NOTE, module_object, "PT_NOTE");
  yr_set_integer(ELF_PT_SHLIB, module_object, "PT_SHLIB");
  yr_set_integer(ELF_PT_PHDR, module_object, "PT_PHDR");
  yr_set_integer(ELF_PT_TLS, module_object, "PT_TLS");
  yr_set_integer(ELF_PT_GNU_EH_FRAME, module_object, "PT_GNU_EH_FRAME");
  yr_set_integer(ELF_PT_GNU_STACK, module_object, "PT_GNU_STACK");

  yr_set_integer(ELF_DT_NULL, module_object, "DT_NULL");
  yr_set_integer(ELF_DT_NEEDED, module_object, "DT_NEEDED");
  yr_set_integer(ELF_DT_PLTRELSZ, module_object, "DT_PLTRELSZ");
  yr_set_integer(ELF_DT_PLTGOT, module_object, "DT_PLTGOT");
  yr_set_integer(ELF_DT_HASH, module_object, "DT_HASH");
  yr_set_integer(ELF_DT_STRTAB, module_object, "DT_STRTAB");
  yr_set_integer(ELF_DT_SYMTAB, module_object, "DT_SYMTAB");
  yr_set_integer(ELF_DT_RELA, module_object, "DT_RELA");
  yr_set_integer(ELF_DT_RELASZ, module_object, "DT_RELASZ");
  yr_set_integer(ELF_DT_RELAENT, module_object, "DT_RELAENT");
  yr_set_integer(ELF_DT_STRSZ, module_object, "DT_STRSZ");
  yr_set_integer(ELF_DT_SYMENT, module_object, "DT_SYMENT");
  yr_set_integer(ELF_DT_INIT, module_object, "DT_INIT");
  yr_set_integer(ELF_DT_FINI, module_object, "DT_FINI");
  yr_set_integer(ELF_DT_SONAME, module_object, "DT_SONAME");
  yr_set_integer(ELF_DT_RPATH, module_object, "DT_RPATH");
  yr_set_integer(ELF_DT_SYMBOLIC, module_object, "DT_SYMBOLIC");
  yr_set_integer(ELF_DT_REL, module_object, "DT_REL");
  yr_set_integer(ELF_DT_RELSZ, module_object, "DT_RELSZ");
  yr_set_integer(ELF_DT_RELENT, module_object, "DT_RELENT");
  yr_set_integer(ELF_DT_PLTREL, module_object, "DT_PLTREL");
  yr_set_integer(ELF_DT_DEBUG, module_object, "DT_DEBUG");
  yr_set_integer(ELF_DT_TEXTREL, module_object, "DT_TEXTREL");
  yr_set_integer(ELF_DT_JMPREL, module_object, "DT_JMPREL");
  yr_set_integer(ELF_DT_BIND_NOW, module_object, "DT_BIND_NOW");
  yr_set_integer(ELF_DT_INIT_ARRAY, module_object, "DT_INIT_ARRAY");
  yr_set_integer(ELF_DT_FINI_ARRAY, module_object, "DT_FINI_ARRAY");
  yr_set_integer(ELF_DT_INIT_ARRAYSZ, module_object, "DT_INIT_ARRAYSZ");
  yr_set_integer(ELF_DT_FINI_ARRAYSZ, module_object, "DT_FINI_ARRAYSZ");
  yr_set_integer(ELF_DT_RUNPATH, module_object, "DT_RUNPATH");
  yr_set_integer(ELF_DT_FLAGS, module_object, "DT_FLAGS");
  yr_set_integer(ELF_DT_ENCODING, module_object, "DT_ENCODING");

  yr_set_integer(ELF_STT_NOTYPE, module_object, "STT_NOTYPE");
  yr_set_integer(ELF_STT_OBJECT, module_object, "STT_OBJECT");
  yr_set_integer(ELF_STT_FUNC, module_object, "STT_FUNC");
  yr_set_integer(ELF_STT_SECTION, module_object, "STT_SECTION");
  yr_set_integer(ELF_STT_FILE, module_object, "STT_FILE");
  yr_set_integer(ELF_STT_COMMON, module_object, "STT_COMMON");
  yr_set_integer(ELF_STT_TLS, module_object, "STT_TLS");

  yr_set_integer(ELF_STB_LOCAL, module_object, "STB_LOCAL");
  yr_set_integer(ELF_STB_GLOBAL, module_object, "STB_GLOBAL");
  yr_set_integer(ELF_STB_WEAK, module_object, "STB_WEAK");

  yr_set_integer(ELF_PF_X, module_object, "PF_X");
  yr_set_integer(ELF_PF_W, module_object, "PF_W");
  yr_set_integer(ELF_PF_R, module_object, "PF_R");

  uint64_t parse_result = ERROR_SUCCESS;

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);

    if (block_data == NULL)
      continue;

    ELF* elf = (ELF*) yr_calloc(1, sizeof(ELF));
    if (elf == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    module_object->data = elf;
    switch (get_elf_class_data(block_data, block->size))
    {
    case CLASS_DATA(ELF_CLASS_32, ELF_DATA_2LSB):

      if (block->size > sizeof(elf32_header_t))
      {
        elf_header32 = (elf32_header_t*) block_data;

        if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
            yr_le16toh(elf_header32->type) == ELF_ET_EXEC)
        {
          parse_result = parse_elf_header_32_le(
              elf,
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
          parse_result = parse_elf_header_32_be(
              elf,
              elf_header32,
              block->base,
              block->size,
              context->flags,
              module_object);
        }
      }

      break;

    case CLASS_DATA(ELF_CLASS_64, ELF_DATA_2LSB):

      if (block->size > sizeof(elf64_header_t))
      {
        elf_header64 = (elf64_header_t*) block_data;

        if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
            yr_le16toh(elf_header64->type) == ELF_ET_EXEC)
        {
          parse_result = parse_elf_header_64_le(
              elf,
              elf_header64,
              block->base,
              block->size,
              context->flags,
              module_object);
        }
      }

      break;

    case CLASS_DATA(ELF_CLASS_64, ELF_DATA_2MSB):

      if (block->size > sizeof(elf64_header_t))
      {
        elf_header64 = (elf64_header_t*) block_data;

        if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
            yr_be16toh(elf_header64->type) == ELF_ET_EXEC)
        {
          parse_result = parse_elf_header_64_be(
              elf,
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

  return parse_result;
}

int module_unload(YR_OBJECT* module_object)
{
  ELF* elf = (ELF*) module_object->data;
  if (elf == NULL)
    return ERROR_SUCCESS;

  if (elf->symtab != NULL)
  {
    ELF_SYMBOL *act = NULL, *next = NULL;
    for (act = elf->symtab->symbols; act != NULL; act = next)
    {
      next = act->next;
      if (act->name != NULL)
        yr_free(act->name);
      yr_free(act);
    }
    yr_free(elf->symtab);
  }

  if (elf->dynsym != NULL)
  {
    ELF_SYMBOL *act = NULL, *next = NULL;
    for (act = elf->dynsym->symbols; act != NULL; act = next)
    {
      next = act->next;
      if (act->name != NULL)
        yr_free(act->name);
      yr_free(act);
    }
    yr_free(elf->dynsym);
  }

  yr_free(elf->telfhash);
  yr_free(elf->import_hash);
  yr_free(elf);

  module_object->data = NULL;

  return ERROR_SUCCESS;
}
