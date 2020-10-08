#ifndef YR_PE_UTILS_H
#define YR_PE_UTILS_H

#include <yara/pe.h>

#define MAX_PE_SECTIONS 96

#define IS_64BITS_PE(pe)                             \
  (yr_le16toh(pe->header64->OptionalHeader.Magic) == \
   IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define OptionalHeader(pe, field)                        \
  (IS_64BITS_PE(pe) ? pe->header64->OptionalHeader.field \
                    : pe->header->OptionalHeader.field)

//
// Imports are stored in a linked list. Each node (IMPORTED_DLL) contains the
// name of the DLL and a pointer to another linked list of
// IMPORT_EXPORT_FUNCTION structures containing the details of imported
// functions.
//

typedef struct _IMPORTED_DLL
{
  char* name;

  struct _IMPORT_FUNCTION* functions;
  struct _IMPORTED_DLL* next;

} IMPORTED_DLL, *PIMPORTED_DLL;

//
// This is used to track imported and exported functions. The "has_ordinal"
// field is only used in the case of imports as those are optional. Every export
// has an ordinal so we don't need the field there, but in the interest of
// keeping duplicate code to a minimum we use this function for both imports and
// exports.
//

typedef struct _IMPORT_FUNCTION
{
  char* name;
  uint8_t has_ordinal;
  uint16_t ordinal;

  struct _IMPORT_FUNCTION* next;

} IMPORT_FUNCTION, *PIMPORT_FUNCTION;

typedef struct _PE
{
  const uint8_t* data;
  size_t data_size;
  YR_MEMORY_REGION* region;
  int memory;

  union
  {
    PIMAGE_NT_HEADERS32 header;
    PIMAGE_NT_HEADERS64 header64;
  };

  YR_HASH_TABLE* hash_table;
  YR_OBJECT* object;
  IMPORTED_DLL* imported_dlls;
  IMPORTED_DLL* delay_imported_dlls;

  uint32_t resources;
  uint32_t version_infos;

} PE;

#define fits_in_pe(pe, pointer, size) \
(pe->memory ? \
  ((size_t)size <= pe->region->data_size && \
    pe->region->block_count > 0 && \
    (uint8_t*)(pointer) >= (uint8_t*)pe->region->blocks[0].context && \
    (uint8_t*)(pointer) <= (uint8_t*)pe->region->blocks[0].context + pe->region->data_size - size) : \
  ((size_t)size <= pe->data_size && \
    (uint8_t*)(pointer) >= pe->data && \
    (uint8_t*)(pointer) <= pe->data + pe->data_size - size))

#define struct_fits_in_pe(pe, pointer, struct_type) \
  fits_in_pe(pe, pointer, sizeof(struct_type))

#define get_data_pointer_memory(pe, offset, value, type) \
for (uint8_t i = 0; i < pe->region->block_count; i++) \
{ \
  if (offset > pe->region->blocks[i].base && \
    offset < pe->region->blocks[i].base + pe->region->blocks[i].size) \
  { \
    value = (type)((uint8_t*)pe->region->blocks[i].context + (offset - pe->region->blocks[i].base)); \
    break; \
  } \
}

#define get_data_pointer_memory_with_size(pe, offset, value, type, maxsize) \
for (uint8_t i = 0; i < pe->region->block_count; i++) \
{ \
  if (offset > pe->region->blocks[i].base && \
    offset < pe->region->blocks[i].base + pe->region->blocks[i].size) \
  { \
    value = (type)((uint8_t*)pe->region->blocks[i].context + (offset - pe->region->blocks[i].base)); \
        maxsize = pe->region->blocks[i].size - (offset - pe->region->blocks[i].base); \
    break; \
  } \
}

PIMAGE_NT_HEADERS32 pe_get_header(const uint8_t* data, size_t data_size);

PIMAGE_DATA_DIRECTORY pe_get_directory_entry(PE* pe, int entry);

int64_t pe_rva_to_offset(PE* pe, uint64_t rva);

char* ord_lookup(char* dll, uint16_t ord);

#if HAVE_LIBCRYPTO
#include <openssl/asn1.h>
time_t ASN1_get_time_t(const ASN1_TIME* time);
#endif

#endif
