#ifndef YR_PE_UTILS_H
#define YR_PE_UTILS_H

#include <yara/pe.h>

#define MAX_PE_SECTIONS              96


#define IS_64BITS_PE(pe) \
    (yr_le16toh(pe->header64->OptionalHeader.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC)


#define OptionalHeader(pe,field)                \
  (IS_64BITS_PE(pe) ?                           \
   pe->header64->OptionalHeader.field :         \
   pe->header->OptionalHeader.field)


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


#define fits_in_pe(pe, pointer, size) \
    ((size_t) size <= pe->data_size && \
     (uint8_t*) (pointer) >= pe->data && \
     (uint8_t*) (pointer) <= pe->data + pe->data_size - size)

#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof(struct_type))


PIMAGE_NT_HEADERS32 pe_get_header(
    uint8_t* data,
    size_t data_size);


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry);


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry);


int64_t pe_rva_to_offset(
    PE* pe,
    uint64_t rva);


char *ord_lookup(
    char *dll,
    uint16_t ord);


#if HAVE_LIBCRYPTO
#include <openssl/asn1.h>
time_t ASN1_get_time_t(ASN1_TIME* time);
#endif

#endif
