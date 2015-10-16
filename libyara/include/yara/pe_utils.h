#ifndef YR_PE_UTILS_H
#define YR_PE_UTILS_H

#include <yara/pe.h>

#define MAX_PE_SECTIONS              96

#define IS_64BITS_PE(pe) \
    (pe->header64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define fits_in_pe(pe, pointer, size) \
    (size <= pe->data_size && \
     (uint8_t*)(pointer) >= pe->data && \
     (uint8_t*)(pointer) <= pe->data + pe->data_size - size)

#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof(struct_type))

PIMAGE_NT_HEADERS32 pe_get_header(uint8_t* data, size_t data_size);
PIMAGE_DATA_DIRECTORY pe_get_directory_entry(PE* pe, int entry);
PIMAGE_DATA_DIRECTORY pe_get_directory_entry(PE* pe, int entry);
int64_t pe_rva_to_offset(PE* pe, uint64_t rva);
char *ord_lookup(char *dll, uint16_t ord);

#if HAVE_LIBCRYPTO
#include <openssl/asn1.h>
time_t ASN1_get_time_t(ASN1_TIME* time);
#endif

#endif
