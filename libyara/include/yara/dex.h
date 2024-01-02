#ifndef _DEX_H
#define _DEX_H

#include <stdlib.h>
#include <yara/integers.h>
#include <yara/types.h>

#define DEX_FILE_MAGIC_035 "dex\n035\x00"
#define DEX_FILE_MAGIC_036 "dex\n036\x00"
#define DEX_FILE_MAGIC_037 "dex\n037\x00"
#define DEX_FILE_MAGIC_038 "dex\n038\x00"
#define DEX_FILE_MAGIC_039 "dex\n039\x00"

#pragma pack(push, 1)

typedef struct
{
  uint8_t magic[8];
  uint32_t checksum;
  uint8_t signature[20];
  uint32_t file_size;
  uint32_t header_size;
  uint32_t endian_tag;
  uint32_t link_size;
  uint32_t link_offset;
  uint32_t map_offset;
  uint32_t string_ids_size;
  uint32_t string_ids_offset;
  uint32_t type_ids_size;
  uint32_t type_ids_offset;
  uint32_t proto_ids_size;
  uint32_t proto_ids_offset;
  uint32_t field_ids_size;
  uint32_t field_ids_offset;
  uint32_t method_ids_size;
  uint32_t method_ids_offset;
  uint32_t class_defs_size;
  uint32_t class_defs_offset;
  uint32_t data_size;
  uint32_t data_offset;
} dex_header_t;

typedef struct
{
  uint32_t string_data_offset;
} string_id_item_t;

typedef struct
{
  uint32_t utf16_size;
} string_data_item_t;

typedef struct
{
  uint32_t descriptor_idx;
} type_id_item_t;

typedef struct
{
  uint32_t shorty_idx;
  uint32_t return_type_idx;
  uint32_t parameters_offset;
} proto_id_item_t;

typedef struct
{
  uint16_t class_idx;
  uint16_t type_idx;
  uint32_t name_idx;
} field_id_item_t;

typedef struct
{
  uint16_t class_idx;
  uint16_t proto_idx;
  uint32_t name_idx;
} method_id_item_t;

typedef struct
{
  uint32_t class_idx;
  uint32_t access_flags;
  uint32_t super_class_idx;
  uint32_t interfaces_offset;
  uint32_t source_file_idx;
  uint32_t annotations_offset;
  uint32_t class_data_offset;
  uint32_t static_values_offset;
} class_id_item_t;

typedef struct
{
  uint32_t static_fields_size;
  uint32_t instance_fields_size;
  uint32_t direct_methods_size;
  uint32_t virtual_methods_size;
} class_data_item_t;

typedef struct
{
  uint32_t field_idx_diff;
  uint32_t access_flags;
} encoded_field_t;

typedef struct
{
  uint32_t method_idx_diff;
  uint32_t access_flags;
  uint32_t code_off;
} encoded_method_t;

typedef struct
{
  uint16_t registers_size;
  uint16_t ins_size;
  uint16_t outs_size;
  uint16_t tries_size;
  uint32_t debug_info_off;
  uint32_t insns_size;
} code_item_t;

typedef struct
{
  uint16_t type;
  uint16_t unused;
  uint32_t size;
  uint32_t offset;
} map_item_t;

typedef struct _DEX
{
  const uint8_t* data;
  size_t data_size;
  dex_header_t* header;
  YR_OBJECT* object;
} DEX;

#define fits_in_dex(dex, pointer, size)                                    \
  ((size_t) size <= dex->data_size && (uint8_t*) (pointer) >= dex->data && \
   (uint8_t*) (pointer) <= dex->data + dex->data_size - size)

#define struct_fits_in_dex(dex, pointer, struct_type) \
  fits_in_dex(dex, pointer, sizeof(struct_type))

#pragma pack(pop)

#endif
