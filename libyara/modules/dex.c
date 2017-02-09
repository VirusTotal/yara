#include <yara/modules.h>
#include <yara/mem.h>
#include <stdbool.h>
#include <stdint.h>

#define IMAGE_DEX_SIGNATURE (uint8_t[8]) { 0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00 }
#define IMAGE_ODEX_SIGNATURE (uint8_t[8]) { 0x64, 0x65, 0x79, 0x0A, 0x30, 0x33, 0x35, 0x00 }

#define member_size(type, member) sizeof(((type *)0)->member)

#define MODULE_NAME dex

typedef struct {
  uint8_t magic[8];
  uint32_t checksum[1];
  uint8_t signature[20];
  uint32_t file_size[1];
  uint32_t header_size[1];
  uint32_t endian_tag[1];
  uint32_t link_size[1];
  uint32_t link_offset[1];
  uint32_t map_offset[1];
  uint32_t string_ids_size[1];
  uint32_t string_ids_offset[1];
  uint32_t type_ids_size[1];
  uint32_t type_ids_offset[1];
  uint32_t proto_ids_size[1];
  uint32_t proto_ids_offset[1];
  uint32_t field_ids_size[1];
  uint32_t field_ids_offset[1];
  uint32_t method_ids_size[1];
  uint32_t method_ids_offset[1];
  uint32_t class_defs_size[1];
  uint32_t class_defs_offset[1];
  uint32_t data_size[1];
  uint32_t data_offset[1];
} DEX_HEADER, *PDEX_HEADER;

typedef struct {
  uint32_t class_idx[1];
  uint32_t access_flags[1];
  uint32_t superclass_idx[1];
  uint32_t interfaces_offset[1];
  uint32_t source_file_idx[1];
  uint32_t annotations_offset[1];
  uint32_t class_data_offset[1];
  uint32_t static_values_offset[1];
} CLASS_DEF_ITEM;

typedef struct {
  uint16_t class_idx[1];
  uint16_t proto_idx[1];
  uint32_t name_idx[1];
} METHOD_ID_ITEM;

typedef struct {
  uint32_t string_data_offset[1];
} STRING_ID_ITEM;

typedef struct {
  uint32_t descriptor_idx[1];
} TYPE_ID_ITEM;

typedef struct {
  uint32_t shorty_idx[1];
  uint32_t return_type_idx[1];
  uint32_t parameters_offset[1];
} PROTO_ID_ITEM;

typedef struct {
  uint16_t type_idx[1];
} TYPE_ITEM;

typedef struct {
  uint32_t size[1];
  TYPE_ITEM type_items[];
} TYPE_LIST;

typedef struct {
  uint16_t class_idx[1];
  uint16_t type_idx[1];
  uint32_t name_idx[1];
} FIELD_ID_ITEM;

typedef struct {
  uint16_t type[1];
  uint16_t unused[1];
  uint32_t size[1];
  uint32_t offset[1];
} MAP_ITEM;

typedef struct {
  uint32_t size[1];
  MAP_ITEM map_items[];
} MAP_LIST;

begin_declarations;
  declare_integer("invalid_dex");

  begin_struct("header");
    declare_string("magic");
    declare_integer("checksum");
    declare_string("signature");
    declare_integer("file_size");
    declare_integer("header_size");
    declare_integer("endian_tag");
    declare_integer("link_size");
    declare_integer("link_offset");
    declare_integer("map_offset");
    declare_integer("string_ids_size");
    declare_integer("string_ids_offset");
    declare_integer("type_ids_size");
    declare_integer("type_ids_offset");
    declare_integer("proto_ids_size");
    declare_integer("proto_ids_offset");
    declare_integer("field_ids_size");
    declare_integer("field_ids_offset");
    declare_integer("method_ids_size");
    declare_integer("method_ids_offset");
    declare_integer("class_defs_size");
    declare_integer("class_defs_offset");
    declare_integer("data_size");
    declare_integer("data_offset");
  end_struct("header");

  begin_struct_array("string_ids");
    declare_integer("offset");
    declare_integer("size");
    declare_integer("item_size");
    declare_integer("utf16_size");
    declare_string("value");
  end_struct_array("string_ids");

  begin_struct_array("type_ids");
    declare_integer("descriptor_idx");
  end_struct_array("type_ids");

  begin_struct_array("class_defs");
    declare_integer("class_idx");
    declare_integer("access_flags");
    declare_integer("superclass_idx");
    declare_integer("interfaces_offset");
    declare_integer("source_file_idx");
    declare_integer("annotations_offset");
    declare_integer("class_data_offset");
    declare_integer("static_values_offset");
  end_struct_array("class_defs");

  begin_struct_array("proto_ids");
    declare_integer("shorty_idx");
    declare_integer("return_type_idx");
    declare_integer("parameters_offset");
  end_struct_array("proto_ids");

  begin_struct_array("field_ids");
    declare_integer("class_idx");
    declare_integer("type_idx");
    declare_integer("name_idx");
  end_struct_array("field_ids");

  begin_struct_array("method_ids");
    declare_integer("class_idx");
    declare_integer("proto_idx");
    declare_integer("name_idx");
  end_struct_array("method_ids");

  begin_struct("map_list");
    declare_integer("size");
    begin_struct_array("map_items");
      declare_integer("type");
      declare_integer("unused");
      declare_integer("size");
      declare_integer("offset");
    end_struct_array("map_items");
  end_struct("map_list");

end_declarations;

PDEX_HEADER dex_get_header(uint8_t *data, size_t data_size);
void load_header(PDEX_HEADER dex_header, YR_OBJECT *module);
void load_string_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_type_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_class_defs(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_proto_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_field_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_method_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
void load_map_list(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module);
char *get_string_item(uint32_t index, YR_OBJECT *module);
char *get_prototype_string(uint16_t proto_idx, uint8_t *data, size_t data_size, YR_OBJECT *module);
uint64_t read_uleb128(uint8_t **buf, unsigned *uleb_size);
uint64_t get_bytes_until_null(const uint8_t **buf);
void print_hex_arr(uint8_t *buf, int len);
bool is_dex_corrupt(PDEX_HEADER dex_header);

int module_initialize(
    YR_MODULE *module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE *module)
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

  foreach_memory_block(iterator, block)
  {
    uint8_t* block_data = block->fetch_data(block);
    if (block_data == NULL) {
      continue;
    }

    PDEX_HEADER dex_header = dex_get_header(block_data, block->size);
    if (dex_header != NULL) {
      /*
      printf("Endian tag: 0x%x (%d)\n", *dex_header->endian_tag, *dex_header->endian_tag);
      printf("Link size: %d\n", *dex_header->link_size);
      printf("Link offset: 0x%x\n", *dex_header->link_offset);
      printf("Map list offset: 0x%x\n", *dex_header->map_offset);
      printf("String IDs size: %d\n", *dex_header->string_ids_size);
      printf("String IDs offset: 0x%x\n", *dex_header->string_ids_offset);
      printf("Type IDs size: %d\n", *dex_header->type_ids_size);
      printf("Type IDS offset: 0x%x\n", *dex_header->type_ids_offset);
      printf("Prototype IDs size: %d\n", *dex_header->proto_ids_size);
      printf("Prototype IDs offset: 0x%x\n", *dex_header->proto_ids_offset);
      printf("Field IDs size: %d\n", *dex_header->field_ids_size);
      printf("Field IDs offset: 0x%x\n", *dex_header->field_ids_offset);
      printf("Method IDs size: %d\n", *dex_header->method_ids_size);
      printf("Method IDs offset: 0x%x\n", *dex_header->method_ids_offset);
      printf("Class definitions size: %d\n", *dex_header->class_defs_size);
      printf("Class definitions offset: 0x%x\n", *dex_header->class_defs_offset);
      printf("Data size: %d bytes\n", *dex_header->data_size);
      printf("Data offset: 0x%x\n", *dex_header->data_offset);
      */

      if (is_dex_corrupt(dex_header)) {
        return ERROR_SUCCESS;
      }

      load_header(dex_header, module_object);
      load_string_ids(dex_header, block_data, block->size, module_object);
      load_type_ids(dex_header, block_data, block->size, module_object);
      load_class_defs(dex_header, block_data, block->size, module_object);
      load_proto_ids(dex_header, block_data, block->size, module_object);
      load_type_ids(dex_header, block_data, block->size, module_object);
      load_field_ids(dex_header, block_data, block->size, module_object);
      load_method_ids(dex_header, block_data, block->size, module_object);
      load_map_list(dex_header, block_data, block->size, module_object);

      break;
    }
  }

  return ERROR_SUCCESS;
}

bool is_dex_corrupt(PDEX_HEADER dex_header) {
  if (*dex_header->endian_tag != 0x12345678) {
    return true;
  }

  if (*dex_header->data_size <= 0) {
    return true;
  }

  return false;
}

int module_unload(YR_OBJECT *module_object) {
  yr_free(module_object->data);

  return ERROR_SUCCESS;
}

PDEX_HEADER dex_get_header(uint8_t *data, size_t data_size) {
  if (data_size < sizeof(DEX_HEADER)) {
    return NULL;
  }

  PDEX_HEADER dex_header;
  dex_header = (PDEX_HEADER) data;
  if (0 != memcmp(dex_header->magic, IMAGE_DEX_SIGNATURE, sizeof(IMAGE_DEX_SIGNATURE))
    && 0 != memcmp(dex_header->magic, IMAGE_ODEX_SIGNATURE, sizeof(IMAGE_ODEX_SIGNATURE))) {
    return NULL;
  }

  return dex_header;
}


void load_header(PDEX_HEADER dex_header, YR_OBJECT *module) {
  unsigned long magic_size = member_size(DEX_HEADER, magic);
  char *magic = yr_malloc(magic_size + 1);
  memcpy(magic, dex_header->magic, magic_size);
  magic[magic_size] = '\0';
  set_string(magic, module, "header.magic");

  set_integer(*dex_header->checksum, module, "header.checksum");

  unsigned long signature_size = member_size(DEX_HEADER, signature);
  char *signature = yr_malloc(signature_size + 1);
  memcpy(signature, dex_header->signature, signature_size);
  signature[signature_size] = '\0';
  set_string(signature, module, "header.signature");

  set_integer(*dex_header->file_size, module, "header.file_size");
  set_integer(*dex_header->header_size, module, "header.header_size");
  set_integer(*dex_header->endian_tag, module, "header.endian_tag");
  set_integer(*dex_header->link_size, module, "header.link_size");
  set_integer(*dex_header->link_offset, module, "header.link_offset");
  set_integer(*dex_header->map_offset, module, "header.map_offset");
  set_integer(*dex_header->string_ids_size, module, "header.string_ids_size");
  set_integer(*dex_header->string_ids_offset, module, "header.string_ids_offset");
  set_integer(*dex_header->type_ids_size, module, "header.type_ids_size");
  set_integer(*dex_header->type_ids_offset, module, "header.type_ids_offset");
  set_integer(*dex_header->proto_ids_size, module, "header.proto_ids_size");
  set_integer(*dex_header->proto_ids_offset, module, "header.proto_ids_offset");
  set_integer(*dex_header->field_ids_size, module, "header.field_ids_size");
  set_integer(*dex_header->field_ids_offset, module, "header.field_ids_offset");
  set_integer(*dex_header->method_ids_size, module, "header.method_ids_size");
  set_integer(*dex_header->method_ids_offset, module, "header.method_ids_offset");
  set_integer(*dex_header->class_defs_size, module, "header.class_defs_size");
  set_integer(*dex_header->class_defs_offset, module, "header.class_defs_offset");
  set_integer(*dex_header->data_size, module, "header.data_size");
  set_integer(*dex_header->data_offset, module, "header.data_offset");
}


void load_string_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->string_ids_offset;
  int string_ids_size = sizeof(STRING_ID_ITEM[*dex_header->string_ids_size]);
  if (offset + string_ids_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  STRING_ID_ITEM *string_ids = yr_malloc(string_ids_size);
  memcpy(string_ids, data + offset, string_ids_size);

  string_ids_size = *dex_header->string_ids_size * sizeof(STRING_ID_ITEM);
  int i = 0;
  int p = 0;
  for (i = 0, p = 0; p < string_ids_size; i += 1, p += sizeof(STRING_ID_ITEM)) {
    uint32_t offset = *string_ids[i].string_data_offset;
    uint8_t *string_data = data + offset;
    unsigned int uleb_size = 0;
    uint64_t utf16_size = read_uleb128(&string_data, &uleb_size);
    uint64_t string_size = get_bytes_until_null(&string_data);
    char *string = yr_malloc(string_size + 1);
    memcpy(string, string_data, string_size);
    /*
     * Dex string_ids aren't null terminated. If we don't pad with null,
     * will sometimes get bytes from previous string.
     */
    string[string_size] = '\0';

    set_integer(offset, module, "string_ids[%i].offset", i);
    set_integer(string_size, module, "string_ids[%i].size", i);
    set_integer(string_size + uleb_size, module, "string_ids[%i].item_size", i);
    set_integer(utf16_size, module, "string_ids[%i].utf16_size", i);
    set_string(string, module, "string_ids[%i].value", i);

    // unsigned int item_size = string_size + uleb_sizeleb;
    // printf("string idx=%d, offset=0x%x, size=%d, item_size=%lu, val=\"%s\"\n", i, offset, string_size, string_size + uleb_size, string);

    yr_free(string);
  }
  yr_free(string_ids);
}


void load_type_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->type_ids_offset;
  int type_ids_size = sizeof(TYPE_ID_ITEM[*dex_header->type_ids_size]);
  if (offset + type_ids_size >= data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  TYPE_ID_ITEM *type_ids = yr_malloc(type_ids_size);
  memcpy(type_ids, data + offset, type_ids_size);

  type_ids_size = *dex_header->type_ids_size * sizeof(TYPE_ID_ITEM);
  int i = 0;
  int p = 0;
  for (i = 0, p = 0; p < type_ids_size; i += 1, p += sizeof(TYPE_ID_ITEM)) {
    uint32_t descriptor_idx = *type_ids[i].descriptor_idx;
    set_integer(descriptor_idx, module, "type_ids[%i].descriptor_idx", i);
  }
  yr_free(type_ids);
}


void load_class_defs(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->class_defs_offset;
  int class_defs_size = sizeof(CLASS_DEF_ITEM[*dex_header->class_defs_size]);
  if (offset + class_defs_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  CLASS_DEF_ITEM *class_defs = yr_malloc(class_defs_size);
  memcpy(class_defs, data + offset, class_defs_size);

  class_defs_size = *dex_header->class_defs_size * sizeof(CLASS_DEF_ITEM);
  int i = 0;
  int p = 0;
  for (i = 0, p = 0; p < class_defs_size; i += 1, p += sizeof(CLASS_DEF_ITEM)) {
    uint32_t class_idx = *class_defs[i].class_idx;
    uint32_t access_flags = *class_defs[i].access_flags;
    uint32_t superclass_idx = *class_defs[i].superclass_idx;
    uint32_t interfaces_offset = *class_defs[i].interfaces_offset;
    uint32_t source_file_idx = *class_defs[i].source_file_idx;
    uint32_t annotations_offset = *class_defs[i].annotations_offset;
    uint32_t class_data_offset = *class_defs[i].class_data_offset;
    uint32_t static_values_offset = *class_defs[i].static_values_offset;

    set_integer(class_idx, module, "class_defs[%i].class_idx", i);
    set_integer(access_flags, module, "class_defs[%i].access_flags", i);
    set_integer(superclass_idx, module, "class_defs[%i].superclass_idx", i);
    set_integer(interfaces_offset, module, "class_defs[%i].interfaces_offset", i);
    set_integer(source_file_idx, module, "class_defs[%i].source_file_idx", i);
    set_integer(annotations_offset, module, "class_defs[%i].annotations_offset", i);
    set_integer(class_data_offset, module, "class_defs[%i].class_data_offset", i);
    set_integer(static_values_offset, module, "class_defs[%i].static_values_offset", i);
  }
  yr_free(class_defs);
}


void load_proto_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->proto_ids_offset;
  int proto_ids_size = sizeof(PROTO_ID_ITEM[*dex_header->proto_ids_size]);
  if (offset + proto_ids_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  PROTO_ID_ITEM *proto_ids = yr_malloc(proto_ids_size);
  memcpy(proto_ids, data + offset, proto_ids_size);

  proto_ids_size = *dex_header->proto_ids_size * sizeof(PROTO_ID_ITEM);
  int i,p;
  for (i = 0, p = 0; p < proto_ids_size; i += 1, p += sizeof(PROTO_ID_ITEM)) {
    uint32_t shorty_idx = *proto_ids[i].shorty_idx;
    uint32_t return_type_idx = *proto_ids[i].return_type_idx;
    uint32_t parameters_offset =  *proto_ids[i].parameters_offset;

    set_integer(shorty_idx, module, "proto_ids[%i].shorty_idx", i);
    set_integer(return_type_idx, module, "proto_ids[%i].return_type_idx", i);
    set_integer(parameters_offset, module, "proto_ids[%i].parameters_offset", i);

    //printf("shorty_idx(%i) = %s\n", shorty_idx, get_string_item(shorty_idx, module));
  }
  yr_free(proto_ids);
}


void load_field_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->field_ids_offset;
  int field_ids_size = sizeof(FIELD_ID_ITEM[*dex_header->field_ids_size]);
  if (offset + field_ids_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  FIELD_ID_ITEM *field_ids = yr_malloc(field_ids_size);
  memcpy(field_ids, data + offset, field_ids_size);

  field_ids_size = *dex_header->field_ids_size * sizeof(FIELD_ID_ITEM);
  int i = 0;
  int p = 0;
  for (i = 0, p = 0; p < field_ids_size; i += 1, p += sizeof(FIELD_ID_ITEM)) {
    uint16_t class_idx = *field_ids[i].class_idx;
    uint16_t type_idx = *field_ids[i].type_idx;
    uint32_t name_idx =  *field_ids[i].name_idx;

    set_integer(class_idx, module, "field_ids[%i].class_idx", i);
    set_integer(type_idx, module, "field_ids[%i].type_idx", i);
    set_integer(name_idx, module, "field_ids[%i].name_idx", i);

    /*
    char *class_name = get_string_item(class_idx, module);
    char *type_name = get_string_item(get_integer(module, "type_ids[%i].descriptor_idx", type_idx), module);
    char *field_name = get_string_item(name_idx, module);
    printf("field(%i) = %s->%s:%s\n", i, class_name, field_name, type_name);
    */
  }
  yr_free(field_ids);
}


void load_method_ids(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->method_ids_offset;
  int method_ids_size = sizeof(METHOD_ID_ITEM[*dex_header->method_ids_size]);
  if (offset + method_ids_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  METHOD_ID_ITEM *method_ids = yr_malloc(method_ids_size);
  memcpy(method_ids, data + offset, method_ids_size);

  method_ids_size = *dex_header->method_ids_size * sizeof(METHOD_ID_ITEM);
  int i, p;
  for (i = 0, p = 0; p < method_ids_size; i += 1, p += sizeof(METHOD_ID_ITEM)) {
    uint16_t class_idx = *method_ids[i].class_idx;
    uint16_t proto_idx = *method_ids[i].proto_idx;
    uint32_t name_idx =  *method_ids[i].name_idx;

    set_integer(class_idx, module, "method_ids[%i].class_idx", i);
    set_integer(proto_idx, module, "method_ids[%i].proto_idx", i);
    set_integer(name_idx, module, "method_ids[%i].name_idx", i);

    /*
    char *class_name = get_string_item(get_integer(module, "type_ids[%i].descriptor_idx", class_idx), module);
    char *method_name = get_string_item(name_idx, module);
    char *prototype = get_prototype_string(proto_idx, data, module);
    uint32_t proto_return_type_idx = get_integer(module, "proto_ids[%i].return_type_idx", proto_idx);
    char *return_type = get_string_item(get_integer(module, "type_ids[%i].descriptor_idx", proto_return_type_idx), module);
    printf("method(%i) = %s->%s(%s)%s\n", i, class_name, method_name, prototype, return_type);
    */
  }
  yr_free(method_ids);
}


void load_map_list(PDEX_HEADER dex_header, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = *dex_header->map_offset;
  uint8_t *pmap_list = data + offset;
  size_t map_size = *pmap_list;
  size_t map_data_size = sizeof(MAP_LIST) + (map_size * sizeof(MAP_ITEM));
  if (offset + map_data_size > data_size) {
    set_integer(1, module, "invalid_dex");
    return;
  }

  MAP_LIST *map_list = yr_malloc(map_data_size);
  memcpy(map_list, pmap_list, map_data_size);

  set_integer(*map_list->size, module, "map_list.size");
  int i = 0;
  for (i = 0; i < map_size; i++) {
    set_integer(*map_list->map_items[i].type, module, "map_list.map_items[%i].type", i);
    set_integer(*map_list->map_items[i].size, module, "map_list.map_items[%i].size", i);
    set_integer(*map_list->map_items[i].offset, module, "map_list.map_items[%i].offset", i);
  }
  yr_free(map_list);
}


char *get_string_item(uint32_t index, YR_OBJECT *module) {
    SIZED_STRING *sized_string = get_string(module, "string_ids[%i].value", index);
    char *string = yr_malloc(sized_string->length + 1);
    strcpy(string, sized_string->c_string);

    // c_string is supposed to be null terminated, but it's not for some reason
    string[sized_string->length] = '\0';

    return string;
}


char *get_prototype_string(uint16_t proto_idx, uint8_t *data, size_t data_size, YR_OBJECT *module) {
  uint32_t offset = get_integer(module, "proto_ids[%i].parameters_offset", proto_idx);
  if (offset == 0) {
    return "";
  }

  uint8_t *ptype_list = data + offset;
  size_t type_list_size = *ptype_list;
  int size = sizeof(TYPE_LIST) + (type_list_size * sizeof(TYPE_ITEM));
  if ((unsigned long)(size) > data_size) {
    return "";
  }

  TYPE_LIST *type_list = yr_malloc(size);
  memcpy(type_list, ptype_list, size);
  char *params[type_list_size];
  int string_size = 0;
  int i = 0;
  for (i = 0; i < type_list_size; i++) {
    char *param = get_string_item(get_integer(module, "type_ids[%i].descriptor_idx", *type_list->type_items[i].type_idx), module);
    string_size += strlen(param);
    params[i] = param;
  }

  char *parameters = yr_malloc(string_size + 1);
  strcpy(parameters, "");
  for (i = 0; i < type_list_size; i++) {
    strcat(parameters, params[i]);
  }
  parameters[string_size] = '\0';

  return parameters;
}


uint64_t read_uleb128(uint8_t **buf, unsigned *uleb_size) {
  uint8_t *ptr = *buf;
  uint64_t value = 0;
  unsigned shift = 0;
  do {
    value += ((uint64_t)(*ptr & 0x7f)) << shift;
    shift += 7;
  } while (*ptr++ >= 128);
  if (uleb_size != NULL) {
    *uleb_size = (unsigned)(ptr - *buf);
  }
  *buf = ptr;

  return value;
}


uint64_t get_bytes_until_null(const uint8_t **buf) {
  uint8_t *ptr = *buf;
  uint64_t count = 0;
  do {
    count++;
  } while (*ptr++ != '\0');

  return count;
}


void print_hex_arr(uint8_t *buf, int len) {
  int i = 0;
  for (i = 0; i < len; i++) {
    if (i > 0) {
      printf(":");
    }
    printf("%02X", buf[i]);
  }
  printf("\n");

  return;
}
