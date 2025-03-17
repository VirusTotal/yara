/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

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

#include <yara/dex.h>
#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME dex

// DEX File layout information:
// https://source.android.com/devices/tech/dalvik/dex-format

define_function(has_method_string)
{
  SIZED_STRING* parsed_name;
  SIZED_STRING* method_name = sized_string_argument(1);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_name = yr_get_string(module, "method[%i].name", i);
    if (parsed_name != NULL &&
        strcmp(parsed_name->c_string, method_name->c_string) == 0)
    {
      return_integer(1);
    }
  }

  return_integer(0);
}

define_function(has_method_and_class_string)
{
  SIZED_STRING* parsed_class;
  SIZED_STRING* parsed_name;
  SIZED_STRING* class_name = sized_string_argument(1);
  SIZED_STRING* method_name = sized_string_argument(2);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_class = yr_get_string(module, "method[%i].class_name", i);
    if (parsed_class != NULL &&
        strcmp(parsed_class->c_string, class_name->c_string) != 0)
    {
      continue;
    }

    parsed_name = yr_get_string(module, "method[%i].name", i);
    if (parsed_name != NULL &&
        strcmp(parsed_name->c_string, method_name->c_string) == 0)
    {
      return_integer(1);
    }
  }

  return_integer(0);
}

define_function(has_method_regexp)
{
  SIZED_STRING* parsed_name;
  RE* regex = regexp_argument(1);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_name = yr_get_string(module, "method[%i].name", i);
    if (parsed_name != NULL &&
        yr_re_match(yr_scan_context(), regex, parsed_name->c_string) != -1)
    {
      return_integer(1);
    }
  }
  return_integer(0);
}

define_function(has_method_and_class_regexp)
{
  SIZED_STRING* parsed_class;
  SIZED_STRING* parsed_name;
  RE* class_regex = regexp_argument(1);
  RE* name_regex = regexp_argument(2);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_class = yr_get_string(module, "method[%i].class_name", i);
    if (parsed_class != NULL &&
        yr_re_match(yr_scan_context(), class_regex, parsed_class->c_string) == -1)
    {
      continue;
    }

    parsed_name = yr_get_string(module, "method[%i].name", i);
    if (parsed_name != NULL &&
        yr_re_match(yr_scan_context(), name_regex, parsed_name->c_string) != -1)
    {
      return_integer(1);
    }
  }
  return_integer(0);
}

define_function(has_class_string)
{
  SIZED_STRING* parsed_class;
  SIZED_STRING* class_name = sized_string_argument(1);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_class = yr_get_string(module, "method[%i].class_name", i);
    if (parsed_class != NULL &&
        strcmp(parsed_class->c_string, class_name->c_string) == 0)
    {
      return_integer(1);
    }
  }

  return_integer(0);
}

define_function(has_class_regexp)
{
  SIZED_STRING* parsed_class;
  RE* regex = regexp_argument(1);
  YR_OBJECT* module = yr_module();
  int64_t number_of_methods = yr_get_integer(module, "number_of_methods");

  if (number_of_methods == YR_UNDEFINED)
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < number_of_methods; i++)
  {
    parsed_class = yr_get_string(module, "method[%i].class_name", i);
    if (parsed_class != NULL &&
        yr_re_match(yr_scan_context(), regex, parsed_class->c_string) != -1)
    {
      return_integer(1);
    }
  }
  return_integer(0);
}

begin_declarations
  declare_string("DEX_FILE_MAGIC_035");
  declare_string("DEX_FILE_MAGIC_036");
  declare_string("DEX_FILE_MAGIC_037");
  declare_string("DEX_FILE_MAGIC_038");
  declare_string("DEX_FILE_MAGIC_039");

  declare_integer("ENDIAN_CONSTANT");
  declare_integer("REVERSE_ENDIAN_CONSTANT");
  declare_integer("NO_INDEX");
  declare_integer("ACC_PUBLIC");
  declare_integer("ACC_PRIVATE");
  declare_integer("ACC_PROTECTED");
  declare_integer("ACC_STATIC");
  declare_integer("ACC_FINAL");
  declare_integer("ACC_SYNCHRONIZED");
  declare_integer("ACC_VOLATILE");
  declare_integer("ACC_BRIDGE");
  declare_integer("ACC_TRANSIENT");
  declare_integer("ACC_VARARGS");
  declare_integer("ACC_NATIVE");
  declare_integer("ACC_INTERFACE");
  declare_integer("ACC_ABSTRACT");
  declare_integer("ACC_STRICT");
  declare_integer("ACC_SYNTHETIC");
  declare_integer("ACC_ANNOTATION");
  declare_integer("ACC_ENUM");
  declare_integer("ACC_CONSTRUCTOR");
  declare_integer("ACC_DECLARED_SYNCHRONIZED");

  declare_integer("TYPE_HEADER_ITEM");
  declare_integer("TYPE_STRING_ID_ITEM");
  declare_integer("TYPE_TYPE_ID_ITEM");
  declare_integer("TYPE_PROTO_ID_ITEM");
  declare_integer("TYPE_FIELD_ID_ITEM");
  declare_integer("TYPE_METHOD_ID_ITEM");
  declare_integer("TYPE_CLASS_DEF_ITEM");
  declare_integer("TYPE_CALL_SITE_ID_ITEM");
  declare_integer("TYPE_METHOD_HANDLE_ITEM");
  declare_integer("TYPE_MAP_LIST");
  declare_integer("TYPE_TYPE_LIST");
  declare_integer("TYPE_ANNOTATION_SET_REF_LIST");
  declare_integer("TYPE_ANNOTATION_SET_ITEM");
  declare_integer("TYPE_CLASS_DATA_ITEM");
  declare_integer("TYPE_CODE_ITEM");
  declare_integer("TYPE_STRING_DATA_ITEM");
  declare_integer("TYPE_DEBUG_INFO_ITEM");
  declare_integer("TYPE_ANNOTATION_ITEM");
  declare_integer("TYPE_ENCODED_ARRAY_ITEM");
  declare_integer("TYPE_ANNOTATIONS_DIRECTORY_ITEM");

  begin_struct("header")
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
  end_struct("header")

  begin_struct_array("string_ids")
    declare_integer("offset");
    declare_integer("size");
    declare_string("value");
  end_struct_array("string_ids")

  begin_struct_array("type_ids")
    declare_integer("descriptor_idx");
  end_struct_array("type_ids")

  begin_struct_array("proto_ids")
    declare_integer("shorty_idx");
    declare_integer("return_type_idx");
    declare_integer("parameters_offset");
  end_struct_array("proto_ids")

  begin_struct_array("field_ids")
    declare_integer("class_idx");
    declare_integer("type_idx");
    declare_integer("name_idx");
  end_struct_array("field_ids")

  begin_struct_array("method_ids")
    declare_integer("class_idx");
    declare_integer("proto_idx");
    declare_integer("name_idx");
  end_struct_array("method_ids")

  begin_struct_array("class_defs")
    declare_integer("class_idx");
    declare_integer("access_flags");
    declare_integer("super_class_idx");
    declare_integer("interfaces_offset");
    declare_integer("source_file_idx");
    declare_integer("annotations_offset");
    declare_integer("class_data_offset");
    declare_integer("static_values_offset");
  end_struct_array("class_defs")

  begin_struct_array("class_data_item")
    declare_integer("static_fields_size");
    declare_integer("instance_fields_size");
    declare_integer("direct_methods_size");
    declare_integer("virtual_methods_size");
  end_struct_array("class_data_item")

  begin_struct("map_list")
    declare_integer("size");
    begin_struct_array("map_item")
      declare_integer("type");
      declare_integer("unused");
      declare_integer("size");
      declare_integer("offset");
    end_struct_array("map_item");
  end_struct("map_list")

  declare_integer("number_of_fields");
  begin_struct_array("field")
    declare_string("class_name");
    declare_string("name");
    declare_string("proto");
    declare_integer("static");
    declare_integer("instance");
    declare_integer("field_idx_diff");
    declare_integer("access_flags");
  end_struct_array("field")

  declare_function("has_method", "s", "i", has_method_string);
  declare_function("has_method", "ss", "i", has_method_and_class_string);
  declare_function("has_method", "r", "i", has_method_regexp);
  declare_function("has_method", "rr", "i", has_method_and_class_regexp);
  declare_function("has_class", "s", "i", has_class_string);
  declare_function("has_class", "r", "i", has_class_regexp);

  declare_integer("number_of_methods");
  begin_struct_array("method")
    declare_string("class_name");
    declare_string("name");
    declare_string("proto");
    declare_integer("direct");
    declare_integer("virtual");
    declare_integer("method_idx_diff");
    declare_integer("access_flags");
    declare_integer("code_off");

    begin_struct("code_item")
      declare_integer("registers_size");
      declare_integer("ins_size");
      declare_integer("outs_size");
      declare_integer("tries_size");
      declare_integer("debug_info_off");
      declare_integer("insns_size");
      declare_string("insns");
    end_struct("code_item")
  end_struct_array("method")
end_declarations

// https://android.googlesource.com/platform/dalvik/+/android-4.4.2_r2/libdex/Leb128.cpp

static int32_t read_uleb128_bounded(
    const uint8_t* pStream,
    const uint8_t* pStreamEnd,
    uint32_t* size,
    bool* error)
{
  const uint8_t* ptr = pStream;
  int32_t result = 0;

  *error = false;
  if (ptr == pStreamEnd)
    goto error;

  result = *(ptr++);
  *size = *size + 1;

  if (result > 0x7f)
  {
    if (ptr == pStreamEnd)
      goto error;
    int cur = *(ptr++);
    *size = *size + 1;
    result = (result & 0x7f) | ((cur & 0x7f) << 7);

    if (cur > 0x7f)
    {
      if (ptr == pStreamEnd)
        goto error;
      cur = *(ptr++);
      *size = *size + 1;
      result |= (cur & 0x7f) << 14;

      if (cur > 0x7f)
      {
        if (ptr == pStreamEnd)
          goto error;
        cur = *(ptr++);
        *size = *size + 1;
        result |= (cur & 0x7f) << 21;

        if (cur > 0x7f)
        {
          if (ptr == pStreamEnd)
            goto error;
          /*
           * Note: We don't check to see if cur is out of
           * range here, meaning we tolerate garbage in the
           * high four-order bits.
           */
          cur = *ptr;
          *size = *size + 1;
          result |= cur << 28;
        }
      }
    }
  }

  return result;

error:
  *error = true;
  return result;
}


static int64_t dex_get_integer(
    YR_OBJECT* object,
    const char* pattern,
    int64_t index)
{
  if (index == YR_UNDEFINED || index < 0)
    return YR_UNDEFINED;

  // Impose a reasonably large limit to table indexes.
  if (index > 0x80000)
    return YR_UNDEFINED;

  return yr_get_integer(object, pattern, (int) index);
}


static SIZED_STRING* dex_get_string(
    YR_OBJECT* object,
    const char* pattern,
    int64_t index)
{
  if (index == YR_UNDEFINED || index < 0)
    return NULL;

  // Impose a reasonably large limit to table indexes.
  if (index > 0x80000)
    return NULL;

  return yr_get_string(object, pattern, (int) index);
}


dex_header_t* dex_get_header(const uint8_t* data, size_t data_size)
{
  dex_header_t* dex_header;

  if (data_size < sizeof(dex_header_t))
    return NULL;

  // Check if we have a valid DEX file
  dex_header = (dex_header_t*) data;

  if (memcmp(dex_header->magic, DEX_FILE_MAGIC_035, 8) != 0 &&
      memcmp(dex_header->magic, DEX_FILE_MAGIC_036, 8) != 0 &&
      memcmp(dex_header->magic, DEX_FILE_MAGIC_037, 8) != 0 &&
      memcmp(dex_header->magic, DEX_FILE_MAGIC_038, 8) != 0 &&
      memcmp(dex_header->magic, DEX_FILE_MAGIC_039, 8) != 0)
  {
    return NULL;
  }

  return dex_header;
}


void dex_parse_header(dex_header_t* dex_header, YR_OBJECT* module_object)
{
  yr_set_sized_string(
      (char*) dex_header->magic, 8, module_object, "header.magic");

  yr_set_integer(
      yr_le32toh(dex_header->checksum), module_object, "header.checksum");

  yr_set_sized_string(
      (char*) dex_header->signature, 20, module_object, "header.signature");

  yr_set_integer(
      yr_le32toh(dex_header->file_size), module_object, "header.file_size");
  yr_set_integer(
      yr_le32toh(dex_header->header_size), module_object, "header.header_size");
  yr_set_integer(
      yr_le32toh(dex_header->endian_tag), module_object, "header.endian_tag");
  yr_set_integer(
      yr_le32toh(dex_header->link_size), module_object, "header.link_size");
  yr_set_integer(
      yr_le32toh(dex_header->link_offset), module_object, "header.link_offset");
  yr_set_integer(
      yr_le32toh(dex_header->map_offset), module_object, "header.map_offset");
  yr_set_integer(
      yr_le32toh(dex_header->string_ids_size),
      module_object,
      "header.string_ids_size");
  yr_set_integer(
      yr_le32toh(dex_header->string_ids_offset),
      module_object,
      "header.string_ids_offset");
  yr_set_integer(
      yr_le32toh(dex_header->type_ids_size),
      module_object,
      "header.type_ids_size");
  yr_set_integer(
      yr_le32toh(dex_header->type_ids_offset),
      module_object,
      "header.type_ids_offset");
  yr_set_integer(
      yr_le32toh(dex_header->proto_ids_size),
      module_object,
      "header.proto_ids_size");
  yr_set_integer(
      yr_le32toh(dex_header->proto_ids_offset),
      module_object,
      "header.proto_ids_offset");
  yr_set_integer(
      yr_le32toh(dex_header->field_ids_size),
      module_object,
      "header.field_ids_size");
  yr_set_integer(
      yr_le32toh(dex_header->field_ids_offset),
      module_object,
      "header.field_ids_offset");
  yr_set_integer(
      yr_le32toh(dex_header->method_ids_size),
      module_object,
      "header.method_ids_size");
  yr_set_integer(
      yr_le32toh(dex_header->method_ids_offset),
      module_object,
      "header.method_ids_offset");
  yr_set_integer(
      yr_le32toh(dex_header->class_defs_size),
      module_object,
      "header.class_defs_size");
  yr_set_integer(
      yr_le32toh(dex_header->class_defs_offset),
      module_object,
      "header.class_defs_offset");
  yr_set_integer(
      yr_le32toh(dex_header->data_size), module_object, "header.data_size");
  yr_set_integer(
      yr_le32toh(dex_header->data_offset), module_object, "header.data_offset");
}


uint32_t load_encoded_field(
    DEX* dex,
    size_t start_offset,
    uint32_t* previous_field_idx,
    int index_encoded_field,
    int static_field,
    int instance_field)
{
#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse encoded field start_offset:0x%zx\n", start_offset);
#endif

  const uint8_t* data_cur_start = dex->data + start_offset;
  if (!fits_in_dex(dex, dex->data + start_offset, sizeof(uint32_t) * 2))
    return 0;

  const uint8_t* data_end = dex->data + dex->data_size;
  uint32_t current_size = 0;
  bool error = false;
  encoded_field_t encoded_field;

  encoded_field.field_idx_diff =
      (uint32_t) read_uleb128_bounded((dex->data + start_offset + current_size),
                                      data_end, &current_size, &error);
  if (error)
    return 0;

  encoded_field.access_flags =
      (uint32_t) read_uleb128_bounded((dex->data + start_offset + current_size),
                                      data_end, &current_size, &error);
  if (error)
    return 0;

  yr_set_integer(
      encoded_field.field_idx_diff,
      dex->object,
      "field[%i].field_idx_diff",
      index_encoded_field);

  yr_set_integer(
      encoded_field.access_flags,
      dex->object,
      "field[%i].access_flags",
      index_encoded_field);

  yr_set_integer(
      static_field, dex->object, "field[%i].static", index_encoded_field);

  yr_set_integer(
      instance_field, dex->object, "field[%i].instance", index_encoded_field);

  *previous_field_idx = encoded_field.field_idx_diff + *previous_field_idx;

#ifdef DEBUG_DEX_MODULE
  printf(
      "[DEX]\tEncoded field field_idx:0x%x field_idx_diff:0x%x "
      "access_flags:0x%x\n",
      *previous_field_idx,
      encoded_field.field_idx_diff,
      encoded_field.access_flags);
#endif

  int64_t name_idx = dex_get_integer(
      dex->object, "field_ids[%i].name_idx", *previous_field_idx);

  if (name_idx == YR_UNDEFINED)
    return 0;

  SIZED_STRING* field_name = dex_get_string(
      dex->object, "string_ids[%i].value", name_idx);

  if (field_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tFIELD_NAME %s NAME_IDX 0x%llx\n", field_name->c_string, name_idx);
#endif

    yr_set_sized_string(
        field_name->c_string,
        field_name->length,
        dex->object,
        "field[%i].name",
        index_encoded_field);
  }

  int64_t class_idx = dex_get_integer(
      dex->object, "field_ids[%i].class_idx", *previous_field_idx);

  int64_t descriptor_idx = dex_get_integer(
      dex->object, "type_ids[%i].descriptor_idx", class_idx);

  SIZED_STRING* class_name = dex_get_string(
      dex->object, "string_ids[%i].value", descriptor_idx);

  if (class_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tCLASS_NAME %s CLASS_IDX 0x%llx DESCRIPTOR_IDX 0x%llx\n",
        class_name->c_string,
        class_idx,
        descriptor_idx);
#endif

    yr_set_sized_string(
        class_name->c_string,
        class_name->length,
        dex->object,
        "field[%i].class_name",
        index_encoded_field);
  }

  int type_idx = dex_get_integer(
      dex->object, "field_ids[%i].type_idx", *previous_field_idx);

  int shorty_idx = dex_get_integer(
      dex->object, "type_ids[%i].descriptor_idx", type_idx);

  SIZED_STRING* proto_name = dex_get_string(
      dex->object, "string_ids[%i].value", shorty_idx);

  if (proto_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tPROTO_NAME %s TYPE_IDX 0x%x SHORTY_IDX 0x%x\n",
        proto_name->c_string,
        type_idx,
        shorty_idx);
#endif

    yr_set_sized_string(
        proto_name->c_string,
        proto_name->length,
        dex->object,
        "field[%i].proto",
        index_encoded_field);
  }

  return current_size;
}


uint32_t load_encoded_method(
    DEX* dex,
    size_t start_offset,
    uint32_t* previous_method_idx,
    int index_encoded_method,
    int direct_method,
    int virtual_method)
{
#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse encoded method start_offset:0x%zx\n", start_offset);
#endif

  const uint8_t* data_cur_start = dex->data + start_offset;
  if (!fits_in_dex(dex, data_cur_start, sizeof(uint32_t) * 3))
    return 0;

  const uint8_t* data_end = dex->data + dex->data_size;
  uint32_t current_size = 0;
  bool error = false;
  encoded_method_t encoded_method;

  encoded_method.method_idx_diff = (uint32_t) read_uleb128_bounded(
      (data_cur_start + current_size), data_end, &current_size, &error);
  if (error)
    return 0;

  encoded_method.access_flags = (uint32_t) read_uleb128_bounded(
      (data_cur_start + current_size), data_end, &current_size, &error);
  if (error)
    return 0;

  encoded_method.code_off = (uint32_t) read_uleb128_bounded(
      (data_cur_start + current_size), data_end, &current_size, &error);
  if (error)
    return 0;

  yr_set_integer(
      encoded_method.method_idx_diff,
      dex->object,
      "method[%i].method_idx_diff",
      index_encoded_method);

  yr_set_integer(
      encoded_method.access_flags,
      dex->object,
      "method[%i].access_flags",
      index_encoded_method);

  yr_set_integer(
      encoded_method.code_off,
      dex->object,
      "method[%i].code_off",
      index_encoded_method);

  yr_set_integer(
      direct_method, dex->object, "method[%i].direct", index_encoded_method);

  yr_set_integer(
      virtual_method, dex->object, "method[%i].virtual", index_encoded_method);

  *previous_method_idx = encoded_method.method_idx_diff + *previous_method_idx;

  int64_t name_idx = dex_get_integer(
      dex->object, "method_ids[%i].name_idx", *previous_method_idx);

  if (name_idx == YR_UNDEFINED)
    return 0;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX]\tNAME_IDX 0x%llx\n", name_idx);
#endif

#ifdef DEBUG_DEX_MODULE
  printf(
      "[DEX]\tEncoded method method_idx:0x%x method_idx_diff:0x%x "
      "access_flags:0x%x code_off:0x%x\n",
      *previous_method_idx,
      encoded_method.method_idx_diff,
      encoded_method.access_flags,
      encoded_method.code_off);
#endif

  SIZED_STRING* method_name = dex_get_string(
      dex->object, "string_ids[%i].value", name_idx);

  if (method_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tMETHOD_NAME %s NAME_IDX 0x%llx\n",
        method_name->c_string,
        name_idx);
#endif

    yr_set_sized_string(
        method_name->c_string,
        method_name->length,
        dex->object,
        "method[%i].name",
        index_encoded_method);
  }

  int64_t class_idx = dex_get_integer(
      dex->object, "method_ids[%i].class_idx", *previous_method_idx);

  int64_t descriptor_idx = dex_get_integer(
      dex->object, "type_ids[%i].descriptor_idx", class_idx);

  SIZED_STRING* class_name = dex_get_string(
      dex->object, "string_ids[%i].value", descriptor_idx);

  if (class_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tCLASS_NAME %s CLASS_IDX 0x%llx DESCRIPTOR_IDX:0x%llx\n",
        class_name->c_string,
        class_idx,
        descriptor_idx);
#endif

    yr_set_sized_string(
        class_name->c_string,
        class_name->length,
        dex->object,
        "method[%i].class_name",
        index_encoded_method);
  }

  int64_t proto_idx = dex_get_integer(
      dex->object, "method_ids[%i].proto_idx", *previous_method_idx);

  int64_t shorty_idx = dex_get_integer(
      dex->object, "proto_ids[%i].shorty_idx", proto_idx);

  SIZED_STRING* proto_name = dex_get_string(
      dex->object, "string_ids[%i].value", shorty_idx);

  if (proto_name != NULL)
  {
#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX]\tPROTO_NAME %s CLASS_IDX 0x%llx DESCRIPTOR_IDX:0x%llx\n",
        proto_name->c_string,
        class_idx,
        descriptor_idx);
#endif

    yr_set_sized_string(
        proto_name->c_string,
        proto_name->length,
        dex->object,
        "method[%i].proto",
        index_encoded_method);
  }

  if (encoded_method.code_off != 0)
  {
#ifdef DEBUG_DEX_MODULE
    printf("[DEX]\t\tParse CODE item\n");
#endif

    if (struct_fits_in_dex(
            dex, dex->data + encoded_method.code_off, code_item_t))
    {
      code_item_t* code_item =
          (code_item_t*) (dex->data + encoded_method.code_off);

      yr_set_integer(
          code_item->registers_size,
          dex->object,
          "method[%i].code_item.registers_size",
          index_encoded_method);
      yr_set_integer(
          code_item->ins_size,
          dex->object,
          "method[%i].code_item.ins_size",
          index_encoded_method);
      yr_set_integer(
          code_item->outs_size,
          dex->object,
          "method[%i].code_item.outs_size",
          index_encoded_method);
      yr_set_integer(
          code_item->tries_size,
          dex->object,
          "method[%i].code_item.tries_size",
          index_encoded_method);
      yr_set_integer(
          code_item->debug_info_off,
          dex->object,
          "method[%i].code_item.debug_info_off",
          index_encoded_method);
      yr_set_integer(
          code_item->insns_size,
          dex->object,
          "method[%i].code_item.insns_size",
          index_encoded_method);

      if (fits_in_dex(
              dex,
              dex->data + encoded_method.code_off + sizeof(code_item_t),
              code_item->insns_size * 2))
      {
        yr_set_sized_string(
            (const char*) (dex->data + encoded_method.code_off + sizeof(code_item_t)),
            code_item->insns_size * 2,
            dex->object,
            "method[%i].code_item.insns",
            index_encoded_method);
      }
    }
  }

  return current_size;
}


void dex_parse(DEX* dex, uint64_t base_address)
{
  dex_header_t* dex_header;

  int i, j;

  uint32_t uleb128_size = 0;
  uint32_t new_size = 0;
  uint32_t index_class_data_item = 0;
  uint32_t index_encoded_method = 0;
  uint32_t index_encoded_field = 0;

  const uint8_t* data_end = dex->data + dex->data_size;

  if (!struct_fits_in_dex(dex, dex->data, dex_header_t))
    return;

  dex_parse_header(dex->header, dex->object);

  dex_header = dex->header;

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->string_ids_offset),
          yr_le32toh(dex_header->string_ids_size) * sizeof(string_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse STRING ID section\n");
#endif

  // Get information about the String ID section
  for (i = 0; i < yr_le32toh(dex_header->string_ids_size); i++)
  {
    string_id_item_t* string_id_item =
        (string_id_item_t*) (dex->data + yr_le32toh(dex_header->string_ids_offset) + i * sizeof(string_id_item_t));

#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX] STRING ID item data_offset:0x%x\n",
        yr_le32toh(string_id_item->string_data_offset));
#endif

    if (!fits_in_dex(
            dex,
            dex->data + yr_le32toh(string_id_item->string_data_offset),
            sizeof(uint32_t)))
      continue;

    bool error = false;
    uint32_t value = (uint32_t) read_uleb128_bounded(
        (dex->data + yr_le32toh(string_id_item->string_data_offset)),
        data_end, &uleb128_size, &error);
    if (error)
      continue;

#ifdef DEBUG_DEX_MODULE
    printf("[DEX] STRING ID item size:0x%x\n", value);
#endif

    if (!fits_in_dex(
            dex,
            dex->data + yr_le32toh(string_id_item->string_data_offset) + 1,
            value))
      continue;

    yr_set_integer(
        yr_le32toh(string_id_item->string_data_offset),
        dex->object,
        "string_ids[%i].offset",
        i);

    yr_set_integer(value, dex->object, "string_ids[%i].size", i);

    yr_set_sized_string(
        (const char*) (
            dex->data + yr_le32toh(string_id_item->string_data_offset) + 1),
        value,
        dex->object,
        "string_ids[%i].value",
        i);
  }

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->type_ids_offset),
          yr_le32toh(dex_header->type_ids_size) * sizeof(type_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse TYPE ID section\n");
#endif

  // Get information about the Type ID section
  for (i = 0; i < yr_le32toh(dex_header->type_ids_size); i++)
  {
    type_id_item_t* type_id_item =
        (type_id_item_t*) (dex->data + yr_le32toh(dex_header->type_ids_offset) + i * sizeof(type_id_item_t));

    yr_set_integer(
        yr_le32toh(type_id_item->descriptor_idx),
        dex->object,
        "type_ids[%i].descriptor_idx",
        i);
  }

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->proto_ids_offset),
          yr_le32toh(dex_header->proto_ids_size) * sizeof(proto_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse PROTO ID section\n");
#endif

  // Get information about the Proto ID section
  for (i = 0; i < yr_le32toh(dex_header->proto_ids_size); i++)
  {
    proto_id_item_t* proto_id_item =
        (proto_id_item_t*) (dex->data + yr_le32toh(dex_header->proto_ids_offset) + i * sizeof(proto_id_item_t));

    yr_set_integer(
        yr_le32toh(proto_id_item->shorty_idx),
        dex->object,
        "proto_ids[%i].shorty_idx",
        i);
    yr_set_integer(
        yr_le32toh(proto_id_item->return_type_idx),
        dex->object,
        "proto_ids[%i].return_type_idx",
        i);
    yr_set_integer(
        yr_le32toh(proto_id_item->parameters_offset),
        dex->object,
        "proto_ids[%i].parameters_offset",
        i);
  }

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->field_ids_offset),
          yr_le32toh(dex_header->field_ids_size) * sizeof(field_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse FIELD ID section\n");
#endif

  // Get information about the Field ID section
  for (i = 0; i < yr_le32toh(dex_header->field_ids_size); i++)
  {
    field_id_item_t* field_id_item =
        (field_id_item_t*) (dex->data + yr_le32toh(dex_header->field_ids_offset) + i * sizeof(field_id_item_t));

    yr_set_integer(
        yr_le16toh(field_id_item->class_idx),
        dex->object,
        "field_ids[%i].class_idx",
        i);
    yr_set_integer(
        yr_le16toh(field_id_item->type_idx),
        dex->object,
        "field_ids[%i].type_idx",
        i);
    yr_set_integer(
        yr_le32toh(field_id_item->name_idx),
        dex->object,
        "field_ids[%i].name_idx",
        i);
  }

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->method_ids_offset),
          yr_le32toh(dex_header->method_ids_size) * sizeof(method_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse METHOD ID section\n");
#endif

  // Get information about the Method ID section
  for (i = 0; i < yr_le32toh(dex_header->method_ids_size); i++)
  {
    method_id_item_t* method_id_item =
        (method_id_item_t*) (dex->data + yr_le32toh(dex_header->method_ids_offset) + i * sizeof(method_id_item_t));

    yr_set_integer(
        yr_le16toh(method_id_item->class_idx),
        dex->object,
        "method_ids[%i].class_idx",
        i);
    yr_set_integer(
        yr_le16toh(method_id_item->proto_idx),
        dex->object,
        "method_ids[%i].proto_idx",
        i);
    yr_set_integer(
        yr_le32toh(method_id_item->name_idx),
        dex->object,
        "method_ids[%i].name_idx",
        i);
  }

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse MAP List ID section\n");
#endif

  // Get information about the Map List ID section
  if (yr_le32toh(dex_header->map_offset) != 0 &&
      fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->map_offset),
          sizeof(uint32_t)))
  {
    uint32_t* map_list_size =
        (uint32_t*) (dex->data + yr_le32toh(dex_header->map_offset));

    yr_set_integer(yr_le32toh(*map_list_size), dex->object, "map_list.size");

    if (!fits_in_dex(
            dex,
            dex->data + yr_le32toh(dex_header->map_offset),
            sizeof(uint32_t) + yr_le32toh(*map_list_size) * sizeof(map_item_t)))
      return;

    for (i = 0; i < yr_le32toh(*map_list_size); i++)
    {
      map_item_t* map_item =
          (map_item_t*) (dex->data + yr_le32toh(dex_header->map_offset) + sizeof(uint32_t) + i * sizeof(map_item_t));

      if (!struct_fits_in_dex(dex, map_item, map_item_t))
        return;

      yr_set_integer(
          yr_le16toh(map_item->type),
          dex->object,
          "map_list.map_item[%i].type",
          i);
      yr_set_integer(
          yr_le16toh(map_item->unused),
          dex->object,
          "map_list.map_item[%i].unused",
          i);
      yr_set_integer(
          yr_le32toh(map_item->size),
          dex->object,
          "map_list.map_item[%i].size",
          i);
      yr_set_integer(
          yr_le32toh(map_item->offset),
          dex->object,
          "map_list.map_item[%i].offset",
          i);
    }
  }

  if (!fits_in_dex(
          dex,
          dex->data + yr_le32toh(dex_header->class_defs_offset),
          yr_le32toh(dex_header->class_defs_size) * sizeof(class_id_item_t)))
    return;

#ifdef DEBUG_DEX_MODULE
  printf("[DEX] Parse CLASS ID section\n");
#endif

  // Get information about the Class ID section
  for (i = 0; i < yr_le32toh(dex_header->class_defs_size); i++)
  {
    class_id_item_t* class_id_item =
        (class_id_item_t*) (dex->data + yr_le32toh(dex_header->class_defs_offset) + i * sizeof(class_id_item_t));

#ifdef DEBUG_DEX_MODULE
    printf(
        "[DEX] CLASS ID item class_idx:0x%x access_flags:0x%x "
        "super_class_idx:0x%x interfaces_offset:0x%x source_file_idx:0x%x "
        "annotations_offset:0x%x class_data_offset:0x%x "
        "static_values_offset:0x%x\n",
        yr_le32toh(class_id_item->class_idx),
        yr_le32toh(class_id_item->access_flags),
        yr_le32toh(class_id_item->super_class_idx),
        yr_le32toh(class_id_item->interfaces_offset),
        yr_le32toh(class_id_item->source_file_idx),
        yr_le32toh(class_id_item->annotations_offset),
        yr_le32toh(class_id_item->class_data_offset),
        yr_le32toh(class_id_item->static_values_offset));
#endif

    yr_set_integer(
        yr_le32toh(class_id_item->class_idx),
        dex->object,
        "class_defs[%i].class_idx",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->access_flags),
        dex->object,
        "class_defs[%i].access_flags",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->super_class_idx),
        dex->object,
        "class_defs[%i].super_class_idx",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->interfaces_offset),
        dex->object,
        "class_defs[%i].interfaces_offset",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->source_file_idx),
        dex->object,
        "class_defs[%i].source_file_idx",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->annotations_offset),
        dex->object,
        "class_defs[%i].annotations_offset",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->class_data_offset),
        dex->object,
        "class_defs[%i].class_data_offset",
        i);
    yr_set_integer(
        yr_le32toh(class_id_item->static_values_offset),
        dex->object,
        "class_defs[%i].static_values_offset",
        i);

    if (yr_le32toh(class_id_item->class_data_offset) != 0)
    {
      class_data_item_t class_data_item;

      if (!fits_in_dex(
              dex,
              dex->data + yr_le32toh(class_id_item->class_data_offset),
              4 * sizeof(uint32_t)))
        return;

      uleb128_size = 0;
      bool error = false;

      class_data_item.static_fields_size = (uint32_t) read_uleb128_bounded(
          (dex->data + yr_le32toh(class_id_item->class_data_offset)),
          data_end, &uleb128_size, &error);
      if (error)
        return;

      class_data_item.instance_fields_size = (uint32_t) read_uleb128_bounded(
          (dex->data + yr_le32toh(class_id_item->class_data_offset) +
           uleb128_size),
          data_end, &uleb128_size, &error);
      if (error)
        return;

      class_data_item.direct_methods_size = (uint32_t) read_uleb128_bounded(
          (dex->data + yr_le32toh(class_id_item->class_data_offset) +
           uleb128_size),
          data_end, &uleb128_size, &error);
      if (error)
        return;

      class_data_item.virtual_methods_size = (uint32_t) read_uleb128_bounded(
          (dex->data + yr_le32toh(class_id_item->class_data_offset) +
           uleb128_size),
          data_end, &uleb128_size, &error);
      if (error)
        return;

      yr_set_integer(
          class_data_item.static_fields_size,
          dex->object,
          "class_data_item[%i].static_fields_size",
          index_class_data_item);

      yr_set_integer(
          class_data_item.instance_fields_size,
          dex->object,
          "class_data_item[%i].instance_fields_size",
          index_class_data_item);

      yr_set_integer(
          class_data_item.direct_methods_size,
          dex->object,
          "class_data_item[%i].direct_methods_size",
          index_class_data_item);

      yr_set_integer(
          class_data_item.virtual_methods_size,
          dex->object,
          "class_data_item[%i].virtual_methods_size",
          index_class_data_item);

#ifdef DEBUG_DEX_MODULE
      printf("[DEX] CLASS DATA item static fields\n");
#endif

      uint32_t previous_field_idx = 0;
      for (j = 0; j < class_data_item.static_fields_size; j++)
      {
        new_size = load_encoded_field(
            dex,
            yr_le32toh(class_id_item->class_data_offset) + uleb128_size,
            &previous_field_idx,
            index_encoded_field,
            1,
            0);

        // If the current field isn't parsed the other fields aren't likely to
        // parse.
        if (new_size == 0)
          break;

        uleb128_size += new_size;
        index_encoded_field += 1;
      }

#ifdef DEBUG_DEX_MODULE
      printf("[DEX] CLASS DATA item instance fields\n");
#endif

      previous_field_idx = 0;

      for (j = 0; j < class_data_item.instance_fields_size; j++)
      {
        new_size = load_encoded_field(
            dex,
            yr_le32toh(class_id_item->class_data_offset) + uleb128_size,
            &previous_field_idx,
            index_encoded_field,
            0,
            1);

        // If the current field isn't parsed the other fields aren't likely to
        // parse.
        if (new_size == 0)
          break;

        uleb128_size += new_size;
        index_encoded_field += 1;
      }

#ifdef DEBUG_DEX_MODULE
      printf("[DEX] CLASS DATA item direct methods\n");
#endif

      uint32_t previous_method_idx = 0;

      for (j = 0; j < class_data_item.direct_methods_size; j++)
      {
        new_size = load_encoded_method(
            dex,
            yr_le32toh(class_id_item->class_data_offset) + uleb128_size,
            &previous_method_idx,
            index_encoded_method,
            1,
            0);

        // If the current field isn't parsed the other fields aren't likely to
        // parse.
        if (new_size == 0)
          break;

        uleb128_size += new_size;
        index_encoded_method += 1;
      }

#ifdef DEBUG_DEX_MODULE
      printf("[DEX] CLASS DATA item virtual methods\n");
#endif

      previous_method_idx = 0;

      for (j = 0; j < class_data_item.virtual_methods_size; j++)
      {
        new_size = load_encoded_method(
            dex,
            yr_le32toh(class_id_item->class_data_offset) + uleb128_size,
            &previous_method_idx,
            index_encoded_method,
            0,
            1);

        // If the current field isn't parsed the other fields aren't likely to
        // parse.
        if (new_size == 0)
          break;

        uleb128_size += new_size;
        index_encoded_method += 1;
      }

      index_class_data_item++;
    }
  }

  yr_set_integer(index_encoded_method, dex->object, "number_of_methods");
  yr_set_integer(index_encoded_field, dex->object, "number_of_fields");
}


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

  dex_header_t* dex_header;

  yr_set_sized_string(
      DEX_FILE_MAGIC_035, 8, module_object, "DEX_FILE_MAGIC_035");
  yr_set_sized_string(
      DEX_FILE_MAGIC_036, 8, module_object, "DEX_FILE_MAGIC_036");
  yr_set_sized_string(
      DEX_FILE_MAGIC_037, 8, module_object, "DEX_FILE_MAGIC_037");
  yr_set_sized_string(
      DEX_FILE_MAGIC_038, 8, module_object, "DEX_FILE_MAGIC_038");
  yr_set_sized_string(
      DEX_FILE_MAGIC_039, 8, module_object, "DEX_FILE_MAGIC_039");

  yr_set_integer(0x12345678, module_object, "ENDIAN_CONSTANT");
  yr_set_integer(0x78563412, module_object, "REVERSE_ENDIAN_CONSTANT");

  yr_set_integer(0xffffffff, module_object, "NO_INDEX");
  yr_set_integer(0x1, module_object, "ACC_PUBLIC");
  yr_set_integer(0x2, module_object, "ACC_PRIVATE");
  yr_set_integer(0x4, module_object, "ACC_PROTECTED");
  yr_set_integer(0x8, module_object, "ACC_STATIC");
  yr_set_integer(0x10, module_object, "ACC_FINAL");
  yr_set_integer(0x20, module_object, "ACC_SYNCHRONIZED");
  yr_set_integer(0x40, module_object, "ACC_VOLATILE");
  yr_set_integer(0x40, module_object, "ACC_BRIDGE");
  yr_set_integer(0x80, module_object, "ACC_TRANSIENT");
  yr_set_integer(0x80, module_object, "ACC_VARARGS");
  yr_set_integer(0x100, module_object, "ACC_NATIVE");
  yr_set_integer(0x200, module_object, "ACC_INTERFACE");
  yr_set_integer(0x400, module_object, "ACC_ABSTRACT");
  yr_set_integer(0x800, module_object, "ACC_STRICT");
  yr_set_integer(0x1000, module_object, "ACC_SYNTHETIC");
  yr_set_integer(0x2000, module_object, "ACC_ANNOTATION");
  yr_set_integer(0x4000, module_object, "ACC_ENUM");
  yr_set_integer(0x10000, module_object, "ACC_CONSTRUCTOR");
  yr_set_integer(0x20000, module_object, "ACC_DECLARED_SYNCHRONIZED");

  yr_set_integer(0x0000, module_object, "TYPE_HEADER_ITEM");
  yr_set_integer(0x0001, module_object, "TYPE_STRING_ID_ITEM");
  yr_set_integer(0x0002, module_object, "TYPE_TYPE_ID_ITEM");
  yr_set_integer(0x0003, module_object, "TYPE_PROTO_ID_ITEM");
  yr_set_integer(0x0004, module_object, "TYPE_FIELD_ID_ITEM");
  yr_set_integer(0x0005, module_object, "TYPE_METHOD_ID_ITEM");
  yr_set_integer(0x0006, module_object, "TYPE_CLASS_DEF_ITEM");
  yr_set_integer(0x0007, module_object, "TYPE_CALL_SITE_ID_ITEM");
  yr_set_integer(0x0008, module_object, "TYPE_METHOD_HANDLE_ITEM");
  yr_set_integer(0x1000, module_object, "TYPE_MAP_LIST");
  yr_set_integer(0x1001, module_object, "TYPE_TYPE_LIST");
  yr_set_integer(0x1002, module_object, "TYPE_ANNOTATION_SET_REF_LIST");
  yr_set_integer(0x1003, module_object, "TYPE_ANNOTATION_SET_ITEM");
  yr_set_integer(0x2000, module_object, "TYPE_CLASS_DATA_ITEM");
  yr_set_integer(0x2001, module_object, "TYPE_CODE_ITEM");
  yr_set_integer(0x2002, module_object, "TYPE_STRING_DATA_ITEM");
  yr_set_integer(0x2003, module_object, "TYPE_DEBUG_INFO_ITEM");
  yr_set_integer(0x2004, module_object, "TYPE_ANNOTATION_ITEM");
  yr_set_integer(0x2005, module_object, "TYPE_ENCODED_ARRAY_ITEM");
  yr_set_integer(0x2006, module_object, "TYPE_ANNOTATIONS_DIRECTORY_ITEM");

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = yr_fetch_block_data(block);

    if (block_data == NULL)
      continue;

    dex_header = dex_get_header(block_data, block->size);

    if (dex_header != NULL)
    {
      DEX* dex = (DEX*) yr_malloc(sizeof(DEX));

      if (dex == NULL)
        return ERROR_INSUFFICIENT_MEMORY;

      dex->data = block_data;
      dex->data_size = block->size;
      dex->object = module_object;
      dex->header = dex_header;

      module_object->data = dex;

      dex_parse(dex, block->base);
      break;
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  DEX* dex = (DEX*) module_object->data;

  if (dex == NULL)
    return ERROR_SUCCESS;

  yr_free(dex);

  return ERROR_SUCCESS;
}

#undef MODULE_NAME
