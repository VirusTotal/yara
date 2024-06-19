/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

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

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <yara/dotnet.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/pe.h>
#include <yara/pe_utils.h>
#include <yara/simple_str.h>
#include <yara/strutils.h>
#include <yara/unaligned.h>

#define MODULE_NAME dotnet

static uint32_t max_rows(int count, ...)
{
  va_list ap;
  uint32_t biggest;
  uint32_t x;

  if (count == 0)
    return 0;

  va_start(ap, count);
  biggest = va_arg(ap, uint32_t);

  for (int i = 1; i < count; i++)
  {
    x = va_arg(ap, uint32_t);
    biggest = (x > biggest) ? x : biggest;
  }

  va_end(ap);
  return biggest;
}

static uint32_t read_u32(const uint8_t** data)
{
  uint32_t result = yr_le32toh(yr_unaligned_u32(*data));
  *data += sizeof(uint32_t);
  return result;
}

static uint16_t read_u16(const uint8_t** data)
{
  uint16_t result = yr_le16toh(yr_unaligned_u16(*data));
  *data += sizeof(uint16_t);
  return result;
}

static uint8_t read_u8(const uint8_t** data)
{
  uint8_t result = **data;
  *data += sizeof(uint8_t);
  return result;
}

static uint32_t read_index(const uint8_t** data, uint8_t len)
{
  if (len == 2)
    return read_u16(data);
  else
    return read_u32(data);
}

// Returns valid offset within the table or NULL
const uint8_t* get_table_offset(const TABLE_INFO* tbl, uint32_t index)
{
  // Indexes to .NET tables are based from 1
  if (index < 1 || index > tbl->RowCount)
    return NULL;

  return tbl->Offset + tbl->RowSize * (index - 1);
}

// Given an offset into a #US or #Blob stream, parse the entry at that position.
// The offset is relative to the start of the PE file.
// if size > 0 then it's valid and readable blob
BLOB_PARSE_RESULT dotnet_parse_blob_entry(PE* pe, const uint8_t* offset)
{
  BLOB_PARSE_RESULT result = {.size = 0, .length = 0};

  // Blob size is encoded in the first 1, 2 or 4 bytes of the blob.
  //
  // If the high bit is not set the length is encoded in one byte.
  //
  // If the high 2 bits are 10 (base 2) then the length is encoded in
  // the rest of the bits and the next byte.
  //
  // If the high 3 bits are 110 (base 2) then the length is encoded
  // in the rest of the bits and the next 3 bytes.
  //
  // See ECMA-335 II.24.2.4 for details.

  // Make sure we have at least one byte.

  if (!fits_in_pe(pe, offset, 1))
    return result;

  if ((*offset & 0x80) == 0x00)
  {
    result.length = (uint32_t) (*offset);
    result.size = 1;
  }
  else if ((*offset & 0xC0) == 0x80)
  {
    // Make sure we have one more byte.
    if (!fits_in_pe(pe, offset, 2))
      return result;

    // Shift remaining 6 bits left by 8 and OR in the remaining byte.
    result.length = ((*offset & 0x3F) << 8) | *(offset + 1);
    result.size = 2;
  }
  else if (offset + 4 < pe->data + pe->data_size && (*offset & 0xE0) == 0xC0)
  {
    // Make sure we have 3 more bytes.
    if (!fits_in_pe(pe, offset, 4))
      return result;

    result.length = ((*offset & 0x1F) << 24) | (*(offset + 1) << 16) |
                    (*(offset + 2) << 8) | *(offset + 3);
    result.size = 4;
  }
  else
  {
    // Return a 0 size as an error.
    return result;
  }

  // Check if the length is actually readable
  if (!fits_in_pe(pe, offset, result.size + result.length))
  {
    result.size = 0;
    return result;
  }

  return result;
}

char* pe_get_dotnet_string(
    PE* pe,
    const uint8_t* heap_offset,
    uint32_t heap_size,
    uint32_t string_index)
{
  size_t remaining;

  char* start;
  char* eos;

  // Start of string must be within boundary
  if (!(heap_offset + string_index >= pe->data &&
        heap_offset + string_index < pe->data + pe->data_size &&
        string_index < heap_size))
    return NULL;

  // Calculate how much until end of boundary, don't scan past that.
  remaining = (pe->data + pe->data_size) - (heap_offset + string_index);

  // Search for a NULL terminator from start of string, up to remaining.
  start = (char*) (heap_offset + string_index);
  eos = (char*) memmem((void*) start, remaining, "\0", 1);

  // If no NULL terminator was found or the string is too large, return NULL.
  if (eos == NULL || eos - start > 1024)
    return NULL;

  return start;
}

static bool is_nested(uint32_t flags)
{
  // ECMA 335 II.22.37
  // Whether a type is nested can be determined by the value of its
  // Flags.Visibility sub-field – it shall be one of the set
  // { NestedPublic, NestedPrivate, NestedFamily, NestedAssembly,
  // NestedFamANDAssem, NestedFamORAssem }

  switch (flags & TYPE_ATTR_VISIBILITY_MASK)
  {
  case TYPE_ATTR_NESTED_PRIVATE:
  case TYPE_ATTR_NESTED_PUBLIC:
  case TYPE_ATTR_NESTED_FAMILY:
  case TYPE_ATTR_NESTED_ASSEMBLY:
  case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
  case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
    return true;
  default:
    return false;
  }
}

// ECMA 335 II.23.1.15 Flags for types [TypeAttribute]
static const char* get_type_visibility(uint32_t flags)
{
  switch (flags & TYPE_ATTR_VISIBILITY_MASK)
  {
  case TYPE_ATTR_NESTED_PRIVATE:
    return "private";
  case TYPE_ATTR_PUBLIC:
  case TYPE_ATTR_NESTED_PUBLIC:
    return "public";
  case TYPE_ATTR_NESTED_FAMILY:
    return "protected";
  case TYPE_ATTR_NOT_PUBLIC:
  case TYPE_ATTR_NESTED_ASSEMBLY:
    return "internal";
  case TYPE_ATTR_NESTED_FAM_AND_ASSEM:
    return "private protected";
  case TYPE_ATTR_NESTED_FAM_OR_ASSEM:
    return "protected internal";
  default:
    return "private";
  }
}

// ECMA 335 II.23.1.10 Flags for methods [MethodAttributes]
static const char* get_method_visibility(uint32_t flags)
{
  switch (flags & METHOD_ATTR_ACCESS_MASK)
  {
  case METHOD_ATTR_PRIVATE:
    return "private";
  case METHOD_ATTR_FAM_AND_ASSEM:
    return "private protected";
  case METHOD_ATTR_ASSEM:
    return "internal";
  case METHOD_ATTR_FAMILY:
    return "protected";
  case METHOD_ATTR_FAM_OR_ASSEM:
    return "protected internal";
  case METHOD_ATTR_PUBLIC:
    return "public";
  default:
    return "private";
  }
}

// ECMA 335 II.23.1.15 Flags for types [TypeAttribute]
static const char* get_typedef_type(uint32_t flags)
{
  switch (flags & TYPE_ATTR_CLASS_SEMANTIC_MASK)
  {
  case TYPE_ATTR_CLASS:
    return "class";
  case TYPE_ATTR_INTERFACE:
    return "interface";
  default:
    return NULL;
  }
}

// returns allocated string <namespace>.<name>, must be freed
static char* create_full_name(const char* name, const char* namespace)
{
  if (!name || !strlen(name))
    return namespace ? yr_strdup(namespace) : NULL;

  // No namespace -> return name only
  if (!namespace || !strlen(namespace))
  {
    // fix generic names
    char* name_copy = yr_strdup(name);
    char* end = strchr(name_copy, '`');
    if (end)
      *end = 0;
    return name_copy;
  }

  size_t name_len = strlen(name);
  size_t namespace_len = strlen(namespace);

  // <namespace>.<name>
  char* full_name = yr_malloc(namespace_len + 1 + name_len + 1);

  memcpy(full_name, namespace, namespace_len);
  full_name[namespace_len] = '.';
  memcpy(full_name + namespace_len + 1, name, name_len + 1);

  // fix generic names
  char* end = strchr(full_name, '`');
  if (end)
    *end = 0;

  return full_name;
}

static bool read_typedef(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPEDEF_ROW* result)
{
  uint32_t row_size = ctx->tables->typedef_.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint8_t ext_size = 2;
    uint32_t row_count = max_rows(
        3,
        ctx->tables->typedef_.RowCount,
        ctx->tables->typeref.RowCount,
        ctx->tables->typespec.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      ext_size = 4;

    result->Flags = read_u32(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Namespace = read_index(&data, ctx->index_sizes->string);
    result->Extends = read_index(&data, ext_size);
    result->Field = read_index(&data, ctx->index_sizes->field);
    result->Method = read_index(&data, ctx->index_sizes->methoddef);

    return true;
  }

  return false;
}

static bool read_typeref(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPEREF_ROW* result)
{
  uint32_t row_size = ctx->tables->typeref.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint8_t res_size = 2;
    uint32_t row_count = max_rows(
        4,
        ctx->tables->module.RowCount,
        ctx->tables->moduleref.RowCount,
        ctx->tables->assemblyref.RowCount,
        ctx->tables->typeref.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      res_size = 4;

    result->ResolutionScope = read_index(&data, res_size);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Namespace = read_index(&data, ctx->index_sizes->string);

    return true;
  }

  return false;
}

static bool read_interfaceimpl(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    INTERFACEIMPL_ROW* result)
{
  uint32_t row_size = ctx->tables->intefaceimpl.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint32_t interface_size = 2;
    uint32_t row_count = max_rows(
        3,
        ctx->tables->typedef_.RowCount,
        ctx->tables->typeref.RowCount,
        ctx->tables->typespec.RowCount);

    if (row_count > (0xFFFF >> 0x02))
      interface_size = 4;

    result->Class = read_index(&data, ctx->index_sizes->typedef_);
    result->Interface = read_index(&data, interface_size);

    return true;
  }

  return false;
}

static bool read_methoddef(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    METHODDEF_ROW* result)
{
  uint32_t row_size = ctx->tables->methoddef.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Rva = read_u32(&data);
    result->ImplFlags = read_u16(&data);
    result->Flags = read_u16(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    result->Signature = read_index(&data, ctx->index_sizes->blob);
    result->ParamList = read_index(&data, ctx->index_sizes->param);
    return true;
  }

  return false;
}

static bool read_param(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    PARAM_ROW* result)
{
  uint32_t row_size = ctx->tables->param.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Flags = read_u16(&data);
    result->Sequence = read_u16(&data);
    result->Name = read_index(&data, ctx->index_sizes->string);
    return true;
  }

  return false;
}

static bool read_genericparam(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    GENERICPARAM_ROW* result)
{
  uint32_t row_size = ctx->tables->genericparam.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    uint32_t owner_idx_size = 2;
    uint32_t row_count = max_rows(
        2, ctx->tables->typedef_.RowCount, ctx->tables->methoddef.RowCount);

    if (row_count > (0xFFFF >> 0x01))
      owner_idx_size = 4;

    result->Number = read_u16(&data);
    result->Flags = read_u16(&data);
    result->Owner = read_index(&data, owner_idx_size);
    result->Name = read_index(&data, ctx->index_sizes->string);
    return true;
  }

  return false;
}

static bool read_typespec(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    TYPESPEC_ROW* result)
{
  uint32_t row_size = ctx->tables->typespec.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->Signature = read_index(&data, ctx->index_sizes->blob);
    return true;
  }

  return false;
}

static bool read_nestedclass(
    const CLASS_CONTEXT* ctx,
    const uint8_t* data,
    NESTEDCLASS_ROW* result)
{
  uint32_t row_size = ctx->tables->nestedclass.RowSize;

  if (fits_in_pe(ctx->pe, data, row_size))
  {
    result->NestedClass = read_index(&data, ctx->index_sizes->typedef_);
    result->EnclosingClass = read_index(&data, ctx->index_sizes->typedef_);
    return true;
  }

  return false;
}

// ECMA-335 II.23.2 blob heap uses variable length encoding of integers
static uint32_t read_blob_unsigned(const uint8_t** data, uint32_t* len)
{
  if (*len < 1)
    return 0;

  // first byte is enough to decode the length
  // without worrying about endiannity
  // Compressed integers use big-endian order
  uint8_t first_byte = *(*data);

  // If the value lies between 0 (0x00) and 127 (0x7F), inclusive, encode as a
  // one-byte integer (bit 7 is clear, value held in bits 6 through 0)
  if (!(first_byte & 0x80))
  {
    *data += sizeof(uint8_t);
    *len -= sizeof(uint8_t);
    return first_byte;
  }

  if (*len < 2)
    return 0;

  // If the value lies between 2^8 (0x80) and 2^14 – 1 (0x3FFF), inclusive,
  // encode as a 2-byte integer with bit 15 set, bit 14 clear (value held in
  // bits 13 through 0)
  if ((first_byte & 0xC0) == 0x80)
  {
    uint32_t result = yr_be16toh(yr_unaligned_u16(*data));
    *data += sizeof(uint16_t);
    *len -= sizeof(uint16_t);
    // value is in lower 14 bits
    return result & 0x3FFF;
  }

  if (*len < 4)
    return 0;

  // Otherwise, encode as a 4-byte integer, with bit 31 set, bit 30 set,
  // bit 29 clear (value held in bits 28 through 0)
  if ((first_byte & 0xE0) == 0xC0)
  {
    uint32_t result = yr_be32toh(yr_unaligned_u32(*data));
    *data += sizeof(uint32_t);
    *len -= sizeof(uint32_t);
    // Uses last 29 bits for the result
    return result & 0x1FFFFFFF;
  }

  return 0;
}

// ECMA-335 II.23.2 blob heap uses variable length encoding of integers
// Probably wouldn't work on non 2's complement arches?
static int32_t read_blob_signed(const uint8_t** data, uint32_t* len)
{
  // Compressed integers use big-endian order!
  if (*len < 1)
    return 0;

  // first byte is enough to decode the length
  // without worrying about endiannity
  int8_t first_byte = *(*data);

  // Encode as a one-byte integer, bit 7 clear, rotated value in bits 6
  // through 0, giving 0x01 (-2^6) to 0x7E (2^6-1).
  if (!(first_byte & 0x80))
  {
    int8_t tmp = first_byte >> 1;
    // sign extension in case of negative number
    if (first_byte & 0x1)
      tmp |= 0xC0;

    *data += sizeof(uint8_t);
    *len -= sizeof(uint8_t);

    return (int32_t) tmp;
  }

  if (*len < 2)
    return 0;

  // Encode as a two-byte integer: bit 15 set, bit 14 clear, rotated value
  // in bits 13 through 0, giving 0x8001 (-2^13) to 0xBFFE (2^13-1).
  if ((first_byte & 0xC0) == 0x80)
  {
    uint16_t tmp1 = yr_be16toh(yr_unaligned_u16(*data));
    // shift and leave top 2 bits clear
    int16_t tmp2 = (tmp1 >> 1) & 0x3FFF;
    // sign extension in case of negative number
    if (tmp1 & 0x1)
      tmp2 |= 0xE000;

    *data += sizeof(uint16_t);
    *len -= sizeof(uint16_t);

    return (int32_t) tmp2;
  }

  if (*len < 4)
    return 0;

  // Encode as a four-byte integer: bit 31 set, 30 set, bit 29 clear,
  // rotated value in bits 28 through 0, giving 0xC0000001 (-2^28) to
  // 0xDFFFFFFE (2^28-1).
  if ((first_byte & 0xE0) == 0xC0)
  {
    uint32_t tmp1 = yr_be32toh(yr_unaligned_u32(*data));
    // shift and leave top 3 bits clear
    int32_t tmp2 = (tmp1 >> 1) & 0x1FFFFFFF;
    // sign extension in case of negative number
    if (tmp1 & 0x1)
      tmp2 |= 0xF0000000;

    *data += sizeof(uint32_t);
    *len -= sizeof(uint32_t);

    return (int32_t) tmp2;
  }

  return 0;
}

// Forward declarations
static char* parse_signature_type(
    const CLASS_CONTEXT* ctx,
    const uint8_t** data,
    uint32_t* len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth);

static char* parse_enclosing_types(
    const CLASS_CONTEXT* ctx,
    uint32_t nested_idx,
    uint32_t depth);

static char* get_type_def_or_ref_fullname(
    const CLASS_CONTEXT* ctx,
    uint32_t coded_index,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth)  // against loops
{
  // first 2 bits define table, index starts with third bit
  uint32_t index = coded_index >> 2;
  if (!index)
    return NULL;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  uint8_t table = coded_index & 0x3;
  if (table == 0)  // TypeDef
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typedef_, index);
    if (!data)
      return NULL;

    TYPEDEF_ROW def_row;
    bool result = read_typedef(ctx, data, &def_row);
    if (result)
    {
      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, def_row.Name);
      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, def_row.Namespace);

      char* result = NULL;
      // Type might be nested, try to find correct namespace
      if (is_nested(def_row.Flags))
      {
        char* nested_namespace = parse_enclosing_types(ctx, index, 1);
        char* tmp = create_full_name(namespace, nested_namespace);
        result = create_full_name(name, tmp);
        yr_free(nested_namespace);
        yr_free(tmp);
      }
      else
        result = create_full_name(name, namespace);

      return result;
    }
  }
  else if (table == 1)  // TypeRef
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typeref, index);
    if (!data)
      return NULL;

    TYPEREF_ROW ref_row;
    bool result = read_typeref(ctx, data, &ref_row);
    if (result)
    {
      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, ref_row.Name);
      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, ref_row.Namespace);

      return create_full_name(name, namespace);
    }
  }
  else if (table == 2)  // TypeSpec
  {
    const uint8_t* data = get_table_offset(&ctx->tables->typespec, index);
    if (!data)
      return NULL;

    TYPESPEC_ROW spec_row;
    bool result = read_typespec(ctx, data, &spec_row);
    if (result)
    {
      const uint8_t* sig_data = ctx->blob_heap + spec_row.Signature;

      // Read the blob entry with the data
      BLOB_PARSE_RESULT blob_res = dotnet_parse_blob_entry(ctx->pe, sig_data);
      sig_data += blob_res.size;
      uint32_t sig_len = blob_res.length;

      // Valid blob
      if (blob_res.size)
        return parse_signature_type(
            ctx, &sig_data, &sig_len, class_gen_params, NULL, depth);
    }
  }
  return NULL;
}

static char* parse_signature_type(
    const CLASS_CONTEXT* ctx,
    const uint8_t** data,
    uint32_t* len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params,
    uint32_t depth  // against loops
)
{
  // If at least first type fits and we are not too nested
  if (*len < 1 || !fits_in_pe(ctx->pe, *data, 1) || depth > MAX_TYPE_DEPTH)
    return NULL;

  bool class = false;
  uint32_t coded_index, index;
  char* tmp = NULL;
  char* ret_type = NULL;

  uint8_t type = read_u8(data);
  *len -= 1;

  switch (type)
  {
  case TYPE_VOID:
    ret_type = "void";
    break;

  case TYPE_BOOL:
    ret_type = "bool";
    break;

  case TYPE_CHAR:
    ret_type = "char";
    break;

  case TYPE_I1:
    ret_type = "sbyte";
    break;

  case TYPE_U1:
    ret_type = "byte";
    break;

  case TYPE_I2:
    ret_type = "short";
    break;

  case TYPE_U2:
    ret_type = "ushort";
    break;

  case TYPE_I4:
    ret_type = "int";
    break;

  case TYPE_U4:
    ret_type = "uint";
    break;

  case TYPE_I8:
    ret_type = "long";
    break;

  case TYPE_U8:
    ret_type = "ulong";
    break;

  case TYPE_R4:
    ret_type = "float";
    break;

  case TYPE_R8:
    ret_type = "double";
    break;

  case TYPE_STRING:
    ret_type = "string";
    break;

  case TYPE_TYPEDREF:
    ret_type = "TypedReference";
    break;

  case TYPE_I:
    ret_type = "IntPtr";
    break;

  case TYPE_U:
    ret_type = "UIntPtr";
    break;

  case TYPE_PTR:  // Ptr followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }
      bool res = sstr_appendf(ss, "Ptr<%s>", tmp);
      if (res)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_BYREF:
    // ByRef followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }
      bool res = sstr_appendf(ss, "ref %s", tmp);
      if (res)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_VALUETYPE:  // ValueType
  case TYPE_CLASS:      // Class
    // followed by TypeDefOrRefOrSpecEncoded index
    coded_index = read_blob_unsigned(data, len);
    return get_type_def_or_ref_fullname(
        ctx, coded_index, class_gen_params, method_gen_params, depth + 1);
    break;

  case TYPE_VAR:   // Generic class var
  case TYPE_MVAR:  // Generic method var
    index = read_blob_unsigned(data, len);
    class = type == TYPE_VAR;
    // return class generic var or method generic var
    if (class && class_gen_params && index < class_gen_params->len)
      ret_type = class_gen_params->names[index];
    else if (!class && method_gen_params && index < method_gen_params->len)
      ret_type = method_gen_params->names[index];
    break;

  case TYPE_ARRAY:
  {
    // Array -> Type -> Rank -> NumSizes -> Size -> NumLobound -> LoBound
    char* tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (!tmp)
      break;

    int32_t* sizes = NULL;
    int32_t* lo_bounds = NULL;

    // Read number of dimensions
    uint32_t rank = read_blob_unsigned(data, len);
    if (!rank || rank > MAX_ARRAY_RANK)
      goto cleanup;

    // Read number of specified sizes
    uint32_t num_sizes = read_blob_unsigned(data, len);
    if (num_sizes > rank)
      goto cleanup;
    sizes = yr_malloc(sizeof(int64_t) * num_sizes);
    if (!sizes)
      goto cleanup;

    for (uint32_t i = 0; i < num_sizes; ++i)
    {
      sizes[i] = (int64_t) read_blob_unsigned(data, len);
    }

    // Read number of specified lower bounds
    uint32_t num_lowbounds = read_blob_unsigned(data, len);
    lo_bounds = yr_malloc(sizeof(int32_t) * num_lowbounds);
    if (!lo_bounds || num_lowbounds > rank)
      goto cleanup;

    for (uint32_t i = 0; i < num_lowbounds; ++i)
    {
      lo_bounds[i] = read_blob_signed(data, len);

      // Adjust higher bound according to lower bound
      if (num_sizes > i && lo_bounds[i] != 0)
        sizes[i] += lo_bounds[i] - 1;
    }

    // Build the resulting array type
    SIMPLE_STR* ss = sstr_new(NULL);
    if (!ss)
      goto cleanup;

    sstr_appendf(ss, "%s[", tmp);

    for (uint32_t i = 0; i < rank; ++i)
    {
      if (num_sizes > i || num_lowbounds > i)
      {
        if (num_lowbounds > i && lo_bounds[i] != 0)
          sstr_appendf(ss, "%d...", lo_bounds[i]);
        if (num_sizes > i)
          sstr_appendf(ss, "%d", sizes[i]);
      }
      if (i + 1 != rank)
        sstr_appendf(ss, ",");
    }
    bool res = sstr_appendf(ss, "]");
    if (res)
      ret_type = sstr_move(ss);

    yr_free(sizes);
    yr_free(lo_bounds);
    yr_free(tmp);
    sstr_free(ss);
    return ret_type;

  cleanup:
    yr_free(sizes);
    yr_free(lo_bounds);
    yr_free(tmp);
  }
  break;

  case TYPE_GENERICINST:
  {
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);

    if (!tmp)
      break;

    uint32_t gen_count = read_blob_unsigned(data, len);

    // Sanity check for corrupted files
    if (gen_count > MAX_GEN_PARAM_COUNT)
    {
      yr_free(tmp);
      break;
    }

    SIMPLE_STR* ss = sstr_new(NULL);
    if (!ss)
    {
      yr_free(tmp);
      break;
    }
    sstr_appendf(ss, "%s<", tmp);
    yr_free(tmp);

    for (int i = 0; i < gen_count; i++)
    {
      char* param_type = parse_signature_type(
          ctx, data, len, class_gen_params, method_gen_params, depth + 1);

      if (param_type != NULL)
      {
        if (i > 0)
          sstr_appendf(ss, ",");

        sstr_appendf(ss, "%s", param_type);
        yr_free(param_type);
      }
    }
    bool res = sstr_appendf(ss, ">");
    if (res)
      ret_type = sstr_move(ss);

    sstr_free(ss);
    return ret_type;
  }
  break;

  case TYPE_FNPTR:
    if (*len > 0)
    {  // Flags -> ParamCount -> RetType -> Param -> Sentinel ->Param
      // Skip flags
      (*data)++;
      (*len)--;

      uint32_t param_count = read_blob_unsigned(data, len);

      // Sanity check for corrupted files
      if (param_count > MAX_PARAM_COUNT)
      {
        yr_free(tmp);
        break;
      }

      tmp = parse_signature_type(
          ctx, data, len, class_gen_params, method_gen_params, depth + 1);

      if (!tmp)
        break;

      SIMPLE_STR* ss = sstr_new(NULL);
      if (!ss)
      {
        yr_free(tmp);
        break;
      }

      sstr_appendf(ss, "FnPtr<%s(", tmp);
      yr_free(tmp);

      for (int i = 0; i < param_count; i++)
      {
        char* param_type = parse_signature_type(
            ctx, data, len, class_gen_params, method_gen_params, depth + 1);

        if (param_type != NULL)
        {
          if (i > 0)
            sstr_appendf(ss, ", ");

          sstr_appendf(ss, "%s", param_type);
          yr_free(param_type);
        }
      }

      if (sstr_appendf(ss, ")>"))
        ret_type = sstr_move(ss);

      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_OBJECT:
    ret_type = "object";
    break;

  case TYPE_SZARRAY:
    // Single dimensional array followed by type
    tmp = parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
    if (tmp)
    {
      SIMPLE_STR* ss = sstr_newf("%s[]", tmp);
      if (ss)
        ret_type = sstr_move(ss);

      yr_free(tmp);
      sstr_free(ss);
      return ret_type;
    }
    break;

  case TYPE_CMOD_REQD:  // Req modifier
  case TYPE_CMOD_OPT:   // Opt modifier
  {
    // What is point of these
    // Right now ignore them...
    read_blob_unsigned(data, len);
    return parse_signature_type(
        ctx, data, len, class_gen_params, method_gen_params, depth + 1);
  }
  break;

  default:
    break;
  }

  if (ret_type)
    return yr_strdup(ret_type);
  else
    return NULL;
}

static void parse_type_parents(
    const CLASS_CONTEXT* ctx,
    uint32_t extends,
    uint32_t type_idx,
    uint32_t out_idx,  // Class idx in output array
    GENERIC_PARAMETERS* class_gen_params)
{
  // Find the parent class
  char* parent = get_type_def_or_ref_fullname(
      ctx, extends, class_gen_params, NULL, 0);

  uint32_t base_type_idx = 0;
  if (parent)
  {
    yr_set_string(
        parent,
        ctx->pe->object,
        "classes[%i].base_types[%i]",
        out_idx,
        base_type_idx++);

    yr_free(parent);
  }

  // linear search for every interface that the class implements
  for (uint32_t idx = 0; idx < ctx->tables->intefaceimpl.RowCount; ++idx)
  {
    const uint8_t* data = get_table_offset(&ctx->tables->intefaceimpl, idx + 1);
    if (!data)
      break;

    INTERFACEIMPL_ROW row = {0};
    bool result = read_interfaceimpl(ctx, data, &row);
    if (!result)
      continue;

    // We found the inherited interface
    if (row.Class == type_idx)
    {
      char* inteface = get_type_def_or_ref_fullname(
          ctx, row.Interface, class_gen_params, NULL, 0);
      if (inteface)
      {
        yr_set_string(
            inteface,
            ctx->pe->object,
            "classes[%i].base_types[%i]",
            out_idx,
            base_type_idx++);

        yr_free(inteface);
      }
    }
  }
  yr_set_integer(
      base_type_idx,
      ctx->pe->object,
      "classes[%i].number_of_base_types",
      out_idx);
}

// Returns true if all parameters were correctly parsed
static bool parse_method_params(
    const CLASS_CONTEXT* ctx,
    uint32_t param_list,
    uint32_t method_idx,  // used for output
    uint32_t class_idx,
    uint32_t param_count,
    const uint8_t* sig_data,
    uint32_t sig_len,
    GENERIC_PARAMETERS* class_gen_params,
    GENERIC_PARAMETERS* method_gen_params)
{
  if (!param_list)  // NULL
    return true;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  // Array to hold all the possible parameters
  PARAMETERS* params = yr_calloc(param_count, sizeof(PARAMETERS));

  if (params == NULL && param_count > 0)
    return false;

  for (uint32_t idx = 0; idx < param_count; ++idx)
  {
    const uint8_t* data = get_table_offset(
        &ctx->tables->param, param_list + idx);

    char* name = NULL;
    bool alloc = false;  // Flag if name needs freeing

    if (data)  // We need param table mostly just for the param name
    {
      PARAM_ROW row = {0};
      bool result = read_param(ctx, data, &row);

      if (!result)
      {  // Cleanup and return
        for (uint32_t j = 0; j < idx; ++j)
        {
          if (params[j].alloc)
            yr_free(params[j].name);

          yr_free(params[j].type);
        }
        yr_free(params);
        return false;
      }

      name = pe_get_dotnet_string(ctx->pe, str_heap, str_size, row.Name);
    }
    else  // We can reconstruct their type from the signature
          // and give them default name
    {
      alloc = true;
      SIMPLE_STR* ss = sstr_newf("P_%lu", idx);
      if (ss)
      {
        name = sstr_move(ss);
        sstr_free(ss);
      }
    }

    char* type = parse_signature_type(
        ctx, &sig_data, &sig_len, class_gen_params, method_gen_params, 0);

    params[idx].alloc = alloc;
    params[idx].name = name;
    params[idx].type = type;

    if (!type)  // If any param fails, whole parsing is aborted
    {
      for (uint32_t j = 0; j <= idx; ++j)
      {
        if (params[j].alloc)
          yr_free(params[j].name);

        yr_free(params[j].type);
      }
      yr_free(params);
      return false;
    }
  }

  // If we got all of them correctly, write to output and cleanup
  YR_OBJECT* out_obj = ctx->pe->object;
  yr_set_integer(
      param_count,
      out_obj,
      "classes[%i].methods[%i].number_of_parameters",
      class_idx,
      method_idx);

  for (uint32_t i = 0; i < param_count; ++i)
  {
    yr_set_string(
        params[i].name,
        out_obj,
        "classes[%i].methods[%i].parameters[%i].name",
        class_idx,
        method_idx,
        i);
    yr_set_string(
        params[i].type,
        out_obj,
        "classes[%i].methods[%i].parameters[%i].type",
        class_idx,
        method_idx,
        i);
    if (params[i].alloc)
      yr_free(params[i].name);

    yr_free(params[i].type);
  }

  yr_free(params);
  return true;
}

// Walks GenericParam table, finds all generic params for the MethodDef or
// TypeDef entry and allocates buffer with the Generic param names into result
static void parse_generic_params(
    const CLASS_CONTEXT* ctx,
    bool method,  // true means MethodDef, false TypeDef index
    uint32_t gen_idx,
    GENERIC_PARAMETERS* result)
{
  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  result->names = NULL;
  result->len = 0;

  // Walk the GenericParam table to find GenParameters of the class/method
  for (uint32_t idx = 0; idx < ctx->tables->genericparam.RowCount; ++idx)
  {
    const uint8_t* data = get_table_offset(&ctx->tables->genericparam, idx + 1);
    if (!data)
      goto cleanup;

    GENERICPARAM_ROW row = {0};
    bool read_result = read_genericparam(ctx, data, &row);
    if (!read_result)
      continue;

    // TypeOrMethodDef coded index
    uint8_t table = row.Owner & 0x1;
    // 0 == TypeDef 1 == MethodDef
    // Check if it's generic param of the type we want
    if (table == method && (row.Owner >> 1) == gen_idx)
    {
      char* name = pe_get_dotnet_string(ctx->pe, str_heap, str_size, row.Name);
      // name must be valid string
      if (!name || !*name)  // ERROR
        goto cleanup;

      result->len += 1;
      char** tmp = yr_realloc(result->names, result->len * sizeof(char*));
      if (!tmp)
        goto cleanup;

      // Update the collection
      result->names = tmp;
      result->names[result->len - 1] = name;
    }
  }
  return;

cleanup:
  yr_free(result->names);
  result->names = NULL;
  result->len = 0;
}

static void parse_methods(
    const CLASS_CONTEXT* ctx,
    uint32_t methodlist,
    uint32_t method_count,
    uint32_t class_idx,  // class index in the YARA output
    GENERIC_PARAMETERS* class_gen_params)
{
  if (!methodlist)
    return;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  uint32_t out_idx = 0;
  for (uint32_t idx = 0; idx < method_count; ++idx)
  {
    const uint8_t* data = get_table_offset(
        &ctx->tables->methoddef, methodlist + idx);

    if (!data)
      break;

    METHODDEF_ROW row = {0};
    bool result = read_methoddef(ctx, data, &row);
    if (!result)
      continue;

    const char* name = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Name);

    // Ignore invalid/empty names
    if (!name || !*name)
      continue;

    // Try to find generic params for the method
    GENERIC_PARAMETERS method_gen_params = {0};
    parse_generic_params(ctx, true, methodlist + idx, &method_gen_params);

    // Read the blob entry with signature data
    const uint8_t* sig_data = ctx->blob_heap + row.Signature;

    BLOB_PARSE_RESULT blob_res = dotnet_parse_blob_entry(ctx->pe, sig_data);
    sig_data += blob_res.size;
    uint32_t sig_len = blob_res.length;
    uint32_t param_count = 0;

    char* return_type = NULL;
    // If there is valid blob and at least minimum to parse
    // (flags, paramCount, retType) parse these basic information
    if (blob_res.size && sig_len >= 3)
    {
      uint8_t flags = read_u8(&sig_data);
      sig_len -= 1;
      if (flags & SIG_FLAG_GENERIC)
        // Generic param count, ignored as we get the
        // information from generic param table
        (void) read_blob_unsigned(&sig_data, &sig_len);

      // Regular param count
      param_count = read_blob_unsigned(&sig_data, &sig_len);
      return_type = parse_signature_type(
          ctx, &sig_data, &sig_len, class_gen_params, &method_gen_params, 0);
    }
    else  // Error, skip
      goto clean_next;

    // Sanity check for corrupted files
    if (!return_type || param_count > MAX_PARAM_COUNT)
      goto clean_next;

    result = parse_method_params(
        ctx,
        row.ParamList,
        out_idx,
        class_idx,
        param_count,
        sig_data,
        sig_len,
        class_gen_params,
        &method_gen_params);

    if (!result)
      goto clean_next;

    const char* visibility = get_method_visibility(row.Flags);
    uint32_t stat = (row.Flags & METHOD_ATTR_STATIC) != 0;
    uint32_t final = (row.Flags & METHOD_ATTR_FINAL) != 0;
    uint32_t virtual = (row.Flags & METHOD_ATTR_VIRTUAL) != 0;
    uint32_t abstract = (row.Flags & METHOD_ATTR_ABSTRACT) != 0;

    YR_OBJECT* out_obj = ctx->pe->object;
    yr_set_string(
        name, out_obj, "classes[%i].methods[%i].name", class_idx, out_idx);
    yr_set_string(
        visibility,
        out_obj,
        "classes[%i].methods[%i].visibility",
        class_idx,
        out_idx);
    yr_set_integer(
        stat, out_obj, "classes[%i].methods[%i].static", class_idx, out_idx);
    yr_set_integer(
        virtual,
        out_obj,
        "classes[%i].methods[%i].virtual",
        class_idx,
        out_idx);
    yr_set_integer(
        final, out_obj, "classes[%i].methods[%i].final", class_idx, out_idx);
    yr_set_integer(
        abstract,
        out_obj,
        "classes[%i].methods[%i].abstract",
        class_idx,
        out_idx);
    yr_set_integer(
        method_gen_params.len,
        out_obj,
        "classes[%i].methods[%i].number_of_generic_parameters",
        class_idx,
        out_idx);

    for (uint32_t i = 0; i < method_gen_params.len; ++i)
    {
      yr_set_string(
          method_gen_params.names[i],
          ctx->pe->object,
          "classes[%i].methods[%i].generic_parameters[%i]",
          class_idx,
          out_idx,
          i);
    }

    // Unset return type for constructors for FileInfo compatibility
    if (strcmp(name, ".ctor") != 0 && strcmp(name, ".cctor") != 0)
    {
      yr_set_string(
          return_type,
          out_obj,
          "classes[%i].methods[%i].return_type",
          class_idx,
          out_idx);
    }

    out_idx++;
  clean_next:
    yr_free(return_type);
    yr_free(method_gen_params.names);
  }

  yr_set_integer(
      out_idx, ctx->pe->object, "classes[%i].number_of_methods", class_idx);
}

// Walks NestedClass table, returns enclosing type fullname or NULL
static char* parse_enclosing_types(
    const CLASS_CONTEXT* ctx,
    uint32_t nested_idx,
    uint32_t depth)
{
  if (depth > MAX_NAMESPACE_DEPTH)
    return NULL;

  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  for (uint32_t idx = 0; idx < ctx->tables->nestedclass.RowCount; ++idx)
  {
    const uint8_t* nested_data = get_table_offset(
        &ctx->tables->nestedclass, idx + 1);

    NESTEDCLASS_ROW nested_row = {0};
    bool read_result = read_nestedclass(ctx, nested_data, &nested_row);
    if (!read_result)
      continue;

    // We found enclosing class, get the namespace
    if (nested_row.NestedClass == nested_idx)
    {
      const uint8_t* typedef_data = get_table_offset(
          &ctx->tables->typedef_, nested_row.EnclosingClass);

      TYPEDEF_ROW typedef_row = {0};
      bool result = read_typedef(ctx, typedef_data, &typedef_row);
      if (!result)
        break;

      const char* name = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, typedef_row.Name);

      // Skip the Module pseudo class
      if (name && strcmp(name, "<Module>") == 0)
        break;

      const char* namespace = pe_get_dotnet_string(
          ctx->pe, str_heap, str_size, typedef_row.Namespace);

      // Type might be further nested, try to find correct namespace,
      // check for self-reference
      if (is_nested(typedef_row.Flags) &&
          nested_row.EnclosingClass != nested_row.NestedClass)
      {
        char* nested_namespace = parse_enclosing_types(
            ctx, nested_row.EnclosingClass, depth + 1);

        char* tmp = create_full_name(namespace, nested_namespace);
        char* fullname = create_full_name(name, tmp);
        yr_free(nested_namespace);
        yr_free(tmp);
        return fullname;
      }

      return create_full_name(name, namespace);
    }
  }

  return NULL;
}

// Parses and reconstructs user defined types with their methods and base types
static void parse_user_types(const CLASS_CONTEXT* ctx)
{
  const uint8_t* str_heap = ctx->str_heap;
  uint32_t str_size = ctx->str_size;

  // Index for output tracking, we can't use
  // offset as some classes can get skipped
  uint32_t out_idx = 0;
  // skip first class as it's module pseudo class -> start at index 1
  for (uint32_t idx = 0; idx < ctx->tables->typedef_.RowCount; ++idx)
  {
    YR_OBJECT* out_obj = ctx->pe->object;
    // Tables indexing starts at 1
    const uint8_t* data = get_table_offset(&ctx->tables->typedef_, idx + 1);

    TYPEDEF_ROW row = {0};
    bool result = read_typedef(ctx, data, &row);
    if (!result)
      continue;

    const char* name = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Name);
    const char* type = get_typedef_type(row.Flags);

    // Ignore invalid types and invalid (empty) names
    if (!name || !*name || !type)
      continue;

    // If the type is generic, it will include ` at the end of a name
    // with number of generic arguments, just use the part before that
    const char* end = strchr(name, '`');
    // If the name will turn out empty, skip it and skip Module pseudo class
    if (end == name || strcmp(name, "<Module>") == 0)
      continue;

    if (end)
      yr_set_sized_string(
          name, end - name, out_obj, "classes[%i].name", out_idx);
    else
      yr_set_string(name, out_obj, "classes[%i].name", out_idx);

    char* fullname = NULL;
    char* namespace = pe_get_dotnet_string(
        ctx->pe, str_heap, str_size, row.Namespace);

    // Type might be nested, if so -> find correct namespace
    if (is_nested(row.Flags))
    {
      char* nested_namespace = parse_enclosing_types(ctx, idx + 1, 1);
      namespace = create_full_name(namespace, nested_namespace);
      yr_set_string(namespace, out_obj, "classes[%i].namespace", out_idx);
      fullname = create_full_name(name, namespace);
      yr_free(nested_namespace);
      yr_free(namespace);
    }
    else
    {
      yr_set_string(namespace, out_obj, "classes[%i].namespace", out_idx);
      fullname = create_full_name(name, namespace);
    }

    const char* visibility = get_type_visibility(row.Flags);
    uint32_t abstract = (row.Flags & TYPE_ATTR_ABSTRACT) != 0;
    uint32_t sealed = (row.Flags & TYPE_ATTR_SEALED) != 0;

    yr_set_string(fullname, out_obj, "classes[%i].fullname", out_idx);
    yr_set_string(visibility, out_obj, "classes[%i].visibility", out_idx);
    yr_set_string(type, out_obj, "classes[%i].type", out_idx);
    yr_set_integer(abstract, out_obj, "classes[%i].abstract", out_idx);
    yr_set_integer(sealed, out_obj, "classes[%i].sealed", out_idx);

    yr_free(fullname);

    // Find if type has any Generic parameters
    GENERIC_PARAMETERS gen_params = {0};
    parse_generic_params(ctx, false, idx + 1, &gen_params);

    yr_set_integer(
        gen_params.len,
        out_obj,
        "classes[%i].number_of_generic_parameters",
        out_idx);

    for (uint32_t i = 0; i < gen_params.len; ++i)
    {
      yr_set_string(
          gen_params.names[i],
          out_obj,
          "classes[%i].generic_parameters[%i]",
          out_idx,
          i);
    }
    // Find type and interfaces the type inherits
    parse_type_parents(ctx, row.Extends, idx + 1, out_idx, &gen_params);

    // To get the number of methods, we must peek where the MethodList
    // of the next type is, then there is next.MethodList - this.MethodList
    // number of methods, or if there is no following type,
    // the rest of the MethodDef table is used
    uint32_t method_count = 0;
    // If there is next method
    if (idx + 1 < ctx->tables->typedef_.RowCount)
    {
      const uint8_t* data = get_table_offset(&ctx->tables->typedef_, idx + 2);

      TYPEDEF_ROW next_row = {0};
      result = read_typedef(ctx, data, &next_row);

      // overflow check
      if (result && next_row.Method >= row.Method)
        method_count = next_row.Method - row.Method;
    }
    // overflow check - use the rest of the methods in the table
    else if (ctx->tables->methoddef.RowCount >= row.Method)
    {
      method_count = ctx->tables->methoddef.RowCount + 1 - row.Method;
    }

    // Sanity check for corrupted files
    if (method_count <= MAX_METHOD_COUNT)
      parse_methods(ctx, row.Method, method_count, out_idx, &gen_params);

    yr_free(gen_params.names);
    out_idx++;
  }

  yr_set_integer(out_idx, ctx->pe->object, "number_of_classes");
}

void dotnet_parse_guid(
    PE* pe,
    int64_t metadata_root,
    PSTREAM_HEADER guid_header)
{
  // GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
  char guid[37];
  int i = 0;

  const uint8_t* guid_offset = pe->data + metadata_root +
                               yr_le32toh(guid_header->Offset);

  DWORD guid_size = yr_le32toh(guid_header->Size);

  // Limit the number of GUIDs to 16.
  guid_size = yr_min(guid_size, 256);

  // Parse GUIDs if we have them. GUIDs are 16 bytes each.
  while (guid_size >= 16 && fits_in_pe(pe, guid_offset, 16))
  {
    sprintf(
        guid,
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        yr_le32toh(*(uint32_t*) guid_offset),
        yr_le16toh(*(uint16_t*) (guid_offset + 4)),
        yr_le16toh(*(uint16_t*) (guid_offset + 6)),
        *(guid_offset + 8),
        *(guid_offset + 9),
        *(guid_offset + 10),
        *(guid_offset + 11),
        *(guid_offset + 12),
        *(guid_offset + 13),
        *(guid_offset + 14),
        *(guid_offset + 15));

    guid[(16 * 2) + 4] = '\0';

    yr_set_string(guid, pe->object, "guids[%i]", i);

    i++;
    guid_size -= 16;
    guid_offset += 16;
  }

  yr_set_integer(i, pe->object, "number_of_guids");
}

void dotnet_parse_us(PE* pe, int64_t metadata_root, PSTREAM_HEADER us_header)
{
  BLOB_PARSE_RESULT blob_result;
  int i = 0;

  const uint32_t ush_sz = yr_le32toh(us_header->Size);

  const uint8_t* offset = pe->data + metadata_root +
                          yr_le32toh(us_header->Offset);
  const uint8_t* end_of_header = offset + ush_sz;

  // Make sure the header size is larger than 0 and its end is not past the
  // end of PE.
  if (ush_sz == 0 || !fits_in_pe(pe, offset, ush_sz))
    return;

  // The first entry MUST be single NULL byte.
  if (*offset != 0x00)
    return;

  offset++;

  while (offset < end_of_header)
  {
    blob_result = dotnet_parse_blob_entry(pe, offset);

    if (blob_result.size == 0)
      break;

    offset += blob_result.size;
    // There is an additional terminal byte which is 0x01 under certain
    // conditions - when any top bit in utf16 top byte is set.
    // The exact conditions are not relevant to our parsing but are
    // documented in ECMA-335 II.24.2.4.
    if (blob_result.length > 0)
      blob_result.length--;

    // Avoid empty strings, which usually happen as padding at the end of the
    // stream.
    if (blob_result.length > 0 && fits_in_pe(pe, offset, blob_result.length))
    {
      yr_set_sized_string(
          (char*) offset,
          blob_result.length,
          pe->object,
          "user_strings[%i]",
          i);

      offset += blob_result.length;
      i++;
    }
  }

  yr_set_integer(i, pe->object, "number_of_user_strings");
}

STREAMS dotnet_parse_stream_headers(
    PE* pe,
    int64_t offset,
    int64_t metadata_root,
    DWORD num_streams)
{
  PSTREAM_HEADER stream_header;
  STREAMS headers;

  char* start;
  char* eos;
  char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
  unsigned int i;

  memset(&headers, '\0', sizeof(STREAMS));
  headers.metadata_root = metadata_root;

  stream_header = (PSTREAM_HEADER) (pe->data + offset);

  for (i = 0; i < num_streams; i++)
  {
    if (!struct_fits_in_pe(pe, stream_header, STREAM_HEADER))
      break;

    start = (char*) stream_header->Name;

    if (!fits_in_pe(pe, start, DOTNET_STREAM_NAME_SIZE))
      break;

    eos = (char*) memmem((void*) start, DOTNET_STREAM_NAME_SIZE, "\0", 1);

    if (eos == NULL)
      break;

    strncpy(stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
    stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

    yr_set_string(stream_name, pe->object, "streams[%i].name", i);

    // Offset is relative to metadata_root.
    yr_set_integer(
        metadata_root + yr_le32toh(stream_header->Offset),
        pe->object,
        "streams[%i].offset",
        i);

    yr_set_integer(
        yr_le32toh(stream_header->Size), pe->object, "streams[%i].size", i);

    // Store necessary bits to parse these later. Not all tables will be
    // parsed, but are referenced from others. For example, the #Strings
    // stream is referenced from various tables in the #~ heap.
    //
    // #- is not documented but it represents unoptimized metadata stream. It
    // may contain additional tables such as FieldPtr, ParamPtr, MethodPtr or
    // PropertyPtr for indirect referencing. We already take into account these
    // tables and they do not interfere with anything we parse in this module.

    if ((strncmp(stream_name, "#~", 2) == 0 ||
         strncmp(stream_name, "#-", 2) == 0) &&
        headers.tilde == NULL)
      headers.tilde = stream_header;
    else if (strncmp(stream_name, "#GUID", 5) == 0)
      headers.guid = stream_header;
    else if (strncmp(stream_name, "#Strings", 8) == 0 && headers.string == NULL)
      headers.string = stream_header;
    else if (strncmp(stream_name, "#Blob", 5) == 0 && headers.blob == NULL)
      headers.blob = stream_header;
    else if (strncmp(stream_name, "#US", 3) == 0 && headers.us == NULL)
      headers.us = stream_header;

    // Stream name is padded to a multiple of 4.
    stream_header = (PSTREAM_HEADER) ((uint8_t*) stream_header +
                                      sizeof(STREAM_HEADER) +
                                      strlen(stream_name) + 4 -
                                      (strlen(stream_name) % 4));
  }

  yr_set_integer(i, pe->object, "number_of_streams");

  return headers;
}

// This is the second pass through the data for #~. The first pass collects
// information on the number of rows for tables which have coded indexes.
// This pass uses that information and the index_sizes to parse the tables
// of interest.
//
// Because the indexes can vary in size depending upon the number of rows in
// other tables it is impossible to use static sized structures. To deal with
// this hardcode the sizes of each table based upon the documentation (for the
// static sized portions) and use the variable sizes accordingly.

void dotnet_parse_tilde_2(
    PE* pe,
    PTILDE_HEADER tilde_header,
    int64_t resource_base,
    ROWS rows,
    INDEX_SIZES index_sizes,
    PSTREAMS streams)
{
  PMODULE_TABLE module_table;
  PASSEMBLY_TABLE assembly_table;
  PASSEMBLYREF_TABLE assemblyref_table;
  PFIELDRVA_TABLE fieldrva_table;
  PMANIFESTRESOURCE_TABLE manifestresource_table;
  PMODULEREF_TABLE moduleref_table;
  PCUSTOMATTRIBUTE_TABLE customattribute_table;
  PCONSTANT_TABLE constant_table;
  DWORD resource_size, implementation;

  // To save important data for future processing, initialize everything to 0
  TABLES tables = {0};

  char* name;
  char typelib[MAX_TYPELIB_SIZE + 1];
  unsigned int i;
  int bit_check;
  int matched_bits = 0;

  int64_t metadata_root = streams->metadata_root;
  int64_t resource_offset, field_offset;
  uint32_t row_size, row_count, counter, str_heap_size;

  const uint8_t* string_offset;
  const uint8_t* blob_offset;

  uint32_t num_rows = 0;
  uint32_t valid_rows = 0;
  uint32_t* row_offset = NULL;
  uint8_t* table_offset = NULL;
  uint8_t* row_ptr = NULL;

  // These are pointers and row sizes for tables of interest to us for special
  // parsing. For example, we are interested in pulling out any CustomAttributes
  // that are GUIDs so we need to be able to walk these tables. To find GUID
  // CustomAttributes you need to walk the CustomAttribute table and look for
  // any row with a Parent that indexes into the Assembly table and Type indexes
  // into the MemberRef table. Then you follow the index into the MemberRef
  // table and check the Class to make sure it indexes into TypeRef table. If it
  // does you follow that index and make sure the Name is "GuidAttribute". If
  // all that is valid then you can take the Value from the CustomAttribute
  // table to find out the index into the Blob stream and parse that.
  //
  // Luckily we can abuse the fact that the order of the tables is guaranteed
  // consistent (though some may not exist, but if they do exist they must exist
  // in a certain order). The order is defined by their position in the Valid
  // member of the tilde_header structure. By the time we are parsing the
  // CustomAttribute table we have already recorded the location of the TypeRef
  // and MemberRef tables, so we can follow the chain back up from
  // CustomAttribute through MemberRef to TypeRef.

  uint8_t* typeref_ptr = NULL;
  uint8_t* memberref_ptr = NULL;
  uint32_t typeref_row_size = 0;
  uint32_t memberref_row_size = 0;
  uint8_t* typeref_row = NULL;
  uint8_t* memberref_row = NULL;

  DWORD type_index;
  DWORD class_index;
  BLOB_PARSE_RESULT blob_result;
  DWORD blob_index;
  DWORD blob_length;

  // These are used to determine the size of coded indexes, which are the
  // dynamically sized columns for some tables. The coded indexes are
  // documented in ECMA-335 Section II.24.2.6.
  uint8_t index_size, index_size2;

  // Number of rows is the number of bits set to 1 in Valid.
  // Should use this technique:
  // http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
  // Count number of Rows size entries in header to skip over them
  for (i = 0; i < 64; i++)
    valid_rows += ((yr_le64toh(tilde_header->Valid) >> i) & 0x01);

  row_offset = (uint32_t*) (tilde_header + 1);
  table_offset = (uint8_t*) row_offset;
  table_offset += sizeof(uint32_t) * valid_rows;

  // Sometimes files have some sort of padding after, from DnSpy source
  // it's denoted by EXTRA_DATA 0x40 flag in heapflags
  // We then need to offset by 4 bytes, otherwise the analysis is wrong
  // https://github.com/dnSpy/dnSpy/blob/2b6dcfaf602fb8ca6462b8b6237fdfc0c74ad994/dnSpy/dnSpy/Hex/Files/DotNet/TablesHeaderDataImpl.cs
  // example: 1c2246af11000c3ce6b05ed6ba25060cbb00273c599428b98cf4013bdd82892f
  if (tilde_header->HeapSizes & HEAP_EXTRA_DATA)
    table_offset += 4;

#define DOTNET_STRING_INDEX(Name)                       \
  index_sizes.string == 2 ? yr_le16toh(Name.Name_Short) \
                          : yr_le32toh(Name.Name_Long)

  string_offset = pe->data + metadata_root +
                  yr_le32toh(streams->string->Offset);

  str_heap_size = yr_le32toh(streams->string->Size);

  // Now walk again this time parsing out what we care about.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    // If the Valid bit is not set for this table, skip it...
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

    if (!fits_in_pe(pe, row_offset + matched_bits, sizeof(uint32_t)))
      return;

    num_rows = yr_le32toh(*(row_offset + matched_bits));

    // Make sure that num_rows has a reasonable value. For example
    // edc05e49dd3810be67942b983455fd43 sets a large value for number of
    // rows for the BIT_MODULE section.
    if (num_rows > 15000)
      return;

    // Those tables which exist, but that we don't care about must be
    // skipped.
    //
    // Sadly, given the dynamic sizes of some columns we can not have well
    // defined structures for all tables and use them accordingly. To deal
    // with this manually move the table_offset pointer by the appropriate
    // number of bytes as described in the documentation for each table.
    //
    // The table structures are documented in ECMA-335 Section II.22.

    switch (bit_check)
    {
    case BIT_MODULE:
      module_table = (PMODULE_TABLE) table_offset;

      if (!struct_fits_in_pe(pe, module_table, MODULE_TABLE))
        break;

      name = pe_get_dotnet_string(
          pe,
          string_offset,
          str_heap_size,
          DOTNET_STRING_INDEX(module_table->Name));

      if (name != NULL)
        yr_set_string(name, pe->object, "module_name");

      row_size = 2 + index_sizes.string + (index_sizes.guid * 3);

      tables.module.Offset = table_offset;
      tables.module.RowCount = num_rows;
      tables.module.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPEREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.module),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.typeref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + (index_sizes.string * 2));
      typeref_row_size = row_size;
      typeref_ptr = table_offset;

      tables.typeref.Offset = table_offset;
      tables.typeref.RowCount = num_rows;
      tables.typeref.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPEDEF:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = 4 + (index_sizes.string * 2) + index_size + index_sizes.field +
                 index_sizes.methoddef;

      tables.typedef_.Offset = table_offset;
      tables.typedef_.RowCount = num_rows;
      tables.typedef_.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_FIELDPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.field) * num_rows;
      break;

    case BIT_FIELD:
      table_offset += (2 + (index_sizes.string) + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODDEFPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.methoddef) * num_rows;
      break;

    case BIT_METHODDEF:
      row_size = 4 + 2 + 2 + index_sizes.string + index_sizes.blob +
                 index_sizes.param;

      tables.methoddef.Offset = table_offset;
      tables.methoddef.RowCount = num_rows;
      tables.methoddef.RowSize = row_size;
      table_offset += row_size * num_rows;
      break;

    case BIT_PARAM:
      row_size = 2 + 2 + index_sizes.string;

      tables.param.Offset = table_offset;
      tables.param.RowCount = num_rows;
      tables.param.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_INTERFACEIMPL:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = index_sizes.typedef_ + index_size;

      tables.intefaceimpl.Offset = table_offset;
      tables.intefaceimpl.RowCount = num_rows;
      tables.intefaceimpl.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_MEMBERREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x03))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + index_sizes.string + index_sizes.blob);
      memberref_row_size = row_size;
      memberref_ptr = table_offset;
      table_offset += row_size * num_rows;
      break;

    case BIT_CONSTANT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.param),
          yr_le32toh(rows.field),
          yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      // Using 'i' is insufficent since we may skip certain constants and
      // it would give an inaccurate count in that case.
      counter = 0;
      row_size = (1 + 1 + index_size + index_sizes.blob);
      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        constant_table = (PCONSTANT_TABLE) row_ptr;

        // Only look for constants of type string.
        if (yr_le32toh(constant_table->Type) != TYPE_STRING)
        {
          row_ptr += row_size;
          continue;
        }

        // Get the blob offset and pull it out of the blob table.
        blob_offset = ((uint8_t*) constant_table) + 2 + index_size;

        if (index_sizes.blob == 4)
          blob_index = *(DWORD*) blob_offset;
        else
          // Cast the value (index into blob table) to a 32bit value.
          blob_index = (DWORD) (*(WORD*) blob_offset);

        // Everything checks out. Make sure the index into the blob field
        // is valid (non-null and within range).
        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset) + blob_index;

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);

        if (blob_result.size == 0)
        {
          row_ptr += row_size;
          continue;
        }

        blob_length = blob_result.length;
        blob_offset += blob_result.size;

        // Quick sanity check to make sure the blob entry is within bounds.
        if (blob_offset + blob_length >= pe->data + pe->data_size)
        {
          row_ptr += row_size;
          continue;
        }

        yr_set_sized_string(
            (char*) blob_offset,
            blob_result.length,
            pe->object,
            "constants[%i]",
            counter);

        counter++;
        row_ptr += row_size;
      }

      yr_set_integer(counter, pe->object, "number_of_constants");
      table_offset += row_size * num_rows;
      break;

    case BIT_CUSTOMATTRIBUTE:
      // index_size is size of the parent column.
      row_count = max_rows(
          21,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.field),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.param),
          yr_le32toh(rows.interfaceimpl),
          yr_le32toh(rows.memberref),
          yr_le32toh(rows.module),
          yr_le32toh(rows.property),
          yr_le32toh(rows.event),
          yr_le32toh(rows.standalonesig),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typespec),
          yr_le32toh(rows.assembly),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.file),
          yr_le32toh(rows.exportedtype),
          yr_le32toh(rows.manifestresource),
          yr_le32toh(rows.genericparam),
          yr_le32toh(rows.genericparamconstraint),
          yr_le32toh(rows.methodspec));

      if (row_count > (0xFFFF >> 0x05))
        index_size = 4;
      else
        index_size = 2;

      // index_size2 is size of the type column.
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x03))
        index_size2 = 4;
      else
        index_size2 = 2;

      row_size = (index_size + index_size2 + index_sizes.blob);

      if (typeref_ptr != NULL && memberref_ptr != NULL)
      {
        row_ptr = table_offset;

        for (i = 0; i < num_rows; i++)
        {
          if (!fits_in_pe(pe, row_ptr, row_size))
            break;

          // Check the Parent field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) row_ptr;

          if (index_size == 4)
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((*(DWORD*) customattribute_table & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }
          else
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((*(WORD*) customattribute_table & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }

          // Check the Type field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) (row_ptr +
                                                            index_size);

          if (index_size2 == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((*(DWORD*) customattribute_table & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            type_index = *(DWORD*) customattribute_table >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((*(WORD*) customattribute_table & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            type_index = (DWORD) ((*(WORD*) customattribute_table >> 3));
          }

          if (type_index > 0)
            type_index--;

          // Now follow the Type index into the MemberRef table.
          memberref_row = memberref_ptr + (memberref_row_size * type_index);

          if (!fits_in_pe(pe, memberref_row, memberref_row_size))
            break;

          if (index_sizes.memberref == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((*(DWORD*) memberref_row & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            class_index = *(DWORD*) memberref_row >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((*(WORD*) memberref_row & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            class_index = (DWORD) (*(WORD*) memberref_row >> 3);
          }

          if (class_index > 0)
            class_index--;

          // Now follow the Class index into the TypeRef table.
          typeref_row = typeref_ptr + (typeref_row_size * class_index);

          if (!fits_in_pe(pe, typeref_row, typeref_row_size))
            break;

          // Skip over the ResolutionScope and check the Name field,
          // which is an index into the Strings heap.
          row_count = max_rows(
              4,
              yr_le32toh(rows.module),
              yr_le32toh(rows.moduleref),
              yr_le32toh(rows.assemblyref),
              yr_le32toh(rows.typeref));

          if (row_count > (0xFFFF >> 0x02))
            typeref_row += 4;
          else
            typeref_row += 2;

          if (index_sizes.string == 4)
          {
            name = pe_get_dotnet_string(
                pe, string_offset, str_heap_size, *(DWORD*) typeref_row);
          }
          else
          {
            name = pe_get_dotnet_string(
                pe, string_offset, str_heap_size, *(WORD*) typeref_row);
          }

          if (name != NULL && strncmp(name, "GuidAttribute", 13) != 0)
          {
            row_ptr += row_size;
            continue;
          }

          // Get the Value field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) (row_ptr +
                                                            index_size +
                                                            index_size2);

          if (index_sizes.blob == 4)
            blob_index = *(DWORD*) customattribute_table;
          else
            // Cast the value (index into blob table) to a 32bit value.
            blob_index = (DWORD) (*(WORD*) customattribute_table);

          // Everything checks out. Make sure the index into the blob field
          // is valid (non-null and within range).
          blob_offset = pe->data + metadata_root +
                        yr_le32toh(streams->blob->Offset) + blob_index;

          // If index into blob is 0 or past the end of the blob stream, skip
          // it. We don't know the size of the blob entry yet because that is
          // encoded in the start.
          if (blob_index == 0x00 || blob_offset >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          blob_result = dotnet_parse_blob_entry(pe, blob_offset);

          if (blob_result.size == 0)
          {
            row_ptr += row_size;
            continue;
          }

          blob_length = blob_result.length;
          blob_offset += blob_result.size;

          // Quick sanity check to make sure the blob entry is within bounds
          // and its length is at least 3 (2 bytes for the 16 bits prolog and
          // 1 byte for the string length)
          if (blob_length < 3 ||
              blob_offset + blob_length >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          // Custom attributes MUST have a 16 bit prolog of 0x0001
          if (*(WORD*) blob_offset != 0x0001)
          {
            row_ptr += row_size;
            continue;
          }

          // The next byte after the 16 bit prolog is the length of the string.
          blob_offset += 2;
          uint8_t str_len = *blob_offset;

          // Increment blob_offset so that it points to the first byte of the
          // string.
          blob_offset += 1;

          if (blob_offset + str_len > pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          if (*blob_offset == 0xFF || *blob_offset == 0x00)
          {
            typelib[0] = '\0';
          }
          else
          {
            strncpy(typelib, (char*) blob_offset, str_len);
            typelib[str_len] = '\0';
          }

          yr_set_string(typelib, pe->object, "typelib");

          row_ptr += row_size;
        }
      }

      table_offset += row_size * num_rows;
      break;

    case BIT_FIELDMARSHAL:
      row_count = max_rows(2, yr_le32toh(rows.field), yr_le32toh(rows.param));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_DECLSECURITY:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.assembly));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_CLASSLAYOUT:
      table_offset += (2 + 4 + index_sizes.typedef_) * num_rows;
      break;

    case BIT_FIELDLAYOUT:
      table_offset += (4 + index_sizes.field) * num_rows;
      break;

    case BIT_STANDALONESIG:
      table_offset += (index_sizes.blob) * num_rows;
      break;

    case BIT_EVENTMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.event) * num_rows;
      break;

    case BIT_EVENTPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.event) * num_rows;
      break;

    case BIT_EVENT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.string + index_size) * num_rows;
      break;

    case BIT_PROPERTYMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTYPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTY:
      table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODSEMANTICS:
      row_count = max_rows(
          2, yr_le32toh(rows.event), yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.methoddef + index_size) * num_rows;
      break;

    case BIT_METHODIMPL:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.typedef_ + (index_size * 2)) * num_rows;
      break;

    case BIT_MODULEREF:
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the string if it is not
      // NULL. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        moduleref_table = (PMODULEREF_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, moduleref_table, MODULEREF_TABLE))
          break;

        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            DOTNET_STRING_INDEX(moduleref_table->Name));

        if (name != NULL)
        {
          yr_set_string(name, pe->object, "modulerefs[%i]", counter);
          counter++;
        }

        row_ptr += index_sizes.string;
      }

      yr_set_integer(counter, pe->object, "number_of_modulerefs");

      row_size = index_sizes.string;

      tables.moduleref.Offset = table_offset;
      tables.moduleref.RowCount = num_rows;
      tables.moduleref.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_TYPESPEC:
      row_size = index_sizes.blob;

      tables.typespec.Offset = table_offset;
      tables.typespec.RowCount = num_rows;
      tables.typespec.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_IMPLMAP:
      row_count = max_rows(
          2, yr_le32toh(rows.field), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.string +
                       index_sizes.moduleref) *
                      num_rows;
      break;

    case BIT_FIELDRVA:
      row_size = 4 + index_sizes.field;
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the field offset if it is
      // valid. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        fieldrva_table = (PFIELDRVA_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, fieldrva_table, FIELDRVA_TABLE))
          break;

        field_offset = pe_rva_to_offset(pe, fieldrva_table->RVA);

        if (field_offset >= 0)
        {
          yr_set_integer(
              field_offset, pe->object, "field_offsets[%i]", counter);
          counter++;
        }

        row_ptr += row_size;
      }

      yr_set_integer(counter, pe->object, "number_of_field_offsets");

      table_offset += row_size * num_rows;
      break;

    case BIT_ENCLOG:
      table_offset += (4 + 4) * num_rows;
      break;

    case BIT_ENCMAP:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLY:
      row_size =
          (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2));

      if (!fits_in_pe(pe, table_offset, row_size))
        break;

      row_ptr = table_offset;
      assembly_table = (PASSEMBLY_TABLE) table_offset;

      yr_set_integer(
          yr_le16toh(assembly_table->MajorVersion),
          pe->object,
          "assembly.version.major");
      yr_set_integer(
          yr_le16toh(assembly_table->MinorVersion),
          pe->object,
          "assembly.version.minor");
      yr_set_integer(
          yr_le16toh(assembly_table->BuildNumber),
          pe->object,
          "assembly.version.build_number");
      yr_set_integer(
          yr_le16toh(assembly_table->RevisionNumber),
          pe->object,
          "assembly.version.revision_number");

      // Can't use assembly_table here because the PublicKey comes before
      // Name and is a variable length field.

      if (index_sizes.string == 4)
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le32toh(*(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
                                  index_sizes.blob)));
      else
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le16toh(
                *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

      if (name != NULL)
        yr_set_string(name, pe->object, "assembly.name");

      // Culture comes after Name.
      if (index_sizes.string == 4)
      {
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le32toh(*(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
                                  index_sizes.blob + index_sizes.string)));
      }
      else
      {
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            yr_le16toh(*(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
                                 index_sizes.blob + index_sizes.string)));
      }

      // Sometimes it will be a zero length string. This is technically
      // against the specification but happens from time to time.
      if (name != NULL && strlen(name) > 0)
        yr_set_string(name, pe->object, "assembly.culture");

      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYPROCESSOR:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLYOS:
      table_offset += (4 + 4 + 4) * num_rows;
      break;

    case BIT_ASSEMBLYREF:
      row_size =
          (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) +
           (index_sizes.string * 2));

      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        assemblyref_table = (PASSEMBLYREF_TABLE) row_ptr;

        yr_set_integer(
            yr_le16toh(assemblyref_table->MajorVersion),
            pe->object,
            "assembly_refs[%i].version.major",
            i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->MinorVersion),
            pe->object,
            "assembly_refs[%i].version.minor",
            i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->BuildNumber),
            pe->object,
            "assembly_refs[%i].version.build_number",
            i);
        yr_set_integer(
            yr_le16toh(assemblyref_table->RevisionNumber),
            pe->object,
            "assembly_refs[%i].version.revision_number",
            i);

        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset);

        if (index_sizes.blob == 4)
          blob_offset += yr_le32toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Long);
        else
          blob_offset += yr_le16toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Short);

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);
        blob_offset += blob_result.size;

        if (blob_result.size == 0 ||
            !fits_in_pe(pe, blob_offset, blob_result.length))
        {
          row_ptr += row_size;
          continue;
        }

        // Avoid empty strings.
        if (blob_result.length > 0)
        {
          yr_set_sized_string(
              (char*) blob_offset,
              blob_result.length,
              pe->object,
              "assembly_refs[%i].public_key_or_token",
              i);
        }

        // Can't use assemblyref_table here because the PublicKey comes before
        // Name and is a variable length field.

        if (index_sizes.string == 4)
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              str_heap_size,
              yr_le32toh(
                  *(DWORD*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));
        else
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              str_heap_size,
              yr_le16toh(
                  *(WORD*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

        if (name != NULL)
          yr_set_string(name, pe->object, "assembly_refs[%i].name", i);

        row_ptr += row_size;
      }

      tables.assemblyref.Offset = table_offset;
      tables.assemblyref.RowCount = num_rows;
      tables.assemblyref.RowSize = row_size;

      yr_set_integer(i, pe->object, "number_of_assembly_refs");
      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYREFPROCESSOR:
      table_offset += (4 + index_sizes.assemblyrefprocessor) * num_rows;
      break;

    case BIT_ASSEMBLYREFOS:
      table_offset += (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
      break;

    case BIT_FILE:
      table_offset += (4 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_EXPORTEDTYPE:
      row_count = max_rows(
          3,
          yr_le32toh(rows.file),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.exportedtype));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (4 + 4 + (index_sizes.string * 2) + index_size) *
                      num_rows;
      break;

    case BIT_MANIFESTRESOURCE:
      // This is an Implementation coded index with no 3rd bit specified.
      row_count = max_rows(
          2, yr_le32toh(rows.file), yr_le32toh(rows.assemblyref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (4 + 4 + index_sizes.string + index_size);
      row_ptr = table_offset;

      // First DWORD is the offset.
      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;

        if (index_size == 4)
          implementation = yr_le32toh(
              *(DWORD*) (row_ptr + 4 + 4 + index_sizes.string));
        else
          implementation = yr_le16toh(
              *(WORD*) (row_ptr + 4 + 4 + index_sizes.string));

        row_ptr += row_size;

        name = pe_get_dotnet_string(
            pe,
            string_offset,
            str_heap_size,
            DOTNET_STRING_INDEX(manifestresource_table->Name));

        if (name != NULL)
          yr_set_string(name, pe->object, "resources[%i].name", i);

        // Only set offset and length if it is in this file, otherwise continue
        // with the next resource.
        if (implementation != 0)
          continue;

        resource_offset = yr_le32toh(manifestresource_table->Offset);

        if (!fits_in_pe(
                pe, pe->data + resource_base + resource_offset, sizeof(DWORD)))
          continue;

        resource_size = yr_le32toh(
            *(DWORD*) (pe->data + resource_base + resource_offset));

        // Add 4 to skip the size.
        yr_set_integer(
            resource_base + resource_offset + 4,
            pe->object,
            "resources[%i].offset",
            i);

        yr_set_integer(resource_size, pe->object, "resources[%i].length", i);
      }

      yr_set_integer(i, pe->object, "number_of_resources");

      table_offset += row_size * num_rows;
      break;

    case BIT_NESTEDCLASS:
      row_size = index_sizes.typedef_ * 2;

      tables.nestedclass.Offset = table_offset;
      tables.nestedclass.RowCount = num_rows;
      tables.nestedclass.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_GENERICPARAM:
      row_count = max_rows(
          2, yr_le32toh(rows.typedef_), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      row_size = (2 + 2 + index_size + index_sizes.string);

      tables.genericparam.Offset = table_offset;
      tables.genericparam.RowCount = num_rows;
      tables.genericparam.RowSize = row_size;

      table_offset += row_size * num_rows;
      break;

    case BIT_METHODSPEC:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_GENERICPARAMCONSTRAINT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.genericparam + index_size) * num_rows;
      break;

    default:
      // printf("Unknown bit: %i\n", bit_check);
      return;
    }

    matched_bits++;
  }

  CLASS_CONTEXT class_context = {
      .pe = pe,
      .tables = &tables,
      .index_sizes = &index_sizes,
      .str_heap = string_offset,
      .str_size = str_heap_size,
      .blob_heap = pe->data + streams->metadata_root +
                   yr_le32toh(streams->blob->Offset),
      .blob_size = yr_le32toh(streams->blob->Size)};

  parse_user_types(&class_context);
}

// Parsing the #~ stream is done in two parts. The first part (this function)
// parses enough of the Stream to provide context for the second pass. In
// particular it is collecting the number of rows for each of the tables. The
// second part parses the actual tables of interest.

void dotnet_parse_tilde(PE* pe, PCLI_HEADER cli_header, PSTREAMS streams)
{
  PTILDE_HEADER tilde_header;
  int64_t resource_base;
  int64_t metadata_root = streams->metadata_root;
  uint32_t* row_offset = NULL;

  int bit_check;

  // This is used as an offset into the rows and tables. For every bit set in
  // Valid this will be incremented. This is because the bit position doesn't
  // matter, just the number of bits that are set, when determining how many
  // rows and what the table structure is.
  int matched_bits = 0;

  // We need to know the number of rows for some tables, because they are
  // indexed into. The index will be either 2 or 4 bytes, depending upon the
  // number of rows being indexed into.
  ROWS rows;
  INDEX_SIZES index_sizes;
  uint32_t heap_sizes;

  // Default all rows to 0. They will be set to actual values later on, if
  // they exist in the file.
  memset(&rows, '\0', sizeof(ROWS));

  // Default index sizes are 2. Will be bumped to 4 if necessary.
  memset(&index_sizes, 2, sizeof(index_sizes));

  tilde_header = (PTILDE_HEADER) (pe->data + metadata_root +
                                  yr_le32toh(streams->tilde->Offset));

  if (!struct_fits_in_pe(pe, tilde_header, TILDE_HEADER))
    return;

  heap_sizes = yr_le32toh(tilde_header->HeapSizes);

  // Set index sizes for various heaps.
  if (heap_sizes & 0x01)
    index_sizes.string = 4;

  if (heap_sizes & 0x02)
    index_sizes.guid = 4;

  if (heap_sizes & 0x04)
    index_sizes.blob = 4;

  // Immediately after the tilde header is an array of 32bit values which
  // indicate how many rows are in each table. The tables are immediately
  // after the rows array.
  //
  // Save the row offset.
  row_offset = (uint32_t*) (tilde_header + 1);

  // Walk all the bits first because we need to know the number of rows for
  // some tables in order to parse others. In particular this applies to
  // coded indexes, which are documented in ECMA-335 II.24.2.6.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

#define ROW_CHECK(name)                                                  \
  if (fits_in_pe(pe, row_offset, (matched_bits + 1) * sizeof(uint32_t))) \
    rows.name = *(row_offset + matched_bits);

#define ROW_CHECK_WITH_INDEX(name)    \
  ROW_CHECK(name);                    \
  if (yr_le32toh(rows.name) > 0xFFFF) \
    index_sizes.name = 4;

    switch (bit_check)
    {
    case BIT_MODULE:
      ROW_CHECK_WITH_INDEX(module);
      break;
    case BIT_MODULEREF:
      ROW_CHECK_WITH_INDEX(moduleref);
      break;
    case BIT_ASSEMBLYREF:
      ROW_CHECK_WITH_INDEX(assemblyref);
      break;
    case BIT_ASSEMBLYREFPROCESSOR:
      ROW_CHECK_WITH_INDEX(assemblyrefprocessor);
      break;
    case BIT_TYPEREF:
      ROW_CHECK_WITH_INDEX(typeref);
      break;
    case BIT_METHODDEF:
      ROW_CHECK_WITH_INDEX(methoddef);
      break;
    case BIT_MEMBERREF:
      ROW_CHECK_WITH_INDEX(memberref);
      break;
    case BIT_TYPEDEF:
      ROW_CHECK_WITH_INDEX(typedef_);
      break;
    case BIT_TYPESPEC:
      ROW_CHECK_WITH_INDEX(typespec);
      break;
    case BIT_FIELD:
      ROW_CHECK_WITH_INDEX(field);
      break;
    case BIT_PARAM:
      ROW_CHECK_WITH_INDEX(param);
      break;
    case BIT_PROPERTY:
      ROW_CHECK_WITH_INDEX(property);
      break;
    case BIT_INTERFACEIMPL:
      ROW_CHECK_WITH_INDEX(interfaceimpl);
      break;
    case BIT_EVENT:
      ROW_CHECK_WITH_INDEX(event);
      break;
    case BIT_STANDALONESIG:
      ROW_CHECK(standalonesig);
      break;
    case BIT_ASSEMBLY:
      ROW_CHECK_WITH_INDEX(assembly);
      break;
    case BIT_FILE:
      ROW_CHECK(file);
      break;
    case BIT_EXPORTEDTYPE:
      ROW_CHECK(exportedtype);
      break;
    case BIT_MANIFESTRESOURCE:
      ROW_CHECK(manifestresource);
      break;
    case BIT_GENERICPARAM:
      ROW_CHECK_WITH_INDEX(genericparam);
      break;
    case BIT_GENERICPARAMCONSTRAINT:
      ROW_CHECK(genericparamconstraint);
      break;
    case BIT_METHODSPEC:
      ROW_CHECK_WITH_INDEX(methodspec);
      break;
    default:
      break;
    }

    matched_bits++;
  }

  // This is used when parsing the MANIFEST RESOURCE table.
  resource_base = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->Resources.VirtualAddress));

  dotnet_parse_tilde_2(
      pe, tilde_header, resource_base, rows, index_sizes, streams);
}

static bool dotnet_is_dotnet(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

  if (!directory)
    return false;

  int64_t offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return false;

  CLI_HEADER* cli_header = (CLI_HEADER*) (pe->data + offset);

  if (yr_le32toh(cli_header->Size) != sizeof(CLI_HEADER))
    return false;

  int64_t metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));
  offset = metadata_root;

  if (!struct_fits_in_pe(pe, pe->data + metadata_root, NET_METADATA))
    return false;

  NET_METADATA* metadata = (NET_METADATA*) (pe->data + metadata_root);

  if (yr_le32toh(metadata->Magic) != NET_METADATA_MAGIC)
    return false;

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  uint32_t md_len = yr_le32toh(metadata->Length);
  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return false;
  }

  if (IS_64BITS_PE(pe))
  {
    if (yr_le32toh(OptionalHeader(pe, NumberOfRvaAndSizes)) <
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
      return false;
  }

  return true;
}

void dotnet_parse_com(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory;
  PCLI_HEADER cli_header;
  PNET_METADATA metadata;
  int64_t metadata_root, offset;
  char* end;
  STREAMS headers;
  WORD num_streams;
  uint32_t md_len;

  if (!dotnet_is_dotnet(pe))
  {
    yr_set_integer(0, pe->object, "is_dotnet");
    return;
  }

  yr_set_integer(1, pe->object, "is_dotnet");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
  if (directory == NULL)
    return;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return;

  cli_header = (PCLI_HEADER) (pe->data + offset);

  offset = metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));

  if (!struct_fits_in_pe(pe, pe->data + offset, NET_METADATA))
    return;

  metadata = (PNET_METADATA) (pe->data + offset);

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  md_len = yr_le32toh(metadata->Length);

  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return;
  }

  // The length includes the NULL terminator and is rounded up to a multiple of
  // 4. We need to exclude the terminator and the padding, so search for the
  // first NULL byte.
  end = (char*) memmem((void*) metadata->Version, md_len, "\0", 1);

  if (end != NULL)
    yr_set_sized_string(
        metadata->Version, (end - metadata->Version), pe->object, "version");

  // The metadata structure has some variable length records after the version.
  // We must manually parse things from here on out.
  //
  // Flags are 2 bytes (always 0).
  offset += sizeof(NET_METADATA) + md_len + 2;

  // 2 bytes for Streams.
  if (!fits_in_pe(pe, pe->data + offset, 2))
    return;

  num_streams = (WORD) * (pe->data + offset);
  offset += 2;

  headers = dotnet_parse_stream_headers(pe, offset, metadata_root, num_streams);

  if (headers.guid != NULL)
    dotnet_parse_guid(pe, metadata_root, headers.guid);

  // Parse the #~ stream, which includes various tables of interest.
  // These tables reference the blob and string streams, so we need to ensure
  // those are not NULL also.
  if (headers.tilde != NULL && headers.string != NULL && headers.blob != NULL)
    dotnet_parse_tilde(pe, cli_header, &headers);

  if (headers.us != NULL)
    dotnet_parse_us(pe, metadata_root, headers.us);
}

begin_declarations
  declare_integer("is_dotnet");
  declare_string("version");
  declare_string("module_name");

  begin_struct_array("streams")
    declare_string("name");
    declare_integer("offset");
    declare_integer("size");
  end_struct_array("streams")

  declare_integer("number_of_streams");

  declare_string_array("guids");
  declare_integer("number_of_guids");

  begin_struct_array("resources")
    declare_integer("offset");
    declare_integer("length");
    declare_string("name");
  end_struct_array("resources")

  declare_integer("number_of_resources");

  begin_struct_array("classes")
    declare_string("fullname");
    declare_string("name");
    declare_string("namespace");
    declare_string("visibility");
    declare_string("type");
    declare_integer("abstract");
    declare_integer("sealed");

    declare_integer("number_of_generic_parameters");
    declare_string_array("generic_parameters");

    declare_integer("number_of_base_types");
    declare_string_array("base_types");

    declare_integer("number_of_methods");
    begin_struct_array("methods")
      declare_string_array("generic_parameters");

      declare_integer("number_of_generic_parameters");

      begin_struct_array("parameters")
        declare_string("name");
        declare_string("type");
      end_struct_array("parameters")

      declare_integer("number_of_parameters");

      declare_string("return_type");
      declare_integer("abstract");
      declare_integer("final");
      declare_integer("virtual");
      declare_integer("static");
      declare_string("visibility");
      declare_string("name");
    end_struct_array("methods")

  end_struct_array("classes")

  declare_integer("number_of_classes");

  begin_struct_array("assembly_refs")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("public_key_or_token");
    declare_string("name");
  end_struct_array("assembly_refs")

  declare_integer("number_of_assembly_refs");

  begin_struct("assembly")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("name");
    declare_string("culture");
  end_struct("assembly")

  declare_string_array("modulerefs");
  declare_integer("number_of_modulerefs");
  declare_string_array("user_strings");
  declare_integer("number_of_user_strings");
  declare_string("typelib");
  declare_string_array("constants");
  declare_integer("number_of_constants");

  declare_integer_array("field_offsets");
  declare_integer("number_of_field_offsets");
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
  const uint8_t* block_data = NULL;

  foreach_memory_block(iterator, block)
  {
    PIMAGE_NT_HEADERS32 pe_header;

    block_data = yr_fetch_block_data(block);

    if (block_data == NULL)
      continue;

    pe_header = pe_get_header(block_data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        PE* pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        pe->data = block_data;
        pe->data_size = block->size;
        pe->object = module_object;
        pe->header = pe_header;

        module_object->data = pe;

        dotnet_parse_com(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  PE* pe = (PE*) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  yr_free(pe);

  return ERROR_SUCCESS;
}
