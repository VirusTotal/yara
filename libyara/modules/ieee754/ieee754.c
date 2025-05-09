#include <math.h>
#include <stdio.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME ieee754

const uint8_t* get_data(
  int64_t offset,
  size_t length,
  YR_SCAN_CONTEXT* context)
{
  bool past_first_block = false;

  size_t i;

  uint8_t* data = (uint8_t*) yr_calloc(length, sizeof(uint8_t));

  if (data == NULL)
    return NULL;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (block == NULL || offset < 0 || length < 0 || offset < block->base)
  {
    yr_free(data);
    return NULL;
  }

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base && offset < block->base + block->size)
    {
      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = yr_fetch_block_data(block);

      if (block_data == NULL)
      {
        yr_free(data);
        return NULL;
      }

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
        data[i] = *(block_data + data_offset + i);

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the distribution over a range of non contiguous blocks. As
      // range contains gaps of undefined data the distribution is
      // undefined.

      yr_free(data);
      return NULL;
    }

    if (block->base + block->size >= offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(data);
    return NULL;
  }

  return data;
}

const double binary_to_float(
  bool sign,
  int32_t exponent,
  int64_t mantissa,
  int32_t exponent_max,
  int16_t mantissa_digits)
{
  double result;

  if (exponent == 0)
    result = sign ? -mantissa * pow(2, 1 - exponent_max) : mantissa * pow(2, 1 - exponent_max);
  else if (exponent == 1 + 2 * exponent_max)
    result = mantissa ? NAN : (sign ? -INFINITY : INFINITY);
  else
    result = sign ? -(1 + mantissa * pow(2, 1 - mantissa_digits)) * pow(2, exponent - exponent_max)
                  : (1 + mantissa * pow(2, 1 - mantissa_digits)) * pow(2, exponent - exponent_max);

  return result;
}

define_function(parse_binary16le)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint16_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[1] >> 7) & 0x1;
  uint8_t exponent = (data[1] >> 2) & 0x1F;
  uint16_t mantissa = (uint16_t)((data[1] & 0x3) << 8) | data[0];
  return_float(binary_to_float(sign, exponent, mantissa, 15, 11));
}

define_function(parse_binary16be)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint16_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[0] >> 7) & 0x1;
  uint8_t exponent = (data[0] >> 2) & 0x1F;
  uint16_t mantissa = (uint16_t)((data[0] & 0x3) << 8) | data[1];
  return_float(binary_to_float(sign, exponent, mantissa, 15, 11));
}

define_function(parse_binary32le)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint32_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[3] >> 7) & 0x1;
  uint8_t exponent = ((data[3] & 0x7F) << 1) | (data[2] >> 7);
  uint32_t mantissa = (uint32_t)((data[2] & 0x7F) << 16) | (uint32_t)(data[1] << 8) | data[0];
  return_float(binary_to_float(sign, exponent, mantissa, 127, 24));
}

define_function(parse_binary32be)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint32_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[0] >> 7) & 0x1;
  uint8_t exponent = ((data[0] & 0x7F) << 1) | (data[1] >> 7);
  uint32_t mantissa = (uint32_t)((data[1] & 0x7F) << 16) | (uint32_t)(data[2] << 8) | data[3];
  return_float(binary_to_float(sign, exponent, mantissa, 127, 24));
}

define_function(parse_binary64le)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint64_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[7] >> 7) & 0x1;
  uint16_t exponent = ((uint16_t)(data[7] & 0x7F) << 4) | ((data[6] >> 4) & 0xF);
  uint64_t mantissa = ((uint64_t)(data[6] & 0xF) << 48) | ((uint64_t)data[5] << 40) |
                      ((uint64_t)data[4] << 32) | ((uint64_t)data[3] << 24) |
                      ((uint64_t)data[2] << 16) | ((uint64_t)data[1] << 8) | data[0];
  return_float(binary_to_float(sign, exponent, mantissa, 1023, 53));
}

define_function(parse_binary64be)
{
  int64_t offset = integer_argument(1);
  YR_SCAN_CONTEXT* context = yr_scan_context();
  const uint8_t* data = get_data(offset, sizeof(uint64_t), context);
  if (data == NULL)
    return_float(YR_UNDEFINED);

  bool sign = (data[0] >> 7) & 0x1;
  uint16_t exponent = ((uint16_t)(data[0] & 0x7F) << 4) | ((data[1] >> 4) & 0xF);
  uint64_t mantissa = ((uint64_t)(data[1] & 0xF) << 48) | ((uint64_t)data[2] << 40) |
                      ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) |
                      ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | data[7];
  return_float(binary_to_float(sign, exponent, mantissa, 1023, 53));
}

begin_declarations;
  // Constants
  // declare_float("NAN");
  // declare_float("INF");
  // Functions
  declare_function("binary16le", "i", "f", parse_binary16le);
  declare_function("binary16be", "i", "f", parse_binary16be);
  declare_function("binary32le", "i", "f", parse_binary32le);
  declare_function("binary32be", "i", "f", parse_binary32be);
  declare_function("binary64le", "i", "f", parse_binary64le);
  declare_function("binary64be", "i", "f", parse_binary64be);
  // Aliases
  declare_function("float32le", "i", "f", parse_binary32le);
  declare_function("float32be", "i", "f", parse_binary32be);
  declare_function("double64le", "i", "f", parse_binary64le);
  declare_function("double64be", "i", "f", parse_binary64be);
end_declarations;

int module_load(
  YR_SCAN_CONTEXT* context,
  YR_OBJECT* module_object,
  void* module_data,
  size_t module_data_size)
{
  // yr_set_float(NAN, module_object, "NAN");
  // yr_set_float(INFINITY, module_object, "INF");
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}
