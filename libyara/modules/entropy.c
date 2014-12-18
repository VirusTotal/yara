/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

#include <stdbool.h>
#include <math.h>

#include <yara/modules.h>
#include <yara/mem.h>

#define MODULE_NAME entropy


define_function(string_entropy)
{
  int i;
  double x;
  uint32_t* data;
  double entropy = 0.0;
  SIZED_STRING* s = sized_string_argument(1);

  if (IS_UNDEFINED(s))
    return_integer(UNDEFINED);

  data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));
  if (data == NULL)
    return_integer(UNDEFINED);

  for (i = 0; i < s->length; i++)
  {
    uint8_t c = s->c_string[i];
    data[c] += 1;
  }

  for (i = 0; i < 256; i++)
  {
    if (data[i] != 0)
    {
      x = (double) (data[i]) / s->length;
      entropy -= x * log2(x);
    }
  }

  yr_free(data);
  return_integer((int) entropy);
}


define_function(data_entropy)
{
  int i;
  double x;
  uint32_t* data;
  double entropy = 0.0;
  bool past_first_block = false;
  uint64_t total_len = 0;

  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want entropy on

  if (IS_UNDEFINED(offset) || IS_UNDEFINED(length))
    return_integer(UNDEFINED);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));
  if (data == NULL)
    return_integer(UNDEFINED);

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = min(length, block->size - data_offset);
      total_len += data_len;

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        uint8_t c = *(block->data + data_offset + i);
        data[c] += 1;
      }

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.

      yr_free(data);
      return_integer(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(data);
    return_integer(UNDEFINED);
  }

  for (i = 0; i < 256; i++)
  {
    if (data[i] != 0)
    {
      x = (double) (data[i]) / total_len;
      entropy -= x * log2(x);
    }
  }
  yr_free(data);
  return_integer((int) entropy);
}


begin_declarations;

  declare_function("entropy", "ii", "i", data_entropy);
  declare_function("entropy", "s", "i", string_entropy);

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

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
