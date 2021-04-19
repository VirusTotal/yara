/*
Copyright (c) 2021. The YARA Authors. All Rights Reserved.

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

#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME stats

uint32_t* get_distribution(int64_t offset, int64_t length, YR_SCAN_CONTEXT* context) {
  bool past_first_block = false;

  size_t i;

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL) {
    return NULL;
  }

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (offset < 0 || length < 0 || offset < block->base)
  {
    yr_free(data);
    return NULL;
  }

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base && offset < block->base + block->size)
    {
      size_t data_offset = (size_t)(offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t)(block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
      {
        yr_free(data);
        return NULL;
      }

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        uint8_t c = *(block_data + data_offset + i);
        data[c]++;
      }

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

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(data);
    return NULL;
  }
  return data;
}

uint32_t* get_distribution_global(YR_SCAN_CONTEXT* context) {

  size_t i;

  int64_t expected_next_offset = 0;

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return NULL;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  foreach_memory_block(iterator, block)
  {
    if (expected_next_offset != block->base)
    {
      // If offset is not directly after the current block then 
      // we are trying to compute the distribution over a range of non 
      // contiguous blocks. As the range contains gaps of 
      // undefined data the distribution is undefined.
      yr_free(data);
      return NULL;
    }
    const uint8_t* block_data = block->fetch_data(block);

    if (block_data == NULL)
    {
      yr_free(data);
      return NULL;
    }

    for (i = 0; i < block->size; i++)
    {
        uint8_t c = *(block_data + i);
        data[c] += 1;
    }
    expected_next_offset = block->base + block->size;
  }
  return data;
}

define_function(count_range)
{
  uint8_t byte = (uint8_t) integer_argument(1);
  int64_t offset = integer_argument(2);
  int64_t length = integer_argument(3);

  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);
  if (distribution == NULL)
  {
    return_integer(YR_UNDEFINED);
  }
  int64_t count = (int64_t) distribution[byte];
  yr_free(distribution);
  return_integer(count);
}

define_function(count_global)
{
  uint8_t byte = (uint8_t) integer_argument(1);

  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution_global(context);
  if (distribution == NULL)
  {
    return_integer(YR_UNDEFINED);
  }
  int64_t count = (int64_t) distribution[byte];
  yr_free(distribution);
  return_integer(count);
}

define_function(count_range_char)
{
  SIZED_STRING* s = sized_string_argument(1);
  int64_t offset = integer_argument(2);
  int64_t length = integer_argument(3);

  YR_SCAN_CONTEXT* context = scan_context();

  bool past_first_block = false;

  size_t i;

  int64_t count = 0;

  // Array to track matches that are currently ongoing. If matches_in_progress[i]
  // is set, it means that at the currently inspected index, the last i bytes matched
  // the first i bytes of the searched string.
  bool* matches_in_progress = (bool*) yr_calloc((size_t) s->length, sizeof(bool));
  if (matches_in_progress == NULL)
  {
    return_integer(YR_UNDEFINED);
  }

  size_t inspected_index;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (offset < 0 || length < 0 || offset < block->base)
  {
    yr_free(matches_in_progress);
    return_integer(YR_UNDEFINED);
  }

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base && offset < block->base + block->size)
    {
      size_t data_offset = (size_t)(offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t)(block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
      {
        yr_free(matches_in_progress);
        return_integer(YR_UNDEFINED);
      }

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        uint8_t c = *(block_data + data_offset + i);
        for (inspected_index = s->length - 1; inspected_index > 0; inspected_index--)
        {
          if (matches_in_progress[inspected_index - 1] && c == s->c_string[inspected_index])
          {
            matches_in_progress[inspected_index] = true;
            matches_in_progress[inspected_index - 1] = false;
          }
        }
        if (c == s->c_string[0])
        {
          matches_in_progress[0] = true;
        }
        if (matches_in_progress[s->length - 1])
        {
          count++;
          matches_in_progress[s->length - 1] = false;
        }
      }

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the distribution over a range of non contiguous blocks. As
      // range contains gaps of undefined data the distribution is
      // undefined.

      yr_free(matches_in_progress);
      return_integer(YR_UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(matches_in_progress);
    return_integer(YR_UNDEFINED);
  }
  return_integer(count);
}

define_function(count_global_char)
{
  SIZED_STRING* s = sized_string_argument(1);

  YR_SCAN_CONTEXT* context = scan_context();

  size_t i;
  int64_t count = 0;

  // Array to track matches that are currently ongoing. If matches_in_progress[i]
  // is set, it means that at the currently inspected index, the last i bytes matched
  // the first i bytes of the searched string.
  bool* matches_in_progress = (bool*) yr_calloc((size_t) s->length, sizeof(bool));
  if (matches_in_progress == NULL)
  {
    return_integer(YR_UNDEFINED);
  }
  size_t inspected_index;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  int64_t expected_next_offset = 0;

  foreach_memory_block(iterator, block)
  {
    if (expected_next_offset != block->base)
    {
      // If offset is not directly after the current block then 
      // we are trying to compute the distribution over a range of non 
      // contiguous blocks. As the range contains gaps of 
      // undefined data the distribution is undefined.
      yr_free(matches_in_progress);
      return_integer(YR_UNDEFINED);
    }
    const uint8_t* block_data = block->fetch_data(block);

    if (block_data == NULL)
    {
      yr_free(matches_in_progress);
      return_integer(YR_UNDEFINED);
    }

    for (i = 0; i < block->size; i++)
    {
      uint8_t c = *(block_data + i);
      for (inspected_index = s->length - 1; inspected_index > 0; inspected_index--)
      {
        if (matches_in_progress[inspected_index - 1] && c == s->c_string[inspected_index])
        {
          matches_in_progress[inspected_index] = true;
          matches_in_progress[inspected_index - 1] = false;
        }
      }
      if (c == s->c_string[0])
      {
        matches_in_progress[0] = true;
      }
      if (matches_in_progress[s->length - 1])
      {
        count++;
        matches_in_progress[s->length - 1] = false;
      }
    }
    expected_next_offset = block->base + block->size;
  }
  return_integer(count);
}

define_function(percentage_range)
{
  uint8_t byte = (uint8_t) integer_argument(1);
  int64_t offset = integer_argument(2);
  int64_t length = integer_argument(3);

  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);
  if (distribution == NULL) {
    return_float(YR_UNDEFINED);
  }
  int64_t count = (int64_t) distribution[byte];
  yr_free(distribution);
  return_float(((float) count) / ((float) length));
}

define_function(percentage_global)
{
  uint8_t byte = (uint8_t) integer_argument(1);

  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution_global(context);
  if (distribution == NULL) {
    return_float(YR_UNDEFINED);
  }
  int64_t count = (int64_t) distribution[byte];
  int64_t total_count = 0;
  int64_t i;
  for (i = 0; i < 256; i++) {
    total_count += distribution[i];
  }
  yr_free(distribution);
  return_float(((float) count) / ((float) total_count));
}

define_function(mode_range)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);
  if (distribution == NULL) {
    return_integer(YR_UNDEFINED);
  }

  int64_t most_common = 0;
  size_t i;
  for (i = 0; i < 256; i++)
  {
    if (distribution[i] > distribution[most_common])
    {
      most_common = (int64_t) i;
    }
  }
  yr_free(distribution);
  return_integer(most_common);
}

define_function(mode_global)
{
  YR_SCAN_CONTEXT* context = scan_context();

  uint32_t* distribution = get_distribution_global(context);
  if (distribution == NULL) {
    return_integer(YR_UNDEFINED);
  }

  int64_t most_common = 0;
  size_t i;
  for (i = 0; i < 256; i++)
  {
    if (distribution[i] > distribution[most_common])
    {
      most_common = (int64_t) i;
    }
  }
  yr_free(distribution);
  return_integer(most_common);
}

begin_declarations
  declare_function("count", "iii", "i", count_range);
  declare_function("count", "sii", "i", count_range_char);
  declare_function("count", "i", "i", count_global);
  declare_function("count", "s", "i", count_global_char);
  declare_function("percentage", "iii", "f", percentage_range);
  declare_function("percentage", "i", "f", percentage_global);
  declare_function("mode", "ii", "i", mode_range);
  declare_function("mode", "", "i", mode_global);
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
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
