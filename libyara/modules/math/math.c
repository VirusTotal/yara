/*
Copyright (c) 2014-2021. The YARA Authors. All Rights Reserved.

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

#include <math.h>
#include <stdlib.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#define MODULE_NAME math

#define PI 3.141592653589793
// This is more than enough space to hold the maximum signed 64bit integer as a
// string in decimal, hex or octal, including the sign and NULL terminator.
#define INT64_MAX_STRING 30

// log2 is not defined by math.h in VC++

#if defined(_MSC_VER) && _MSC_VER < 1800
static double log2(double n)
{
  return log(n) / log(2.0);
}
#endif

uint32_t* get_distribution(
    int64_t offset,
    int64_t length,
    YR_SCAN_CONTEXT* context)
{
  bool past_first_block = false;

  size_t i;

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

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
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = yr_fetch_block_data(block);

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

uint32_t* get_distribution_global(YR_SCAN_CONTEXT* context)
{
  size_t i;

  int64_t expected_next_offset = 0;

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return NULL;

  YR_MEMORY_BLOCK* block;
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
    const uint8_t* block_data = yr_fetch_block_data(block);

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

define_function(string_entropy)
{
  size_t i;
  double entropy = 0.0;

  SIZED_STRING* s = sized_string_argument(1);

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return_float(YR_UNDEFINED);

  for (i = 0; i < s->length; i++)
  {
    uint8_t c = s->c_string[i];
    data[c] += 1;
  }

  for (i = 0; i < 256; i++)
  {
    if (data[i] != 0)
    {
      double x = (double) (data[i]) / s->length;
      entropy -= x * log2(x);
    }
  }

  yr_free(data);
  return_float(entropy);
}

define_function(data_entropy)
{
  double entropy = 0.0;

  int64_t offset = integer_argument(1);  // offset where to start
  int64_t length = integer_argument(2);  // length of bytes we want entropy on

  YR_SCAN_CONTEXT* context = yr_scan_context();

  size_t i;

  size_t total_len = 0;

  uint32_t* data = get_distribution(offset, length, context);

  if (data == NULL)
    return_float(YR_UNDEFINED);

  for (i = 0; i < 256; i++)
  {
    total_len += data[i];
  }

  for (i = 0; i < 256; i++)
  {
    if (data[i] != 0)
    {
      double x = (double) (data[i]) / total_len;
      entropy -= x * log2(x);
    }
  }

  yr_free(data);
  return_float(entropy);
}

define_function(string_deviation)
{
  SIZED_STRING* s = sized_string_argument(1);

  double mean = float_argument(2);
  double sum = 0.0;

  size_t i;

  for (i = 0; i < s->length; i++) sum += fabs(((double) s->c_string[i]) - mean);

  return_float(sum / s->length);
}

define_function(data_deviation)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  double mean = float_argument(3);
  double sum = 0.0;

  size_t total_len = 0;
  size_t i;

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* data = get_distribution(offset, length, context);

  if (data == NULL)
    return_float(YR_UNDEFINED);

  for (i = 0; i < 256; i++)
  {
    total_len += data[i];
    sum += fabs(((double) i) - mean) * data[i];
  }

  yr_free(data);
  return_float(sum / total_len);
}

define_function(string_mean)
{
  size_t i;
  double sum = 0.0;

  SIZED_STRING* s = sized_string_argument(1);

  for (i = 0; i < s->length; i++) sum += (double) s->c_string[i];

  return_float(sum / s->length);
}

define_function(data_mean)
{
  double sum = 0.0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  size_t total_len = 0;
  size_t i;

  uint32_t* data = get_distribution(offset, length, context);

  if (data == NULL)
    return_float(YR_UNDEFINED);

  for (i = 0; i < 256; i++)
  {
    total_len += data[i];
    sum += ((double) i) * data[i];
  }

  yr_free(data);
  return_float(sum / total_len);
}

define_function(data_serial_correlation)
{
  int past_first_block = false;

  size_t total_len = 0;
  size_t i;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (block == NULL)
    return_float(YR_UNDEFINED);

  double sccun = 0;
  double sccfirst = 0;
  double scclast = 0;
  double scct1 = 0;
  double scct2 = 0;
  double scct3 = 0;
  double scc = 0;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(YR_UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base && offset < block->base + block->size)
    {
      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = yr_fetch_block_data(block);

      if (block_data == NULL)
        return_float(YR_UNDEFINED);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        sccun = (double) *(block_data + data_offset + i);
        if (i == 0)
        {
          sccfirst = sccun;
        }
        scct1 += scclast * sccun;
        scct2 += sccun;
        scct3 += sccun * sccun;
        scclast = sccun;
      }

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_float(YR_UNDEFINED);
    }

    if (block->base + block->size >= offset + length)
      break;
  }

  if (!past_first_block)
    return_float(YR_UNDEFINED);

  scct1 += scclast * sccfirst;
  scct2 *= scct2;

  scc = total_len * scct3 - scct2;

  if (scc == 0)
    scc = -100000;
  else
    scc = (total_len * scct1 - scct2) / scc;

  return_float(scc);
}

define_function(string_serial_correlation)
{
  SIZED_STRING* s = sized_string_argument(1);

  double sccun = 0;
  double scclast = 0;
  double scct1 = 0;
  double scct2 = 0;
  double scct3 = 0;
  double scc = 0;

  size_t i;

  for (i = 0; i < s->length; i++)
  {
    sccun = (double) s->c_string[i];
    scct1 += scclast * sccun;
    scct2 += sccun;
    scct3 += sccun * sccun;
    scclast = sccun;
  }

  if (s->length > 0)
  {
    scct1 += scclast * (double) s->c_string[0];
  }
  scct2 *= scct2;

  scc = s->length * scct3 - scct2;

  if (scc == 0)
    scc = -100000;
  else
    scc = (s->length * scct1 - scct2) / scc;

  return_float(scc);
}

define_function(data_monte_carlo_pi)
{
  int past_first_block = false;
  int mcount = 0;
  int inmont = 0;

  double INCIRC = pow(pow(256.0, 3.0) - 1, 2.0);
  double mpi = 0;

  size_t i;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (block == NULL)
    return_float(YR_UNDEFINED);

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(YR_UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base && offset < block->base + block->size)
    {
      unsigned int monte[6];

      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = yr_fetch_block_data(block);

      if (block_data == NULL)
        return_float(YR_UNDEFINED);

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        monte[i % 6] = (unsigned int) *(block_data + data_offset + i);

        if (i % 6 == 5)
        {
          double mx = 0;
          double my = 0;
          int j;

          mcount++;

          for (j = 0; j < 3; j++)
          {
            mx = (mx * 256.0) + monte[j];
            my = (my * 256.0) + monte[j + 3];
          }

          if ((mx * mx + my * my) <= INCIRC)
            inmont++;
        }
      }

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_float(YR_UNDEFINED);
    }

    if (block->base + block->size >= offset + length)
      break;
  }

  if (!past_first_block || mcount == 0)
    return_float(YR_UNDEFINED);

  mpi = 4.0 * ((double) inmont / mcount);

  return_float(fabs((mpi - PI) / PI));
}

define_function(string_monte_carlo_pi)
{
  SIZED_STRING* s = sized_string_argument(1);

  double INCIRC = pow(pow(256.0, 3.0) - 1, 2.0);
  double mpi = 0;

  unsigned int monte[6];

  int mcount = 0;
  int inmont = 0;

  size_t i;

  for (i = 0; i < s->length; i++)
  {
    monte[i % 6] = (unsigned int) s->c_string[i];

    if (i % 6 == 5)
    {
      double mx = 0;
      double my = 0;

      int j;

      mcount++;

      for (j = 0; j < 3; j++)
      {
        mx = (mx * 256.0) + monte[j];
        my = (my * 256.0) + monte[j + 3];
      }

      if ((mx * mx + my * my) <= INCIRC)
        inmont++;
    }
  }

  if (mcount == 0)
    return_float(YR_UNDEFINED);

  mpi = 4.0 * ((double) inmont / mcount);
  return_float(fabs((mpi - PI) / PI));
}

define_function(in_range)
{
  double test = float_argument(1);
  double lower = float_argument(2);
  double upper = float_argument(3);

  return_integer((lower <= test && test <= upper) ? 1 : 0);
}

// Undefine existing "min" and "max" macros in order to avoid conflicts with
// function names.
#undef min
#undef max

define_function(min)
{
  uint64_t i = integer_argument(1);
  uint64_t j = integer_argument(2);

  return_integer(i < j ? i : j);
}

define_function(max)
{
  uint64_t i = integer_argument(1);
  uint64_t j = integer_argument(2);

  return_integer(i > j ? i : j);
}

define_function(to_number)
{
  return_integer(integer_argument(1) ? 1 : 0);
}

define_function(yr_math_abs)
{
  return_integer(llabs(integer_argument(1)));
}

define_function(count_range)
{
  int64_t byte = integer_argument(1);
  int64_t offset = integer_argument(2);
  int64_t length = integer_argument(3);

  if (byte < 0 || byte > 255)
    return_integer(YR_UNDEFINED);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);

  if (distribution == NULL)
    return_integer(YR_UNDEFINED);

  int64_t count = (int64_t) distribution[byte];
  yr_free(distribution);
  return_integer(count);
}

define_function(count_global)
{
  int64_t byte = integer_argument(1);

  if (byte < 0 || byte > 255)
    return_integer(YR_UNDEFINED);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution_global(context);

  if (distribution == NULL)
    return_integer(YR_UNDEFINED);

  int64_t count = (int64_t) distribution[byte];
  yr_free(distribution);
  return_integer(count);
}

define_function(percentage_range)
{
  int64_t byte = integer_argument(1);
  int64_t offset = integer_argument(2);
  int64_t length = integer_argument(3);

  if (byte < 0 || byte > 255)
    return_float(YR_UNDEFINED);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);

  if (distribution == NULL)
    return_float(YR_UNDEFINED);

  int64_t count = (int64_t) distribution[byte];
  int64_t total_count = 0;
  int64_t i;

  for (i = 0; i < 256; i++) total_count += distribution[i];

  yr_free(distribution);
  return_float(((float) count) / ((float) total_count));
}

define_function(percentage_global)
{
  int64_t byte = integer_argument(1);

  if (byte < 0 || byte > 255)
    return_float(YR_UNDEFINED);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution_global(context);

  if (distribution == NULL)
    return_float(YR_UNDEFINED);

  int64_t count = (int64_t) distribution[byte];
  int64_t total_count = 0;
  int64_t i;

  for (i = 0; i < 256; i++) total_count += distribution[i];

  yr_free(distribution);
  return_float(((float) count) / ((float) total_count));
}

define_function(mode_range)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution(offset, length, context);

  if (distribution == NULL)
    return_integer(YR_UNDEFINED);

  int64_t most_common = 0;
  size_t i;

  for (i = 0; i < 256; i++)
  {
    if (distribution[i] > distribution[most_common])
      most_common = (int64_t) i;
  }

  yr_free(distribution);
  return_integer(most_common);
}

define_function(mode_global)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();

  uint32_t* distribution = get_distribution_global(context);

  if (distribution == NULL)
    return_integer(YR_UNDEFINED);

  int64_t most_common = 0;
  size_t i;

  for (i = 0; i < 256; i++)
  {
    if (distribution[i] > distribution[most_common])
      most_common = (int64_t) i;
  }

  yr_free(distribution);
  return_integer(most_common);
}

define_function(to_string)
{
  int64_t i = integer_argument(1);
  char str[INT64_MAX_STRING];
  snprintf(str, INT64_MAX_STRING, "%" PRId64, i);
  return_string(&str);
}

define_function(to_string_base)
{
  int64_t i = integer_argument(1);
  int64_t base = integer_argument(2);
  char str[INT64_MAX_STRING];
  char* fmt;
  switch (base)
  {
  case 10:
    fmt = "%" PRId64;
    break;
  case 8:
    fmt = "%" PRIo64;
    break;
  case 16:
    fmt = "%" PRIx64;
    break;
  default:
    return_string(YR_UNDEFINED);
  }
  snprintf(str, INT64_MAX_STRING, fmt, i);
  return_string(&str);
}

begin_declarations
  declare_float("MEAN_BYTES");
  declare_function("in_range", "fff", "i", in_range);
  declare_function("deviation", "iif", "f", data_deviation);
  declare_function("deviation", "sf", "f", string_deviation);
  declare_function("mean", "ii", "f", data_mean);
  declare_function("mean", "s", "f", string_mean);
  declare_function("serial_correlation", "ii", "f", data_serial_correlation);
  declare_function("serial_correlation", "s", "f", string_serial_correlation);
  declare_function("monte_carlo_pi", "ii", "f", data_monte_carlo_pi);
  declare_function("monte_carlo_pi", "s", "f", string_monte_carlo_pi);
  declare_function("entropy", "ii", "f", data_entropy);
  declare_function("entropy", "s", "f", string_entropy);
  declare_function("min", "ii", "i", min);
  declare_function("max", "ii", "i", max);
  declare_function("to_number", "b", "i", to_number);
  declare_function("abs", "i", "i", yr_math_abs);
  declare_function("count", "iii", "i", count_range);
  declare_function("count", "i", "i", count_global);
  declare_function("percentage", "iii", "f", percentage_range);
  declare_function("percentage", "i", "f", percentage_global);
  declare_function("mode", "ii", "i", mode_range);
  declare_function("mode", "", "i", mode_global);
  declare_function("to_string", "i", "s", to_string);
  declare_function("to_string", "ii", "s", to_string_base);
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
  yr_set_float(127.5, module_object, "MEAN_BYTES");
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
