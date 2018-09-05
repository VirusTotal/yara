/*
Copyright (c) 2014-2015. The YARA Authors. All Rights Reserved.

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

#include <yara/utils.h>
#include <yara/modules.h>
#include <yara/mem.h>

#define MODULE_NAME math

#define PI 3.141592653589793

// log2 is not defined by math.h in VC++

#ifdef _MSC_VER
double log2(double n)
{
  return log(n) / log(2.0);
}
#endif


define_function(string_entropy)
{
  size_t i;
  double entropy = 0.0;

  SIZED_STRING* s = sized_string_argument(1);

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return_float(UNDEFINED);

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
  bool past_first_block = false;
  double entropy = 0.0;

  size_t total_len = 0;
  size_t i;

  uint32_t* data;

  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want entropy on

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(UNDEFINED);

  data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return_float(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
      {
        yr_free(data);
        return_float(UNDEFINED);
      }

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        uint8_t c = *(block_data + data_offset + i);
        data[c] += 1;
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

      yr_free(data);
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(data);
    return_float(UNDEFINED);
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

  for (i = 0; i < s->length; i++)
    sum += fabs(((double) s->c_string[i]) - mean);

  return_float(sum / s->length);
}


define_function(data_deviation)
{
  int past_first_block = false;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  double mean = float_argument(3);
  double sum = 0.0;

  size_t total_len = 0;
  size_t i;

  size_t data_offset = 0;
  size_t data_len = 0;
  const uint8_t* block_data = NULL;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      data_offset = (size_t)(offset - block->base);
      data_len = (size_t)yr_min(
          length, (size_t)(block->size - data_offset));
      block_data = block->fetch_data(block);

      if (block_data == NULL)
        return_float(UNDEFINED);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
        sum += fabs(((double)* (block_data + data_offset + i)) - mean);

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_float(UNDEFINED);

  return_float(sum / total_len);
}


define_function(string_mean)
{
  size_t i;
  double sum = 0.0;

  SIZED_STRING* s = sized_string_argument(1);

  for (i = 0; i < s->length; i++)
    sum += (double) s->c_string[i];

  return_float(sum / s->length);
}


define_function(data_mean)
{
  int past_first_block = false;
  double sum = 0.0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  size_t total_len = 0;
  size_t i;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
        return_float(UNDEFINED);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
        sum += (double)* (block_data + data_offset + i);

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_float(UNDEFINED);

  return_float(sum / total_len);
}


define_function(data_serial_correlation)
{
  int past_first_block = false;

  size_t total_len = 0;
  size_t i;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  double sccun = 0;
  double scclast = 0;
  double scct1 = 0;
  double scct2 = 0;
  double scct3 = 0;
  double scc = 0;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      size_t data_offset = (size_t)(offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
        return_float(UNDEFINED);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        sccun = (double)* (block_data + data_offset + i);
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
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_float(UNDEFINED);

  scct1 += scclast * sccun;
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

  scct1 += scclast * sccun;
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

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (offset < 0 || length < 0 || offset < block->base)
    return_float(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      unsigned int monte[6];

      size_t data_offset = (size_t) (offset - block->base);
      size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

      const uint8_t* block_data = block->fetch_data(block);

      if (block_data == NULL)
        return_float(UNDEFINED);

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        monte[i % 6] = (unsigned int)* (block_data + data_offset + i);

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
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block || mcount == 0)
    return_float(UNDEFINED);

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
    return_float(UNDEFINED);

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


begin_declarations;

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
  set_float(127.5, module_object, "MEAN_BYTES");
  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
