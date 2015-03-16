/*
Copyright (c) 2014-2015. The YARA Authors. All Rights Reserved.

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

#include <math.h>

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
  SIZED_STRING* s = sized_string_argument(1);

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return_float(UNDEFINED);

  for (int i = 0; i < s->length; i++)
  {
    uint8_t c = s->c_string[i];
    data[c] += 1;
  }

  double entropy = 0.0;

  for (int i = 0; i < 256; i++)
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
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want entropy on

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  uint32_t* data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));

  if (data == NULL)
    return_float(UNDEFINED);

  int past_first_block = FALSE;
  uint64_t total_len = 0;

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = yr_min(length, block->size - data_offset);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (int i = 0; i < data_len; i++)
      {
        uint8_t c = *(block->data + data_offset + i);
        data[c] += 1;
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
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

  double entropy = 0.0;

  for (int i = 0; i < 256; i++)
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

  for (int i = 0; i < s->length; i++)
    sum += fabs(((double) s->c_string[i]) - mean);

  return_float(sum / s->length);
}


define_function(data_deviation)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  double mean = float_argument(3);
  double sum = 0.0;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  int past_first_block = FALSE;
  uint64_t total_len = 0;

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = yr_min(length, block->size - data_offset);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (int i = 0; i < data_len; i++)
        sum += fabs(((double) *(block->data + data_offset + i)) - mean);

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
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
  SIZED_STRING* s = sized_string_argument(1);

  double sum = 0.0;

  for (int i = 0; i < s->length; i++)
    sum += (double) s->c_string[i];

  return_float(sum / s->length);
}


define_function(data_mean)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  int past_first_block = FALSE;
  uint64_t total_len = 0;
  double sum = 0.0;

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = yr_min(length, block->size - data_offset);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (int i = 0; i < data_len; i++)
        sum += (double) *(block->data + data_offset + i);

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
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
  int past_first_block = FALSE;
  uint64_t total_len = 0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  double sccun = 0;
  double scclast = 0;
  double scct1 = 0;
  double scct2 = 0;
  double scct3 = 0;

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = yr_min(length, block->size - data_offset);

      total_len += data_len;
      offset += data_len;
      length -= data_len;

      for (int i = 0; i < data_len; i++)
      {
        sccun = (double) *(block->data + data_offset + i);
        scct1 += scclast * sccun;
        scct2 += sccun;
        scct3 += sccun * sccun;
        scclast = sccun;
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
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

  double scc = total_len * scct3 - scct2;

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

  for (int i = 0; i < s->length; i++)
  {
    sccun = (double) s->c_string[i];
    scct1 += scclast * sccun;
    scct2 += sccun;
    scct3 += sccun * sccun;
    scclast = sccun;
  }

  scct1 += scclast * sccun;
  scct2 *= scct2;

  double scc = s->length * scct3 - scct2;

  if (scc == 0)
    scc = -100000;
  else
    scc = (s->length * scct1 - scct2) / scc;

  return_float(scc);
}


define_function(data_monte_carlo_pi)
{
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  double INCIRC = pow(pow(256.0, 3.0) - 1, 2.0);

  int mcount = 0;
  int inmont = 0;

  int past_first_block = FALSE;

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = yr_min(length, block->size - data_offset);

      offset += data_len;
      length -= data_len;

      unsigned int monte[6];

      for (int i = 0; i < data_len; i++)
      {
        monte[i % 6] = (unsigned int) *(block->data + data_offset + i);

        if (i % 6 == 5)
        {
          mcount++;

          double mx = 0;
          double my = 0;

          for (int j = 0; j < 3; j++)
          {
            mx = (mx * 256.0) + monte[j];
            my = (my * 256.0) + monte[j + 3];
          }

          if ((mx * mx + my * my) <= INCIRC)
            inmont++;
        }
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_float(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_float(UNDEFINED);

  double mpi = 4.0 * ((double) inmont / mcount);

  return_float(fabs((mpi - PI) / PI));
}


define_function(string_monte_carlo_pi)
{
  SIZED_STRING* s = sized_string_argument(1);

  double INCIRC = pow(pow(256.0, 3.0) - 1, 2.0);
  unsigned int monte[6];

  int mcount = 0;
  int inmont = 0;

  for (int i = 0; i < s->length; i++)
  {
    monte[i % 6] = (unsigned int) s->c_string[i];

    if (i % 6 == 5)
    {
      mcount++;

      double mx = 0;
      double my = 0;

      for (int j = 0; j < 3; j++)
      {
        mx = (mx * 256.0) + monte[j];
        my = (my * 256.0) + monte[j + 3];
      }

      if ((mx * mx + my * my) <= INCIRC)
        inmont++;
    }
  }

  double mpi = 4.0 * ((double) inmont / mcount);
  return_float(fabs((mpi - PI) / PI));
}


define_function(in_range)
{
  double test = float_argument(1);
  double lower = float_argument(2);
  double upper = float_argument(3);

  return_integer((lower <= test && test <= upper) ? 1 : 0);
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
