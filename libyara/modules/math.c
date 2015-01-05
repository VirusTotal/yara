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

#define MODULE_NAME math

#define PI 3.141592653589793


define_function(string_entropy)
{
  int i;
  double x;
  uint32_t* data;
  double entropy = 0.0;
  SIZED_STRING* s = sized_string_argument(1);

  data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));
  if (data == NULL)
    return_double(UNDEFINED);

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
  return_double(entropy);
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

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  data = (uint32_t*) yr_calloc(256, sizeof(uint32_t));
  if (data == NULL)
    return_double(UNDEFINED);

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
      return_double(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
  {
    yr_free(data);
    return_double(UNDEFINED);
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
  return_double(entropy);
}


define_function(string_deviation)
{
  int i;
  double sum = 0.0;

  SIZED_STRING* s = sized_string_argument(1);
  double mean = double_argument(2);

  for (i = 0; i < s->length; i++)
    sum += fabs(((double) s->c_string[i]) - mean);

  return_double(((double) 1 / s->length) * sum);
}


define_function(data_deviation)
{
  int i;
  double sum = 0.0;
  bool past_first_block = false;
  uint64_t total_len = 0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);
  double mean = double_argument(3);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

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
        sum += fabs(((double) *(block->data + data_offset + i)) - mean);

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_double(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_double(UNDEFINED);

  return_double(((double) 1 / total_len) * sum);
}


define_function(string_mean)
{
  int i;
  double sum = 0.0;

  SIZED_STRING* s = sized_string_argument(1);

  for (i = 0; i < s->length; i++)
    sum += (double) s->c_string[i];


  return_double(sum / (double) s->length);
}


define_function(data_mean)
{
  int i;
  double sum = 0.0;
  bool past_first_block = false;
  uint64_t total_len = 0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

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
        sum += (double) *(block->data + data_offset + i);

      past_first_block = true;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguos blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_double(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_double(UNDEFINED);

  return_double(sum / (double) total_len);
}


define_function(data_serial_correlation)
{
  int i;
  double scc, sccun, scclast, scct1, scct2, scct3;
  bool past_first_block = false;
  bool first_byte = true;
  uint64_t total_len = 0;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  scct1 = scct2 = scct3 = 0.0;
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
        sccun = (double) *(block->data + data_offset + i);
        if (first_byte)
          first_byte = false;
        else
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
      // the checksum over a range of non contiguos blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.
      return_double(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_double(UNDEFINED);

  scct1 += scclast * sccun;
  scct2 *= scct2;
  scc = total_len * scct3 - scct2;
  if (scc == 0)
    scc = -100000;
  else
    scc = (total_len * scct1 - scct2) / scc;

  return_double(scc);
}


define_function(string_serial_correlation)
{
  int i;
  bool first_byte = true;
  double scc, sccun, scclast, scct1, scct2, scct3;
  SIZED_STRING* s = sized_string_argument(1);

  scct1 = scct2 = scct3 = 0.0;
  for (i = 0; i < s->length; i++)
  {
    sccun = (double) s->c_string[i];
    if (first_byte)
      first_byte = false;
    else
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

  return_double(scc);
}


define_function(data_monte_carlo_pi)
{
  int i, j;
  bool past_first_block = false;
  unsigned int monte[6];
  int idx = 0;
  int mcount = 0;
  int inmont = 0;
  double incirc = pow(pow(256.0, 3.0) - 1, 2.0);
  double mx, my, mpi;

  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  foreach_memory_block(context, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = min(length, block->size - data_offset);

      offset += data_len;
      length -= data_len;

      for (i = 0; i < data_len; i++)
      {
        monte[idx++] = (unsigned int) *(block->data + data_offset + i);
        if (idx == 6)
        {
          idx = 0;
          mcount++;
          mx = my = 0;
          for (j = 0; j < 3; j++)
          {
            mx = (mx * 256.0) + monte[j];
            my = (my * 256.0) + monte[j + 3];
          }
          if ((mx * mx + my * my) <= incirc)
            inmont++;
        }
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
      return_double(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_double(UNDEFINED);

  mpi = 4.0 * ((double) inmont / mcount);
  return_double(fabs((mpi - PI) / PI));
}


define_function(string_monte_carlo_pi)
{
  int i, j;
  unsigned int monte[6];
  int idx = 0;
  int mcount = 0;
  int inmont = 0;
  double incirc = pow(pow(256.0, 3.0) - 1, 2.0);
  double mx, my, mpi;

  SIZED_STRING* s = sized_string_argument(1);

  for (i = 0; i < s->length; i++)
  {
    monte[idx++] = (unsigned int) s->c_string[i];
    if (idx == 6)
    {
      idx = 0;
      mcount++;
      mx = my = 0;
      for (j = 0; j < 3; j++)
      {
        mx = (mx * 256.0) + monte[j];
        my = (my * 256.0) + monte[j + 3];
      }
      if ((mx * mx + my * my) <= incirc)
        inmont++;
    }
  }

  mpi = 4.0 * ((double) inmont / mcount);
  return_double(fabs((mpi - PI) / PI));
}


define_function(in_range)
{
  double test = double_argument(1);
  double lower = double_argument(2);
  double upper = double_argument(3);

  return_integer((lower <= test && test <= upper) ? 1 : 0);
}


begin_declarations;

  declare_double("MEAN_BYTES");
  declare_function("in_range", "ddd", "i", in_range);
  declare_function("deviation", "iid", "d", data_deviation);
  declare_function("deviation", "sd", "d", string_deviation);
  declare_function("mean", "ii", "d", data_mean);
  declare_function("mean", "s", "d", string_mean);
  declare_function("serial_correlation", "ii", "d", data_serial_correlation);
  declare_function("serial_correlation", "s", "d", string_serial_correlation);
  declare_function("monte_carlo_pi", "ii", "d", data_monte_carlo_pi);
  declare_function("monte_carlo_pi", "s", "d", string_monte_carlo_pi);
  declare_function("entropy", "ii", "d", data_entropy);
  declare_function("entropy", "s", "d", string_entropy);

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
  set_double(127.5, module_object, "MEAN_BYTES");
  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
