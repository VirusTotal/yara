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

/*
 * xordiff - search for XOR differentials of strings.  Useful for matching
 * known strings encrypted with an unknown XOR key of known key length.
 */

#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME xordiff

define_function(xordiff_match)
{
  int rv = 0;
  int64_t period = integer_argument(1);
  SIZED_STRING* pattern = sized_string_argument(2);

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (period < 0)
    return_integer(UNDEFINED);
  if (period >= pattern->length)
    return_integer(UNDEFINED);
  int64_t diff_length = pattern->length - period;
  uint8_t *diff = yr_malloc(diff_length);
  int64_t rembuf_length = diff_length + period;
  uint8_t *rembuf = yr_malloc(rembuf_length);
  if (!diff)
    return ERROR_INSUFFICIENT_MEMORY;
  for (int64_t i = 0; i < diff_length; i++) {
    diff[i] = (uint8_t)(pattern->c_string[i] ^ pattern->c_string[i+period]);
  }

  int64_t remaining = 0;
  foreach_memory_block(iterator, block)
  {
    const uint8_t *block_data = block->fetch_data(block);
    if (!block_data)
      continue;

    if (remaining > 0) {
      /* search across remaining bytes in rembuf and continue into block */
      for (int64_t i = 0;
           (i < remaining) &&
           (i + diff_length + period < remaining + block->size);
           i++) {
        for (int64_t j = 0; j < diff_length; j++) {
          if (i + j + period < remaining) {
            if ((rembuf[i+j] ^ rembuf[i+j+period]) != diff[j])
              goto next_i_1;
          } else if (i + j < remaining) {
            if ((rembuf[i+j] ^ block_data[i+j+period-remaining]) != diff[j])
              goto next_i_1;
          } else {
            if ((block_data[i+j-remaining] ^ block_data[i+j+period-remaining]) != diff[j])
              goto next_i_1;
          }
          if (j == diff_length - 1) {
            rv = 1;
            goto leave;
          }
        }
next_i_1:;
      }
    }
    /* do regular search completely contained within block */
    for (int64_t i = 0; i < block->size - diff_length - period; i++) {
      for (int64_t j = 0; j < diff_length; j++) {
        if ((block_data[i+j] ^ block_data[i+j+period]) != diff[j])
          goto next_i_2;
        if (j == diff_length - 1) {
          rv = 1;
          goto leave;
        }
      }
next_i_2:;
    }
    /* store remaining unsearched bytes at the end of block in rembuf */
    remaining = diff_length + period;
    if (block->size < remaining)
      remaining = block->size;
    memcpy(rembuf, &block_data[block->size - remaining], remaining);
  }

leave:
  yr_free(rembuf);
  yr_free(diff);
  return_integer(rv);
}



begin_declarations;

  declare_function("match", "is", "i", xordiff_match);

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
