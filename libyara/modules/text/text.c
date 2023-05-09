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

#include <stdio.h>

#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/strutils.h>

#define MODULE_NAME text

define_function(data_text)
{
  int64_t arg_offset = integer_argument(1);  // offset where to start
  int64_t arg_length = integer_argument(2);  // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;
  int64_t index = 0;

  bool past_first_block = false;

  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  if (block == NULL)
  {
    return_string(YR_UNDEFINED);
  }

  if (offset < 0 || length < 0 || offset < block->base)
  {
    return_string(YR_UNDEFINED);
  }

  char* text = (char*) yr_calloc(length + 1, sizeof(char));

  foreach_memory_block(iterator, block)
  {
    // if desired block within current block
    if (offset >= block->base && offset < block->base + block->size)
    {
      const uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(
            length, (size_t) block->size - data_offset);

        offset += data_len;
        length -= data_len;

        memcpy(text + index, block_data + data_offset, data_len);
        index += data_len;
      }

      past_first_block = true;
    }
    else if (past_first_block)
    {
      return_string(YR_UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  return_string(text);
}

begin_declarations
  declare_function("text", "ii", "s", data_text);
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