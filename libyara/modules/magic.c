/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

The original idea and inspiration for this module comes from Armin Buescher.

*/

#include <yara/modules.h>
#include <magic.h>

#define MODULE_NAME magic

magic_t magic_cookie[YR_MAX_THREADS];

const char* cached_types[YR_MAX_THREADS];
const char* cached_mime_types[YR_MAX_THREADS];


define_function(magic_mime_type)
{
  YR_MEMORY_BLOCK* block;
  YR_SCAN_CONTEXT* context = scan_context();

  const uint8_t* block_data;

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(UNDEFINED);

  if (cached_mime_types[context->tidx] == NULL)
  {
    block = first_memory_block(context);
    block_data = block->fetch_data(block);

    if (block_data != NULL)
    {
      magic_setflags(magic_cookie[context->tidx], MAGIC_MIME_TYPE);

      cached_mime_types[context->tidx] = magic_buffer(
          magic_cookie[context->tidx],
          block_data,
          block->size);
    }
  }

  if (cached_mime_types[context->tidx] == NULL)
    return_string(UNDEFINED);

  return_string((char*) cached_mime_types[context->tidx]);
}


define_function(magic_type)
{
  YR_MEMORY_BLOCK* block;
  YR_SCAN_CONTEXT* context = scan_context();

  const uint8_t* block_data;

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(UNDEFINED);

  if (cached_types[context->tidx] == NULL)
  {
    block = first_memory_block(context);
    block_data = block->fetch_data(block);

    if (block_data != NULL)
    {
      magic_setflags(magic_cookie[context->tidx], 0);

      cached_types[context->tidx] = magic_buffer(
          magic_cookie[context->tidx],
          block_data,
          block->size);
    }
  }

  if (cached_types[context->tidx] == NULL)
    return_string(UNDEFINED);

  return_string((char*) cached_types[context->tidx]);
}

begin_declarations;

  declare_function("mime_type", "", "s", magic_mime_type);
  declare_function("type", "", "s", magic_type);

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  int i;

  for (i = 0; i < YR_MAX_THREADS; i++)
    magic_cookie[i] = NULL;

  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  int i;

  for (i = 0; i < YR_MAX_THREADS; i++)
    if (magic_cookie[i] != NULL)
      magic_close(magic_cookie[i]);

  return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  cached_types[context->tidx] = NULL;
  cached_mime_types[context->tidx] = NULL;

  if (magic_cookie[context->tidx] == NULL)
  {
    magic_cookie[context->tidx] = magic_open(0);

    if (magic_cookie[context->tidx] != NULL)
    {
      if (magic_load(magic_cookie[context->tidx], NULL) != 0)
      {
        magic_close(magic_cookie[context->tidx]);
        return ERROR_INTERNAL_FATAL_ERROR;
      }
    }
    else
    {
      return ERROR_INSUFFICIENT_MEMORY;
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}
