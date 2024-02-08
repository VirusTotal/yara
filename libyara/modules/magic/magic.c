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

#include <magic.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME magic

// Thread-local storage key used to store a pointer to a MAGIC_CACHE struct.
YR_THREAD_STORAGE_KEY magic_tls;

typedef struct
{
  magic_t magic_cookie;
  const char* cached_type;
  const char* cached_mime_type;

} MAGIC_CACHE;

static int get_cache(MAGIC_CACHE** cache)
{
  *cache = (MAGIC_CACHE*) yr_thread_storage_get_value(&magic_tls);

  if (*cache == NULL)
  {
    *cache = (MAGIC_CACHE*) yr_malloc(sizeof(MAGIC_CACHE));

    if (*cache == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    (*cache)->magic_cookie = magic_open(0);

    if ((*cache)->magic_cookie == NULL)
    {
      yr_free(*cache);
      return ERROR_INSUFFICIENT_MEMORY;
    }

    if (magic_load((*cache)->magic_cookie, NULL) != 0)
    {
      magic_close((*cache)->magic_cookie);
      yr_free(*cache);
      return ERROR_INTERNAL_FATAL_ERROR;
    }

    (*cache)->cached_type = NULL;
    (*cache)->cached_mime_type = NULL;

    return yr_thread_storage_set_value(&magic_tls, *cache);
  }

  return ERROR_SUCCESS;
}

define_function(magic_mime_type)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block;
  MAGIC_CACHE* cache;

  const uint8_t* block_data;

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(YR_UNDEFINED);

  FAIL_ON_ERROR(get_cache(&cache));

  if (cache->cached_mime_type == NULL)
  {
    block = first_memory_block(context);

    if (block == NULL)
      return_string(YR_UNDEFINED);

    block_data = yr_fetch_block_data(block);

    if (block_data != NULL)
    {
      magic_setflags(cache->magic_cookie, MAGIC_MIME_TYPE);

      const char* type = magic_buffer(
          cache->magic_cookie, block_data, block->size);

      cache->cached_mime_type = (type == NULL) ? NULL : yr_strdup(type);
    }
  }

  if (cache->cached_mime_type == NULL)
    return_string(YR_UNDEFINED);

  return_string((char*) cache->cached_mime_type);
}

define_function(magic_type)
{
  MAGIC_CACHE* cache;
  YR_MEMORY_BLOCK* block;
  YR_SCAN_CONTEXT* context = yr_scan_context();

  const uint8_t* block_data;

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(YR_UNDEFINED);

  FAIL_ON_ERROR(get_cache(&cache));

  if (cache->cached_type == NULL)
  {
    block = first_memory_block(context);

    if (block == NULL)
      return_string(YR_UNDEFINED);

    block_data = yr_fetch_block_data(block);

    if (block_data != NULL)
    {
      magic_setflags(cache->magic_cookie, 0);

      const char* type = magic_buffer(
          cache->magic_cookie, block_data, block->size);

      cache->cached_type = (type == NULL) ? NULL : yr_strdup(type);
    }
  }

  if (cache->cached_type == NULL)
    return_string(YR_UNDEFINED);

  return_string((char*) cache->cached_type);
}

begin_declarations
  declare_function("mime_type", "", "s", magic_mime_type);
  declare_function("type", "", "s", magic_type);
end_declarations

int module_initialize(YR_MODULE* module)
{
  return yr_thread_storage_create(&magic_tls);
}

int module_finalize(YR_MODULE* module)
{
  MAGIC_CACHE* cache = (MAGIC_CACHE*) yr_thread_storage_get_value(&magic_tls);

  if (cache != NULL)
  {
    magic_close(cache->magic_cookie);
    yr_free(cache);
  }

  return yr_thread_storage_destroy(&magic_tls);
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module)
{
  MAGIC_CACHE* cache = (MAGIC_CACHE*) yr_thread_storage_get_value(&magic_tls);

  if (cache != NULL)
  {
    if (cache->cached_type != NULL)
      yr_free((void*) cache->cached_type);

    if (cache->cached_mime_type != NULL)
      yr_free((void*) cache->cached_mime_type);

    cache->cached_type = NULL;
    cache->cached_mime_type = NULL;
  }

  return ERROR_SUCCESS;
}
