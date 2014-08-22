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

/*

The original idea and inspiration for this module comes from Armin Buescher.

*/

#include <yara/modules.h>
#include <magic.h>

#define MODULE_NAME magic

magic_t magic_cookie[MAX_THREADS];

const char* cached_types[MAX_THREADS];
const char* cached_mime_types[MAX_THREADS];


define_function(magic_mime_type)
{
  YR_MEMORY_BLOCK* block;
  YR_SCAN_CONTEXT* context = scan_context();

  int tidx = yr_get_tidx();

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(UNDEFINED);

  if (cached_mime_types[tidx] == NULL)
  {
    block = first_memory_block(context);

    magic_setflags(magic_cookie[tidx], MAGIC_MIME_TYPE);

    cached_mime_types[tidx] = magic_buffer(
        magic_cookie[tidx],
        block->data,
        block->size);
  }

  return_string((char*) cached_mime_types[tidx]);
}


define_function(magic_type)
{
  YR_MEMORY_BLOCK* block;
  YR_SCAN_CONTEXT* context = scan_context();

  int tidx = yr_get_tidx();

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
    return_string(UNDEFINED);

  if (cached_types[tidx] == NULL)
  {
    block = first_memory_block(context);

    magic_setflags(magic_cookie[tidx], 0);

    cached_types[tidx] = magic_buffer(
        magic_cookie[tidx],
        block->data,
        block->size);
  }

  return_string((char*) cached_types[tidx]);
}

begin_declarations;

  declare_function("mime_type", "", "s", magic_mime_type);
  declare_function("type", "", "s", magic_type);

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  for (int i = 0; i < MAX_THREADS; i++)
    magic_cookie[i] = NULL;

  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  for (int i = 0; i < MAX_THREADS; i++)
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
  int tidx = yr_get_tidx();

  cached_types[tidx] = NULL;
  cached_mime_types[tidx] = NULL;

  if (magic_cookie[tidx] == NULL)
  {
    magic_cookie[tidx] = magic_open(0);

    if (magic_cookie[tidx] != NULL)
    {
      if (magic_load(magic_cookie[tidx], NULL) != 0)
      {
        magic_close(magic_cookie[tidx]);
        return ERROR_INTERNAL_FATAL_ERROR;
      }
    }
    else
    {
      return ERROR_INSUFICIENT_MEMORY;
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}
