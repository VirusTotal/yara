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



MD5 Modules usage acepts two agurments offset and length

mdh.hash(offset, length)

# to hash the entire file
mdh.hash(0, filesize)


#example below checking empty hash
import "hash"

rule hash_test
{
    condition:
        hash.md5(0,0) == "d41d8cd98f00b204e9800998ecf8427e"
}

*/

#include <stdbool.h>
#include <openssl/md5.h>

#if _WIN32
#define PRIu64 "%I64d"
#define PRIx64 "%I64x"
#else
#include <inttypes.h>
#endif

#include <yara/modules.h>

#define MODULE_NAME hash

#ifdef HASH_DEBUG
#define DBG(FMT, ...) \
    fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \

#else
#define DBG(FMT, ... )
#endif

#define MD5_DIGEST_LENGTH 16


define_function(md5_hash)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on

  YR_SCAN_CONTEXT*  context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  MD5_CTX md5_context;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];
  bool md5_updated = false;

  DBG("offset=%" PRIx64 ", length=%" PRIu64 "\n", offset, length);

  MD5_Init(&md5_context);

  if (offset < 0 || length < 0 || offset < context->mem_block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  foreach_memory_block(context, block)
  {
    // if desired block within current block
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint64_t data_offset = offset - block->base;
      uint64_t data_len = min(length, block->size - data_offset);

      offset += data_len;
      length -= data_len;

      DBG("update data=%p length=%" PRIu64 "\n",
          block->data + data_offset,
          data_len);

      MD5_Update(&md5_context, block->data + data_offset, data_len);

      md5_updated = true;
    }
    else if (md5_updated)
    {
      // non contigous block
      DBG("undefined =%zu\n", block->base);

      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!md5_updated)
    return_string(UNDEFINED);

  MD5_Final(digest, &md5_context);

  // transform the binary digest to ascii
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
  }

  digest_ascii[32] = '\0';

  DBG("md5 hash result=%s\n", digest_ascii);
  return_string(digest_ascii);
}


begin_declarations;

  declare_function("md5", "ii", "s", md5_hash)

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
