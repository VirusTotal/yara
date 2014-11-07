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
#include <openssl/md5.h>
#include <openssl/sha.h>

#if _WIN32
#define PRIu64 "%I64d"
#define PRIx64 "%I64x"
#else
#include <inttypes.h>
#endif

#include <yara/modules.h>

#define MODULE_NAME hash


void digest_to_ascii(
    unsigned char* digest,
    char* digest_ascii,
    size_t digest_length)
{
  for (int i = 0; i < digest_length; i++)
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);

  digest_ascii[digest_length * 2] = '\0';
}


define_function(string_md5)
{
  SIZED_STRING* s = sized_string_argument(1);

  if (IS_UNDEFINED(s))
    return_string(UNDEFINED);

  MD5_CTX md5_context;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];

  MD5_Init(&md5_context);
  MD5_Update(&md5_context, s->c_string, s->length);
  MD5_Final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, MD5_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(string_sha256)
{
  SIZED_STRING* s = sized_string_argument(1);

  if (IS_UNDEFINED(s))
    return_string(UNDEFINED);

  SHA256_CTX sha256_context;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  char digest_ascii[SHA256_DIGEST_LENGTH * 2 + 1];

  SHA256_Init(&sha256_context);
  SHA256_Update(&sha256_context, s->c_string, s->length);
  SHA256_Final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, SHA256_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(string_sha1)
{
  SIZED_STRING* s = sized_string_argument(1);

  if (IS_UNDEFINED(s))
    return_string(UNDEFINED);

  SHA_CTX sha_context;
  unsigned char digest[SHA_DIGEST_LENGTH];
  char digest_ascii[SHA_DIGEST_LENGTH * 2 + 1];

  SHA1_Init(&sha_context);
  SHA1_Update(&sha_context, s->c_string, s->length);
  SHA1_Final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, SHA_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(data_md5)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on

  YR_SCAN_CONTEXT*  context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  MD5_CTX md5_context;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];
  bool md5_updated = false;

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

      MD5_Update(&md5_context, block->data + data_offset, data_len);

      md5_updated = true;
    }
    else if (md5_updated)
    {
      // non contigous block
      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!md5_updated)
    return_string(UNDEFINED);

  MD5_Final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, MD5_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(data_sha1)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on

  YR_SCAN_CONTEXT*  context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  SHA_CTX sha_context;

  unsigned char digest[SHA_DIGEST_LENGTH];
  char digest_ascii[SHA_DIGEST_LENGTH * 2 + 1];
  bool sha_updated = false;

  SHA1_Init(&sha_context);

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

      SHA1_Update(&sha_context, block->data + data_offset, data_len);

      sha_updated = true;
    }
    else if (sha_updated)
    {
      // non-contigous
      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!sha_updated)
    return_string(UNDEFINED);

  SHA1_Final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, SHA_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(data_sha256)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on

  YR_SCAN_CONTEXT*  context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;

  SHA256_CTX sha256_context;

  unsigned char digest[SHA256_DIGEST_LENGTH];
  char digest_ascii[SHA256_DIGEST_LENGTH * 2 + 1];
  bool sha256_updated = false;

  SHA256_Init(&sha256_context);

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

      SHA256_Update(&sha256_context, block->data + data_offset, data_len);

      sha256_updated = true;
    }
    else if (sha256_updated)
    {
      // non-contigous
      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!sha256_updated)
    return_string(UNDEFINED);

  SHA256_Final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, SHA256_DIGEST_LENGTH);

  return_string(digest_ascii);
}




begin_declarations;

  declare_function("md5", "ii", "s", data_md5);
  declare_function("sha1", "ii", "s", data_sha1);
  declare_function("sha256", "ii", "s", data_sha256);

  declare_function("md5", "s", "s", string_md5);
  declare_function("sha1", "s", "s", string_sha1);
  declare_function("sha256", "s", "s", string_sha256);

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
