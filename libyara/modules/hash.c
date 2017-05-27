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

#include <openssl/md5.h>
#include <openssl/sha.h>

#if _WIN32 || __CYGWIN__

#ifndef PRIu64
#define PRIu64 "%I64d"
#endif

#ifndef PRIx64
#define PRIx64 "%I64x"
#endif

#else
#include <inttypes.h>
#endif


#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME hash


typedef struct _CACHE_KEY
{
  int64_t offset;
  int64_t length;

} CACHE_KEY;


void digest_to_ascii(
    unsigned char* digest,
    char* digest_ascii,
    size_t digest_length)
{
  size_t i;

  for (i = 0; i < digest_length; i++)
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);

  digest_ascii[digest_length * 2] = '\0';
}


char* get_from_cache(
    YR_OBJECT* module_object,
    const char* ns,
    int64_t offset,
    int64_t length)
{
  CACHE_KEY key;
  YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*) module_object->data;

  key.offset = offset;
  key.length = length;

  return (char*) yr_hash_table_lookup_raw_key(
      hash_table,
      &key,
      sizeof(key),
      ns);
}


int add_to_cache(
    YR_OBJECT* module_object,
    const char* ns,
    int64_t offset,
    int64_t length,
    const char* digest)
{
  CACHE_KEY key;
  YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*) module_object->data;

  char* copy = yr_strdup(digest);

  key.offset = offset;
  key.length = length;

  if (copy == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  return yr_hash_table_add_raw_key(
      hash_table,
      &key,
      sizeof(key),
      ns,
      (void*) copy);
}


define_function(string_md5)
{
  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];

  MD5_CTX md5_context;
  SIZED_STRING* s = sized_string_argument(1);

  MD5_Init(&md5_context);
  MD5_Update(&md5_context, s->c_string, s->length);
  MD5_Final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, MD5_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(string_sha256)
{
  unsigned char digest[SHA256_DIGEST_LENGTH];
  char digest_ascii[SHA256_DIGEST_LENGTH * 2 + 1];

  SHA256_CTX sha256_context;
  SIZED_STRING* s = sized_string_argument(1);

  SHA256_Init(&sha256_context);
  SHA256_Update(&sha256_context, s->c_string, s->length);
  SHA256_Final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, SHA256_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(string_sha1)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  char digest_ascii[SHA_DIGEST_LENGTH * 2 + 1];

  SHA_CTX sha_context;
  SIZED_STRING* s = sized_string_argument(1);

  SHA1_Init(&sha_context);
  SHA1_Update(&sha_context, s->c_string, s->length);
  SHA1_Final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, SHA_DIGEST_LENGTH);

  return_string(digest_ascii);
}


define_function(string_checksum32)
{
  size_t i;

  SIZED_STRING* s = sized_string_argument(1);
  uint32_t checksum = 0;

  for (i = 0; i < s->length; i++)
    checksum += (uint8_t)(s->c_string[i]);

  return_integer(checksum);
}


define_function(data_md5)
{
  MD5_CTX md5_context;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];
  char* cached_ascii_digest;

  int past_first_block = FALSE;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  MD5_Init(&md5_context);

  if (offset < 0 || length < 0 || offset < block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  cached_ascii_digest = get_from_cache(
      module(), "md5", arg_offset, arg_length);

  if (cached_ascii_digest != NULL)
    return_string(cached_ascii_digest);

  foreach_memory_block(iterator, block)
  {
    // if desired block within current block

    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

        offset += data_len;
        length -= data_len;

        MD5_Update(&md5_context, block_data + data_offset, data_len);
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.

      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_string(UNDEFINED);

  MD5_Final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, MD5_DIGEST_LENGTH);

  FAIL_ON_ERROR(
      add_to_cache(module(), "md5", arg_offset, arg_length, digest_ascii));

  return_string(digest_ascii);
}


define_function(data_sha1)
{
  SHA_CTX sha_context;

  unsigned char digest[SHA_DIGEST_LENGTH];
  char digest_ascii[SHA_DIGEST_LENGTH * 2 + 1];
  char* cached_ascii_digest;

  int past_first_block = FALSE;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  SHA1_Init(&sha_context);

  if (offset < 0 || length < 0 || offset < block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  cached_ascii_digest = get_from_cache(
      module(), "sha1", arg_offset, arg_length);

  if (cached_ascii_digest != NULL)
    return_string(cached_ascii_digest);

  foreach_memory_block(iterator, block)
  {
    // if desired block within current block
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(
          length, (size_t) block->size - data_offset);

        offset += data_len;
        length -= data_len;

        SHA1_Update(&sha_context, block_data + data_offset, data_len);
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.

      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_string(UNDEFINED);

  SHA1_Final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, SHA_DIGEST_LENGTH);

  FAIL_ON_ERROR(
      add_to_cache(module(), "sha1", arg_offset, arg_length, digest_ascii));

  return_string(digest_ascii);
}


define_function(data_sha256)
{
  SHA256_CTX sha256_context;

  unsigned char digest[SHA256_DIGEST_LENGTH];
  char digest_ascii[SHA256_DIGEST_LENGTH * 2 + 1];
  char* cached_ascii_digest;

  int past_first_block = FALSE;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  SHA256_Init(&sha256_context);

  if (offset < 0 || length < 0 || offset < block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  cached_ascii_digest = get_from_cache(
      module(), "sha256", arg_offset, arg_length);

  if (cached_ascii_digest != NULL)
    return_string(cached_ascii_digest);

  foreach_memory_block(iterator, block)
  {
    // if desired block within current block
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(length, block->size - data_offset);

        offset += data_len;
        length -= data_len;

        SHA256_Update(&sha256_context, block_data + data_offset, data_len);
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.

      return_string(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_string(UNDEFINED);

  SHA256_Final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, SHA256_DIGEST_LENGTH);

  FAIL_ON_ERROR(
      add_to_cache(module(), "sha256", arg_offset, arg_length, digest_ascii));

  return_string(digest_ascii);
}


define_function(data_checksum32)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  uint32_t checksum = 0;
  int past_first_block = FALSE;

  if (offset < 0 || length < 0 || offset < block->base)
  {
    return ERROR_WRONG_ARGUMENTS;
  }

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t i;

        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(length, block->size - data_offset);

        offset += data_len;
        length -= data_len;

        for (i = 0; i < data_len; i++)
          checksum += *(block_data + data_offset + i);
      }

      past_first_block = TRUE;
    }
    else if (past_first_block)
    {
      // If offset is not within current block and we already
      // past the first block then the we are trying to compute
      // the checksum over a range of non contiguous blocks. As
      // range contains gaps of undefined data the checksum is
      // undefined.

      return_integer(UNDEFINED);
    }

    if (block->base + block->size > offset + length)
      break;
  }

  if (!past_first_block)
    return_integer(UNDEFINED);

  return_integer(checksum);
}



begin_declarations;

  declare_function("md5", "ii", "s", data_md5);
  declare_function("md5", "s", "s", string_md5);

  declare_function("sha1", "ii", "s", data_sha1);
  declare_function("sha1", "s", "s", string_sha1);

  declare_function("sha256", "ii", "s", data_sha256);
  declare_function("sha256", "s", "s", string_sha256);

  declare_function("checksum32", "ii", "i", data_checksum32);
  declare_function("checksum32", "s", "i", string_checksum32);

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
  YR_HASH_TABLE* hash_table;

  FAIL_ON_ERROR(yr_hash_table_create(17, &hash_table));

  module_object->data = hash_table;

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*) module_object->data;

  if (hash_table != NULL)
    yr_hash_table_destroy(
        hash_table,
        (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_free);

  return ERROR_SUCCESS;
}
