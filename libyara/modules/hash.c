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

#include "../crypto.h"

#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME hash


typedef struct _CACHE_KEY
{
  int64_t offset;
  int64_t length;

} CACHE_KEY;


const uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


static void digest_to_ascii(
    unsigned char* digest,
    char* digest_ascii,
    size_t digest_length)
{
  size_t i;

  for (i = 0; i < digest_length; i++)
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);

  digest_ascii[digest_length * 2] = '\0';
}


static char* get_from_cache(
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


static int add_to_cache(
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
  unsigned char digest[YR_MD5_LEN];
  char digest_ascii[YR_MD5_LEN * 2 + 1];

  yr_md5_ctx md5_context;
  SIZED_STRING* s = sized_string_argument(1);

  yr_md5_init(&md5_context);
  yr_md5_update(&md5_context, s->c_string, s->length);
  yr_md5_final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, YR_MD5_LEN);

  return_string(digest_ascii);
}


define_function(string_sha256)
{
  unsigned char digest[YR_SHA256_LEN];
  char digest_ascii[YR_SHA256_LEN * 2 + 1];

  yr_sha256_ctx sha256_context;
  SIZED_STRING* s = sized_string_argument(1);

  yr_sha256_init(&sha256_context);
  yr_sha256_update(&sha256_context, s->c_string, s->length);
  yr_sha256_final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, YR_SHA256_LEN);

  return_string(digest_ascii);
}


define_function(string_sha1)
{
  unsigned char digest[YR_SHA1_LEN];
  char digest_ascii[YR_SHA1_LEN * 2 + 1];

  yr_sha1_ctx sha_context;
  SIZED_STRING* s = sized_string_argument(1);

  yr_sha1_init(&sha_context);
  yr_sha1_update(&sha_context, s->c_string, s->length);
  yr_sha1_final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, YR_SHA1_LEN);

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
  yr_md5_ctx md5_context;

  unsigned char digest[YR_MD5_LEN];
  char digest_ascii[YR_MD5_LEN * 2 + 1];
  char* cached_ascii_digest;

  bool past_first_block = false;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  yr_md5_init(&md5_context);

  if (offset < 0 || length < 0 || offset < block->base)
    return_string(UNDEFINED);

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
      const uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(
          length, (size_t) (block->size - data_offset));

        offset += data_len;
        length -= data_len;

        yr_md5_update(&md5_context, block_data + data_offset, data_len);
      }

      past_first_block = true;
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

  yr_md5_final(digest, &md5_context);

  digest_to_ascii(digest, digest_ascii, YR_MD5_LEN);

  FAIL_ON_ERROR(
      add_to_cache(module(), "md5", arg_offset, arg_length, digest_ascii));

  return_string(digest_ascii);
}


define_function(data_sha1)
{
  yr_sha1_ctx sha_context;

  unsigned char digest[YR_SHA1_LEN];
  char digest_ascii[YR_SHA1_LEN * 2 + 1];
  char* cached_ascii_digest;

  int past_first_block = false;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  yr_sha1_init(&sha_context);

  if (offset < 0 || length < 0 || offset < block->base)
    return_string(UNDEFINED);

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
      const uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(
          length, (size_t) block->size - data_offset);

        offset += data_len;
        length -= data_len;

        yr_sha1_update(&sha_context, block_data + data_offset, data_len);
      }

      past_first_block = true;
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

  yr_sha1_final(digest, &sha_context);

  digest_to_ascii(digest, digest_ascii, YR_SHA1_LEN);

  FAIL_ON_ERROR(
      add_to_cache(module(), "sha1", arg_offset, arg_length, digest_ascii));

  return_string(digest_ascii);
}


define_function(data_sha256)
{
  yr_sha256_ctx sha256_context;

  unsigned char digest[YR_SHA256_LEN];
  char digest_ascii[YR_SHA256_LEN * 2 + 1];
  char* cached_ascii_digest;

  int past_first_block = false;

  int64_t arg_offset = integer_argument(1);   // offset where to start
  int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

  int64_t offset = arg_offset;
  int64_t length = arg_length;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  yr_sha256_init(&sha256_context);

  if (offset < 0 || length < 0 || offset < block->base)
    return_string(UNDEFINED);

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
      const uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(length, block->size - data_offset);

        offset += data_len;
        length -= data_len;

        yr_sha256_update(&sha256_context, block_data + data_offset, data_len);
      }

      past_first_block = true;
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

  yr_sha256_final(digest, &sha256_context);

  digest_to_ascii(digest, digest_ascii, YR_SHA256_LEN);

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
  int past_first_block = false;

  if (offset < 0 || length < 0 || offset < block->base)
    return_integer(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      const uint8_t* block_data = block->fetch_data(block);

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

      past_first_block = true;
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


define_function(string_crc32)
{
  size_t i;
  SIZED_STRING* s = sized_string_argument(1);
  uint32_t checksum = 0xFFFFFFFF;

  for (i = 0; i < s->length; i++)
    checksum = crc32_tab[(checksum ^ (uint8_t)s->c_string[i]) & 0xFF] ^ (checksum >> 8);

  return_integer(checksum ^ 0xFFFFFFFF);
}


define_function(data_crc32)
{
  int64_t offset = integer_argument(1);   // offset where to start
  int64_t length = integer_argument(2);   // length of bytes we want hash on
  uint32_t checksum = 0xFFFFFFFF;

  YR_SCAN_CONTEXT* context = scan_context();
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  int past_first_block = false;

  if (offset < 0 || length < 0 || offset < block->base)
    return_integer(UNDEFINED);

  foreach_memory_block(iterator, block)
  {
    if (offset >= block->base &&
        offset < block->base + block->size)
    {
      const uint8_t* block_data = block->fetch_data(block);

      if (block_data != NULL)
      {
        size_t i;

        size_t data_offset = (size_t) (offset - block->base);
        size_t data_len = (size_t) yr_min(length, block->size - data_offset);

        offset += data_len;
        length -= data_len;

        for (i = 0; i < data_len; i++)
          checksum = crc32_tab[(checksum ^ *(block_data + data_offset + i)) & 0xFF] ^ (checksum >> 8);
      }

      past_first_block = true;
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

  return_integer(checksum ^ 0xFFFFFFFF);
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

  declare_function("crc32", "ii", "i", data_crc32);
  declare_function("crc32", "s", "i", string_crc32);

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
