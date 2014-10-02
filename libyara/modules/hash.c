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
import "md5"

rule hash_test
{
    condition:
        md5.hash(0,0) == "d41d8cd98f00b204e9800998ecf8427e"
}

*/

#include <openssl/md5.h>
#include <yara/modules.h>

#define MODULE_NAME hash
#define MODULE_NAME_STR "hash"
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))


#ifdef HASH_DEBUG
#define DBG(FMT, ...) \
    fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \

#else
#define DBG(FMT, ... )
#endif



#define MD5_DIGEST_LENGTH 16
define_function(md5_hash)
{

  YR_SCAN_CONTEXT*  context = scan_context();
  YR_MEMORY_BLOCK* block = NULL;
  unsigned char digest[MD5_DIGEST_LENGTH];  /* message digest */
  char digest_ascii[MD5_DIGEST_LENGTH*2 + 1] = { 0,}; // (16*2) +1
  MD5_CTX md5_context;
  int i;
  int64_t offset = integer_argument(1);
  int64_t length = integer_argument(2);
  uint64_t read_length = 0;
  uint64_t block_pos = 0; // position within block

  DBG("offset=%llx, length=%lld \n", (long long) offset, (long long) length);
  MD5_Init(&md5_context);

  if (offset < 0 || length < 0 || offset < context->mem_block->base) {
    return ERROR_WRONG_ARGUMENTS;
  }

  foreach_memory_block(context, block)
  {
    block_pos = 0;

    // if we need to offset within the block
    if (offset > block->base) {
      read_length = MIN(offset - block->base, block->size);  // do not skip past end of block
      block_pos += read_length;  // update position within block

      DBG("md5_hash offset  data=%p  base=0x%zx size=%zd read_length=%lld \n",
             block->data,  block->base, block->size,
             (long long) read_length);

      if (offset > block->base)
        continue; // need to continue to next block
    }


    read_length = MIN(block->size, length);  // do not read past the end of the block
    length -= read_length;  // remove length from remaining length

    DBG("md5_hash update  data=%p  base=0x%zx size=%zd read_length=%lld \n",
           block->data,  block->base, block->size,
           (long long) read_length);

    MD5_Update(&md5_context, block->data + block_pos, read_length);


    if (length == 0)
      break; // done reading
  }

  MD5_Final(digest, &md5_context);

  // transform the binary digest to ascii
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(digest_ascii+(i*2), "%02x", digest[i]);
  }
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
