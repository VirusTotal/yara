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

#ifndef YR_SCAN_H
#define YR_SCAN_H

#include <yara/types.h>
#include <yara/hash.h>
#include <yara/rules.h>


#define SCAN_FLAGS_FAST_MODE		 1
#define SCAN_FLAGS_PROCESS_MEMORY    2


typedef struct _YR_SCAN_CONTEXT
{
  uint64_t  file_size;
  uint64_t  entry_point;

  int flags;
  void* user_data;

  YR_MEMORY_BLOCK*  mem_block;
  YR_HASH_TABLE*  objects_table;
  YR_CALLBACK_FUNC  callback;

} YR_SCAN_CONTEXT;


int yr_scan_verify_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t offset,
    YR_ARENA* matches_arena,
    int flags);

#endif