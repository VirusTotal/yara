/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#ifndef YR_ARENA_H
#define YR_ARENA_H

#include <stdint.h>
#include <stddef.h>

#include "yara.h"

#define ARENA_FLAGS_FIXED_SIZE   1
#define ARENA_FLAGS_COALESCED    2


int yr_arena_create(
    size_t initial_size,
    int flags,
    YR_ARENA** arena);


void yr_arena_destroy(
    YR_ARENA* arena);


void* yr_arena_base_address(
  YR_ARENA* arena);


void* yr_arena_next_address(
  YR_ARENA* arena,
  void* address,
  int offset);


int yr_arena_coalesce(
    YR_ARENA* arena);


int yr_arena_allocate_memory(
    YR_ARENA* arena,
    size_t size,
    void** allocated_memory);


int yr_arena_allocate_struct(
    YR_ARENA* arena,
    size_t size,
    void** allocated_memory,
    ...);


int yr_arena_make_relocatable(
    YR_ARENA* arena,
    void* base,
    ...);


int yr_arena_write_data(
    YR_ARENA* arena,
    void* data,
    size_t size,
    void** written_data);


int yr_arena_write_string(
    YR_ARENA* arena,
    const char* string,
    char** written_string);


int yr_arena_append(
    YR_ARENA* target_arena,
    YR_ARENA* source_arena);


int yr_arena_save(
  YR_ARENA* arena,
  const char* filename);


int yr_arena_load(
    const char* filename,
    YR_ARENA** arena);


int yr_arena_duplicate(
    YR_ARENA* arena,
    YR_ARENA** duplicated);

#endif


