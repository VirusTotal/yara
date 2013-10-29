/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

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

#ifndef _ARENA_H
#define _ARENA_H

#include <stdint.h>
#include <stddef.h>

#include "yara.h"

int yr_arena_create(
    ARENA** arena);


void yr_arena_destroy(
    ARENA* arena);


void* yr_arena_base_address(
  ARENA* arena);


void* yr_arena_current_address(
  ARENA* arena);


void* yr_arena_next_address(
  ARENA* arena,
  void* address,
  size_t increment);


int yr_arena_coalesce(
    ARENA* arena);


int yr_arena_allocate_memory(
    ARENA* arena,
    int32_t size,
    void** allocated_memory);


int yr_arena_allocate_struct(
    ARENA* arena,
    int32_t size,
    void** allocated_memory,
    ...);


int yr_arena_make_relocatable(
    ARENA* arena,
    void* base,
    ...);


int yr_arena_write_data(
    ARENA* arena,
    void* data,
    int32_t size,
    void** written_data);


int yr_arena_write_string(
    ARENA* arena,
    const char* string,
    char** written_string);


int yr_arena_append(
    ARENA* target_arena,
    ARENA* source_arena);


int yr_arena_save(
  ARENA* arena,
  const char* filename);


int yr_arena_load(
    const char* filename,
    ARENA** arena);

#endif


