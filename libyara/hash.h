/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#ifndef _HASH_H
#define _HASH_H

#include "yara.h"

int yr_hash_table_create(
    int size,
    HASH_TABLE** table);


void yr_hash_table_destroy(
    HASH_TABLE* table);


void* yr_hash_table_lookup(
    HASH_TABLE* table,
    const char* key,
    const char* namespace);


int yr_hash_table_add(
    HASH_TABLE* table,
    const char* key,
    const char* namespace,
    void* value);

#endif
