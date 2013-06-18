/*
Copyright(c) 2011, Google, Inc. [mjwiacek@google.com].

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

#ifndef _REGEX_H
#define _REGEX_H

#include "yara.h"


#ifdef __cplusplus
extern "C" {
#endif


void yr_regex_free(REGEXP* regex);


int yr_regex_exec(
    REGEXP* regex,
    int anchored,
    const char *buffer,
    size_t buffer_size);


int yr_regex_compile(
    REGEXP* output,
    const char* pattern,
    int case_insensitive,
    char* error_message,
    size_t error_message_size,
    int* error_offset);


int yr_regex_get_first_bytes(
    REGEXP* regex,
    uint8_t* table);

#ifdef __cplusplus
}
#endif

#endif
