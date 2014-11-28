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

#ifndef YR_LIBYARA_H
#define YR_LIBYARA_H

#include <yara/utils.h>

YR_API int yr_initialize(void);


YR_API int yr_finalize(void);


YR_API void yr_finalize_thread(void);


YR_API int yr_get_tidx(void);


YR_API void yr_set_tidx(int);


YR_API int yr_set_mem_functions(
        void *(*_malloc)(size_t size), void *(*_calloc)(size_t count, size_t size), void *(*_realloc)(void *ptr, size_t size),
        void (*_free)(void *ptr),
        char *(*_strdup)(const char *str), char *(*_strndup)(const char *str, size_t size) );


#endif
