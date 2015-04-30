/*
Copyright (c) 2007-2015. The YARA Authors. All Rights Reserved.

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

#ifndef YR_FILEMAP_H
#define YR_FILEMAP_H

#ifdef _MSC_VER
#define off_t              int64_t
#else
#include <sys/types.h>
#endif

#ifdef _WIN32
#include <windows.h>
#define YR_FILE_DESCRIPTOR    HANDLE
#else
#define YR_FILE_DESCRIPTOR    int
#endif

#include <stdlib.h>
#include <stdint.h>

#include <yara/utils.h>


typedef struct _YR_MAPPED_FILE
{
  YR_FILE_DESCRIPTOR  file;
  size_t              size;
  uint8_t*            data;
  #ifdef _WIN32
  HANDLE              mapping;
  #endif

} YR_MAPPED_FILE;


YR_API int yr_filemap_map(
    const char* file_path,
    YR_MAPPED_FILE* pmapped_file);


YR_API int yr_filemap_map_fd(
    YR_FILE_DESCRIPTOR file,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file);


YR_API int yr_filemap_map_ex(
    const char* file_path,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file);


YR_API void yr_filemap_unmap(
    YR_MAPPED_FILE* pmapped_file);

#endif
