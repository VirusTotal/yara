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

#include <fcntl.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <yara/filemap.h>
#include <yara/error.h>


//
// yr_filemap_map
//
// Maps a whole file into memory.
//
// Args:
//    const char* file_path        - Path of the file to map.
//    YR_MAPPED_FILE* pmapped_file - Pointer to a YR_MAPPED_FILE that will be
//                                   filled with information about the mapping.
// Returns:
//    One of the following error codes:
//       ERROR_SUCCESS
//       ERROR_INVALID_ARGUMENT
//       ERROR_COULD_NOT_OPEN_FILE
//       ERROR_COULD_NOT_MAP_FILE
//

YR_API int yr_filemap_map(
    const char* file_path,
    YR_MAPPED_FILE* pmapped_file)
{
  return yr_filemap_map_ex(file_path, 0, 0, pmapped_file);
}

//
// yr_filemap_map_fd
//
// Maps a portion of a file (specified by descriptor) into memory.
//
// Args:
//    YR_FILE_DESCRIPTOR file      - File descriptor representing the file to
//                                   map
//    off_t offset                 - File offset where the mapping will begin.
//                                   This offset must be multiple of 1MB and not
//                                   greater than the actual file size.
//    size_t size                  - Number of bytes that will be mapped. If
//                                   zero or greater than the actual file size
//                                   all content until the end of the file will
//                                   be mapped.
//    YR_MAPPED_FILE* pmapped_file - Pointer to a YR_MAPPED_FILE struct that
//                                   will be filled with the new mapping.
// Returns:
//    One of the following error codes:
//       ERROR_SUCCESS
//       ERROR_INVALID_ARGUMENT
//       ERROR_COULD_NOT_OPEN_FILE
//       ERROR_COULD_NOT_MAP_FILE
//

#ifdef _WIN32

YR_API int yr_filemap_map_fd(
    YR_FILE_DESCRIPTOR file,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  pmapped_file->file = file;
  pmapped_file->mapping = NULL;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;

  // Ensure that offset is aligned to 1MB
  if (offset >> 20 << 20 != offset)
    return ERROR_INVALID_ARGUMENT;

  LARGE_INTEGER fs;
  size_t file_size;

  if (GetFileSizeEx(pmapped_file->file, &fs))
  {
    #ifdef _WIN64
    file_size = fs.QuadPart;
    #else
    file_size = fs.LowPart;
    #endif
  }
  else
  {
    CloseHandle(pmapped_file->file);
    pmapped_file->file = INVALID_HANDLE_VALUE;
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  if (offset > file_size)
    return ERROR_COULD_NOT_MAP_FILE;

  if (size == 0)
    size = file_size - offset;

  pmapped_file->size = yr_min(size, file_size - offset);

  if (pmapped_file->size != 0)
  {
    pmapped_file->mapping = CreateFileMapping(
        pmapped_file->file,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);

    if (pmapped_file->mapping == NULL)
    {
      CloseHandle(pmapped_file->file);
      pmapped_file->file = INVALID_HANDLE_VALUE;
      return ERROR_COULD_NOT_MAP_FILE;
    }

    pmapped_file->data = (uint8_t*) MapViewOfFile(
        pmapped_file->mapping,
        FILE_MAP_READ,
        offset >> 32,
        offset & 0xFFFFFFFF,
        pmapped_file->size);

    if (pmapped_file->data == NULL)
    {
      CloseHandle(pmapped_file->mapping);
      CloseHandle(pmapped_file->file);
      pmapped_file->file = INVALID_HANDLE_VALUE;
      pmapped_file->mapping = NULL;
      return ERROR_COULD_NOT_MAP_FILE;
    }
  }
  else
  {
    pmapped_file->mapping = NULL;
    pmapped_file->data = NULL;
  }

  return ERROR_SUCCESS;
}

#else // POSIX

YR_API int yr_filemap_map_fd(
    YR_FILE_DESCRIPTOR file,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  struct stat st;

  pmapped_file->file = file;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;

  // Ensure that offset is aligned to 1MB
  if (offset >> 20 << 20 != offset)
    return ERROR_INVALID_ARGUMENT;

  if (fstat(file, &st) != 0 || S_ISDIR(st.st_mode))
    return ERROR_COULD_NOT_OPEN_FILE;

  if (offset > st.st_size)
    return ERROR_COULD_NOT_MAP_FILE;

  if (size == 0)
    size = st.st_size - offset;

  pmapped_file->size = yr_min(size, st.st_size - offset);

  if (pmapped_file->size != 0)
  {
    pmapped_file->data = (uint8_t*) mmap(
        0,
        pmapped_file->size,
        PROT_READ,
        MAP_PRIVATE,
        pmapped_file->file,
        offset);

    if (pmapped_file->data == MAP_FAILED)
    {
      close(pmapped_file->file);

      pmapped_file->data = NULL;
      pmapped_file->size = 0;
      pmapped_file->file = -1;

      return ERROR_COULD_NOT_MAP_FILE;
    }

    madvise(pmapped_file->data, pmapped_file->size, MADV_SEQUENTIAL);
  }
  else
  {
    pmapped_file->data = NULL;
  }

  return ERROR_SUCCESS;
}

#endif

//
// yr_filemap_map_ex
//
// Maps a portion of a file (specified by path) into memory.
//
// Args:
//    const char* file_path        - Path of the file to map.
//    off_t offset                 - File offset where the mapping will begin.
//                                   This offset must be multiple of 1MB and not
//                                   greater than the actual file size.
//    size_t size                  - Number of bytes that will be mapped. If
//                                   zero or greater than the actual file size
//                                   all content until the end of the file will
//                                   be mapped.
//    YR_MAPPED_FILE* pmapped_file - Pointer to a YR_MAPPED_FILE struct that
//                                   will be filled with the new mapping.
// Returns:
//    One of the following error codes:
//       ERROR_SUCCESS
//       ERROR_INVALID_ARGUMENT
//       ERROR_COULD_NOT_OPEN_FILE
//       ERROR_COULD_NOT_MAP_FILE
//

#ifdef _WIN32

YR_API int yr_filemap_map_ex(
    const char* file_path,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  YR_FILE_DESCRIPTOR fd = CreateFileA(
      file_path,
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  return yr_filemap_map_fd(fd, offset, size, pmapped_file);
}

#else // POSIX

YR_API int yr_filemap_map_ex(
    const char* file_path,
    off_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  YR_FILE_DESCRIPTOR fd = open(file_path, O_RDONLY);

  if (fd == -1)
    return ERROR_COULD_NOT_OPEN_FILE;

  return yr_filemap_map_fd(fd, offset, size, pmapped_file);
}

#endif


//
// yr_filemap_unmap
//
// Unmaps a file mapping.
//
// Args:
//    YR_MAPPED_FILE* pmapped_file - Pointer to a YR_MAPPED_FILE that struct.
//

#ifdef WIN32

YR_API void yr_filemap_unmap(
    YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    UnmapViewOfFile(pmapped_file->data);

  if (pmapped_file->mapping != NULL)
    CloseHandle(pmapped_file->mapping);

  if (pmapped_file->file != INVALID_HANDLE_VALUE)
    CloseHandle(pmapped_file->file);

  pmapped_file->file = INVALID_HANDLE_VALUE;
  pmapped_file->mapping = NULL;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;
}

#else // POSIX

YR_API void yr_filemap_unmap(
    YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    munmap(pmapped_file->data, pmapped_file->size);

  if (pmapped_file->file != -1)
    close(pmapped_file->file);

  pmapped_file->file = -1;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;
}

#endif
