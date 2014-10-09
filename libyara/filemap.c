/*
Copyright (c) 2007. The YARA Authors. All Rights Reserved.

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


#ifdef _WIN32

//
// Win32 implementation
//

YR_API int yr_filemap_map(
    const char* file_path,
    YR_MAPPED_FILE* pmapped_file)
{
  LARGE_INTEGER size;

  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  pmapped_file->file = CreateFile(
      file_path,
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (pmapped_file->file == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  if (GetFileSizeEx(pmapped_file->file, &size))
  {
    #ifdef _WIN64
    pmapped_file->size = size.QuadPart;
    #else
    pmapped_file->size = size.LowPart;
    #endif
  }
  else
  {
    CloseHandle(pmapped_file->file);
    return ERROR_COULD_NOT_OPEN_FILE;
  }

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
      return ERROR_COULD_NOT_MAP_FILE;
    }

    pmapped_file->data = (uint8_t*) MapViewOfFile(
        pmapped_file->mapping,
        FILE_MAP_READ,
        0,
        0,
        0);

    if (pmapped_file->data == NULL)
    {
      CloseHandle(pmapped_file->mapping);
      CloseHandle(pmapped_file->file);
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

YR_API void yr_filemap_unmap(
    YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    UnmapViewOfFile(pmapped_file->data);

  if (pmapped_file->mapping != NULL)
    CloseHandle(pmapped_file->mapping);

  CloseHandle(pmapped_file->file);
}

#else

//
// POSIX implementation
//

YR_API int yr_filemap_map(
    const char* file_path,
    YR_MAPPED_FILE* pmapped_file)
{
  struct stat fstat;

  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  if (stat(file_path,&fstat) != 0 || S_ISDIR(fstat.st_mode))
    return ERROR_COULD_NOT_OPEN_FILE;

  pmapped_file->file = open(file_path, O_RDONLY);

  if (pmapped_file->file == -1)
    return ERROR_COULD_NOT_OPEN_FILE;

  pmapped_file->size = fstat.st_size;

  if (pmapped_file->size != 0)
  {
    pmapped_file->data = (uint8_t*) mmap(
        0,
        pmapped_file->size,
        PROT_READ,
        MAP_PRIVATE,
        pmapped_file->file,
        0);

    if (pmapped_file->data == MAP_FAILED)
    {
      close(pmapped_file->file);
      return ERROR_COULD_NOT_MAP_FILE;
    }
  }
  else
  {
    pmapped_file->data = NULL;
  }

  return ERROR_SUCCESS;
}

YR_API void yr_filemap_unmap(
    YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    munmap(pmapped_file->data, pmapped_file->size);

  close(pmapped_file->file);
}

#endif
