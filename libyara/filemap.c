/*
Copyright (c) 2007-2015. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <fcntl.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <yara/error.h>
#include <yara/filemap.h>

////////////////////////////////////////////////////////////////////////////////
// Maps a whole file into memory.
//
// Args:
//   file_path: Path of the file to map.
//   pmapped_file: Pointer to a YR_MAPPED_FILE that will be filled with
//                 information about the mapping.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_COULD_NOT_OPEN_FILE
//   ERROR_COULD_NOT_MAP_FILE
//
YR_API int yr_filemap_map(const char* file_path, YR_MAPPED_FILE* pmapped_file)
{
  return yr_filemap_map_ex(file_path, 0, 0, pmapped_file);
}

////////////////////////////////////////////////////////////////////////////////
// Maps a portion of a file (specified by descriptor) into memory.
//
// Args:
//   file: File descriptor representing the file to map.
//   offset: File offset where the mapping will begin. This offset must be
//           multiple of 1MB and not greater than the actual file size.
//   size: Number of bytes that will be mapped. If zero or greater than the
//         actual file size all content until the end of the file will be
//         mapped.
//   pmapped_file: Pointer to a YR_MAPPED_FILE struct that will be filled with
//                 the new mapping.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_COULD_NOT_OPEN_FILE
//   ERROR_COULD_NOT_MAP_FILE
//
#if defined(_WIN32) || defined(__CYGWIN__)

YR_API int yr_filemap_map_fd(
    YR_FILE_DESCRIPTOR file,
    uint64_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  LARGE_INTEGER fs;
  size_t file_size;

  pmapped_file->file = file;
  pmapped_file->mapping = NULL;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;

  // Ensure that offset is aligned to 1MB
  if (offset >> 20 << 20 != offset)
    return ERROR_INVALID_ARGUMENT;

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
    pmapped_file->file = INVALID_HANDLE_VALUE;
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  if (offset > (uint64_t) file_size)
    return ERROR_COULD_NOT_MAP_FILE;

  if (size == 0)
    size = (size_t)(file_size - offset);

  pmapped_file->size = yr_min(size, (size_t)(file_size - offset));

  if (pmapped_file->size != 0)
  {
    pmapped_file->mapping = CreateFileMapping(
        pmapped_file->file, NULL, PAGE_READONLY, 0, 0, NULL);

    if (pmapped_file->mapping == NULL)
    {
      pmapped_file->file = INVALID_HANDLE_VALUE;
      pmapped_file->size = 0;
      return ERROR_COULD_NOT_MAP_FILE;
    }

    pmapped_file->data = (const uint8_t*) MapViewOfFile(
        pmapped_file->mapping,
        FILE_MAP_READ,
        offset >> 32,
        offset & 0xFFFFFFFF,
        pmapped_file->size);

    if (pmapped_file->data == NULL)
    {
      CloseHandle(pmapped_file->mapping);
      pmapped_file->mapping = NULL;
      pmapped_file->file = INVALID_HANDLE_VALUE;
      pmapped_file->size = 0;
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

#else  // POSIX

#ifdef __linux__
#include <sys/vfs.h>
// This constant can be found in linux/magic.h and the statfs(2) manpage.
// 
// We don't want to include linux/magic.h here because it may not be
// available in cross-build environments, see
// https://github.com/Hugal31/yara-rust/issues/115
#define PROC_SUPER_MAGIC 0x9fa0
#endif

#define MAP_EXTRA_FLAGS 0

#if defined(__APPLE__)
// MacOS defines some extra flags for mmap.The MAP_RESILIENT_CODESIGN allows
// to read from binaries whose code signature is invalid, without this flags
// any attempt to read from such binaries causes a crash, see:
// https://github.com/VirusTotal/yara/issues/1309.
//
// Also, reading from files in removable media that becomes unavailable
// crashes the program if the MAP_RESILIENT_MEDIA flag is not set.
#if defined(MAP_RESILIENT_CODESIGN)
#undef MAP_EXTRA_FLAGS
#if defined(MAP_RESILIENT_MEDIA)
#define MAP_EXTRA_FLAGS MAP_RESILIENT_CODESIGN | MAP_RESILIENT_MEDIA
#else
#define MAP_EXTRA_FLAGS MAP_RESILIENT_CODESIGN
#endif
#endif  // #if defined(MAP_RESILIENT_CODESIGN)
#endif  // #if defined (__APPLE__)

YR_API int yr_filemap_map_fd(
    YR_FILE_DESCRIPTOR file,
    uint64_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  struct stat st;
#ifdef __linux__
  struct statfs stfs;
#endif

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

#ifdef __linux__
  if (fstatfs(file, &stfs) != 0)
    return ERROR_COULD_NOT_OPEN_FILE;

  switch (stfs.f_type) {
  case PROC_SUPER_MAGIC:
    return ERROR_COULD_NOT_OPEN_FILE;
  }
#endif

  if (size == 0)
    size = (size_t)(st.st_size - offset);

  pmapped_file->size = yr_min(size, (size_t)(st.st_size - offset));

  if (pmapped_file->size != 0)
  {
    pmapped_file->data = (const uint8_t*) mmap(
        0,
        pmapped_file->size,
        PROT_READ,
        MAP_PRIVATE | MAP_EXTRA_FLAGS,
        pmapped_file->file,
        offset);

    if (pmapped_file->data == MAP_FAILED)
    {
      pmapped_file->data = NULL;
      pmapped_file->size = 0;
      pmapped_file->file = -1;

      return ERROR_COULD_NOT_MAP_FILE;
    }

    madvise((void*) pmapped_file->data, pmapped_file->size, MADV_SEQUENTIAL);
  }
  else
  {
    pmapped_file->data = NULL;
  }

  return ERROR_SUCCESS;
}

#endif

////////////////////////////////////////////////////////////////////////////////
// Maps a portion of a file (specified by path) into memory.
//
// Args:
//   file_path: Path of the file to map.
//   offset: File offset where the mapping will begin. This offset must be
//           multiple of 1MB and not greater than the actual file size.
//   size: Number of bytes that will be mapped. If zero or greater than the
//         actual file size all content until the end of the file will be
//         mapped.
//   pmapped_file: Pointer to a YR_MAPPED_FILE struct that will be filled with
//                 the new mapping.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_COULD_NOT_OPEN_FILE
//   ERROR_COULD_NOT_MAP_FILE
//
#if defined(_WIN32) || defined(__CYGWIN__)

YR_API int yr_filemap_map_ex(
    const char* file_path,
    uint64_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  YR_FILE_DESCRIPTOR fd;
  int result;

  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  fd = CreateFileA(
      file_path,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  result = yr_filemap_map_fd(fd, offset, size, pmapped_file);

  if (result != ERROR_SUCCESS)
    CloseHandle(fd);

  return result;
}

#else  // POSIX

YR_API int yr_filemap_map_ex(
    const char* file_path,
    uint64_t offset,
    size_t size,
    YR_MAPPED_FILE* pmapped_file)
{
  YR_FILE_DESCRIPTOR fd;
  int result;

  if (file_path == NULL)
    return ERROR_INVALID_ARGUMENT;

  fd = open(file_path, O_RDONLY);

  if (fd == -1)
    return ERROR_COULD_NOT_OPEN_FILE;

  result = yr_filemap_map_fd(fd, offset, size, pmapped_file);

  if (result != ERROR_SUCCESS)
    close(fd);

  return result;
}

#endif

////////////////////////////////////////////////////////////////////////////////
// Unmaps a file mapping.
//
// Args:
//   pmapped_file: Pointer to a YR_MAPPED_FILE that struct.
//
#ifdef WIN32

YR_API void yr_filemap_unmap_fd(YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    UnmapViewOfFile(pmapped_file->data);

  if (pmapped_file->mapping != NULL)
    CloseHandle(pmapped_file->mapping);

  pmapped_file->mapping = NULL;
  pmapped_file->data = NULL;
  pmapped_file->size = 0;
}

YR_API void yr_filemap_unmap(YR_MAPPED_FILE* pmapped_file)
{
  yr_filemap_unmap_fd(pmapped_file);

  if (pmapped_file->file != INVALID_HANDLE_VALUE)
  {
    CloseHandle(pmapped_file->file);
    pmapped_file->file = INVALID_HANDLE_VALUE;
  }
}

#else  // POSIX

YR_API void yr_filemap_unmap_fd(YR_MAPPED_FILE* pmapped_file)
{
  if (pmapped_file->data != NULL)
    munmap((void*) pmapped_file->data, pmapped_file->size);

  pmapped_file->data = NULL;
  pmapped_file->size = 0;
}

YR_API void yr_filemap_unmap(YR_MAPPED_FILE* pmapped_file)
{
  yr_filemap_unmap_fd(pmapped_file);

  if (pmapped_file->file != -1)
  {
    close(pmapped_file->file);
    pmapped_file->file = -1;
  }
}

#endif
