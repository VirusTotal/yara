/*
Copyright (c) 2007-2021. The YARA Authors. All Rights Reserved.

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

#if defined(USE_LINUX_PROC)

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yara/error.h>
#include <yara/globals.h>
#include <yara/libyara.h>
#include <yara/mem.h>
#include <yara/proc.h>
#include <yara/strutils.h>

typedef struct _YR_PROC_INFO
{
  int pid;
  int mem_fd;
  int pagemap_fd;
  FILE* maps;
  uint64_t map_offset;
  uint64_t next_block_end;
  int page_size;
  char map_path[YR_MAX_PATH];
  uint64_t map_dmaj;
  uint64_t map_dmin;
  uint64_t map_ino;
} YR_PROC_INFO;

static int page_size = -1;

int _yr_process_attach(int pid, YR_PROC_ITERATOR_CTX* context)
{
  char buffer[256];

  page_size = sysconf(_SC_PAGE_SIZE);
  if (page_size < 0)
    page_size = 4096;

  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) yr_malloc(sizeof(YR_PROC_INFO));

  if (proc_info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  proc_info->pid = pid;
  proc_info->maps = NULL;
  proc_info->mem_fd = -1;
  proc_info->pagemap_fd = -1;
  proc_info->next_block_end = 0;

  snprintf(buffer, sizeof(buffer), "/proc/%u/maps", pid);
  proc_info->maps = fopen(buffer, "r");

  if (proc_info->maps == NULL)
    goto err;

  snprintf(buffer, sizeof(buffer), "/proc/%u/mem", pid);
  proc_info->mem_fd = open(buffer, O_RDONLY);

  if (proc_info->mem_fd == -1)
    goto err;

  snprintf(buffer, sizeof(buffer), "/proc/%u/pagemap", pid);
  proc_info->pagemap_fd = open(buffer, O_RDONLY);

  if (proc_info->pagemap_fd == -1)
    goto err;

  context->proc_info = proc_info;

  return ERROR_SUCCESS;

err:
  if (proc_info)
  {
    if (proc_info->pagemap_fd != -1)
      close(proc_info->pagemap_fd);

    if (proc_info->mem_fd != -1)
      close(proc_info->mem_fd);

    if (proc_info->maps != NULL)
      fclose(proc_info->maps);

    yr_free(proc_info);
  }

  return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
}

int _yr_process_detach(YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;
  if (proc_info)
  {
    fclose(proc_info->maps);
    close(proc_info->mem_fd);
    close(proc_info->pagemap_fd);
  }

  if (context->buffer != NULL)
  {
    munmap((void*) context->buffer, context->buffer_size);
    context->buffer = NULL;
    context->buffer_size = 0;
  }

  return ERROR_SUCCESS;
}

YR_API const uint8_t* yr_process_fetch_memory_block_data(YR_MEMORY_BLOCK* block)
{
  const uint8_t* result = NULL;
  uint64_t* pagemap = NULL;

  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  if (context->buffer != NULL)
  {
    munmap((void*) context->buffer, context->buffer_size);
    context->buffer = NULL;
    context->buffer_size = 0;
  }

  int fd = -2;  // Assume mapping not connected with a file.

  // Only try mapping the file if it has a path and belongs to a device
  if (strlen(proc_info->map_path) > 0 &&
      !(proc_info->map_dmaj == 0 && proc_info->map_dmin == 0))
  {
    struct stat st;

    if (stat(proc_info->map_path, &st) < 0)
    {
      // Why should stat fail after file open? Treat like missing.
      fd = -1;
    }
    else if (
        (major(st.st_dev) != proc_info->map_dmaj) ||
        (minor(st.st_dev) != proc_info->map_dmin) ||
        (st.st_ino != proc_info->map_ino))
    {
      // Wrong file, may have been replaced. Treat like missing.
      fd = -1;
    }
    else if (st.st_size < proc_info->map_offset + block->size)
    {
      // Mapping extends past end of file. Treat like missing.
      fd = -1;
    }
    else if ((st.st_mode & S_IFMT) != S_IFREG)
    {
      // Correct filesystem object, but not a regular file. Treat like
      // uninitialized mapping.
      fd = -2;
    }
    else
    {
      fd = open(proc_info->map_path, O_RDONLY);
      // Double-check against race conditions
      struct stat st2;
      if (fstat(fd, &st2) < 0)
      {
        close(fd);
        fd = -1;
      }
      else if ((st.st_dev != st2.st_dev) || (st.st_ino != st2.st_ino))
      {
        // File has been changed from under us, so ignore.
        close(fd);
        fd = -1;
      }
    }
  }

  if (fd >= 0)
  {
    context->buffer = mmap(
        NULL,
        block->size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE,
        fd,
        proc_info->map_offset);
    close(fd);
    if (context->buffer == MAP_FAILED)
    {
      // Notify the code below that we couldn't read from the file
      // fallback to pread() from the process
      fd = -1;
    }
    context->buffer_size = block->size;
  }

  if (fd < 0)
  {
    context->buffer = mmap(
        NULL,
        block->size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (context->buffer == MAP_FAILED)
    {
      context->buffer = NULL;
      context->buffer_size = 0;
      goto _exit;
    }
    context->buffer_size = block->size;
  }

  // If mapping can't be accessed through the filesystem, read everything from
  // target process VM.
  if (fd == -1)
  {
    if (pread(
            proc_info->mem_fd,
            (void*) context->buffer,
            block->size,
            block->base) == -1)
    {
      goto _exit;
    }
  }
  else
  {
    pagemap = calloc(block->size / page_size, sizeof(uint64_t));
    if (pagemap == NULL)
    {
      goto _exit;
    }
    if (pread(
            proc_info->pagemap_fd,
            pagemap,
            sizeof(uint64_t) * block->size / page_size,
            sizeof(uint64_t) * block->base / page_size) == -1)
    {
      goto _exit;
    }

    for (uint64_t i = 0; i < block->size / page_size; i++)
    {
      if (pagemap[i] >> 61 == 0)
      {
        continue;
      }
      // Overwrite our mapping if the page is present, file-backed, or
      // swap-backed and if it differs from our mapping.
      uint8_t buffer[page_size];

      if (pread(
              proc_info->mem_fd,
              buffer,
              page_size,
              block->base + i * page_size) == -1)
      {
        goto _exit;
      }

      if (memcmp(
              (void*) context->buffer + i * page_size,
              (void*) buffer,
              page_size) != 0)
      {
        memcpy(
            (void*) context->buffer + i * page_size, (void*) buffer, page_size);
      }
    }
  }

  result = context->buffer;

_exit:;

  if (pagemap)
  {
    free(pagemap);
    pagemap = NULL;
  }

  YR_DEBUG_FPRINTF(2, stderr, "- %s() {} = %p\n", __FUNCTION__, result);

  return result;
}

YR_API YR_MEMORY_BLOCK* yr_process_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  char buffer[YR_MAX_PATH];
  char perm[5];

  uint64_t begin, end;
  uint64_t current_begin = context->current_block.base +
                           context->current_block.size;

  uint64_t max_process_memory_chunk;

  yr_get_configuration_uint64(
      YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, &max_process_memory_chunk);

  iterator->last_error = ERROR_SUCCESS;

  if (proc_info->next_block_end <= current_begin)
  {
    int path_start, n = 0;
    char* p;

    while (fgets(buffer, sizeof(buffer), proc_info->maps) != NULL)
    {
      // locate the '\n' character
      p = strrchr(buffer, '\n');
      // If we haven't read the whole line, skip over the rest.
      if (p == NULL)
      {
        int c;
        do
        {
          c = fgetc(proc_info->maps);
        } while (c >= 0 && c != '\n');
      }
      // otherwise remove '\n' at the end of the line
      else
      {
        *p = '\0';
      }

      // Each row in /proc/$PID/maps describes a region of contiguous virtual
      // memory in a process or thread. Each row has the following fields:
      //
      // address           perms offset  dev   inode   pathname
      // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
      //
      n = sscanf(
          buffer,
          "%" SCNx64 "-%" SCNx64 " %4s "
          "%" SCNx64 " %" SCNx64 ":%" SCNx64 " %" SCNu64 " %n",
          &begin,
          &end,
          perm,
          &(proc_info->map_offset),
          &(proc_info->map_dmaj),
          &(proc_info->map_dmin),
          &(proc_info->map_ino),
          &path_start);

      // If the row was parsed correctly sscan must return 7.
      if (n == 7)
      {
        // skip the memory region that doesn't have read permission.
        if (perm[0] != 'r')
        {
          continue;
        }
        // path_start contains the offset within buffer where the path starts,
        // the path should start with /.
        if (buffer[path_start] == '/')
          strncpy(
              proc_info->map_path,
              buffer + path_start,
              sizeof(proc_info->map_path) - 1);
        else
          proc_info->map_path[0] = '\0';
        break;
      }
    }

    if (n == 7)
    {
      current_begin = begin;
      proc_info->next_block_end = end;
    }
    else
    {
      YR_DEBUG_FPRINTF(2, stderr, "- %s() = NULL\n", __FUNCTION__);
      return NULL;
    }
  }

  context->current_block.base = current_begin;
  context->current_block.size = yr_min(
      proc_info->next_block_end - current_begin, max_process_memory_chunk);

  assert(context->current_block.size > 0);

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "- %s() {} = %p // .base=0x%" PRIx64 " .size=%" PRIu64 "\n",
      __FUNCTION__,
      context->current_block,
      context->current_block.base,
      context->current_block.size);

  return &context->current_block;
}

YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_DEBUG_FPRINTF(2, stderr, "+ %s() {\n", __FUNCTION__);

  YR_MEMORY_BLOCK* result = NULL;
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  if (fseek(proc_info->maps, 0, SEEK_SET) != 0)
  {
    result = NULL;
    goto _exit;
  }

  proc_info->next_block_end = 0;

  result = yr_process_get_next_memory_block(iterator);

_exit:

  if (result == NULL)
    iterator->last_error = ERROR_COULD_NOT_READ_PROCESS_MEMORY;

  YR_DEBUG_FPRINTF(2, stderr, "} = %p // %s()\n", result, __FUNCTION__);

  return result;
}

#endif
