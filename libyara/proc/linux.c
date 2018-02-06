/*
Copyright (c) 2007-2017. The YARA Authors. All Rights Reserved.

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

#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>

#if defined(__NetBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#define _XOPEN_SOURCE 500
#endif

#include <yara/error.h>
#include <yara/proc.h>
#include <yara/mem.h>


typedef struct _YR_PROC_INFO {
  int             pid;
  int             mem_fd;
  FILE*           maps;
} YR_PROC_INFO;


int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  int status;
  char buffer[256];

  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) yr_malloc(sizeof(YR_PROC_INFO));

  if (proc_info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  context->proc_info = proc_info;

  proc_info->pid = pid;
  proc_info->maps = NULL;
  proc_info->mem_fd = -1;

  snprintf(buffer, sizeof(buffer), "/proc/%u/maps", pid);
  proc_info->maps = fopen(buffer, "r");

  if (proc_info->maps == NULL)
  {
    yr_free(proc_info);
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  snprintf(buffer, sizeof(buffer), "/proc/%u/mem", pid);
  proc_info->mem_fd = open(buffer, O_RDONLY);

  if (proc_info->mem_fd == -1)
  {
    fclose(proc_info->maps);
    proc_info->maps = NULL;

    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
  {
    fclose(proc_info->maps);
    proc_info->maps = NULL;

    close(proc_info->mem_fd);
    proc_info->mem_fd = -1;

    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  status = 0;

  if (waitpid(pid, &status, 0) == -1)
  {
    // this is a strange error state where we attached but the proc didn't
    // stop. Try to detach and clean up.
    ptrace(PTRACE_DETACH, proc_info->pid, NULL, 0);

    fclose(proc_info->maps);
    proc_info->maps = NULL;

    close(proc_info->mem_fd);
    proc_info->mem_fd = -1;

    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  fclose(proc_info->maps);
  close(proc_info->mem_fd);
  ptrace(PTRACE_DETACH, proc_info->pid, NULL, 0);

  return ERROR_SUCCESS;
}


YR_API const uint8_t* yr_process_fetch_memory_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  if (context->buffer_size < block->size)
  {
    if (context->buffer != NULL)
      yr_free((void*) context->buffer);

    context->buffer = (const uint8_t*) yr_malloc(block->size);

    if (context->buffer != NULL)
    {
      context->buffer_size = block->size;
    }
    else
    {
      context->buffer_size = 0;
      return NULL;
    }
  }

  if (pread(proc_info->mem_fd,
            (void *) context->buffer,
            block->size,
            block->base) == -1)
  {
    return NULL;
  }

  return context->buffer;
}


YR_API YR_MEMORY_BLOCK* yr_process_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  char buffer[256];
  uint64_t begin, end;

  if (fgets(buffer, sizeof(buffer), proc_info->maps) != NULL)
  {
    sscanf(buffer, "%"SCNx64"-%"SCNx64, &begin, &end);

    context->current_block.base = begin;
    context->current_block.size = end - begin;

    return &context->current_block;
  }

  return NULL;
}


YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  if (fseek(proc_info->maps, 0, SEEK_SET) != 0)
    return NULL;

  return yr_process_get_next_memory_block(iterator);
}

#endif
