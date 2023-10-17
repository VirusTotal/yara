/*
Copyright (c) 2007. The YARA Authors. All Rights Reserved.

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

#ifndef YR_PROC_H
#define YR_PROC_H

#include <yara/types.h>

typedef struct _YR_PROC_ITERATOR_CTX
{
  const uint8_t* buffer;
  size_t buffer_size;
  YR_MEMORY_BLOCK current_block;
  void* proc_info;
} YR_PROC_ITERATOR_CTX;

YR_API int yr_process_open_iterator(
    int pid,
    YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API int yr_process_close_iterator(YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API YR_MEMORY_BLOCK* yr_process_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API const uint8_t* yr_process_fetch_memory_block_data(
    YR_MEMORY_BLOCK* block);


#if defined(USE_WINDOWS_PROC)

#include <windows.h>

typedef struct _YR_PROC_INFO
{
  HANDLE hProcess;
  SYSTEM_INFO si;
} YR_PROC_INFO;
#elif defined(USE_LINUX_PROC)

#include <unistd.h>

typedef struct _YR_PROC_INFO
{
  int pid;
  int mem_fd;
  int pagemap_fd;
  FILE* maps;
  uint64_t map_offset;
  uint64_t next_block_end;
  int page_size;
  char map_path[PATH_MAX];
  uint64_t map_dmaj;
  uint64_t map_dmin;
  uint64_t map_ino;
} YR_PROC_INFO;

#elif defined(USE_MACH_PROC)

#include <mach/mach.h>

typedef struct _YR_PROC_INFO
{
  task_t task;
} YR_PROC_INFO;

#elif defined(USE_OPENBSD_PROC)

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

typedef struct _YR_PROC_INFO
{
  int pid;
  uint64_t old_end;
  struct kinfo_vmentry vm_entry;
} YR_PROC_INFO;

#elif defined(USE_FREEBSD_PROC)

#include <sys/ptrace.h>

typedef struct _YR_PROC_INFO
{
  int pid;
  struct ptrace_vm_entry vm_entry;
} YR_PROC_INFO;

#endif

#endif
