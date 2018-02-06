/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

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

#if defined(USE_OPENBSD_PROC)

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <errno.h>

#include <yara/error.h>
#include <yara/proc.h>
#include <yara/mem.h>


typedef struct _YR_PROC_INFO {
  int                  pid;
  uint64_t             old_end;
  struct kinfo_vmentry vm_entry;
} YR_PROC_INFO;


int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  int status;
  size_t len = sizeof(struct kinfo_vmentry);

  int mib[] = { CTL_KERN, KERN_PROC_VMMAP, pid };
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) yr_malloc(sizeof(YR_PROC_INFO));

  if (proc_info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  proc_info->pid = pid;
  if (ptrace(PT_ATTACH, pid, NULL, 0) == -1)
  {
    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  status = 0;
  if (waitpid(pid, &status, 0) == -1)
  {
    ptrace(PT_DETACH, proc_info->pid, NULL, 0);
    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  if (sysctl(mib, 3, &proc_info->vm_entry, &len, NULL, 0) < 0)
  {
    ptrace(PT_DETACH, proc_info->pid, NULL, 0);
    yr_free(proc_info);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  context->proc_info = proc_info;

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  ptrace(PT_DETACH, proc_info->pid, NULL, 0);

  return ERROR_SUCCESS;
}


YR_API const uint8_t* yr_process_fetch_memory_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  struct ptrace_io_desc io_desc;

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

  io_desc.piod_op = PIOD_READ_D;
  io_desc.piod_offs = (void*)block->base;
  io_desc.piod_addr = (void*)context->buffer;
  io_desc.piod_len = block->size;

  if (ptrace(PT_IO, proc_info->pid, (char*)&io_desc, 0) == -1)
    return NULL;

  return context->buffer;
}


YR_API YR_MEMORY_BLOCK* yr_process_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  int mib[] = { CTL_KERN, KERN_PROC_VMMAP, proc_info->pid };
  size_t len = sizeof(struct kinfo_vmentry);

  if (sysctl(mib, 3, &proc_info->vm_entry, &len, NULL, 0) < 0)
    return NULL;

  // no more blocks
  if (proc_info->old_end == proc_info->vm_entry.kve_end)
    return NULL;

  proc_info->old_end = proc_info->vm_entry.kve_end;
  context->current_block.base = proc_info->vm_entry.kve_start;
  context->current_block.size =
      proc_info->vm_entry.kve_end - proc_info->vm_entry.kve_start;

  proc_info->vm_entry.kve_start = proc_info->vm_entry.kve_start + 1;

  return &context->current_block;
}


YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  proc_info->vm_entry.kve_start = 0;

  return yr_process_get_next_memory_block(iterator);
}

#endif
