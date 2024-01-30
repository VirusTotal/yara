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

#if defined(USE_MACH_PROC)

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <yara/error.h>
#include <yara/libyara.h>
#include <yara/mem.h>
#include <yara/proc.h>

typedef struct _YR_PROC_INFO
{
  task_t task;
} YR_PROC_INFO;

int _yr_process_attach(int pid, YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) yr_malloc(sizeof(YR_PROC_INFO));

  if (proc_info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  kern_return_t kr = task_for_pid(mach_task_self(), pid, &proc_info->task);

  if (kr != KERN_SUCCESS)
  {
    yr_free(proc_info);
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  context->proc_info = proc_info;

  return ERROR_SUCCESS;
}

int _yr_process_detach(YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = context->proc_info;

  if (proc_info->task != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), proc_info->task);

  return ERROR_SUCCESS;
}

YR_API const uint8_t* yr_process_fetch_memory_block_data(YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  YR_PROC_INFO* proc_info = context->proc_info;
  vm_size_t size = block->size;

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

  if (vm_read_overwrite(
          proc_info->task,
          (vm_address_t) block->base,
          block->size,
          (vm_address_t) context->buffer,
          &size) != KERN_SUCCESS)
  {
    return NULL;
  }

  return context->buffer;
}

YR_API YR_MEMORY_BLOCK* yr_process_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = context->proc_info;

  kern_return_t kr;
  mach_msg_type_number_t info_count;
  mach_port_t object;
  vm_region_basic_info_data_64_t info;
  vm_size_t size = 0;

  uint64_t current_begin = (vm_address_t) context->current_block.base +
                           context->current_block.size;
  vm_address_t address = current_begin;
  uint64_t max_process_memory_chunk;

  yr_get_configuration_uint64(
      YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, &max_process_memory_chunk);

  iterator->last_error = ERROR_SUCCESS;

  do
  {
    info_count = VM_REGION_BASIC_INFO_COUNT_64;

    kr = vm_region_64(
        proc_info->task,
        &address,
        &size,
        VM_REGION_BASIC_INFO,
        (vm_region_info_t) &info,
        &info_count,
        &object);

    if (kr == KERN_SUCCESS)
    {
      size_t chunk_size;

      if (current_begin < address) {
        // current_begin is outside of any region, and the next region was
        // returned, so advance to it.
        current_begin = address;
        chunk_size = size;
      } else {
        // address <= current_begin, compute the size for the current chunk.
        chunk_size = size - (size_t) (current_begin - address);
      }

      if (((uint64_t) chunk_size) > max_process_memory_chunk)
      {
        chunk_size = (size_t) max_process_memory_chunk;
      }

      context->current_block.base = (size_t) current_begin;
      context->current_block.size = chunk_size;

      return &context->current_block;
    }

    current_begin = address;

  } while (kr != KERN_INVALID_ADDRESS);

  return NULL;
}

YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  context->current_block.base = 0;
  context->current_block.size = 0;

  YR_MEMORY_BLOCK* result = yr_process_get_next_memory_block(iterator);

  if (result == NULL)
    iterator->last_error = ERROR_COULD_NOT_READ_PROCESS_MEMORY;

  return result;
}

#endif
