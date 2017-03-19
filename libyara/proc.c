/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#if defined(_WIN32) || defined(__CYGWIN__)

#include <windows.h>

#include <yara/mem.h>
#include <yara/error.h>
#include <yara/proc.h>

// Windows

typedef struct _YR_PROC_ITERATOR_CTX
{
  HANDLE          hProcess;
  uint8_t*        buffer;
  size_t          buffer_size;
  SYSTEM_INFO     si;
  YR_MEMORY_BLOCK current_block;

} YR_PROC_ITERATOR_CTX;


int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  TOKEN_PRIVILEGES tokenPriv;
  LUID luidDebug;
  HANDLE hToken = NULL;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) &&
      LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
  {
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luidDebug;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tokenPriv,
        sizeof(tokenPriv),
        NULL,
        NULL);
  }

  if (hToken != NULL)
    CloseHandle(hToken);

  context->hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
      FALSE,
      pid);

  if (context->hProcess == NULL)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  GetSystemInfo(&context->si);

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  CloseHandle(context->hProcess);
  return ERROR_SUCCESS;
}


uint8_t* _yr_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  SIZE_T read;

  if (context->buffer_size < block->size)
  {
    if (context->buffer != NULL)
      yr_free(context->buffer);

    context->buffer = (uint8_t*) yr_malloc(block->size);

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

  if (ReadProcessMemory(
        context->hProcess,
        (LPCVOID) block->base,
        context->buffer,
        (SIZE_T) block->size,
        &read) == FALSE)
    {
      return NULL;
    }

  return context->buffer;
}


YR_MEMORY_BLOCK* _yr_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  MEMORY_BASIC_INFORMATION mbi;
  PVOID address = (PVOID) (context->current_block.base + \
	                       context->current_block.size);

  while (address < context->si.lpMaximumApplicationAddress &&
    VirtualQueryEx(context->hProcess, address, &mbi, sizeof(mbi)) != 0)
  {
    if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_NOACCESS) == 0))
    {
      context->current_block.base = (size_t) mbi.BaseAddress;
      context->current_block.size = mbi.RegionSize;

      return &context->current_block;
    }

    address = (uint8_t*) address + mbi.RegionSize;
  }

  return NULL;
}


YR_MEMORY_BLOCK* _yr_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  context->current_block.base = (size_t) context->si.lpMinimumApplicationAddress;
  context->current_block.size = 0;

  return _yr_get_next_block(iterator);
}

#else

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__OpenBSD__) || defined(__MACH__)
#else
#define _XOPEN_SOURCE 500
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <yara/error.h>
#include <yara/proc.h>
#include <yara/mem.h>

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__OpenBSD__) || defined(__MACH__)
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#endif

#if defined(__MACH__)

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

// Mac OS X

typedef struct _YR_PROC_ITERATOR_CTX {

  task_t            task;
  uint8_t*          buffer;
  size_t            buffer_size;
  YR_MEMORY_BLOCK   current_block;

} YR_PROC_ITERATOR_CTX;


int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &context->task);

  if (kr != KERN_SUCCESS)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  if (context->task != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), context->task);

  return ERROR_SUCCESS;
}


uint8_t* _yr_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;
  vm_size_t size = block->size;

  if (context->buffer_size < block->size)
  {
    if (context->buffer != NULL)
      yr_free(context->buffer);

    context->buffer = yr_malloc(block->size);

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
      context->task,
      block->base,
      block->size,
      (vm_address_t) context->buffer,
      &size) != KERN_SUCCESS)
  {
    return NULL;
  }

  return context->buffer;
}


YR_MEMORY_BLOCK* _yr_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  kern_return_t kr;
  mach_msg_type_number_t info_count;
  mach_port_t object;
  vm_region_basic_info_data_64_t info;
  vm_size_t size = 0;
  vm_address_t address = context->current_block.base \
                       + context->current_block.size;
  do
  {
    info_count = VM_REGION_BASIC_INFO_COUNT_64;

    kr = vm_region_64(
        context->task,
        &address,
        &size,
        VM_REGION_BASIC_INFO,
        (vm_region_info_t) &info,
        &info_count,
        &object);

    if (kr == KERN_SUCCESS)
    {
      context->current_block.base = address;
      context->current_block.size = size;

      return &context->current_block;
    }

  } while (kr != KERN_INVALID_ADDRESS);

  return NULL;
}


YR_MEMORY_BLOCK* _yr_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  context->current_block.base = 0;
  context->current_block.size = 0;

  return _yr_get_next_block(iterator);
}


#else

#include <errno.h>

// Linux


typedef struct _YR_PROC_ITERATOR_CTX {

  int             pid;
  int             mem_fd;
  FILE*           maps;
  uint8_t*        buffer;
  size_t          buffer_size;
  YR_MEMORY_BLOCK current_block;

} YR_PROC_ITERATOR_CTX;



int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  int status;
  char buffer[256];

  context->pid = pid;
  context->maps = NULL;
  context->mem_fd = -1;

  snprintf(buffer, sizeof(buffer), "/proc/%u/maps", pid);
  context->maps = fopen(buffer, "r");

  if (context->maps == NULL)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  snprintf(buffer, sizeof(buffer), "/proc/%u/mem", pid);
  context->mem_fd = open(buffer, O_RDONLY);

  if (context->mem_fd == -1)
  {
    fclose(context->maps);
    context->maps = NULL;

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
  {
    fclose(context->maps);
    context->maps = NULL;

    close(context->mem_fd);
    context->mem_fd = -1;

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  status = 0;
  if (waitpid(pid, &status, 0) == -1)
  {
    // this is a strange error state where we attached but the proc didn't
    // stop. Try to detach and clean up.
    ptrace(PTRACE_DETACH, context->pid, NULL, 0);

    fclose(context->maps);
    context->maps = NULL;

    close(context->mem_fd);
    context->mem_fd = -1;

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  fclose(context->maps);
  close(context->mem_fd);
  ptrace(PTRACE_DETACH, context->pid, NULL, 0);

  return ERROR_SUCCESS;
}


uint8_t* _yr_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) block->context;

  if (context->buffer_size < block->size)
  {
    if (context->buffer != NULL)
      yr_free(context->buffer);

    context->buffer = yr_malloc(block->size);

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

  if (pread(context->mem_fd,
            context->buffer,
            block->size,
            block->base) == -1)
  {
    return NULL;
  }

  return context->buffer;
}


YR_MEMORY_BLOCK* _yr_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  char buffer[256];
  size_t begin, end;

  if (fgets(buffer, sizeof(buffer), context->maps) != NULL)
  {
    sscanf(buffer, "%zx-%zx", &begin, &end);

    context->current_block.base = begin;
    context->current_block.size = end - begin;

    return &context->current_block;
  }

  return NULL;
}


YR_MEMORY_BLOCK* _yr_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  if (fseek(context->maps, 0, SEEK_SET) != 0)
    return NULL;

  return _yr_get_next_block(iterator);
}


#endif
#endif



int yr_process_open_iterator(
    int pid,
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) \
      yr_malloc(sizeof(YR_PROC_ITERATOR_CTX));

  if (context == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  iterator->context = context;
  iterator->first = _yr_get_first_block;
  iterator->next = _yr_get_next_block;

  context->buffer = NULL;
  context->buffer_size = 0;

  context->current_block.base = 0;
  context->current_block.size = 0;
  context->current_block.context = context;
  context->current_block.fetch_data = _yr_fetch_block_data;

  return _yr_process_attach(pid, context);
}


int yr_process_close_iterator(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  if (context != NULL)
  {
    _yr_process_detach(context);

    if (context->buffer != NULL)
      yr_free(context->buffer);

    yr_free(context);

    iterator->context = NULL;
  }

  return ERROR_SUCCESS;
}
