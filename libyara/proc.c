/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#if defined(_WIN32) || defined(__CYGWIN__)

#include <windows.h>

#include <yara/mem.h>
#include <yara/error.h>
#include <yara/proc.h>


int _yr_process_attach(
    int pid,
    void** hProcess)
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

  *hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
      FALSE,
      pid);

  if (*hProcess == NULL)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    void* hProcess)
{
  if (hProcess != NULL)
    CloseHandle(hProcess);

  return ERROR_SUCCESS;
}


int _yr_process_get_blocks(
    void* hProcess,
    YR_MEMORY_BLOCK** head)
{
  PVOID address;
  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current = NULL;
  SYSTEM_INFO si;
  MEMORY_BASIC_INFORMATION mbi;

  GetSystemInfo(&si);
  address = si.lpMinimumApplicationAddress;

  *head = NULL;

  while (address < si.lpMaximumApplicationAddress &&
    VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0)
  {
    if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_NOACCESS) == 0))
    {
      new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

      if (new_block == NULL)
        return ERROR_INSUFICIENT_MEMORY;

      new_block->base = (size_t) mbi.BaseAddress;
      new_block->size = mbi.RegionSize;
      new_block->next = NULL;

      if (*head == NULL)
        *head = new_block;

      if (current != NULL)
        current->next = new_block;

      current = new_block;
    }

    address = (uint8_t*) address + mbi.RegionSize;
  }

  return ERROR_SUCCESS;
}


int _yr_process_read_block(
    void* hProcess,
    YR_MEMORY_BLOCK* block,
    uint8_t** data)
{
  SIZE_T read;
  uint8_t* buffer = NULL;
  int result = ERROR_SUCCESS;
  *data = NULL;

  buffer = (uint8_t*) yr_malloc(block->size);

  if (buffer == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  if (ReadProcessMemory(
      (HANDLE) hProcess,
      (LPCVOID) block->base,
      buffer,
      (SIZE_T) block->size,
      &read) == FALSE)
  {
    result = ERROR_COULD_NOT_READ_PROCESS_MEMORY;

    if (buffer != NULL)
    {
      yr_free(buffer);
      buffer = NULL;
    }
  }

  // TODO: compare read with block size
  // it would be bad to assume block size bytes were read
  *data = buffer;

  return result;
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

typedef struct _YR_MACH_CONTEXT
{
  task_t task;

} YR_MACH_CONTEXT;


int _yr_process_attach(
  int pid,
  void** context)
{
  YR_MACH_CONTEXT* ctx = (YR_MACH_CONTEXT*) yr_malloc(sizeof(YR_MACH_CONTEXT));
  *context = ctx;

  if (ctx == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  kern_return_t kr;

  if ((kr = task_for_pid(mach_task_self(), pid, &ctx->task)) != KERN_SUCCESS)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  return ERROR_SUCCESS;
}


int _yr_process_detach(
  void* context)
{
  if (context == NULL)
    return ERROR_SUCCESS;

  YR_MACH_CONTEXT* ctx = (YR_MACH_CONTEXT*)context;

  if (ctx->task != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), ctx->task);

  yr_free(ctx);

  return ERROR_SUCCESS;
}


int _yr_process_get_blocks(
  void* context,
  YR_MEMORY_BLOCK** head)
{
  YR_MACH_CONTEXT* ctx = (YR_MACH_CONTEXT*)context;

  kern_return_t kr;
  vm_size_t size = 0;
  vm_address_t address = 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t info_count;
  mach_port_t object;

  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current = NULL;

  *head = NULL;

  do
  {
    info_count = VM_REGION_BASIC_INFO_COUNT_64;

    kr = vm_region_64(
        ctx->task,
        &address,
        &size,
        VM_REGION_BASIC_INFO,
        (vm_region_info_t) &info,
        &info_count,
        &object);

    if (kr == KERN_SUCCESS)
    {
      new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

      if (new_block == NULL)
        return ERROR_INSUFICIENT_MEMORY;

      new_block->base = address;
      new_block->size = size;
      new_block->next = NULL;

      if (*head == NULL)
        *head = new_block;

      if (current != NULL)
        current->next = new_block;

      current = new_block;
      address += size;
    }

  } while (kr != KERN_INVALID_ADDRESS);

  return ERROR_SUCCESS;
}


int _yr_process_read_block(
  void* context,
  YR_MEMORY_BLOCK* block,
  uint8_t** data)
{
  YR_MACH_CONTEXT* ctx = (YR_MACH_CONTEXT*)context;

  int result = ERROR_SUCCESS;
  uint8_t* buffer;
  vm_size_t size = block->size;
  *data = NULL;

  buffer = (uint8_t*) yr_malloc(size);

  if (buffer == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  if (vm_read_overwrite(
      ctx->task,
      block->base,
      block->size,
      (vm_address_t) buffer,
      &size) != KERN_SUCCESS)
  {
    result = ERROR_COULD_NOT_READ_PROCESS_MEMORY;

    if (buffer != NULL)
    {
      yr_free(buffer);
      buffer = NULL;
    }
  }

  // TODO: compare read with block size
  // it would be bad to assume block size bytes were read
  *data = buffer;

  return result;
}

#else

#include <errno.h>

typedef struct _YR_PTRACE_CONTEXT
{
  int pid;
  int mem_fd;
  FILE* maps;
  int attached;

} YR_PTRACE_CONTEXT;


int _yr_process_attach(
  int pid,
  void** context)
{
  char buffer[256];

  YR_PTRACE_CONTEXT* ctx = (YR_PTRACE_CONTEXT*) yr_malloc(
      sizeof(YR_PTRACE_CONTEXT));

  *context = ctx;

  if (ctx == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  ctx->pid = pid;
  ctx->maps = NULL;
  ctx->mem_fd = -1;
  ctx->attached = 0;

  snprintf(buffer, sizeof(buffer), "/proc/%u/maps", pid);
  ctx->maps = fopen(buffer, "r");

  if (ctx->maps == NULL)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  snprintf(buffer, sizeof(buffer), "/proc/%u/mem", pid);
  ctx->mem_fd = open(buffer, O_RDONLY);

  if (ctx->mem_fd == -1)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) != -1)
    ctx->attached = 1;
  else
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  wait(NULL);

  return ERROR_SUCCESS;
}


int _yr_process_detach(
  void* context)
{
  if (context == NULL)
    return ERROR_SUCCESS;

  YR_PTRACE_CONTEXT* ctx = (YR_PTRACE_CONTEXT*)context;

  if(ctx->attached)
    ptrace(PTRACE_DETACH, ctx->pid, NULL, 0);

  if (ctx->mem_fd != -1)
    close(ctx->mem_fd);

  if (ctx->maps != NULL)
    fclose(ctx->maps);

  yr_free(ctx);

  return ERROR_SUCCESS;
}


int _yr_process_get_blocks(
  void* context,
  YR_MEMORY_BLOCK** head)
{
  char buffer[256];
  size_t begin, end;

  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current = NULL;

  YR_PTRACE_CONTEXT* ctx = (YR_PTRACE_CONTEXT*) context;

  *head = NULL;

  while (fgets(buffer, sizeof(buffer), ctx->maps) != NULL)
  {
    sscanf(buffer, "%zx-%zx", &begin, &end);

    new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

    if (new_block == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    new_block->base = begin;
    new_block->size = end - begin;
    new_block->next = NULL;

    if (*head == NULL)
      *head = new_block;

    if (current != NULL)
      current->next = new_block;

    current = new_block;
  }

  return ERROR_SUCCESS;
}


int _yr_process_read_block(
  void* context,
  YR_MEMORY_BLOCK* block,
  uint8_t** data)
{
  uint8_t* buffer = NULL;
  int result = ERROR_SUCCESS;
  *data = NULL;

  YR_PTRACE_CONTEXT* ctx = (YR_PTRACE_CONTEXT*)context;

  buffer = (uint8_t*) yr_malloc(block->size);

  if (buffer == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  if (pread(ctx->mem_fd, buffer, block->size, block->base) == -1)
  {
    result = ERROR_COULD_NOT_READ_PROCESS_MEMORY;

    if (buffer != NULL)
    {
      yr_free(buffer);
      buffer = NULL;
    }
  }

  *data = buffer;

  return result;
}

#endif
#endif

// process iterator abstraction

static void _yr_free_context_data(
    YR_PROCESS_CONTEXT* context)
{
  if (context->data != NULL)
  {
    yr_free(context->data);
    context->data = NULL;
  }
}


static YR_MEMORY_BLOCK* _yr_get_first_block(
    YR_BLOCK_ITERATOR* iterator)
{
  YR_PROCESS_CONTEXT* ctx = (YR_PROCESS_CONTEXT*)iterator->context;

  _yr_free_context_data(ctx);
  ctx->current = ctx->blocks;

  return ctx->current;
}


static YR_MEMORY_BLOCK* _yr_get_next_block(
    YR_BLOCK_ITERATOR* iterator)
{
  YR_PROCESS_CONTEXT* ctx = (YR_PROCESS_CONTEXT*)iterator->context;

  _yr_free_context_data(ctx);

  if (ctx->current == NULL)
    return NULL;

  ctx->current = ctx->current->next;

  return ctx->current;
}


static uint8_t* _yr_fetch_block_data(
    YR_BLOCK_ITERATOR* iterator)
{
  YR_PROCESS_CONTEXT* ctx = (YR_PROCESS_CONTEXT*)iterator->context;

  if (ctx->current == NULL)
    return NULL;

  // reuse cached data if available
  if (ctx->data != NULL)
    return ctx->data;

  _yr_free_context_data(ctx);

  _yr_process_read_block(
      ctx->process_context,
      ctx->current,
      &ctx->data);

  // TODO should this return error code?
  // On one hand it's useful, on the other failure
  // is expected in cases when the section isn't
  // readable and that's not a reason to exit

  return ctx->data;
}


int yr_process_open_iterator(
    int pid,
    YR_BLOCK_ITERATOR* iterator)
{
  YR_PROCESS_CONTEXT* context = (YR_PROCESS_CONTEXT*) yr_malloc(
      sizeof(YR_PROCESS_CONTEXT));

  if (context == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  context->blocks = NULL;
  context->current = NULL;
  context->data = NULL;
  context->process_context = NULL;

  iterator->context = context;
  iterator->first = _yr_get_first_block;
  iterator->next = _yr_get_next_block;
  iterator->fetch_data = _yr_fetch_block_data;

  int result = _yr_process_attach(
      pid,
      &context->process_context);

  if (result == ERROR_SUCCESS)
    result = _yr_process_get_blocks(
        context->process_context,
        &context->blocks);

  return result;
}


int yr_process_close_iterator(
    YR_BLOCK_ITERATOR* iterator)
{
  YR_PROCESS_CONTEXT* ctx = (YR_PROCESS_CONTEXT*) iterator->context;

  if (ctx == NULL)
    return ERROR_SUCCESS;

  // NOTE: detach must free allocated process context
  _yr_process_detach(ctx->process_context);

  _yr_free_context_data(ctx);

  YR_MEMORY_BLOCK* current = ctx->blocks;
  YR_MEMORY_BLOCK* next;

  // free blocks list
  while(current != NULL)
  {
    next = current->next;
    yr_free(current);
    current = next;
  }

  // free the context
  yr_free(iterator->context);
  iterator->context = NULL;

  return ERROR_SUCCESS;
}
