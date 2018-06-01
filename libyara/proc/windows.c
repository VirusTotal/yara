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

#if defined(USE_WINDOWS_PROC)

#include <windows.h>

#include <yara/mem.h>
#include <yara/error.h>
#include <yara/proc.h>


typedef struct _YR_PROC_INFO {
  HANDLE          hProcess;
  SYSTEM_INFO     si;
} YR_PROC_INFO;

int _yr_process_attach(
    int pid,
    YR_PROC_ITERATOR_CTX* context)
{
  TOKEN_PRIVILEGES tokenPriv;
  LUID luidDebug;
  HANDLE hToken = NULL;

  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) yr_malloc(sizeof(YR_PROC_INFO));

  if (proc_info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

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

  proc_info->hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
      FALSE,
      pid);

  if (proc_info->hProcess == NULL)
  {
    yr_free(proc_info);
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  GetSystemInfo(&proc_info->si);

  context->proc_info = proc_info;

  return ERROR_SUCCESS;
}


int _yr_process_detach(
    YR_PROC_ITERATOR_CTX* context)
{
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*)context->proc_info;

  CloseHandle(proc_info->hProcess);
  return ERROR_SUCCESS;
}


YR_API const uint8_t* yr_process_fetch_memory_block_data(
    YR_MEMORY_BLOCK* block)
{
  SIZE_T read;

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

  if (ReadProcessMemory(
        proc_info->hProcess,
        (LPCVOID) block->base,
        (LPVOID) context->buffer,
        (SIZE_T) block->size,
        &read) == FALSE)
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

  MEMORY_BASIC_INFORMATION mbi;
  PVOID address = (PVOID) (context->current_block.base + \
                           context->current_block.size);

  while (address < proc_info->si.lpMaximumApplicationAddress &&
         VirtualQueryEx(proc_info->hProcess, address, &mbi, sizeof(mbi)) != 0)
  {
    // mbi.RegionSize can overflow address while scanning a 64-bit process
    // with a 32-bit YARA.
    if ((uint8_t*) address + mbi.RegionSize <= (uint8_t*) address)
      break;

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


YR_API YR_MEMORY_BLOCK* yr_process_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;
  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) context->proc_info;

  context->current_block.size = 0;
  context->current_block.base = \
      (size_t) proc_info->si.lpMinimumApplicationAddress;

  return yr_process_get_next_memory_block(iterator);
}

#endif
