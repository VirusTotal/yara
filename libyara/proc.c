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

#ifdef _WIN32

#include <windows.h>

#include <yara/mem.h>
#include <yara/error.h>
#include <yara/proc.h>

int yr_process_get_memory(
    int pid,
    YR_MEMORY_BLOCK** first_block)
{
  PVOID address;
  SIZE_T read;

  unsigned char* data;
  int result = ERROR_SUCCESS;

  SYSTEM_INFO si;
  MEMORY_BASIC_INFORMATION mbi;

  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current_block = NULL;

  TOKEN_PRIVILEGES tokenPriv;
  LUID luidDebug;
  HANDLE hProcess = NULL;
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

  hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
      FALSE,
      pid);

  *first_block = NULL;

  if (hProcess == NULL)
  {
    if (hToken != NULL)
      CloseHandle(hToken);

    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  GetSystemInfo(&si);

  address = si.lpMinimumApplicationAddress;

  while (address < si.lpMaximumApplicationAddress &&
         VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0)
  {
    if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_NOACCESS) == 0))
    {
      data = (unsigned char*) yr_malloc(mbi.RegionSize);

      if (data == NULL)
      {
        result = ERROR_INSUFICIENT_MEMORY;
        break;
      }

      if (ReadProcessMemory(
              hProcess,
              mbi.BaseAddress,
              data,
              mbi.RegionSize,
              &read))
      {
        new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

        if (new_block == NULL)
        {
          yr_free(data);
          result = ERROR_INSUFICIENT_MEMORY;
          break;
        }

        if (*first_block == NULL)
          *first_block = new_block;

        new_block->base = (size_t) mbi.BaseAddress;
        new_block->size = mbi.RegionSize;
        new_block->data = data;
        new_block->next = NULL;

        if (current_block != NULL)
          current_block->next = new_block;

        current_block = new_block;
      }
      else
      {
        yr_free(data);
      }
    }

    address = (PVOID)((ULONG_PTR) mbi.BaseAddress + mbi.RegionSize);
  }

  if (hToken != NULL)
    CloseHandle(hToken);

  if (hProcess != NULL)
    CloseHandle(hProcess);

  return result;
}

#else

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <yara/error.h>
#include <yara/proc.h>
#include <yara/mem.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__MACH__)
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#endif

#if defined(__MACH__)

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

int yr_process_get_memory(
    pid_t pid,
    YR_MEMORY_BLOCK** first_block)
{
  task_t task;
  kern_return_t kr;

  vm_size_t size = 0;
  vm_address_t address = 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t info_count;
  mach_port_t object;

  unsigned char* data;

  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current_block = NULL;

  *first_block = NULL;

  if ((kr = task_for_pid(mach_task_self(), pid, &task)) != KERN_SUCCESS)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  do {

    info_count = VM_REGION_BASIC_INFO_COUNT_64;

    kr = vm_region_64(
        task,
        &address,
        &size,
        VM_REGION_BASIC_INFO,
        (vm_region_info_t) &info,
        &info_count,
        &object);

    if (kr == KERN_SUCCESS)
    {
      data = (unsigned char*) yr_malloc(size);

      if (data == NULL)
        return ERROR_INSUFICIENT_MEMORY;

      if (vm_read_overwrite(
              task,
              address,
              size,
              (vm_address_t)
              data,
              &size) == KERN_SUCCESS)
      {
        new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

        if (new_block == NULL)
        {
          yr_free(data);
          return ERROR_INSUFICIENT_MEMORY;
        }

        if (*first_block == NULL)
          *first_block = new_block;

        new_block->base = address;
        new_block->size = size;
        new_block->data = data;
        new_block->next = NULL;

        if (current_block != NULL)
          current_block->next = new_block;

        current_block = new_block;
      }
      else
      {
        yr_free(data);
      }

      address += size;
    }


  } while (kr != KERN_INVALID_ADDRESS);

  if (task != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), task);

  return ERROR_SUCCESS;
}

#else

#include <errno.h>

int yr_process_get_memory(
    pid_t pid,
    YR_MEMORY_BLOCK** first_block)
{
  char buffer[256];
  unsigned char* data;
  size_t begin, end, length;

  YR_MEMORY_BLOCK* new_block;
  YR_MEMORY_BLOCK* current_block = NULL;

  *first_block = NULL;

  snprintf(buffer, sizeof(buffer), "/proc/%u/maps", pid);

  FILE* maps = fopen(buffer, "r");

  if (maps == NULL)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  snprintf(buffer, sizeof(buffer), "/proc/%u/mem", pid);

  int mem = open(buffer, O_RDONLY);

  if (mem == -1)
  {
    fclose(maps);
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;

  wait(NULL);

  while (fgets(buffer, sizeof(buffer), maps) != NULL)
  {
    sscanf(buffer, "%zx-%zx", &begin, &end);

    length = end - begin;

    data = yr_malloc(length);

    if (data == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    if (pread(mem, data, length, begin) != -1)
    {
      new_block = (YR_MEMORY_BLOCK*) yr_malloc(sizeof(YR_MEMORY_BLOCK));

      if (new_block == NULL)
      {
        yr_free(data);
        return ERROR_INSUFICIENT_MEMORY;
      }

      if (*first_block == NULL)
        *first_block = new_block;

      new_block->base = begin;
      new_block->size = length;
      new_block->data = data;
      new_block->next = NULL;

      if (current_block != NULL)
        current_block->next = new_block;

      current_block = new_block;
    }
    else
    {
      yr_free(data);
    }
  }

  ptrace(PTRACE_DETACH, pid, NULL, 0);

  close(mem);
  fclose(maps);

  return ERROR_SUCCESS;
}

#endif
#endif
