/*

Copyright(c) 2010. Victor M. Alvarez [plusvic@gmail.com] & 
                   Stefan Buehlmann [stefan.buehlmann@joebox.org].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/



#ifdef WIN32

#include <windows.h>
#include "mem.h"
#include "proc.h"

int get_process_memory(int pid, MEMORY_BLOCK** first_block)
{
    PVOID address;
    SIZE_T read;
    
    unsigned char* data;
    
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION mbi;

    MEMORY_BLOCK* new_block;
    MEMORY_BLOCK* current_block = NULL;
    
    TOKEN_PRIVILEGES tokenPriv;
    LUID luidDebug; 
    HANDLE hProcess;
	HANDLE hToken;
    
    if( OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) && 
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) 
    {  
            tokenPriv.PrivilegeCount = 1; 
            tokenPriv.Privileges[0].Luid = luidDebug; 
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

    	    AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL); 
    }  
 
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    
    *first_block = NULL;
    
    if (hProcess == NULL)
    {
        return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
    }
    
    GetSystemInfo(&si);
    
    address = si.lpMinimumApplicationAddress;

    while (address < si.lpMaximumApplicationAddress) 
    {
         if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0)
         {         
             if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS)
             {    
                 data = (unsigned char*) yr_malloc(mbi.RegionSize);
             
                 if (data == NULL)
                     return ERROR_INSUFICIENT_MEMORY;
             
                 if (ReadProcessMemory(hProcess, address, data, mbi.RegionSize, &read))
                 {                
                     new_block = (MEMORY_BLOCK*) yr_malloc(sizeof(MEMORY_BLOCK));
                 
                     if (new_block == NULL)
                     {
                         yr_free(data);
                         return ERROR_INSUFICIENT_MEMORY;
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
             
             address = (PVOID)((DWORD) mbi.BaseAddress + mbi.RegionSize);
         }    
     }
     
     return ERROR_SUCCESS;
}

#else

#include <fcntl.h>
#include <unistd.h> 
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>  

#include "mem.h"
#include "proc.h"

#ifdef __MACH__

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH


int get_process_memory(pid_t pid, MEMORY_BLOCK** first_block)
{
    task_t task;
    kern_return_t kr;
    
    vm_size_t size = 0;
    vm_address_t address = 0;  
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count;
    mach_port_t object;
    
    unsigned char* data;
    
    MEMORY_BLOCK* new_block;
    MEMORY_BLOCK* current_block = NULL;
    
    *first_block = NULL;
    
    if ((kr = task_for_pid(mach_task_self(), pid, &task)) != KERN_SUCCESS)
    {
        return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
    }

    do {

         info_count = VM_REGION_BASIC_INFO_COUNT_64;
         
         kr = vm_region_64(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &info_count, &object);
                  
         if (kr == KERN_SUCCESS) 
         {         
             data = (unsigned char*) yr_malloc(size);
             
             if (data == NULL)
                 return ERROR_INSUFICIENT_MEMORY;
             
             if (vm_read_overwrite(task, address, size, (vm_address_t) data, &size) == KERN_SUCCESS)
             {                
                 new_block = (MEMORY_BLOCK*) yr_malloc(sizeof(MEMORY_BLOCK));
                 
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
             
             address += size;
         } 

         
     } while (kr != KERN_INVALID_ADDRESS);
     
     if (task != MACH_PORT_NULL) 
     {
          mach_port_deallocate(mach_task_self(), task);
     }
     
     return ERROR_SUCCESS;
}

#else

#include <errno.h>

int get_process_memory(pid_t pid, MEMORY_BLOCK** first_block)
{
    char buffer[256];
    unsigned char* data;
    size_t begin, end, length;
    
    MEMORY_BLOCK* new_block;
    MEMORY_BLOCK* current_block = NULL;
    
    *first_block = NULL;

    sprintf(buffer, "/proc/%u/maps", pid);

    FILE* maps = fopen(buffer, "r");
    
    if (maps == NULL)
    {
        return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
    }

    sprintf(buffer, "/proc/%u/mem", pid);

    int mem = open(buffer, O_RDONLY);

    if (mem == -1)
    {
        fclose(maps);
        return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1)
    {
        return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
    }
       
    wait(NULL);

    while (fgets(buffer, sizeof(buffer), maps) != NULL)
    {
        sscanf(buffer, "%lx-%lx", &begin, &end);

        length = end - begin;

        data = yr_malloc(length);
        
        if (data == NULL)
            return ERROR_INSUFICIENT_MEMORY;

        if (pread(mem, data, length, begin) != -1)
        {
            new_block = (MEMORY_BLOCK*) yr_malloc(sizeof(MEMORY_BLOCK));
            
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
    }

    ptrace(PTRACE_DETACH, pid, NULL, 0);

    close(mem);
    fclose(maps);
 
    return ERROR_SUCCESS;
}

#endif
#endif