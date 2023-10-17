/*
Copyright (c) 2023. The YARA Authors. All Rights Reserved.

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

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <yara/modules.h>
#include <yara/proc.h>
#include <yara/utils.h>

#include "memory.h"

define_function(protection)
{
  YR_OBJECT* module = yr_module();
  if (module->data == NULL)
  {
    return_integer(YR_UNDEFINED);
  }
  int64_t address = integer_argument(1);

  if (address == YR_UNDEFINED)
  {
    return_integer(YR_UNDEFINED);
  }

  YR_PROC_INFO* proc_info = (YR_PROC_INFO*) module->data;  
  
  struct ptrace_vm_entry vm_entry;
  memset(&vm_entry, 0, sizeof(struct ptrace_vm_entry));

  while (vm_entry.pve_end <= address)
  {
    if (ptrace(
            PT_VM_ENTRY, proc_info->pid, (char*) (&vm_entry), 0) ==
        -1)
    {
      return_integer(YR_UNDEFINED);
    }
  }

  if (vm_entry.pve_start > address || vm_entry.pve_end <= address)
  {
      return_integer(YR_UNDEFINED);
  }

  int protection = 0;
  if (vm_entry.pve_prot & 1)
  {
    protection |= READ;
  }
  if (vm_entry.pve_prot & 2)
  {
    protection |= WRITE;
  }
  if (vm_entry.pve_prot & 4)
  {
    protection |= EXECUTE;
  }
  return_integer(protection);
}

int get_page_size()
{
  return PAGE_SIZE;
}
