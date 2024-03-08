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

#include <unistd.h>

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

  int mib[] = {CTL_KERN, KERN_PROC_VMMAP, proc_info->pid};
  size_t len = sizeof(struct kinfo_vmentry);
  
  struct kinfo_vmentry entry;
  memset(&entry, 0, len);
  
  entry.kve_start = address;

  if (sysctl(mib, 3, &entry, &len, NULL, 0) < 0)
  {
    return_integer(YR_UNDEFINED);
  }

  int protection = 0;
  if (entry.kve_protection & KVE_PROT_READ)
  {
    protection |= READ;
  }
  if (entry.kve_protection & KVE_PROT_WRITE)
  {
    protection |= WRITE;
  }
  if (entry.kve_protection & KVE_PROT_EXEC)
  {
    protection |= EXECUTE;
  }
  return_integer(protection);
}

int get_page_size()
{
  int page_size = sysconf(_SC_PAGE_SIZE);
  if (page_size < 0)
    page_size = 4096;
  return page_size;
}
