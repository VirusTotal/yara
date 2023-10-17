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

#include <linux/limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

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

  char buffer[PATH_MAX];
  char perm[5];

  fseek(proc_info->maps, 0, 0);

  while (fgets(buffer, sizeof(buffer), proc_info->maps) != NULL)
  {
    char* p;
    // locate the '\n' character
    p = strrchr(buffer, '\n');
    // If we haven't read the whole line, skip over the rest.
    if (p == NULL)
    {
      int c;
      do
      {
        c = fgetc(proc_info->maps);
      } while (c >= 0 && c != '\n');
    }
    // otherwise remove '\n' at the end of the line
    else
    {
      *p = '\0';
    }


    // Each row in /proc/$PID/maps describes a region of contiguous virtual
    // memory in a process or thread. Each row has the following fields:
    //
    // address           perms offset  dev   inode   pathname
    // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
    //
    // For this use case, we only need the first 2 columns (range and perms)
    uint64_t begin, end;
    int n = 0;
    n = sscanf(
        buffer,
        "%" SCNx64 "-%" SCNx64 " %4s ",
        &begin,
        &end,
        perm);

    // If the row was parsed correctly sscan must return 3.
    if (n == 3)
    {
      if (begin <= address && end > address)
      {
        // Found correct block in maps
        int protection = 0;
        if (perm[0] == 'r')
        {
          protection |= READ;
        }
        if (perm[1] == 'w')
        {
          protection |= WRITE;
        }
        if (perm[2] == 'x')
        {
          protection |= EXECUTE;
        }
        return_integer(protection);
      }
      continue;
    }
  }
  return_integer(YR_UNDEFINED);
}

int get_page_size()
{
  int page_size = sysconf(_SC_PAGE_SIZE);
  if (page_size < 0)
    page_size = 4096;
  return page_size;
}
