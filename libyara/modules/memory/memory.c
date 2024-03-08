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

#include <stdlib.h>
#include <errno.h>

#include <yara/modules.h>
#include <yara/proc.h>
#include <yara/utils.h>

#define MODULE_NAME memory

#include "memory.h"

#if defined(USE_LINUX_PROC)
#include "memory_linux.c"
#elif defined(USE_WINDOWS_PROC)
#include "memory_windows.c"
#elif defined(USE_MACH_PROC)
#include "memory_mach.c"
#elif defined(USE_OPENBSD_PROC)
#include "memory_openbsd.c"
#elif defined(USE_FREEBSD_PROC)
#include "memory_freebsd.c"
#else
#include "memory_others.c"
#endif

begin_declarations
  declare_integer("PAGE_SIZE");
  declare_integer("EXECUTE");
  declare_integer("WRITE");
  declare_integer("READ");
  declare_function("protection", "i", "i", protection);
end_declarations

int module_initialize(YR_MODULE* module)
{
  page_size = get_page_size();
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
  {
    YR_PROC_ITERATOR_CTX* proc_context = (YR_PROC_ITERATOR_CTX*) context->iterator->context;
    module_object->data = proc_context->proc_info;
  }

  yr_set_integer(page_size, module_object, "PAGE_SIZE");
  yr_set_integer(EXECUTE, module_object, "EXECUTE");
  yr_set_integer(WRITE, module_object, "WRITE");
  yr_set_integer(READ, module_object, "READ");

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
