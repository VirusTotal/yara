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

#include <yara/error.h>
#include <yara/proc.h>
#include <yara/mem.h>

int _yr_process_attach(int, YR_PROC_ITERATOR_CTX*);
int _yr_process_detach(YR_PROC_ITERATOR_CTX*);

YR_API int yr_process_open_iterator(
    int pid,
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) \
      yr_malloc(sizeof(YR_PROC_ITERATOR_CTX));

  if (context == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  iterator->context = context;
  iterator->first = yr_process_get_first_memory_block;
  iterator->next = yr_process_get_next_memory_block;

  context->buffer = NULL;
  context->buffer_size = 0;
  context->current_block.base = 0;
  context->current_block.size = 0;
  context->current_block.context = context;
  context->current_block.fetch_data = yr_process_fetch_memory_block_data;
  context->proc_info = NULL;

  return _yr_process_attach(pid, context);
}


YR_API int yr_process_close_iterator(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_PROC_ITERATOR_CTX* context = (YR_PROC_ITERATOR_CTX*) iterator->context;

  if (context != NULL)
  {
    _yr_process_detach(context);

    if (context->buffer != NULL)
      yr_free((void*) context->buffer);

    yr_free(context->proc_info);
    yr_free(context);

    iterator->context = NULL;
  }

  return ERROR_SUCCESS;
}
