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

#include <yara/mem.h>
#include <yara/error.h>

#if defined(_WIN32) || defined(__CYGWIN__)

#include <windows.h>
#include <string.h>

static HANDLE hHeap;

int yr_heap_alloc(void)
{
  hHeap = HeapCreate(0, 0x8000, 0);

  if (hHeap == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_heap_free(void)
{
  if (HeapDestroy(hHeap))
    return ERROR_SUCCESS;
  else
    return ERROR_INTERNAL_FATAL_ERROR;
}


void* yr_calloc(size_t count, size_t size)
{
  return (void*) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, count * size);
}


void* yr_malloc(size_t size)
{
  return (void*) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
}


void* yr_realloc(void* ptr, size_t size)
{
  return (void*) HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, ptr, size);
}


void yr_free(void* ptr)
{
  HeapFree(hHeap, 0, ptr);
}


char* yr_strdup(const char *str)
{
  size_t len = strlen(str);
  char *dup = (char*) yr_malloc(len + 1);

  if (dup == NULL)
    return NULL;

  memcpy(dup, str, len);
  dup[len] = '\0';

  return (char*) dup;
}


char* yr_strndup(const char *str, size_t n)
{
  size_t len = strnlen(str, n);
  char *dup = (char*) yr_malloc(len + 1);

  if (dup == NULL)
    return NULL;

  memcpy(dup, str, len);
  dup[len] = '\0';

  return (char *) dup;
}

#else

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int yr_heap_alloc(void)
{
  return ERROR_SUCCESS;
}


int yr_heap_free(void)
{
  return ERROR_SUCCESS;
}


void* yr_calloc(size_t count, size_t size)
{
  return calloc(count, size);
}


void* yr_malloc(size_t size)
{
  return malloc(size);
}


void* yr_realloc(void* ptr, size_t size)
{
  return realloc(ptr, size);
}


void yr_free(void *ptr)
{
  free(ptr);
}


char* yr_strdup(const char *str)
{
  return strdup(str);
}


char* yr_strndup(const char *str, size_t n)
{
  return strndup(str, n);
}

#endif
