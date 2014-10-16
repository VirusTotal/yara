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
#include <string.h>

#include <yara/error.h>

static HANDLE hHeap;

int yr_heap_alloc()
{
  hHeap = HeapCreate(0, 0x8000, 0);

  if (hHeap == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_heap_free()
{
  if (HeapDestroy(hHeap))
    return ERROR_SUCCESS;
  else
    return ERROR_INTERNAL_FATAL_ERROR;
}


// Call yr_malloc(), which does HEAP_ZERO_MEMORY.
void* yr_calloc(size_t count, size_t size)
{
  return yr_malloc(count * size);
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
  void *dup = yr_malloc(len + 1);

  if (dup == NULL)
    return NULL;

  memcpy(dup, str, len);
  dup[len] = '\0';

  return (char*) dup;
}


char* yr_strndup(const char *str, size_t n)
{
  size_t len = strnlen(str, n);
  void *dup = yr_malloc(len + 1);

  if (dup == NULL)
    return NULL;

  memcpy(dup, s, len);
  dup[len] = '\0';

  return (char *) dup;
}

#else

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <yara/error.h>

int yr_heap_alloc()
{
  return ERROR_SUCCESS;
}


int yr_heap_free()
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
