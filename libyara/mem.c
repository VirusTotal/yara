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

#ifdef WIN32

#include <windows.h>

static HANDLE hHeap;

void yr_heap_alloc()
{
  hHeap = HeapCreate(0, 0x8000, 0);
}


void yr_heap_free()
{
  HeapDestroy(hHeap);
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
  char *dup = yr_malloc(len + 1);

  if (dup != NULL)
    strcpy(dup, str);

  return dup;
}

#else

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif


void yr_heap_alloc()
{
  return;
}


void yr_heap_free()
{
  return;
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

#endif