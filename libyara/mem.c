/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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


char* yr_strdup(const char *s)
{
  size_t len = strlen(s);
  char *r = yr_malloc(len + 1);
  strcpy(r, s);
  return r;
}

#else

#include <stdlib.h>
#include <string.h>
#include <stdio.h>



#ifdef DEBUG_HEAP
static int count;
#endif

void yr_heap_alloc()
{
  #ifdef DEBUG_HEAP
  count = 0;
  #endif
  return;
}


void yr_heap_free()
{
  #ifdef DEBUG_HEAP
  printf("malloc count: %d\n", count);
  #endif
  return;
}


void* yr_malloc(size_t size)
{
  void* result = malloc(size);

  #ifdef DEBUG_HEAP
  count++;
  printf("malloc: %p %zd\n", result, size);
  #endif

  return result;
}


void* yr_realloc(void* ptr, size_t size)
{
  void* result = realloc(ptr, size);

  #ifdef DEBUG_HEAP
  printf("realloc: %p -> %p\n", ptr, result);
  #endif

  return result;
}


void yr_free(void *ptr)
{
  #ifdef DEBUG_HEAP
  count--;
  printf("free: %p\n", ptr);
  #endif

  free(ptr);
}


char* yr_strdup(const char *str)
{
  void* result = strdup(str);

  #ifdef DEBUG_HEAP
  count++;
  printf("strdup: %p %zd %s\n", result, strlen(str) + 1, str);
  #endif

  return result;
}

#endif