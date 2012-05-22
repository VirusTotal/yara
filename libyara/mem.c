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


void yr_free(void* ptr)
{
    HeapFree(hHeap, 0, ptr);
}


char* yr_strdup(const char *s)
{
    size_t len;
    char *r;
    
    len = strlen(s);
    
    r = yr_malloc(len + 1);
    
    strcpy(r, s);
    
    return r;
}

#else

#include <stdlib.h>
#include <string.h>

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


void yr_free(void *ptr)
{
    free(ptr);
}


char* yr_strdup(const char *s)
{
    return strdup(s);
}

#endif