/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Victor M. Alvarez and its 
   contributors.
4. Neither the name of Victor M. Alvarez nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
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