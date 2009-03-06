/*

Copyright(c) 2007. Victor M. Alvarez [plusvic@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

#ifdef WIN32

#include <windows.h>

void* yr_malloc(size_t size)
{
    return (void*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}


void yr_free(void* ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
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