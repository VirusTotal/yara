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

#ifndef _MEM_H 
#define _MEM_H

#include <stdio.h>

void yr_heap_alloc();
void yr_heap_free();
void* yr_malloc(size_t size);
void yr_free(void *ptr);
char* yr_strdup(const char *s);

#endif


