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
#define FILE_DESCRIPTOR         HANDLE
#else
#define FILE_DESCRIPTOR         int
#endif

#include "stdlib.h"
#include "yara.h"


typedef struct _MAPPED_FILE
{
    FILE_DESCRIPTOR     file;
    size_t			    size;
    unsigned char*      data;
    #ifdef WIN32
    HANDLE              mapping;
    #endif

} MAPPED_FILE;


int map_file(const char* file_path, MAPPED_FILE* pmapped_file);

void unmap_file(MAPPED_FILE* pmapped_file);
