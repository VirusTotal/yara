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

#include <fcntl.h>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "filemap.h"

#ifdef WIN32

//
// Win32 implementation
//

int map_file(const char* file_path, MAPPED_FILE* pmapped_file)
{
	if (file_path == NULL)
		return ERROR_INVALID_ARGUMENT;

	pmapped_file->file = CreateFile(	file_path, 
										GENERIC_READ, 
										FILE_SHARE_READ, 
										NULL, 
										OPEN_EXISTING, 
										FILE_FLAG_SEQUENTIAL_SCAN, 
										NULL );
	
	if (pmapped_file->file == INVALID_HANDLE_VALUE) 
	{     
		return ERROR_COULD_NOT_OPEN_FILE;
	}

	pmapped_file->size = GetFileSize(pmapped_file->file, NULL);

	if (pmapped_file->size == 0)
	{
		return ERROR_ZERO_LENGTH_FILE;
	}

	pmapped_file->mapping = CreateFileMapping(pmapped_file->file, NULL, PAGE_READONLY, 0, 0, NULL); 

	if (pmapped_file->mapping == INVALID_HANDLE_VALUE) 
	{ 
		CloseHandle(pmapped_file->file);
		return ERROR_COULD_NOT_MAP_FILE;
	}

	pmapped_file->data = (unsigned char*) MapViewOfFile(pmapped_file->mapping, FILE_MAP_READ, 0, 0, 0);

	if (pmapped_file->data == NULL)
	{
		CloseHandle(pmapped_file->mapping);
		CloseHandle(pmapped_file->file);
		return ERROR_COULD_NOT_MAP_FILE;
	}

	return ERROR_SUCCESS;
}

void unmap_file(MAPPED_FILE* pmapped_file)
{
	UnmapViewOfFile(pmapped_file->data);
	CloseHandle(pmapped_file->mapping);
	CloseHandle(pmapped_file->file);
}

#else

//
// POSIX implementation
//

int map_file(const char* file_path, MAPPED_FILE* pmapped_file)
{
	struct stat fstat;

	if (file_path == NULL)
		return ERROR_INVALID_ARGUMENT;
		
	if (stat(file_path,&fstat) != 0 || S_ISDIR(fstat.st_mode)) 
	{
	    return ERROR_COULD_NOT_OPEN_FILE;
	}
 
	pmapped_file->file = open(file_path, O_RDONLY);
	
	if (pmapped_file->file == -1) 
	{ 
		return ERROR_COULD_NOT_OPEN_FILE;
	}

	pmapped_file->size = fstat.st_size;

	if (pmapped_file->size == 0)
	{
		return ERROR_ZERO_LENGTH_FILE;
	}
	
	pmapped_file->data = (unsigned char*) mmap(0, pmapped_file->size, PROT_READ, MAP_PRIVATE, pmapped_file->file, 0);

	if (pmapped_file->data == NULL)
	{
		close(pmapped_file->file);
		return ERROR_COULD_NOT_MAP_FILE;
	}

	return ERROR_SUCCESS;
}

void unmap_file(MAPPED_FILE* pmapped_file)
{
	munmap(pmapped_file->data, pmapped_file->size);
	close(pmapped_file->file);
}

#endif

