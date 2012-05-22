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

    pmapped_file->file = CreateFile(    file_path, 
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
        CloseHandle(pmapped_file->file);
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
        close(pmapped_file->file);
        return ERROR_ZERO_LENGTH_FILE;
    }
    
    pmapped_file->data = (unsigned char*) mmap(0, pmapped_file->size, PROT_READ, MAP_PRIVATE, pmapped_file->file, 0);

    if (pmapped_file->data == MAP_FAILED)
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

