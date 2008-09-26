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
#else
#include "pe.h"
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef MIN
#define MIN(x,y) ((x < y)?(x):(y))
#endif

PIMAGE_NT_HEADERS get_nt_headers(unsigned char* buffer, unsigned int buffer_length)
{
	PIMAGE_DOS_HEADER mz_header;
	PIMAGE_NT_HEADERS nt_header;
	
	unsigned int headers_size = 0;
	
	if (buffer_length < sizeof(IMAGE_DOS_HEADER))
		return NULL;

	mz_header = (PIMAGE_DOS_HEADER) buffer;
	
	if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
		
	headers_size = mz_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(IMAGE_FILE_HEADER);
	
	if (buffer_length < headers_size)
		return NULL;
			
	nt_header = (PIMAGE_NT_HEADERS) (buffer + mz_header->e_lfanew);
	
	headers_size += nt_header->FileHeader.SizeOfOptionalHeader;
	
	if (nt_header->Signature == IMAGE_NT_SIGNATURE &&
	    nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
	    buffer_length > headers_size)
	{
		return nt_header;
	}	
	else
	{
		return NULL;
	}	
}

unsigned int rva_to_offset(PIMAGE_NT_HEADERS nt_header, unsigned int rva, unsigned int buffer_length)
{
	int i = 0;	
	PIMAGE_SECTION_HEADER section;
	
	section = IMAGE_FIRST_SECTION(nt_header);
	
	while(i < MIN(nt_header->FileHeader.NumberOfSections, 60))
	{
		if ((unsigned char*) section - (unsigned char*) nt_header + sizeof(IMAGE_SECTION_HEADER) < buffer_length)
		{
			if (rva >= section->VirtualAddress &&
			    rva <  section->VirtualAddress + section->SizeOfRawData)
			{
				return section->PointerToRawData + (rva - section->VirtualAddress);
			}
			
			section++;
			i++;
		}
		else
		{
			break;
		}
	}
	
	return 0xFFFFFFFF;
}

int get_entry_point_offset(unsigned char* buffer, unsigned int buffer_length)
{
	PIMAGE_NT_HEADERS nt_header;
	int result = 0;
		
	nt_header = get_nt_headers(buffer, buffer_length);
	
	if (nt_header != NULL)
	{
		result = rva_to_offset(	nt_header, 
								nt_header->OptionalHeader.AddressOfEntryPoint, 
								buffer_length - ((unsigned char*) nt_header - buffer));
	}
	
	return result;
}

int is_pe(unsigned char* buffer, unsigned int buffer_length)
{
	return (get_nt_headers(buffer, buffer_length) != NULL);
}

