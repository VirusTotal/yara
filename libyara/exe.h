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
#ifndef _PE_H 
#define _PE_H

int is_pe(unsigned char* buffer, unsigned int buffer_length);
int is_elf(unsigned char* buffer, unsigned int buffer_length);

unsigned long long get_entry_point_offset(unsigned char* buffer, unsigned int buffer_length);
unsigned long long get_entry_point_address(unsigned char* buffer, unsigned int buffer_length, size_t base_address);

#endif

