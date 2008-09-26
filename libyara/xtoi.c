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

//
//  receives an string representing an hex number (without the leading 0x)
//  and returns its value as integer
// 

#include <string.h>

unsigned int xtoi(const char* hexstr)
{
	unsigned int r = 0;
	int i;
	int l = strlen(hexstr);
	
	for (i = 0; i < l; i++)
	{
		switch(hexstr[i])
		{
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':			
				r |= (hexstr[i] - '0') << ((l - i - 1) * 4);
				break;
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
				r |= (hexstr[i] - 'a' + 10) << ((l - i - 1) * 4);
				break;
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
				r |= (hexstr[i] - 'A' + 10) << ((l - i - 1) * 4);
				break;
			default:
				i = l;  // force loop exit
		}
	}
	
	return r;
}
