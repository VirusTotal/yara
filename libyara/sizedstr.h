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

#ifndef _SIZEDSTR_H
#define _SIZEDSTR_H

//
// This struct is used to support strings containing null chars. The length of 
// the string is stored along the string data. However the string data is also
// terminated with a null char.
//

typedef struct _SIZED_STRING
{
    int length;
    char c_string[1];  

} SIZED_STRING;

#endif

