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

#include "weight.h"

int string_weight(STRING* string, int multiplier)
{
    int len;

    if (IS_REGEXP(string))
    {
        return (16 * multiplier);
    }
    else
    {
        len = string->length;
    
        if (len > 8)
        {
            return (1 * multiplier);
        }
        else if (len > 4)
        {
            return (2 * multiplier);
        }
        else
        {
            return (4 * multiplier);
        }                  
    }
}

