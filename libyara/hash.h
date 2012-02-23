/*

Copyright(c) 2012. Victor M. Alvarez [plusvic@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

#ifndef _HASH_H
#define _HASH_H

inline unsigned int hash(unsigned int seed, const unsigned char* buffer, int len);
inline unsigned int hash_update(unsigned int hash, unsigned char new, unsigned char old, int len);

#endif
