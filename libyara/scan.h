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

#ifndef _SCAN_H 
#define _SCAN_H

#include "yara.h"

int populate_hash_table(HASH_TABLE* hash_table, RULE_LIST* rule_list);
void clear_hash_table(HASH_TABLE* hash_table);

#endif