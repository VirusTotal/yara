/*

Copyright(c) 2010. Victor M. Alvarez [plusvic@gmail.com] & 
                   Stefan Buehlmann [stefan.buehlmann@joebox.org].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/


#ifndef _PROC_H
#define _PROC_H

#include "yara.h"

int get_process_memory(int pid, MEMORY_BLOCK** first_block);

#endif
