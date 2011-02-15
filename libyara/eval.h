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

#ifndef _EVAL_H
#define _EVAL_H

#include "yara.h"

typedef struct _EVALUATION_CONTEXT
{
	unsigned long long    file_size;
	unsigned long long    entry_point;

    MEMORY_BLOCK*   mem_block;
    RULE*           rule;
    STRING*         current_string;

} EVALUATION_CONTEXT;



long long evaluate(TERM* term, EVALUATION_CONTEXT* context);

#endif

