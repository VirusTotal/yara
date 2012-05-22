/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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

typedef long long (*EVALUATION_FUNCTION)(TERM* term, EVALUATION_CONTEXT* context);

long long evaluate(TERM* term, EVALUATION_CONTEXT* context);

#endif

