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

#ifndef _EXEC_H
#define _EXEC_H

#include "yara.h"


#define UNDEFINED           0xFABADAFABADALL
#define IS_UNDEFINED(x)     ((x) == UNDEFINED)

#define HALT        255

#define AND         4
#define OR          5
#define XOR         6
#define NOT         7
#define LT          8
#define GT          9
#define LE          10
#define GE          11
#define EQ          12
#define NEQ         13
#define ADD         14
#define SUB         15
#define MUL         16
#define DIV         17
#define MOD         18
#define NEG         19
#define SHL         20
#define SHR         21
#define RULE_PUSH   22
#define RULE_POP    23
#define SCOUNT      24
#define SFOUND      25
#define SFOUND_AT   26
#define SFOUND_IN   27
#define SOFFSET     28
#define OF          30
#define EXT_BOOL    31
#define EXT_INT     32
#define EXT_STR     33

#define PUSH        60
#define PUSH_A      61
#define PUSH_B      62
#define PUSH_C      63
#define POP_A       64
#define POP_B       65
#define POP_C       66
#define CLEAR_B     67
#define CLEAR_C     68
#define INCR_A      69
#define INCR_B      70
#define INCR_C      71
#define PNUNDEF_A_B 72
#define JLE_A_B     74
#define JNUNDEF_A   75

#define SIZE        76
#define ENTRYPOINT  77
#define INT8        78
#define INT16       79
#define INT32       80
#define UINT8       81
#define UINT16      82
#define UINT32      83
#define CONTAINS    84
#define MATCHES     85


typedef struct _EVALUATION_CONTEXT
{
  uint64_t  file_size;
  uint64_t  entry_point;

  MEMORY_BLOCK*   mem_block;

} EVALUATION_CONTEXT;


int yr_execute_code(
    YARA_RULES* rules,
    EVALUATION_CONTEXT* context);

#endif

