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

#ifndef _AST_H
#define _AST_H

#include "yara.h"
#include "sizedstr.h"
#include "eval.h"

/* 
    Mask examples:
    
    string : B1 (  01 02 |  03 04 )  3? ?? 45 
    mask:    FF AA FF FF AA FF FF BB F0 00 FF

    string : C5 45 [3]   00 45|
    mask:    FF FF CC 03 FF FF
    
    string : C5 45 [2-5]    00 45
    mask:    FF FF DD 02 03 FF FF
    
*/

#define MASK_OR                                 0xAA
#define MASK_OR_END                             0xBB
#define MASK_EXACT_SKIP                         0xCC
#define MASK_RANGE_SKIP                         0xDD
#define MASK_END                                0xEE
#define MASK_MAX_SKIP                           255

#define TERM_TYPE_CONST                              0 
#define TERM_TYPE_AND                                2 
#define TERM_TYPE_OR                                 3 
#define TERM_TYPE_NOT                                4 
#define TERM_TYPE_ADD                                5 
#define TERM_TYPE_SUB                                6 
#define TERM_TYPE_MUL                                7 
#define TERM_TYPE_DIV                                8 
#define TERM_TYPE_GT                                 9 
#define TERM_TYPE_LT                                 10
#define TERM_TYPE_GE                                 11
#define TERM_TYPE_LE                                 12
#define TERM_TYPE_EQ                                 13
#define TERM_TYPE_NOT_EQ                             14
#define TERM_TYPE_STRING                             15
#define TERM_TYPE_STRING_AT                          16
#define TERM_TYPE_STRING_IN_RANGE                    17
#define TERM_TYPE_STRING_IN_SECTION_BY_NAME          18
#define TERM_TYPE_STRING_IN_SECTION_BY_INDEX         19
#define TERM_TYPE_STRING_COUNT                       20
#define TERM_TYPE_STRING_OFFSET                      21
#define TERM_TYPE_OF                                 22
#define TERM_TYPE_STRING_FOR                         23
#define TERM_TYPE_FILESIZE                           24
#define TERM_TYPE_ENTRYPOINT                         25
#define TERM_TYPE_RULE                               26
#define TERM_TYPE_INT8_AT_OFFSET                     27
#define TERM_TYPE_INT16_AT_OFFSET                    28
#define TERM_TYPE_INT32_AT_OFFSET                    29
#define TERM_TYPE_UINT8_AT_OFFSET                    30
#define TERM_TYPE_UINT16_AT_OFFSET                   31
#define TERM_TYPE_UINT32_AT_OFFSET                   32
#define TERM_TYPE_VARIABLE                           33
#define TERM_TYPE_STRING_MATCH                       34
#define TERM_TYPE_STRING_CONTAINS                    35
#define TERM_TYPE_INTEGER_FOR                        36
#define TERM_TYPE_VECTOR                             37
#define TERM_TYPE_RANGE                              38
#define TERM_TYPE_BITWISE_AND                        39
#define TERM_TYPE_BITWISE_OR                         40
#define TERM_TYPE_BITWISE_NOT                        41
#define TERM_TYPE_SHIFT_LEFT                         42
#define TERM_TYPE_SHIFT_RIGHT                        43


#define MAX_VECTOR_SIZE                              64



typedef struct _TERM_CONST
{
    int             type;
    size_t          value;

} TERM_CONST;


typedef struct _TERM_STRING_CONST
{
    int             type;
    char*           value;

} TERM_STRING_CONST;


typedef struct _TERM_UNARY_OPERATION
{
    int             type;
    TERM*           op;
    
} TERM_UNARY_OPERATION;


typedef struct _TERM_BINARY_OPERATION
{
    int             type;
    TERM*           op1;
    TERM*           op2;
    
} TERM_BINARY_OPERATION;


typedef struct _TERM_TERNARY_OPERATION
{
    int             type;
    TERM*           op1;
    TERM*           op2;
    TERM*           op3;
    
} TERM_TERNARY_OPERATION;


struct _TERM_ITERABLE;

typedef TERM* (*ITERATOR)(struct _TERM_ITERABLE* self, EVALUATION_FUNCTION evaluate, EVALUATION_CONTEXT* context);


typedef struct _TERM_ITERABLE
{
    int             type;
    ITERATOR        first;
    ITERATOR        next;
    
} TERM_ITERABLE;


typedef struct _TERM_RANGE
{
    int             type;
    ITERATOR        first;
    ITERATOR        next;
    TERM*           min;
    TERM*           max;
    TERM_CONST*     current;
    
} TERM_RANGE;


typedef struct _TERM_VECTOR
{
    int             type;
    ITERATOR        first;
    ITERATOR        next;
    int             count;
    int             current;
    TERM*           items[MAX_VECTOR_SIZE];

} TERM_VECTOR;


typedef struct _TERM_INTEGER_FOR
{
    int             type;
    TERM*           count;    
    TERM_ITERABLE*  items;
    TERM*           expression;
    VARIABLE*       variable;
    
} TERM_INTEGER_FOR;


typedef struct _TERM_STRING
{
    int                     type;
    struct _TERM_STRING*    next;           /* used to link a set of terms for the OF operator e.g: 2 OF ($A,$B,$C) */
    STRING*                 string;
    
    union {
        TERM*           offset;
        TERM*           index;
        TERM*           range;
        char*           section_name;
        unsigned int    section_index;
    };
    
} TERM_STRING;


typedef struct _TERM_VARIABLE
{ 
    int        type;
    VARIABLE*  variable;

} TERM_VARIABLE;


typedef struct _TERM_STRING_OPERATION
{
    int        type;
    VARIABLE*  variable;
   
    union {
        REGEXP              re;
        char*               string;
    };

} TERM_STRING_OPERATION;



int new_rule(RULE_LIST* rules, char* identifier, NAMESPACE* ns, int flags, TAG* tag_list_head, META* meta_list_head, STRING* string_list_head, TERM* condition);

int new_string(YARA_CONTEXT* context, char* identifier, SIZED_STRING* charstr, int flags, STRING** string);

int new_simple_term(int type, TERM** term);

int new_unary_operation(int type, TERM* op1, TERM_UNARY_OPERATION** term);

int new_binary_operation(int type, TERM* op1, TERM* op2, TERM_BINARY_OPERATION** term);

int new_ternary_operation(int type, TERM* op1, TERM* op2, TERM* op3, TERM_TERNARY_OPERATION** term);

int new_constant(size_t constant, TERM_CONST** term);

int new_string_identifier(int type, STRING* defined_strings, char* identifier, TERM_STRING** term);

int new_variable(YARA_CONTEXT* context, char* identifier, TERM_VARIABLE** term);

int new_range(TERM* min, TERM* max, TERM_RANGE** term);

int new_vector(TERM_VECTOR** term);

int add_term_to_vector(TERM_VECTOR* vector, TERM* term);

#endif

