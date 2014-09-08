/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#ifndef YR_EXEC_H
#define YR_EXEC_H

#include <yara/hash.h>
#include <yara/scan.h>
#include <yara/types.h>
#include <yara/rules.h>


#define UNDEFINED           0xFFFABADAFABADAFFLL
#define IS_UNDEFINED(x)     ((x) == UNDEFINED)

#define OP_HALT           255

#define OP_AND            1
#define OP_OR             2
#define OP_XOR            3
#define OP_NOT            4
#define OP_LT             5
#define OP_GT             6
#define OP_LE             7
#define OP_GE             8
#define OP_EQ             9
#define OP_NEQ            10
#define OP_SZ_EQ          11
#define OP_SZ_NEQ         12
#define OP_SZ_TO_BOOL     13
#define OP_ADD            14
#define OP_SUB            15
#define OP_MUL            16
#define OP_DIV            17
#define OP_MOD            18
#define OP_NEG            19
#define OP_SHL            20
#define OP_SHR            21
#define OP_PUSH           22
#define OP_POP            23
#define OP_CALL           24
#define OP_OBJ_LOAD       25
#define OP_OBJ_VALUE      26
#define OP_OBJ_FIELD      27
#define OP_INDEX_ARRAY    28
#define OP_STR_COUNT      29
#define OP_STR_FOUND      30
#define OP_STR_FOUND_AT   31
#define OP_STR_FOUND_IN   32
#define OP_STR_OFFSET     33
#define OP_OF             34
#define OP_PUSH_RULE      35
#define OP_MATCH_RULE     36
#define OP_INCR_M         37
#define OP_CLEAR_M        38
#define OP_ADD_M          39
#define OP_POP_M          40
#define OP_PUSH_M         41
#define OP_SWAPUNDEF      42
#define OP_JNUNDEF        43
#define OP_JLE            44
#define OP_FILESIZE       45
#define OP_ENTRYPOINT     46
#define OP_INT8           47
#define OP_INT16          48
#define OP_INT32          49
#define OP_UINT8          50
#define OP_UINT16         51
#define OP_UINT32         52
#define OP_CONTAINS       53
#define OP_MATCHES        54
#define OP_IMPORT         55
#define OP_LOOKUP_DICT    56


#define OPERATION(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (UNDEFINED) : (op1 operator op2)


#define COMPARISON(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (0) : (op1 operator op2)


int yr_execute_code(
    YR_RULES* rules,
    YR_SCAN_CONTEXT* context,
    int timeout,
    time_t start_time);

#endif
