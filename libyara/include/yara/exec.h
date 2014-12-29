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
#define IS_UNDEFINED(x)     ((size_t)(x) == (size_t) UNDEFINED)

#define OP_HALT           255

#define OP_AND            1
#define OP_OR             2
#define OP_NOT            3
#define OP_LT             4
#define OP_GT             5
#define OP_LE             6
#define OP_GE             7
#define OP_EQ             8
#define OP_NEQ            9
#define OP_STR_EQ         10
#define OP_STR_NEQ        11
#define OP_STR_TO_BOOL    12
#define OP_ADD            13
#define OP_SUB            14
#define OP_MUL            15
#define OP_DIV            16
#define OP_MOD            17
#define OP_BITWISE_NOT    18
#define OP_BITWISE_AND    19
#define OP_BITWISE_OR     20
#define OP_BITWISE_XOR    21
#define OP_SHL            22
#define OP_SHR            23
#define OP_PUSH           24
#define OP_POP            25
#define OP_CALL           26
#define OP_OBJ_LOAD       27
#define OP_OBJ_VALUE      28
#define OP_OBJ_FIELD      29
#define OP_INDEX_ARRAY    30
#define OP_COUNT          31
#define OP_FOUND          32
#define OP_FOUND_AT       33
#define OP_FOUND_IN       34
#define OP_OFFSET         35
#define OP_OF             36
#define OP_PUSH_RULE      37
#define OP_MATCH_RULE     38
#define OP_INCR_M         39
#define OP_CLEAR_M        40
#define OP_ADD_M          41
#define OP_POP_M          42
#define OP_PUSH_M         43
#define OP_SWAPUNDEF      44
#define OP_JNUNDEF        45
#define OP_JLE            46
#define OP_FILESIZE       47
#define OP_ENTRYPOINT     48
#define OP_CONTAINS       49
#define OP_MATCHES        50
#define OP_IMPORT         51
#define OP_LOOKUP_DICT    52
#define OP_ITD            53
#define OP_LTD            54
#define OP_GTD            55
#define OP_LED            56
#define OP_GED            57
#define OP_EQD            58
#define OP_NEQD           59
#define OP_ADD_DBL        60
#define OP_SUB_DBL        61
#define OP_MUL_DBL        62
#define OP_DIV_DBL        63


#define OP_INT            100
#define OP_INT8           (OP_INT + 0)
#define OP_INT16          (OP_INT + 1)
#define OP_INT32          (OP_INT + 2)
#define OP_UINT8          (OP_INT + 3)
#define OP_UINT16         (OP_INT + 4)
#define OP_UINT32         (OP_INT + 5)
#define OP_INT8BE         (OP_INT + 6)
#define OP_INT16BE        (OP_INT + 7)
#define OP_INT32BE        (OP_INT + 8)
#define OP_UINT8BE        (OP_INT + 9)
#define OP_UINT16BE       (OP_INT + 10)
#define OP_UINT32BE       (OP_INT + 11)


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
