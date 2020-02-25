/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef YR_COMPILER_H
#define YR_COMPILER_H

#include <stdio.h>
#include <setjmp.h>

#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/arena2.h>
#include <yara/hash.h>
#include <yara/utils.h>
#include <yara/filemap.h>


#define YARA_ERROR_LEVEL_ERROR   0
#define YARA_ERROR_LEVEL_WARNING 1


// Expression type constants are powers of two because they are used as flags.
#define EXPRESSION_TYPE_UNKNOWN   0
#define EXPRESSION_TYPE_BOOLEAN   1
#define EXPRESSION_TYPE_INTEGER   2
#define EXPRESSION_TYPE_STRING    4
#define EXPRESSION_TYPE_REGEXP    8
#define EXPRESSION_TYPE_OBJECT    16
#define EXPRESSION_TYPE_FLOAT     32


// The compiler uses an arena to store the data it generates during the
// compilation. Each buffer in the arena is used for storing a different type
// of data. The following identifiers indicate the purpose of each buffer.
#define YR_NAMESPACES_TABLE           0
#define YR_RULES_TABLE                1
#define YR_METAS_TABLE                2
#define YR_STRINGS_TABLE              3
#define YR_EXTERNAL_VARIABLES_TABLE   4
#define YR_SZ_POOL                    5
#define YR_CODE_SECTION               6
#define YR_RE_CODE_SECTION            7


// This is the number of buffers used by the compiler, should match the number
// of items in the list above.
#define YR_NUM_SECTIONS               8


typedef struct _YR_EXPRESSION
{
  int type;

  union {
    int64_t integer;
    YR_OBJECT* object;
    SIZED_STRING* sized_string;
  } value;

  // An expression can have an associated identifier, if "ptr" is not NULL it
  // points to the identifier name, if it is NULL, then "ref" holds a reference
  // to the identifier within YR_SZ_POOL. When the identifier is in YR_SZ_POOL
  // a pointer can't be used as the YR_SZ_POOL can be moved to a different
  // memory location.
  struct {
    const char* ptr;
    YR_ARENA2_REFERENCE ref;
  } identifier ;

} YR_EXPRESSION;


typedef void (*YR_COMPILER_CALLBACK_FUNC)(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message,
    void* user_data);


typedef const char* (*YR_COMPILER_INCLUDE_CALLBACK_FUNC)(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);


typedef void (*YR_COMPILER_INCLUDE_FREE_FUNC)(
    const char* callback_result_ptr,
    void* user_data);


typedef void (*YR_COMPILER_RE_AST_CALLBACK_FUNC)(
    const YR_RULE* rule,
    const char* string_identifier,
    const RE_AST* re_ast,
    void* user_data);


typedef struct _YR_FIXUP
{
  YR_ARENA2_REFERENCE ref;
  struct _YR_FIXUP* next;

} YR_FIXUP;


// Each "for" loop in the condition has an associated context which holds
// information about loop, like the target address for the jump instruction
// that goes back to the beginning of the loop and the local variables used
// by the loop.

typedef struct _YR_LOOP_CONTEXT
{
  // Reference indicating the the place in the code where the loop starts. The
  // loop goes back to this address on each iteration.
  YR_ARENA2_REFERENCE start_ref;

  // vars_count is the number of local variables defined by the loop, and vars
  // is an array of expressions with the identifier and type for each of those
  // local variables.
  int               vars_count;
  YR_EXPRESSION     vars[YR_MAX_LOOP_VARS];

  // vars_internal_count is the number of variables used by the loop which are
  // not defined by the rule itself but that are necessary for keeping the
  // loop's state. One example is the iteration counter.
  int               vars_internal_count;
} YR_LOOP_CONTEXT;


typedef struct _YR_COMPILER
{
  // Arena that contains the data generated by the compiled. The arena has
  // the following buffers:
  //
  //   YR_RULES_TABLE:
  //      An array of YR_RULE structures, one per each rule.
  //   YR_STRINGS_TABLE:
  //      An array of YR_STRING structures, one per each string.
  //   YR_METAS_TABLE:
  //      An array of YR_META structures, one per each meta definition.
  //   YR_NAMESPACES_TABLE:
  //      An array of YR_NAMESPACE structures, one per each namespace.
  //   YR_EXTERNAL_VARIABLES_TABLE:
  //      An array of YR_EXTERNAL_VARIABLE structures, one per each external
  //      variable defined.
  //   YR_SZ_POOL:
  //      A collection of null-terminated strings. This buffer contains
  //      identifiers, literal strings, and in general any null-terminated
  //      string referenced by other data structures.
  //   YR_CODE_SECTION:
  //      The code for the condition section of all the rules. This is the
  //      code executed by yr_execute_code.
  //   YR_RE_CODE_SECTION:
  //      Similar to YR_CODE_SECTION, but it contains the code for regular
  //      expressions. This is the code executed by yr_re_exec and
  //      yr_re_fast_exec.
  //   YR_AC_TRANSITION_TABLE:
  //      Contains the Aho-Corasick transition table.
  //   YR_AC_MATCHES_TABLE:
  //      An array of YR_AC_MATCH structures.
  //
  YR_ARENA2* arena;

  // Index of the rule being compiled in the array of YR_RULE structures
  // stored in YR_RULES_TABLE.
  uint32_t current_rule_idx;

  // Index of the string being compiled in the array of YR_STRING structures
  // stored in YR_STRINGS_TABLE.
  uint32_t current_string_idx;

  // Index of the current namespace in the array of YR_NAMESPACE structures
  // stored in YR_NAMESPACES_TABLE.
  uint32_t current_namespace_idx;

  int               errors;
  int               current_line;
  int               last_error;
  int               last_error_line;

  jmp_buf           error_recovery;

  //YR_ARENA*         code_arena;
  YR_ARENA*         re_code_arena;
  YR_ARENA*         compiled_rules_arena;
  YR_ARENA*         matches_arena;
  YR_ARENA*         automaton_arena;

  YR_AC_AUTOMATON*  automaton;
  YR_HASH_TABLE*    rules_table;
  YR_HASH_TABLE*    objects_table;
  YR_HASH_TABLE*    strings_table;

  YR_FIXUP*         fixup_stack_head;

  int               namespaces_count;

  YR_LOOP_CONTEXT   loop[YR_MAX_LOOP_NESTING];
  int               loop_index;
  int               loop_for_of_var_index;

  char*             file_name_stack[YR_MAX_INCLUDE_DEPTH];
  int               file_name_stack_ptr;

  char              last_error_extra_info[YR_MAX_COMPILER_ERROR_EXTRA_INFO];

  char              lex_buf[YR_LEX_BUF_SIZE];
  char*             lex_buf_ptr;
  unsigned short    lex_buf_len;

  char              include_base_dir[MAX_PATH];
  void*             user_data;
  void*             incl_clbk_user_data;
  void*             re_ast_clbk_user_data;

  YR_COMPILER_CALLBACK_FUNC            callback;
  YR_COMPILER_INCLUDE_CALLBACK_FUNC    include_callback;
  YR_COMPILER_INCLUDE_FREE_FUNC        include_free;
  YR_COMPILER_RE_AST_CALLBACK_FUNC     re_ast_callback;
  YR_ATOMS_CONFIG                      atoms_config;

} YR_COMPILER;


#define yr_compiler_set_error_extra_info(compiler, info) \
    strlcpy( \
        compiler->last_error_extra_info, \
        info, \
        sizeof(compiler->last_error_extra_info)); \


#define yr_compiler_set_error_extra_info_fmt(compiler, fmt, ...) \
    snprintf( \
        compiler->last_error_extra_info, \
        sizeof(compiler->last_error_extra_info), \
        fmt, __VA_ARGS__);


int _yr_compiler_push_file_name(
    YR_COMPILER* compiler,
    const char* file_name);


void _yr_compiler_pop_file_name(
    YR_COMPILER* compiler);


int _yr_compiler_get_var_frame(
    YR_COMPILER* compiler);


const char* _yr_compiler_default_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);


YR_RULE* _yr_compiler_get_rule_by_idx(
    YR_COMPILER* compiler, uint32_t rule_idx);


YR_API int yr_compiler_create(
    YR_COMPILER** compiler);


YR_API void yr_compiler_destroy(
    YR_COMPILER* compiler);


YR_API void yr_compiler_set_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_CALLBACK_FUNC callback,
    void* user_data);


YR_API void yr_compiler_set_include_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_INCLUDE_CALLBACK_FUNC include_callback,
    YR_COMPILER_INCLUDE_FREE_FUNC include_free,
    void* user_data);


YR_API void yr_compiler_set_re_ast_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_RE_AST_CALLBACK_FUNC re_ast_callback,
    void* user_data);


YR_API void yr_compiler_set_atom_quality_table(
    YR_COMPILER* compiler,
    const void* table,
    int entries,
    unsigned char warning_threshold);


YR_API int yr_compiler_load_atom_quality_table(
    YR_COMPILER* compiler,
    const char* filename,
    unsigned char warning_threshold);


YR_API int yr_compiler_add_file(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_,
    const char* file_name);


YR_API int yr_compiler_add_fd(
    YR_COMPILER* compiler,
    YR_FILE_DESCRIPTOR rules_fd,
    const char* namespace_,
    const char* file_name);


YR_API int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_);


YR_API char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size);


YR_API char* yr_compiler_get_current_file_name(
    YR_COMPILER* compiler);


YR_API int yr_compiler_define_integer_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int64_t value);


YR_API int yr_compiler_define_boolean_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int value);


YR_API int yr_compiler_define_float_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    double value);


YR_API int yr_compiler_define_string_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    const char* value);


YR_API int yr_compiler_get_rules(
    YR_COMPILER* compiler,
    YR_RULES** rules);


#endif
