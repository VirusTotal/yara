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

#include <setjmp.h>
#include <stdio.h>
#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/filemap.h>
#include <yara/hash.h>
#include <yara/utils.h>

#define YARA_ERROR_LEVEL_ERROR   0
#define YARA_ERROR_LEVEL_WARNING 1

// Expression type constants are powers of two because they are used as flags.
#define EXPRESSION_TYPE_UNKNOWN 0
#define EXPRESSION_TYPE_BOOLEAN 1
#define EXPRESSION_TYPE_INTEGER 2
#define EXPRESSION_TYPE_STRING  4
#define EXPRESSION_TYPE_REGEXP  8
#define EXPRESSION_TYPE_OBJECT  16
#define EXPRESSION_TYPE_FLOAT   32

// The compiler uses an arena to store the data it generates during the
// compilation. Each buffer in the arena is used for storing a different type
// of data. The following identifiers indicate the purpose of each buffer.
#define YR_NAMESPACES_TABLE         0
#define YR_RULES_TABLE              1
#define YR_METAS_TABLE              2
#define YR_STRINGS_TABLE            3
#define YR_EXTERNAL_VARIABLES_TABLE 4
#define YR_SZ_POOL                  5
#define YR_CODE_SECTION             6
#define YR_RE_CODE_SECTION          7
#define YR_AC_TRANSITION_TABLE      8
#define YR_AC_STATE_MATCHES_TABLE   9
#define YR_AC_STATE_MATCHES_POOL    10
#define YR_SUMMARY_SECTION          11

// This is the number of buffers used by the compiler, should match the number
// of items in the list above.
#define YR_NUM_SECTIONS 12

// Number of variables used by loops. This doesn't include user defined
// variables.
#define YR_INTERNAL_LOOP_VARS 3

typedef struct _YR_EXPRESSION
{
  int type;

  union
  {
    int64_t integer;
    YR_OBJECT* object;
    YR_ARENA_REF sized_string_ref;
  } value;

  // An expression can have an associated identifier, if "ptr" is not NULL it
  // points to the identifier name, if it is NULL, then "ref" holds a reference
  // to the identifier within YR_SZ_POOL. When the identifier is in YR_SZ_POOL
  // a pointer can't be used as the YR_SZ_POOL can be moved to a different
  // memory location.
  struct
  {
    const char* ptr;
    YR_ARENA_REF ref;
  } identifier;

} YR_EXPRESSION;

typedef void (*YR_COMPILER_CALLBACK_FUNC)(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
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
  YR_ARENA_REF ref;
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
  YR_ARENA_REF start_ref;

  // vars_count is the number of local variables defined by the loop, and vars
  // is an array of expressions with the identifier and type for each of those
  // local variables.
  int vars_count;
  YR_EXPRESSION vars[YR_MAX_LOOP_VARS];

  // vars_internal_count is the number of variables used by the loop which are
  // not defined by the rule itself but that are necessary for keeping the
  // loop's state. One example is the iteration counter.
  int vars_internal_count;
} YR_LOOP_CONTEXT;

typedef struct _YR_COMPILER
{
  // Arena that contains the data generated by the compiled. The arena has
  // the following buffers:
  //
  //   YR_SUMMARY_SECTION:
  //      A YR_SUMMARY struct.
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
  //      An array of uint32_t containing the Aho-Corasick transition table.
  //      See comment in _yr_ac_build_transition_table for details.
  //   YR_AC_STATE_MATCHES_TABLE:
  //      An array of uint32_t with the same number of items than the transition
  //      table. If entry N in the transition table corresponds to some
  //      Aho-Corasick state, the N-th item in this array has the index within
  //      the matches pool where the list of matches for that state begins.
  //   YR_AC_STATE_MATCHES_POOL:
  //      An array of YR_AC_MATCH structures.
  //
  YR_ARENA* arena;

  // Index of the rule being compiled in the array of YR_RULE structures
  // stored in YR_RULES_TABLE. If this is MAX_UINT32 the compiler is not
  // parsing a rule.
  uint32_t current_rule_idx;

  // Index of the rule that comes next during parsing.
  uint32_t next_rule_idx;

  // Index of the string being compiled in the array of YR_STRING structures
  // stored in YR_STRINGS_TABLE.
  uint32_t current_string_idx;

  // Index of the current namespace in the array of YR_NAMESPACE structures
  // stored in YR_NAMESPACES_TABLE.
  uint32_t current_namespace_idx;

  // Index of the current meta in the array of YR_META structures stored in
  // YR_METAS_TABLE.
  uint32_t current_meta_idx;

  // Pointer to a YR_RULES structure that represents the compiled rules. This
  // is what yr_compiler_get_rules returns. Once these rules are generated you
  // can't call any of the yr_compiler_add_xxx functions.
  YR_RULES* rules;

  int errors;
  int current_line;
  int last_error;
  int last_error_line;

  jmp_buf error_recovery;

  YR_AC_AUTOMATON* automaton;
  YR_HASH_TABLE* rules_table;
  YR_HASH_TABLE* objects_table;
  YR_HASH_TABLE* strings_table;

  // Hash table that contains all the strings that has been written to the
  // YR_SZ_POOL buffer in the compiler's arena. Values in the hash table are
  // the offset within the YR_SZ_POOL where the string resides. This allows to
  // know is some string has already been written in order to reuse instead of
  // writting it again.
  YR_HASH_TABLE* sz_table;

  YR_FIXUP* fixup_stack_head;

  int num_namespaces;

  YR_LOOP_CONTEXT loop[YR_MAX_LOOP_NESTING];
  int loop_index;
  int loop_for_of_var_index;

  char* file_name_stack[YR_MAX_INCLUDE_DEPTH];
  int file_name_stack_ptr;

  char last_error_extra_info[YR_MAX_COMPILER_ERROR_EXTRA_INFO];

  // This buffer is used by the lexer for accumulating text strings. Those
  // strings are copied from flex's internal variables. lex_buf_ptr points to
  // the end of the string and lex_buf_len contains the number of bytes that
  // have been copied into lex_buf.
  char lex_buf[YR_LEX_BUF_SIZE];
  char* lex_buf_ptr;
  unsigned short lex_buf_len;

  char include_base_dir[MAX_PATH];
  void* user_data;
  void* incl_clbk_user_data;
  void* re_ast_clbk_user_data;

  YR_COMPILER_CALLBACK_FUNC callback;
  YR_COMPILER_INCLUDE_CALLBACK_FUNC include_callback;
  YR_COMPILER_INCLUDE_FREE_FUNC include_free;
  YR_COMPILER_RE_AST_CALLBACK_FUNC re_ast_callback;
  YR_ATOMS_CONFIG atoms_config;

} YR_COMPILER;

#define yr_compiler_set_error_extra_info(compiler, info) \
  strlcpy(                                               \
      compiler->last_error_extra_info,                   \
      info,                                              \
      sizeof(compiler->last_error_extra_info));

#define yr_compiler_set_error_extra_info_fmt(compiler, fmt, ...) \
  snprintf(                                                      \
      compiler->last_error_extra_info,                           \
      sizeof(compiler->last_error_extra_info),                   \
      fmt,                                                       \
      __VA_ARGS__);

int _yr_compiler_push_file_name(YR_COMPILER* compiler, const char* file_name);

void _yr_compiler_pop_file_name(YR_COMPILER* compiler);

int _yr_compiler_get_var_frame(YR_COMPILER* compiler);

const char* _yr_compiler_default_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);

YR_RULE* _yr_compiler_get_rule_by_idx(YR_COMPILER* compiler, uint32_t rule_idx);

int _yr_compiler_store_string(
    YR_COMPILER* compiler,
    const char* string,
    YR_ARENA_REF* ref);

int _yr_compiler_store_data(
    YR_COMPILER* compiler,
    const void* data,
    size_t data_length,
    YR_ARENA_REF* ref);

YR_API int yr_compiler_create(YR_COMPILER** compiler);

YR_API void yr_compiler_destroy(YR_COMPILER* compiler);

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

YR_API char* yr_compiler_get_current_file_name(YR_COMPILER* compiler);

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

YR_API int yr_compiler_get_rules(YR_COMPILER* compiler, YR_RULES** rules);

#endif
