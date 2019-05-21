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
#include <yara/hash.h>
#include <yara/utils.h>
#include <yara/filemap.h>


#define YARA_ERROR_LEVEL_ERROR   0
#define YARA_ERROR_LEVEL_WARNING 1


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
  void* address;
  struct _YR_FIXUP* next;

} YR_FIXUP;


typedef struct _YR_COMPILER
{
  int               errors;
  int               current_line;
  int               last_error;
  int               last_error_line;

  jmp_buf           error_recovery;

  YR_ARENA*         sz_arena;
  YR_ARENA*         rules_arena;
  YR_ARENA*         strings_arena;
  YR_ARENA*         code_arena;
  YR_ARENA*         re_code_arena;
  YR_ARENA*         compiled_rules_arena;
  YR_ARENA*         externals_arena;
  YR_ARENA*         namespaces_arena;
  YR_ARENA*         metas_arena;
  YR_ARENA*         matches_arena;
  YR_ARENA*         automaton_arena;

  YR_AC_AUTOMATON*  automaton;
  YR_HASH_TABLE*    rules_table;
  YR_HASH_TABLE*    objects_table;
  YR_HASH_TABLE*    strings_table;
  YR_NAMESPACE*     current_namespace;
  YR_RULE*          current_rule;

  YR_FIXUP*         fixup_stack_head;

  int               namespaces_count;

  uint8_t*          loop_address[YR_MAX_LOOP_NESTING];
  char*             loop_identifier[YR_MAX_LOOP_NESTING];
  int               loop_depth;
  int               loop_for_of_mem_offset;

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


const char* _yr_compiler_default_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data);


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
