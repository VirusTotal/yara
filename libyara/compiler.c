/*
Copyright (c) 2013-2018. The YARA Authors. All Rights Reserved.

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

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _MSC_VER
#include <io.h>
#include <share.h>
#else
#include <unistd.h>
#endif

#include <yara/libyara.h>
#include <yara/utils.h>
#include <yara/compiler.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/object.h>
#include <yara/lexer.h>
#include <yara/strutils.h>


static void _yr_compiler_default_include_free(
    const char* callback_result_ptr,
    void* user_data)
{
  if (callback_result_ptr != NULL)
  {
    yr_free((void*)callback_result_ptr);
  }
}


const char* _yr_compiler_default_include_callback(
    const char* include_name,
    const char* calling_rule_filename,
    const char* calling_rule_namespace,
    void* user_data)
{
  #ifndef _MSC_VER
  struct stat stbuf;
  #endif

  char* file_buffer;

  #ifdef _MSC_VER
  long file_size;
  #else
  off_t file_size;
  #endif

  int fd = -1;

  #if defined(_MSC_VER)
  _sopen_s(&fd, include_name, _O_RDONLY | _O_BINARY, _SH_DENYRW, _S_IREAD);
  #elif defined(_WIN32) || defined(__CYGWIN__)
  fd = open(include_name, O_RDONLY | O_BINARY);
  #else
  fd = open(include_name, O_RDONLY);
  #endif

  if (fd == -1)
    return NULL;

  #ifdef _MSC_VER
  file_size = _filelength(fd);
  if (file_size == -1)
  {
    _close(fd);
    return NULL;
  }
  #else
  if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode)))
  {
    close(fd);
    return NULL;
  }
  file_size = stbuf.st_size;
  #endif

  file_buffer = (char*) yr_malloc((size_t) file_size + 1);

  if (file_buffer == NULL)
  {
    #ifdef _MSC_VER
    _close(fd);
    #else
    close(fd);
    #endif

    return NULL;
  }

  if (file_size != read(fd, file_buffer, (size_t) file_size))
  {
    yr_free(file_buffer);

    #ifdef _MSC_VER
    _close(fd);
    #else
    close(fd);
    #endif

    return NULL;
  }
  else
  {
    file_buffer[file_size] = '\0';
  }

  #ifdef _MSC_VER
  _close(fd);
  #else
  close(fd);
  #endif

  return file_buffer;
}


YR_API int yr_compiler_create(
    YR_COMPILER** compiler)
{
  int result;
  YR_COMPILER* new_compiler;

  new_compiler = (YR_COMPILER*) yr_calloc(1, sizeof(YR_COMPILER));

  if (new_compiler == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  new_compiler->errors = 0;
  new_compiler->callback = NULL;
  new_compiler->include_callback = _yr_compiler_default_include_callback;
  new_compiler->incl_clbk_user_data = NULL;
  new_compiler->include_free = _yr_compiler_default_include_free;
  new_compiler->re_ast_callback = NULL;
  new_compiler->re_ast_clbk_user_data = NULL;
  new_compiler->last_error = ERROR_SUCCESS;
  new_compiler->last_error_line = 0;
  new_compiler->current_line = 0;
  new_compiler->file_name_stack_ptr = 0;
  new_compiler->fixup_stack_head = NULL;
  new_compiler->loop_depth = 0;
  new_compiler->loop_for_of_mem_offset = -1;
  new_compiler->compiled_rules_arena = NULL;
  new_compiler->namespaces_count = 0;
  new_compiler->current_rule = NULL;
  new_compiler->atoms_config.get_atom_quality = yr_atoms_heuristic_quality;
  new_compiler->atoms_config.quality_warning_threshold = \
      YR_ATOM_QUALITY_WARNING_THRESHOLD;

  result = yr_hash_table_create(10007, &new_compiler->rules_table);

  if (result == ERROR_SUCCESS)
    result = yr_hash_table_create(10007, &new_compiler->objects_table);

  if (result == ERROR_SUCCESS)
    result = yr_hash_table_create(101, &new_compiler->strings_table);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->sz_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->rules_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->strings_arena);

  if (result == ERROR_SUCCESS)
      result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->code_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->re_code_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->externals_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->namespaces_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->metas_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->automaton_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(
        65536, ARENA_FLAGS_RELOCATABLE, &new_compiler->matches_arena);

  if (result == ERROR_SUCCESS)
    result = yr_ac_automaton_create(&new_compiler->automaton);

  if (result == ERROR_SUCCESS)
  {
    *compiler = new_compiler;
  }
  else  // if error, do cleanup
  {
    yr_compiler_destroy(new_compiler);
  }

  return result;
}


YR_API void yr_compiler_destroy(
    YR_COMPILER* compiler)
{
  YR_FIXUP* fixup;
  int i;

  yr_arena_destroy(compiler->compiled_rules_arena);
  yr_arena_destroy(compiler->sz_arena);
  yr_arena_destroy(compiler->rules_arena);
  yr_arena_destroy(compiler->strings_arena);
  yr_arena_destroy(compiler->code_arena);
  yr_arena_destroy(compiler->re_code_arena);
  yr_arena_destroy(compiler->externals_arena);
  yr_arena_destroy(compiler->namespaces_arena);
  yr_arena_destroy(compiler->metas_arena);
  yr_arena_destroy(compiler->automaton_arena);
  yr_arena_destroy(compiler->matches_arena);

  yr_ac_automaton_destroy(compiler->automaton);

  yr_hash_table_destroy(
      compiler->rules_table,
      NULL);

  yr_hash_table_destroy(
      compiler->strings_table,
      NULL);

  yr_hash_table_destroy(
      compiler->objects_table,
      (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_object_destroy);

  if (compiler->  atoms_config.free_quality_table)
    yr_free(compiler->atoms_config.quality_table);

  for (i = 0; i < compiler->file_name_stack_ptr; i++)
    yr_free(compiler->file_name_stack[i]);

  fixup = compiler->fixup_stack_head;

  while (fixup != NULL)
  {
    YR_FIXUP* next_fixup = fixup->next;
    yr_free(fixup);
    fixup = next_fixup;
  }

  yr_free(compiler);
}


YR_API void yr_compiler_set_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_CALLBACK_FUNC callback,
    void* user_data)
{
  compiler->callback = callback;
  compiler->user_data = user_data;
}


YR_API void yr_compiler_set_include_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_INCLUDE_CALLBACK_FUNC include_callback,
    YR_COMPILER_INCLUDE_FREE_FUNC include_free,
    void* user_data)
{
  compiler->include_callback = include_callback;
  compiler->include_free = include_free;
  compiler->incl_clbk_user_data = user_data;
}


YR_API void yr_compiler_set_re_ast_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_RE_AST_CALLBACK_FUNC re_ast_callback,
    void* user_data)
{
  compiler->re_ast_callback = re_ast_callback;
  compiler->re_ast_clbk_user_data = user_data;
}


//
// yr_compiler_set_atom_quality_table
//
// This function allows to specify an atom quality table to be used by the
// compiler for choosing the best atoms from regular expressions and strings.
// When a quality table is set, the compiler uses yr_atoms_table_quality
// instead of yr_atoms_heuristic_quality for computing atom quality. The table
// has an arbitary number of entries, each composed of YR_MAX_ATOM_LENGTH + 1
// bytes. The first YR_MAX_ATOM_LENGTH bytes from each entry are the atom's
// ones, and the remaining byte is a value in the range 0-255 determining the
// atom's quality. Entries must be lexicografically sorted by atom in ascending
// order.
//
//  [ atom (YR_MAX_ATOM_LENGTH bytes) ] [ quality (1 byte) ]
//
//  [ 00 00 .. 00 00 ] [ 00 ]
//  [ 00 00 .. 00 01 ] [ 45 ]
//  [ 00 00 .. 00 02 ] [ 13 ]
//  ...
//  [ FF FF .. FF FF ] [ 03 ]
//
// The "table" argument must point to a buffer containing the quality in
// the format explained above, and "entries" must contain the number of entries
// in the table. The table can not be freed while the compiler is in use, the
// caller is responsible for freeing the table.
//
// The "warning_threshold" argument must be a number between 0 and 255, if some
// atom choosen for a string have a quality below the specified threshold a
// warning like "<string> is slowing down scanning" is shown.

YR_API void yr_compiler_set_atom_quality_table(
    YR_COMPILER* compiler,
    const void* table,
    int entries,
    unsigned char warning_threshold)
{
  compiler->atoms_config.free_quality_table = false;
  compiler->atoms_config.quality_warning_threshold = warning_threshold;
  compiler->atoms_config.get_atom_quality = yr_atoms_table_quality;
  compiler->atoms_config.quality_table_entries = entries;
  compiler->atoms_config.quality_table = \
      (YR_ATOM_QUALITY_TABLE_ENTRY*) table;
}

//
// yr_compiler_set_atom_quality_table
//
// Load an atom quality table from a file. The file's content must have the
// format explained in the decription for yr_compiler_set_atom_quality_table.
//

YR_API int yr_compiler_load_atom_quality_table(
    YR_COMPILER* compiler,
    const char* filename,
    unsigned char warning_threshold)
{
  long file_size;
  int entries;
  void* table;

  FILE* fh = fopen(filename, "rb");

  if (fh == NULL)
    return ERROR_COULD_NOT_OPEN_FILE;

  fseek(fh, 0L, SEEK_END);
  file_size = ftell(fh);
  fseek(fh, 0L, SEEK_SET);

  table = yr_malloc(file_size);

  if (table == NULL)
  {
    fclose(fh);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  entries = (int) file_size / sizeof(YR_ATOM_QUALITY_TABLE_ENTRY);

  if (fread(table, sizeof(YR_ATOM_QUALITY_TABLE_ENTRY), entries, fh) != entries)
  {
    fclose(fh);
    yr_free(table);
    return ERROR_COULD_NOT_READ_FILE;
  }

  fclose(fh);

  yr_compiler_set_atom_quality_table(
      compiler, table, entries, warning_threshold);

  compiler->atoms_config.free_quality_table = true;

  return ERROR_SUCCESS;
}


int _yr_compiler_push_file_name(
    YR_COMPILER* compiler,
    const char* file_name)
{
  char* str;
  int i;

  for (i = 0; i < compiler->file_name_stack_ptr; i++)
  {
    if (strcmp(file_name, compiler->file_name_stack[i]) == 0)
      return ERROR_INCLUDES_CIRCULAR_REFERENCE;
  }

  if (compiler->file_name_stack_ptr == YR_MAX_INCLUDE_DEPTH)
    return ERROR_INCLUDE_DEPTH_EXCEEDED;

  str = yr_strdup(file_name);

  if (str == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  compiler->file_name_stack[compiler->file_name_stack_ptr] = str;
  compiler->file_name_stack_ptr++;

  return ERROR_SUCCESS;
}


void _yr_compiler_pop_file_name(
    YR_COMPILER* compiler)
{
  if (compiler->file_name_stack_ptr > 0)
  {
    compiler->file_name_stack_ptr--;
    yr_free(compiler->file_name_stack[compiler->file_name_stack_ptr]);
    compiler->file_name_stack[compiler->file_name_stack_ptr] = NULL;
  }
}


YR_API char* yr_compiler_get_current_file_name(
    YR_COMPILER* compiler)
{
  if (compiler->file_name_stack_ptr > 0)
  {
    return compiler->file_name_stack[compiler->file_name_stack_ptr - 1];
  }
  else
  {
    return NULL;
  }
}


static int _yr_compiler_set_namespace(
    YR_COMPILER* compiler,
    const char* namespace_)
{
  YR_NAMESPACE* ns;

  char* ns_name;
  int result;
  int i;
  bool found;

  ns = (YR_NAMESPACE*) yr_arena_base_address(compiler->namespaces_arena);
  found = false;

  for (i = 0; i < compiler->namespaces_count; i++)
  {
    if (strcmp(ns->name, namespace_) == 0)
    {
      found = true;
      break;
    }

    ns = (YR_NAMESPACE*) yr_arena_next_address(
        compiler->namespaces_arena,
        ns,
        sizeof(YR_NAMESPACE));
  }

  if (!found)
  {
    result = yr_arena_write_string(
        compiler->sz_arena,
        namespace_,
        &ns_name);

    if (result == ERROR_SUCCESS)
      result = yr_arena_allocate_struct(
          compiler->namespaces_arena,
          sizeof(YR_NAMESPACE),
          (void**) &ns,
          offsetof(YR_NAMESPACE, name),
          EOL);

    if (result != ERROR_SUCCESS)
      return result;

    ns->name = ns_name;

    for (i = 0; i < YR_MAX_THREADS; i++)
      ns->t_flags[i] = 0;

    compiler->namespaces_count++;
  }

  compiler->current_namespace = ns;
  return ERROR_SUCCESS;
}


YR_API int yr_compiler_add_file(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_,
    const char* file_name)
{
  int result;

  // Don't allow yr_compiler_add_file() after
  // yr_compiler_get_rules() has been called.

  assert(compiler->compiled_rules_arena == NULL);

  // Don't allow calls to yr_compiler_add_file() if a previous call to
  // yr_compiler_add_XXXX failed.

  assert(compiler->errors == 0);

  if (namespace_ != NULL)
    compiler->last_error = _yr_compiler_set_namespace(compiler, namespace_);
  else
    compiler->last_error = _yr_compiler_set_namespace(compiler, "default");

  if (compiler->last_error == ERROR_SUCCESS && file_name != NULL)
    compiler->last_error = _yr_compiler_push_file_name(compiler, file_name);

  if (compiler->last_error != ERROR_SUCCESS)
    return ++compiler->errors;

  result = yr_lex_parse_rules_file(rules_file, compiler);

  if (file_name != NULL)
    _yr_compiler_pop_file_name(compiler);

  return result;
}


YR_API int yr_compiler_add_fd(
    YR_COMPILER* compiler,
    YR_FILE_DESCRIPTOR rules_fd,
    const char* namespace_,
    const char* file_name)
{
  int result;

  // Don't allow yr_compiler_add_fd() after
  // yr_compiler_get_rules() has been called.

  assert(compiler->compiled_rules_arena == NULL);

  // Don't allow calls to yr_compiler_add_fd() if a previous call to
  // yr_compiler_add_XXXX failed.

  assert(compiler->errors == 0);

  if (namespace_ != NULL)
    compiler->last_error = _yr_compiler_set_namespace(compiler, namespace_);
  else
    compiler->last_error = _yr_compiler_set_namespace(compiler, "default");

  if (compiler->last_error == ERROR_SUCCESS && file_name != NULL)
    compiler->last_error = _yr_compiler_push_file_name(compiler, file_name);

  if (compiler->last_error != ERROR_SUCCESS)
    return ++compiler->errors;

  result = yr_lex_parse_rules_fd(rules_fd, compiler);

  if (file_name != NULL)
    _yr_compiler_pop_file_name(compiler);

  return result;
}


YR_API int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_)
{
  // Don't allow calls to yr_compiler_add_string() after
  // yr_compiler_get_rules() has been called.

  assert(compiler->compiled_rules_arena == NULL);

  // Don't allow calls to yr_compiler_add_string() if a previous call to
  // yr_compiler_add_XXXX failed.

  assert(compiler->errors == 0);

  if (namespace_ != NULL)
    compiler->last_error = _yr_compiler_set_namespace(compiler, namespace_);
  else
    compiler->last_error = _yr_compiler_set_namespace(compiler, "default");

  if (compiler->last_error != ERROR_SUCCESS)
    return ++compiler->errors;

  return yr_lex_parse_rules_string(rules_string, compiler);
}


static int _yr_compiler_compile_rules(
    YR_COMPILER* compiler)
{
  YARA_RULES_FILE_HEADER* rules_file_header = NULL;
  YR_ARENA* arena = NULL;
  YR_RULE null_rule;
  YR_EXTERNAL_VARIABLE null_external;
  YR_AC_TABLES tables;

  uint8_t halt = OP_HALT;
  int result;

  // Write halt instruction at the end of code.
  yr_arena_write_data(
      compiler->code_arena,
      &halt,
      sizeof(uint8_t),
      NULL);

  // Write a null rule indicating the end.
  memset(&null_rule, 0xFA, sizeof(YR_RULE));
  null_rule.g_flags = RULE_GFLAGS_NULL;

  yr_arena_write_data(
      compiler->rules_arena,
      &null_rule,
      sizeof(YR_RULE),
      NULL);

  // Write a null external the end.
  memset(&null_external, 0xFA, sizeof(YR_EXTERNAL_VARIABLE));
  null_external.type = EXTERNAL_VARIABLE_TYPE_NULL;

  yr_arena_write_data(
      compiler->externals_arena,
      &null_external,
      sizeof(YR_EXTERNAL_VARIABLE),
      NULL);

  // Write Aho-Corasick automaton to arena.
  result = yr_ac_compile(
      compiler->automaton,
      compiler->automaton_arena,
      &tables);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(1024, ARENA_FLAGS_RELOCATABLE, &arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_allocate_struct(
        arena,
        sizeof(YARA_RULES_FILE_HEADER),
        (void**) &rules_file_header,
        offsetof(YARA_RULES_FILE_HEADER, rules_list_head),
        offsetof(YARA_RULES_FILE_HEADER, externals_list_head),
        offsetof(YARA_RULES_FILE_HEADER, code_start),
        offsetof(YARA_RULES_FILE_HEADER, ac_match_table),
        offsetof(YARA_RULES_FILE_HEADER, ac_transition_table),
        EOL);

  if (result == ERROR_SUCCESS)
  {
    rules_file_header->rules_list_head = (YR_RULE*) yr_arena_base_address(
        compiler->rules_arena);

    rules_file_header->externals_list_head = (YR_EXTERNAL_VARIABLE*)
		yr_arena_base_address(compiler->externals_arena);

    rules_file_header->code_start = (uint8_t*) yr_arena_base_address(
        compiler->code_arena);

    rules_file_header->ac_match_table = tables.matches;
    rules_file_header->ac_transition_table = tables.transitions;
    rules_file_header->ac_tables_size = compiler->automaton->tables_size;
  }

  if (result == ERROR_SUCCESS)
  {
    result = yr_arena_append(
        arena,
        compiler->code_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->code_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->re_code_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->re_code_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->rules_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->rules_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->strings_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->strings_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->externals_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->externals_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->namespaces_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->namespaces_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->metas_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->metas_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->sz_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->sz_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->automaton_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->automaton_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->matches_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->matches_arena = NULL;
    compiler->compiled_rules_arena = arena;
    result = yr_arena_coalesce(arena);
  }
  else
  {
    yr_arena_destroy(arena);
  }

  return result;
}


YR_API int yr_compiler_get_rules(
    YR_COMPILER* compiler,
    YR_RULES** rules)
{
  YR_RULES* yara_rules;
  YARA_RULES_FILE_HEADER* rules_file_header;

  // Don't allow calls to yr_compiler_get_rules() if a previous call to
  // yr_compiler_add_XXXX failed.

  assert(compiler->errors == 0);

  *rules = NULL;

  if (compiler->compiled_rules_arena == NULL)
     FAIL_ON_ERROR(_yr_compiler_compile_rules(compiler));

  yara_rules = (YR_RULES*) yr_malloc(sizeof(YR_RULES));

  if (yara_rules == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_arena_duplicate(compiler->compiled_rules_arena, &yara_rules->arena),
      yr_free(yara_rules));

  rules_file_header = (YARA_RULES_FILE_HEADER*) yr_arena_base_address(
      yara_rules->arena);

  yara_rules->externals_list_head = rules_file_header->externals_list_head;
  yara_rules->rules_list_head = rules_file_header->rules_list_head;
  yara_rules->ac_match_table = rules_file_header->ac_match_table;
  yara_rules->ac_transition_table = rules_file_header->ac_transition_table;
  yara_rules->ac_tables_size = rules_file_header->ac_tables_size;
  yara_rules->code_start = rules_file_header->code_start;
  yara_rules->time_cost = 0;

  memset(yara_rules->tidx_mask, 0, sizeof(yara_rules->tidx_mask));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_mutex_create(&yara_rules->mutex),
      // cleanup
      yr_arena_destroy(yara_rules->arena);
      yr_free(yara_rules));

  *rules = yara_rules;

  return ERROR_SUCCESS;
}

int _yr_compiler_define_variable(
    YR_COMPILER* compiler,
    YR_EXTERNAL_VARIABLE* external)
{
  YR_EXTERNAL_VARIABLE* ext;
  YR_OBJECT* object;

  char* id;

  object = (YR_OBJECT*) yr_hash_table_lookup(
      compiler->objects_table,
      external->identifier,
      NULL);

  if (object != NULL)
    return ERROR_DUPLICATED_EXTERNAL_VARIABLE;

  FAIL_ON_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      external->identifier,
      &id));

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->externals_arena,
      sizeof(YR_EXTERNAL_VARIABLE),
      (void**) &ext,
      offsetof(YR_EXTERNAL_VARIABLE, identifier),
      EOL));

  ext->identifier = id;
  ext->type = external->type;
  ext->value = external->value;

  if (external->type == EXTERNAL_VARIABLE_TYPE_STRING)
  {
    char* val;

    FAIL_ON_ERROR(yr_arena_write_string(
        compiler->sz_arena,
        external->value.s,
        &val));

    ext->value.s = val;

    FAIL_ON_ERROR(yr_arena_make_ptr_relocatable(
        compiler->externals_arena,
        ext,
        offsetof(YR_EXTERNAL_VARIABLE, value.s),
        EOL));
  }

  FAIL_ON_ERROR(yr_object_from_external_variable(
      external,
      &object));

  FAIL_ON_ERROR(yr_hash_table_add(
      compiler->objects_table,
      external->identifier,
      NULL,
      (void*) object));

  return ERROR_SUCCESS;
}


YR_API int yr_compiler_define_integer_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int64_t value)
{
  YR_EXTERNAL_VARIABLE external;

  external.type = EXTERNAL_VARIABLE_TYPE_INTEGER;
  external.identifier = identifier;
  external.value.i = value;

  FAIL_ON_ERROR(_yr_compiler_define_variable(
      compiler, &external));

  return ERROR_SUCCESS;
}


YR_API int yr_compiler_define_boolean_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int value)
{
  YR_EXTERNAL_VARIABLE external;

  external.type = EXTERNAL_VARIABLE_TYPE_BOOLEAN;
  external.identifier = identifier;
  external.value.i = value;

  FAIL_ON_ERROR(_yr_compiler_define_variable(
      compiler, &external));

  return ERROR_SUCCESS;
}


YR_API int yr_compiler_define_float_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    double value)
{
  YR_EXTERNAL_VARIABLE external;

  external.type = EXTERNAL_VARIABLE_TYPE_FLOAT;
  external.identifier = identifier;
  external.value.f = value;

  FAIL_ON_ERROR(_yr_compiler_define_variable(
      compiler, &external));

  return ERROR_SUCCESS;
}


YR_API int yr_compiler_define_string_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    const char* value)
{
  YR_EXTERNAL_VARIABLE external;

  external.type = EXTERNAL_VARIABLE_TYPE_STRING;
  external.identifier = identifier;
  external.value.s = (char*) value;

  FAIL_ON_ERROR(_yr_compiler_define_variable(
      compiler, &external));

  return ERROR_SUCCESS;
}


YR_API char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size)
{
  uint32_t max_strings_per_rule;

  switch(compiler->last_error)
  {
    case ERROR_INSUFFICIENT_MEMORY:
      snprintf(buffer, buffer_size, "not enough memory");
      break;
    case ERROR_DUPLICATED_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicated identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATED_STRING_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicated string identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATED_TAG_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicated tag identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATED_META_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicated metadata identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATED_LOOP_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicated loop identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_UNDEFINED_STRING:
      snprintf(
          buffer,
          buffer_size,
          "undefined string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_UNDEFINED_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "undefined identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_UNREFERENCED_STRING:
      snprintf(
          buffer,
          buffer_size,
          "unreferenced string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_EMPTY_STRING:
      snprintf(
          buffer,
          buffer_size,
          "empty string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_NOT_A_STRUCTURE:
      snprintf(
          buffer,
          buffer_size,
          "\"%s\" is not a structure",
          compiler->last_error_extra_info);
      break;
    case ERROR_NOT_INDEXABLE:
      snprintf(
          buffer,
          buffer_size,
          "\"%s\" is not an array or dictionary",
          compiler->last_error_extra_info);
      break;
    case ERROR_NOT_A_FUNCTION:
      snprintf(
          buffer,
          buffer_size,
          "\"%s\" is not a function",
          compiler->last_error_extra_info);
      break;
    case ERROR_INVALID_FIELD_NAME:
      snprintf(
          buffer,
          buffer_size,
          "invalid field name \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_MISPLACED_ANONYMOUS_STRING:
      snprintf(
          buffer,
          buffer_size,
          "wrong use of anonymous string");
      break;
    case ERROR_INCLUDES_CIRCULAR_REFERENCE:
      snprintf(
          buffer,
          buffer_size,
          "include circular reference");
      break;
    case ERROR_INCLUDE_DEPTH_EXCEEDED:
      snprintf(buffer,
          buffer_size,
          "too many levels of included rules");
      break;
    case ERROR_LOOP_NESTING_LIMIT_EXCEEDED:
      snprintf(buffer,
          buffer_size,
          "loop nesting limit exceeded");
      break;
    case ERROR_NESTED_FOR_OF_LOOP:
      snprintf(buffer,
          buffer_size,
          "'for <quantifier> of <string set>' loops can't be nested");
      break;
    case ERROR_UNKNOWN_MODULE:
      snprintf(
          buffer,
          buffer_size,
          "unknown module \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_INVALID_MODULE_NAME:
      snprintf(
          buffer,
          buffer_size,
          "invalid module name \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATED_STRUCTURE_MEMBER:
      snprintf(buffer,
          buffer_size,
          "duplicated structure member");
      break;
    case ERROR_WRONG_ARGUMENTS:
      snprintf(
          buffer,
          buffer_size,
          "wrong arguments for function \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_WRONG_RETURN_TYPE:
      snprintf(buffer,
          buffer_size,
          "wrong return type for overloaded function");
      break;
    case ERROR_INVALID_HEX_STRING:
    case ERROR_INVALID_REGULAR_EXPRESSION:
    case ERROR_SYNTAX_ERROR:
    case ERROR_WRONG_TYPE:
      snprintf(
          buffer,
          buffer_size,
          "%s",
          compiler->last_error_extra_info);
      break;
    case ERROR_INTERNAL_FATAL_ERROR:
      snprintf(
          buffer,
          buffer_size,
          "internal fatal error");
      break;
    case ERROR_DIVISION_BY_ZERO:
      snprintf(
          buffer,
          buffer_size,
          "division by zero");
      break;
    case ERROR_REGULAR_EXPRESSION_TOO_LARGE:
      snprintf(
          buffer,
          buffer_size,
          "regular expression is too large");
      break;
    case ERROR_REGULAR_EXPRESSION_TOO_COMPLEX:
      snprintf(
          buffer,
          buffer_size,
          "regular expression is too complex");
      break;
    case ERROR_TOO_MANY_STRINGS:
       yr_get_configuration(
          YR_CONFIG_MAX_STRINGS_PER_RULE,
          &max_strings_per_rule);
       snprintf(
          buffer,
          buffer_size,
          "too many strings in rule \"%s\" (limit: %d)",
          compiler->last_error_extra_info,
          max_strings_per_rule);
      break;
    case ERROR_INTEGER_OVERFLOW:
      snprintf(
          buffer,
          buffer_size,
          "integer overflow in \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_COULD_NOT_READ_FILE:
      snprintf(
          buffer,
          buffer_size,
          "could not read file");
      break;
  }

  return buffer;
}
