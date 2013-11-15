/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

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

#include <stddef.h>
#include <string.h>

#include "atoms.h"
#include "exec.h"
#include "hash.h"
#include "mem.h"
#include "parser.h"
#include "re.h"
#include "utils.h"


#define todigit(x)  ((x) >='A'&& (x) <='F')? \
                    ((uint8_t) (x - 'A' + 10)) : \
                    ((uint8_t) (x - '0'))


int yr_parser_emit(
    yyscan_t yyscanner,
    int8_t instruction,
    int8_t** instruction_address)
{
  return yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);
}


int yr_parser_emit_with_arg(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(int64_t),
        NULL);

  return result;
}


int yr_parser_emit_with_arg_reloc(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
  void* ptr;

  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(int64_t),
        &ptr);

  if (result == ERROR_SUCCESS)
    result = yr_arena_make_relocatable(
        yyget_extra(yyscanner)->code_arena,
        ptr,
        0,
        EOL);

  return result;
}


void yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  STRING* string = compiler->current_rule_strings;
  const char* string_identifier;
  const char* target_identifier;

  while(!STRING_IS_NULL(string))
  {
    string_identifier = string->identifier;
    target_identifier = identifier;

    while (*target_identifier != '\0' &&
           *string_identifier != '\0' &&
           *target_identifier == *string_identifier)
    {
      target_identifier++;
      string_identifier++;
    }

    if ((*target_identifier == '\0' && *string_identifier == '\0') ||
         *target_identifier == '*')
    {
      yr_parser_emit_with_arg_reloc(
          yyscanner,
          PUSH,
          PTR_TO_UINT64(string),
          NULL);

      string->g_flags |= STRING_GFLAGS_REFERENCED;
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(STRING));
  }
}


STRING* yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier)
{
  STRING* string;
  YARA_COMPILER* compiler = yyget_extra(yyscanner);

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    if (strcmp(string->identifier, identifier) == 0)
      return string;

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(STRING));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);
  compiler->last_result = ERROR_UNDEFINED_STRING;

  return NULL;
}


EXTERNAL_VARIABLE* yr_parser_lookup_external_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  EXTERNAL_VARIABLE* external;
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  external = (EXTERNAL_VARIABLE*) yr_arena_base_address(
      compiler->externals_arena);

  for (i = 0; i < compiler->externals_count; i++)
  {
    if (strcmp(external->identifier, identifier) == 0)
      return external;

    external = yr_arena_next_address(
        compiler->externals_arena,
        external,
        sizeof(EXTERNAL_VARIABLE));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);
  compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;

  return NULL;
}


STRING* yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    SIZED_STRING* str)
{
  int i;
  int error_offset;
  int min_atom_length;
  char* file_name;
  char message[512];

  STRING* string;
  AC_MATCH* new_match;
  ATOM_TREE* atom_tree;
  ATOM_LIST_ITEM* atom;
  ATOM_LIST_ITEM* atom_list = NULL;
  RE* re = NULL;

  uint8_t* literal_string;
  int literal_string_len;
  int max_string_len;

  YARA_COMPILER* compiler = yyget_extra(yyscanner);

  compiler->last_result = yr_arena_allocate_struct(
      compiler->strings_arena,
      sizeof(STRING),
      (void**) &string,
      offsetof(STRING, identifier),
      offsetof(STRING, string),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &string->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  if (strcmp(identifier,"$") == 0)
    flags |= STRING_GFLAGS_ANONYMOUS;

  if (!(flags & STRING_GFLAGS_WIDE))
    flags |= STRING_GFLAGS_ASCII;

  // The STRING_GFLAGS_SINGLE_MATCH flag indicates that finding
  // a single match for the string is enough. This is true in
  // most cases, except when the string count (#) and string offset (@)
  // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
  // initially, and unmarked later if required.

  flags |= STRING_GFLAGS_SINGLE_MATCH;

  string->g_flags = flags;

  for (i = 0; i < MAX_THREADS; i++)
  {
    string->matches[i].head = NULL;
    string->matches[i].tail = NULL;
  }

  if (flags & STRING_GFLAGS_HEXADECIMAL ||
      flags & STRING_GFLAGS_REGEXP)
  {
    if (flags & STRING_GFLAGS_HEXADECIMAL)
      compiler->last_result = yr_re_compile_hex(
          str->c_string, &re);
    else
      compiler->last_result = yr_re_compile(
          str->c_string, &re);

    if (compiler->last_result != ERROR_SUCCESS)
    {
      snprintf(
          message,
          sizeof(message),
          "invalid %s in string \"%s\": %s",
          (flags & STRING_GFLAGS_HEXADECIMAL) ?
              "hex string" : "regular expression",
          identifier,
          re->error_message);

      yr_compiler_set_error_extra_info(compiler, message);
      string = NULL;
      goto _exit;
    }

    //
    //yr_re_print(re);
    //printf("\n");
    //

    if (re->flags & RE_FLAGS_START_ANCHORED)
      string->g_flags |= STRING_GFLAGS_START_ANCHORED;

    if (re->flags & RE_FLAGS_END_ANCHORED)
      string->g_flags |= STRING_GFLAGS_END_ANCHORED;

    if (re->flags & RE_FLAGS_LITERAL_STRING)
    {
      string->g_flags |= STRING_GFLAGS_LITERAL;
      literal_string = re->literal_string;
      literal_string_len = re->literal_string_len;

      compiler->last_result = yr_atoms_extract_from_string(
          re->literal_string,
          re->literal_string_len,
          string->g_flags,
          &atom_list);
    }
    else
    {
      compiler->last_result = yr_re_emit_code(
          re, compiler->re_code_arena);

      if (compiler->last_result != ERROR_SUCCESS)
      {
        string = NULL;
        goto _exit;
      }

      compiler->last_result = yr_atoms_extract_from_re(
          re, string->g_flags, &atom_list);
    }
  }
  else
  {
    string->g_flags |= STRING_GFLAGS_LITERAL;
    literal_string = str->c_string;
    literal_string_len = str->length;

    compiler->last_result  = yr_atoms_extract_from_string(
        str->c_string, str->length, string->g_flags, &atom_list);
  }

  if (compiler->last_result != ERROR_SUCCESS)
  {
    string = NULL;
    goto _exit;
  }

  if (STRING_IS_LITERAL(string))
  {
    compiler->last_result = yr_arena_write_data(
        compiler->sz_arena,
        literal_string,
        literal_string_len,
        (void*) &string->string);

    if (compiler->last_result != ERROR_SUCCESS)
    {
      string = NULL;
      goto _exit;
    }

    string->length = literal_string_len;
  }

  // Add the string to Aho-Corasick automaton.

  if (atom_list != NULL)
  {
    compiler->last_result = yr_ac_add_string(
      compiler->automaton_arena,
      compiler->automaton,
      string,
      atom_list);
  }
  else
  {
    compiler->last_result = yr_arena_allocate_struct(
        compiler->automaton_arena,
        sizeof(AC_MATCH),
        (void**) &new_match,
        offsetof(AC_MATCH, string),
        offsetof(AC_MATCH, forward_code),
        offsetof(AC_MATCH, backward_code),
        offsetof(AC_MATCH, next),
        EOL);

    if (compiler->last_result == ERROR_SUCCESS)
    {
      new_match->backtrack = 0;
      new_match->string = string;
      new_match->forward_code = re->root_node->forward_code;
      new_match->backward_code = NULL;
      new_match->next = compiler->automaton->root->matches;
      compiler->automaton->root->matches = new_match;
    }
  }

  atom = atom_list;

  if (atom != NULL)
    min_atom_length = MAX_ATOM_LENGTH;
  else
    min_atom_length = 0;

  while (atom != NULL)
  {
    if (atom->atom_length < min_atom_length)
      min_atom_length = atom->atom_length;
    atom = atom->next;
  }

  if (STRING_IS_LITERAL(string))
  {
    if (STRING_IS_WIDE(string))
      max_string_len = string->length * 2;
    else
      max_string_len = string->length;

    if (max_string_len == min_atom_length)
      string->g_flags |= STRING_GFLAGS_FITS_IN_ATOM;
  }

  if (compiler->file_name_stack_ptr > 0)
    file_name = compiler->file_name_stack[compiler->file_name_stack_ptr - 1];
  else
    file_name = NULL;

  if (min_atom_length < 2 && compiler->error_report_function != NULL)
  {
    snprintf(
        message,
        sizeof(message),
        "%s is slowing down scanning%s",
        string->identifier,
        min_atom_length == 0 ? " (critical!)" : "");

    compiler->error_report_function(
        YARA_ERROR_LEVEL_WARNING,
        file_name,
        yyget_lineno(yyscanner),
        message);
  }

  if (compiler->last_result != ERROR_SUCCESS)
    string = NULL;

_exit:

  if (atom_list != NULL)
    yr_atoms_list_destroy(atom_list);

  if (re != NULL)
    yr_re_destroy(re);

  return string;
}


int yr_parser_reduce_rule_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    char* tags,
    STRING* strings,
    META* metas)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  RULE* rule;
  STRING* string;

  if (yr_hash_table_lookup(
        compiler->rules_table,
        identifier,
        compiler->current_namespace->name) != NULL)
  {
    // A rule with the same identifier already exists, return the
    // appropriate error.

    yr_compiler_set_error_extra_info(compiler, identifier);
    compiler->last_result = ERROR_DUPLICATE_RULE_IDENTIFIER;
    return compiler->last_result;
  }

  // Check for unreferenced (unused) strings.

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    if (!STRING_IS_REFERENCED(string))
    {
      yr_compiler_set_error_extra_info(compiler, string->identifier);
      compiler->last_result = ERROR_UNREFERENCED_STRING;
      break;
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(STRING));
  }

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_arena_allocate_struct(
      compiler->rules_arena,
      sizeof(RULE),
      (void**) &rule,
      offsetof(RULE, identifier),
      offsetof(RULE, tags),
      offsetof(RULE, strings),
      offsetof(RULE, metas),
      offsetof(RULE, ns),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &rule->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_parser_emit_with_arg_reloc(
      yyscanner,
      RULE_POP,
      PTR_TO_UINT64(rule),
      NULL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  rule->g_flags = flags | compiler->current_rule_flags;
  rule->tags = tags;
  rule->strings = strings;
  rule->metas = metas;
  rule->ns = compiler->current_namespace;

  compiler->current_rule_flags = 0;
  compiler->current_rule_strings = NULL;

  yr_hash_table_add(
      compiler->rules_table,
      identifier,
      compiler->current_namespace->name,
      (void*) rule);

  return compiler->last_result;
}


int yr_parser_reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t instruction)
{
  STRING* string;
  YARA_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0)
  {
    if (compiler->loop_depth > 0)
    {
      yr_parser_emit_with_arg(
          yyscanner,
          PUSH_M,
          LOOP_LOCAL_VARS * (compiler->loop_depth - 1),
          NULL);

      yr_parser_emit(yyscanner, instruction, NULL);

      if (instruction != SFOUND)
      {
        string = compiler->current_rule_strings;

        while(!STRING_IS_NULL(string))
        {
          string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;
          string = yr_arena_next_address(
              compiler->strings_arena,
              string,
              sizeof(STRING));
        }
      }
    }
    else
    {
      compiler->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
  }
  else
  {
    string = yr_parser_lookup_string(yyscanner, identifier);

    if (string != NULL)
    {
      yr_parser_emit_with_arg_reloc(
          yyscanner,
          PUSH,
          PTR_TO_UINT64(string),
          NULL);

      if (instruction != SFOUND)
        string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

      yr_parser_emit(yyscanner, instruction, NULL);

      string->g_flags |= STRING_GFLAGS_REFERENCED;
    }
  }

  return compiler->last_result;
}


int yr_parser_reduce_external(
  yyscan_t yyscanner,
  const char* identifier,
  int8_t instruction)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  EXTERNAL_VARIABLE* external;

  external = yr_parser_lookup_external_variable(yyscanner, identifier);

  if (external != NULL)
  {
    if (instruction == EXT_BOOL)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_BOOL,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_INT &&
             external->type == EXTERNAL_VARIABLE_TYPE_INTEGER)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_INT,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_STR &&
             external->type == EXTERNAL_VARIABLE_TYPE_FIXED_STRING)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_STR,
          PTR_TO_UINT64(external),
          NULL);
    }
    else
    {
      yr_compiler_set_error_extra_info(compiler, external->identifier);
      compiler->last_result = ERROR_INCORRECT_VARIABLE_TYPE;
    }
  }

  return compiler->last_result;
}


META* yr_parser_reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int32_t integer)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  META* meta;

  compiler->last_result = yr_arena_allocate_struct(
      compiler->metas_arena,
      sizeof(META),
      (void**) &meta,
      offsetof(META, identifier),
      offsetof(META, string),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &meta->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  if (string != NULL)
    compiler->last_result = yr_arena_write_string(
        compiler->sz_arena,
        string,
        &meta->string);
  else
    meta->string = NULL;

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  meta->integer = integer;
  meta->type = type;

  return meta;
}


int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  for (i = 0; i < compiler->loop_depth; i++)
  {
    if (strcmp(identifier, compiler->loop_identifier[i]) == 0)
      return i;
  }

  return -1;
}


