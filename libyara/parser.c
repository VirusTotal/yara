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

#include <stddef.h>
#include <string.h>

#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/object.h>
#include <yara/strutils.h>
#include <yara/utils.h>
#include <yara/modules.h>
#include <yara/parser.h>
#include <yara/mem.h>

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


int yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* string = compiler->current_rule_strings;

  const char* string_identifier;
  const char* target_identifier;

  int matching = 0;

  while(!STRING_IS_NULL(string))
  {
    // Don't generate pushes for strings chained to another one, we are
    // only interested in non-chained strings or the head of the chain.

    if (string->chained_to == NULL)
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
            OP_PUSH,
            PTR_TO_UINT64(string),
            NULL);

        string->g_flags |= STRING_GFLAGS_REFERENCED;
        string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        matching++;
      }
    }

    string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  if (matching == 0)
  {
    yr_compiler_set_error_extra_info(compiler, identifier);
    compiler->last_result = ERROR_UNDEFINED_STRING;
  }

  return compiler->last_result;
}


int yr_parser_check_types(
    YR_COMPILER* compiler,
    YR_OBJECT_FUNCTION* function,
    const char* actual_args_fmt)
{
  for (int i = 0; i < MAX_OVERLOADED_FUNCTIONS; i++)
  {
    if (function->prototypes[i].arguments_fmt == NULL)
      break;

    if (strcmp(function->prototypes[i].arguments_fmt, actual_args_fmt) == 0)
    {
      compiler->last_result = ERROR_SUCCESS;
      return compiler->last_result;
    }
  }

  yr_compiler_set_error_extra_info(compiler, function->identifier);
  compiler->last_result = ERROR_WRONG_ARGUMENTS;

  return compiler->last_result;
}


YR_STRING* yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    // If some string $a gets fragmented into multiple chained
    // strings, all those fragments have the same $a identifier
    // but we are interested in the heading fragment, which is
    // that with chained_to == NULL

    if (strcmp(string->identifier, identifier) == 0 &&
        string->chained_to == NULL)
    {
      return string;
    }

    string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);
  compiler->last_result = ERROR_UNDEFINED_STRING;

  return NULL;
}


int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  for (i = 0; i < compiler->loop_depth; i++)
  {
    if (compiler->loop_identifier[i] != NULL &&
        strcmp(identifier, compiler->loop_identifier[i]) == 0)
      return i;
  }

  return -1;
}


int _yr_parser_write_string(
    const char* identifier,
    int flags,
    YR_COMPILER* compiler,
    SIZED_STRING* str,
    RE* re,
    YR_STRING** string,
    int* min_atom_quality)
{
  SIZED_STRING* literal_string;
  YR_AC_MATCH* new_match;
  YR_ATOM_LIST_ITEM* atom_list = NULL;

  int result;
  int max_string_len;
  int free_literal = FALSE;

  *string = NULL;

  result = yr_arena_allocate_struct(
      compiler->strings_arena,
      sizeof(YR_STRING),
      (void**) string,
      offsetof(YR_STRING, identifier),
      offsetof(YR_STRING, string),
      offsetof(YR_STRING, chained_to),
      EOL);

  if (result != ERROR_SUCCESS)
    return result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &(*string)->identifier);

  if (result != ERROR_SUCCESS)
    return result;

  if (flags & STRING_GFLAGS_HEXADECIMAL ||
      flags & STRING_GFLAGS_REGEXP)
  {
    literal_string = yr_re_extract_literal(re);

    if (literal_string != NULL)
    {
      flags |= STRING_GFLAGS_LITERAL;
      free_literal = TRUE;
    }
    else
    {
      // Non-literal strings can't be marked as fixed offset because once we
      // find a string atom in the scanned data we don't know the offset where
      // the string should start, as the non-literal strings can contain
      // variable-length portions.

      flags &= ~STRING_GFLAGS_FIXED_OFFSET;
    }
  }
  else
  {
    literal_string = str;
    flags |= STRING_GFLAGS_LITERAL;
  }

  (*string)->g_flags = flags;
  (*string)->chained_to = NULL;
  (*string)->fixed_offset = UNDEFINED;

  #ifdef PROFILING_ENABLED
  (*string)->clock_ticks = 0;
  #endif

  memset((*string)->matches, 0,
         sizeof((*string)->matches));

  memset((*string)->unconfirmed_matches, 0,
         sizeof((*string)->unconfirmed_matches));

  if (flags & STRING_GFLAGS_LITERAL)
  {
    (*string)->length = literal_string->length;

    result = yr_arena_write_data(
        compiler->sz_arena,
        literal_string->c_string,
        literal_string->length,
        (void**) &(*string)->string);

    if (result == ERROR_SUCCESS)
    {
      result = yr_atoms_extract_from_string(
          (uint8_t*) literal_string->c_string,
          literal_string->length,
          flags,
          &atom_list);
    }
  }
  else
  {
    result = yr_re_emit_code(re, compiler->re_code_arena);

    if (result == ERROR_SUCCESS)
      result = yr_atoms_extract_from_re(re, flags, &atom_list);
  }

  if (result == ERROR_SUCCESS)
  {
    // Add the string to Aho-Corasick automaton.

    if (atom_list != NULL)
    {
      result = yr_ac_add_string(
          compiler->automaton_arena,
          compiler->automaton,
          *string,
          atom_list);
    }
    else
    {
      result = yr_arena_allocate_struct(
          compiler->automaton_arena,
          sizeof(YR_AC_MATCH),
          (void**) &new_match,
          offsetof(YR_AC_MATCH, string),
          offsetof(YR_AC_MATCH, forward_code),
          offsetof(YR_AC_MATCH, backward_code),
          offsetof(YR_AC_MATCH, next),
          EOL);

      if (result == ERROR_SUCCESS)
      {
        new_match->backtrack = 0;
        new_match->string = *string;
        new_match->forward_code = re->root_node->forward_code;
        new_match->backward_code = NULL;
        new_match->next = compiler->automaton->root->matches;
        compiler->automaton->root->matches = new_match;
      }
    }
  }

  *min_atom_quality = yr_atoms_min_quality(atom_list);

  if (flags & STRING_GFLAGS_LITERAL)
  {
    if (flags & STRING_GFLAGS_WIDE)
      max_string_len = (*string)->length * 2;
    else
      max_string_len = (*string)->length;

    if (max_string_len <= MAX_ATOM_LENGTH)
      (*string)->g_flags |= STRING_GFLAGS_FITS_IN_ATOM;
  }

  if (free_literal)
    yr_free(literal_string);

  if (atom_list != NULL)
    yr_atoms_list_destroy(atom_list);

  return result;
}

#include <stdint.h>
#include <limits.h>


YR_STRING* yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t string_flags,
    const char* identifier,
    SIZED_STRING* str)
{
  int min_atom_quality;
  int min_atom_quality_aux;
  int re_flags = 0;

  int32_t min_gap;
  int32_t max_gap;

  char message[512];

  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* string = NULL;
  YR_STRING* aux_string;
  YR_STRING* prev_string;

  RE* re = NULL;
  RE* remainder_re;

  RE_ERROR re_error;

  if (str->flags & SIZED_STRING_FLAGS_NO_CASE)
    string_flags |= STRING_GFLAGS_NO_CASE;

  if (str->flags & SIZED_STRING_FLAGS_DOT_ALL)
    re_flags |= RE_FLAGS_DOT_ALL;

  if (strcmp(identifier,"$") == 0)
    string_flags |= STRING_GFLAGS_ANONYMOUS;

  if (!(string_flags & STRING_GFLAGS_WIDE))
    string_flags |= STRING_GFLAGS_ASCII;

  if (string_flags & STRING_GFLAGS_NO_CASE)
    re_flags |= RE_FLAGS_NO_CASE;

  // The STRING_GFLAGS_SINGLE_MATCH flag indicates that finding
  // a single match for the string is enough. This is true in
  // most cases, except when the string count (#) and string offset (@)
  // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
  // initially, and unmarked later if required.

  string_flags |= STRING_GFLAGS_SINGLE_MATCH;

  // The STRING_GFLAGS_FIXED_OFFSET indicates that the string doesn't
  // need to be searched all over the file because the user is using the
  // "at" operator. The string must be searched at a fixed offset in the
  // file. All strings are marked STRING_GFLAGS_FIXED_OFFSET initially,
  // and unmarked later if required.

  string_flags |= STRING_GFLAGS_FIXED_OFFSET;

  if (string_flags & STRING_GFLAGS_HEXADECIMAL ||
      string_flags & STRING_GFLAGS_REGEXP)
  {
    if (string_flags & STRING_GFLAGS_HEXADECIMAL)
      compiler->last_result = yr_re_parse_hex(
          str->c_string, re_flags, &re, &re_error);
    else
      compiler->last_result = yr_re_parse(
          str->c_string, re_flags, &re, &re_error);

    if (compiler->last_result != ERROR_SUCCESS)
    {
      snprintf(
          message,
          sizeof(message),
          "invalid %s \"%s\": %s",
          (string_flags & STRING_GFLAGS_HEXADECIMAL) ?
              "hex string" : "regular expression",
          identifier,
          re_error.message);

      yr_compiler_set_error_extra_info(
          compiler, message);

      goto _exit;
    }

    if (re->flags & RE_FLAGS_FAST_HEX_REGEXP)
      string_flags |= STRING_GFLAGS_FAST_HEX_REGEXP;

    if (yr_re_contains_dot_star(re))
    {
      snprintf(
        message,
        sizeof(message),
        "%s contains .*, consider using .{N} with a reasonable value for N",
        identifier);

        yywarning(yyscanner, message);
    }

    compiler->last_result = yr_re_split_at_chaining_point(
        re, &re, &remainder_re, &min_gap, &max_gap);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;

    compiler->last_result = _yr_parser_write_string(
        identifier,
        string_flags,
        compiler,
        NULL,
        re,
        &string,
        &min_atom_quality);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;

    if (remainder_re != NULL)
    {
      string->g_flags |= STRING_GFLAGS_CHAIN_TAIL | STRING_GFLAGS_CHAIN_PART;
      string->chain_gap_min = min_gap;
      string->chain_gap_max = max_gap;
    }

    // Use "aux_string" from now on, we want to keep the value of "string"
    // because it will returned.

    aux_string = string;

    while (remainder_re != NULL)
    {
      // Destroy regexp pointed by 're' before yr_re_split_at_jmp
      // overwrites 're' with another value.

      yr_re_destroy(re);

      compiler->last_result = yr_re_split_at_chaining_point(
          remainder_re, &re, &remainder_re, &min_gap, &max_gap);

      if (compiler->last_result != ERROR_SUCCESS)
        goto _exit;

      prev_string = aux_string;

      compiler->last_result = _yr_parser_write_string(
          identifier,
          string_flags,
          compiler,
          NULL,
          re,
          &aux_string,
          &min_atom_quality_aux);

      if (compiler->last_result != ERROR_SUCCESS)
        goto _exit;

      if (min_atom_quality_aux < min_atom_quality)
        min_atom_quality = min_atom_quality_aux;

      aux_string->g_flags |= STRING_GFLAGS_CHAIN_PART;
      aux_string->chain_gap_min = min_gap;
      aux_string->chain_gap_max = max_gap;

      prev_string->chained_to = aux_string;

      // prev_string is now chained to aux_string, an string chained
      // to another one can't have a fixed offset, only the head of the
      // string chain can have a fixed offset.

      prev_string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
    }
  }
  else
  {
    compiler->last_result = _yr_parser_write_string(
        identifier,
        string_flags,
        compiler,
        str,
        NULL,
        &string,
        &min_atom_quality);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;
  }

  if (min_atom_quality < 3 && compiler->callback != NULL)
  {
    snprintf(
        message,
        sizeof(message),
        "%s is slowing down scanning%s",
        string->identifier,
        min_atom_quality < 2 ? " (critical!)" : "");

    yywarning(yyscanner, message);
  }

_exit:

  if (re != NULL)
    yr_re_destroy(re);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  return string;
}


int yr_parser_reduce_rule_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    char* tags,
    YR_STRING* strings,
    YR_META* metas)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  YR_RULE* rule;
  YR_STRING* string;

  if (yr_hash_table_lookup(
        compiler->rules_table,
        identifier,
        compiler->current_namespace->name) != NULL ||
      yr_hash_table_lookup(
        compiler->objects_table,
        identifier,
        compiler->current_namespace->name) != NULL)
  {
    // A rule or variable with the same identifier already exists, return the
    // appropriate error.

    yr_compiler_set_error_extra_info(compiler, identifier);
    compiler->last_result = ERROR_DUPLICATED_IDENTIFIER;
    return compiler->last_result;
  }

  // Check for unreferenced (unused) strings.

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    // Only the heading fragment in a chain of strings (the one with
    // chained_to == NULL) must be referenced. All other fragments
    // are never marked as referenced.

    if (!STRING_IS_REFERENCED(string) &&
        string->chained_to == NULL)
    {
      yr_compiler_set_error_extra_info(compiler, string->identifier);
      compiler->last_result = ERROR_UNREFERENCED_STRING;
      break;
    }

    string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  FAIL_ON_COMPILER_ERROR(yr_arena_allocate_struct(
      compiler->rules_arena,
      sizeof(YR_RULE),
      (void**) &rule,
      offsetof(YR_RULE, identifier),
      offsetof(YR_RULE, tags),
      offsetof(YR_RULE, strings),
      offsetof(YR_RULE, metas),
      offsetof(YR_RULE, ns),
      EOL));

  rule->g_flags = flags | compiler->current_rule_flags;
  rule->tags = tags;
  rule->strings = strings;
  rule->metas = metas;
  rule->ns = compiler->current_namespace;

  #ifdef PROFILING_ENABLED
  rule->clock_ticks = 0;
  #endif

  FAIL_ON_COMPILER_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      (char**) &rule->identifier));

  FAIL_ON_COMPILER_ERROR(yr_parser_emit_with_arg_reloc(
      yyscanner,
      OP_MATCH_RULE,
      PTR_TO_UINT64(rule),
      NULL));

  FAIL_ON_COMPILER_ERROR(yr_hash_table_add(
      compiler->rules_table,
      identifier,
      compiler->current_namespace->name,
      (void*) rule));

  compiler->current_rule_flags = 0;
  compiler->current_rule_strings = NULL;

  return compiler->last_result;
}


int yr_parser_reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t instruction,
    uint64_t at_offset)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0) // is an anonymous string ?
  {
    if (compiler->loop_for_of_mem_offset >= 0) // inside a loop ?
    {
      yr_parser_emit_with_arg(
          yyscanner,
          OP_PUSH_M,
          compiler->loop_for_of_mem_offset,
          NULL);

      yr_parser_emit(yyscanner, instruction, NULL);

      string = compiler->current_rule_strings;

      while(!STRING_IS_NULL(string))
      {
        if (instruction != OP_FOUND)
          string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

        if (instruction == OP_FOUND_AT)
        {
          // Avoid overwriting any previous fixed offset

          if (string->fixed_offset == UNDEFINED)
            string->fixed_offset = at_offset;

          // If a previous fixed offset was different, disable
          // the STRING_GFLAGS_FIXED_OFFSET flag because we only
          // have room to store a single fixed offset value

          if (string->fixed_offset != at_offset)
            string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        }
        else
        {
          string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        }

        string = (YR_STRING*) yr_arena_next_address(
            compiler->strings_arena,
            string,
            sizeof(YR_STRING));
      }
    }
    else
    {
      // Anonymous strings not allowed outside of a loop
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
          OP_PUSH,
          PTR_TO_UINT64(string),
          NULL);

      if (instruction != OP_FOUND)
        string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

      if (instruction == OP_FOUND_AT)
      {
        // Avoid overwriting any previous fixed offset

        if (string->fixed_offset == UNDEFINED)
          string->fixed_offset = at_offset;

        // If a previous fixed offset was different, disable
        // the STRING_GFLAGS_FIXED_OFFSET flag because we only
        // have room to store a single fixed offset value

        if (string->fixed_offset == UNDEFINED ||
            string->fixed_offset != at_offset)
        {
          string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        }
      }
      else
      {
        string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
      }

      yr_parser_emit(yyscanner, instruction, NULL);

      string->g_flags |= STRING_GFLAGS_REFERENCED;
    }
  }

  return compiler->last_result;
}


YR_META* yr_parser_reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int32_t integer)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_META* meta;

  compiler->last_result = yr_arena_allocate_struct(
      compiler->metas_arena,
      sizeof(YR_META),
      (void**) &meta,
      offsetof(YR_META, identifier),
      offsetof(YR_META, string),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      (char**) &meta->identifier);

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


int yr_parser_reduce_import(
    yyscan_t yyscanner,
    SIZED_STRING* module_name)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_OBJECT* module_structure;

  char* name;

  module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      compiler->objects_table,
      module_name->c_string,
      compiler->current_namespace->name);

  // if module already imported, do nothing

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  compiler->last_result = yr_object_create(
      OBJECT_TYPE_STRUCTURE,
      module_name->c_string,
      NULL,
      &module_structure);

  if (compiler->last_result == ERROR_SUCCESS)
    compiler->last_result = yr_hash_table_add(
        compiler->objects_table,
        module_name->c_string,
        compiler->current_namespace->name,
        module_structure);

  if (compiler->last_result == ERROR_SUCCESS)
  {
    compiler->last_result = yr_modules_do_declarations(
        module_name->c_string,
        module_structure);

    if (compiler->last_result == ERROR_UNKNOWN_MODULE)
      yr_compiler_set_error_extra_info(compiler, module_name->c_string);
  }

  if (compiler->last_result == ERROR_SUCCESS)
    compiler->last_result = yr_arena_write_string(
        compiler->sz_arena,
        module_name->c_string,
        &name);

  if (compiler->last_result == ERROR_SUCCESS)
    compiler->last_result = yr_parser_emit_with_arg_reloc(
        yyscanner,
        OP_IMPORT,
        PTR_TO_UINT64(name),
        NULL);

  return compiler->last_result;
}
