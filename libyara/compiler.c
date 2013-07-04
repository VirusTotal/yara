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
#include <stdio.h>
#include <string.h>

#include "arena.h"
#include "exec.h"
#include "filemap.h"
#include "lex.h"
#include "mem.h"
#include "utils.h"
#include "yara.h"


int yr_compiler_create(
    YARA_COMPILER** compiler)
{
  int result;
  YARA_COMPILER* new_compiler;

  new_compiler = (YARA_COMPILER*) yr_malloc(sizeof(YARA_COMPILER));

  if (new_compiler == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  new_compiler->errors = 0;
  new_compiler->error_report_function = NULL;
  new_compiler->last_error = ERROR_SUCCESS;
  new_compiler->last_error_line = 0;
  new_compiler->last_result = ERROR_SUCCESS;
  new_compiler->file_stack_ptr = 0;
  new_compiler->file_name_stack_ptr = 0;
  new_compiler->current_rule_flags = 0;
  new_compiler->inside_for = 0;
  new_compiler->allow_includes = 1;
  new_compiler->loop_identifier = NULL;
  new_compiler->compiled_rules_arena = NULL;
  new_compiler->externals_count = 0;
  new_compiler->namespaces_count = 0;

  result = yr_hash_table_create(10007, &new_compiler->rules_table);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->sz_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->rules_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->strings_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->code_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->automaton_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->externals_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->namespaces_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(&new_compiler->metas_arena);

  if (result == ERROR_SUCCESS)
    result = yr_ac_create_automaton(
        new_compiler->automaton_arena,
        &new_compiler->automaton);

  if (result == ERROR_SUCCESS)
  {
    *compiler = new_compiler;
  }
  else  // if error, do cleanup
  {
    if (new_compiler->sz_arena != NULL)
      yr_arena_destroy(new_compiler->sz_arena);

    if (new_compiler->rules_arena != NULL)
      yr_arena_destroy(new_compiler->rules_arena);

    if (new_compiler->strings_arena != NULL)
      yr_arena_destroy(new_compiler->strings_arena);

    if (new_compiler->code_arena != NULL)
      yr_arena_destroy(new_compiler->code_arena);

    if (new_compiler->automaton_arena != NULL)
      yr_arena_destroy(new_compiler->automaton_arena);

    if (new_compiler->externals_arena != NULL)
      yr_arena_destroy(new_compiler->externals_arena);

    if (new_compiler->namespaces_arena != NULL)
      yr_arena_destroy(new_compiler->namespaces_arena);

    if (new_compiler->metas_arena != NULL)
      yr_arena_destroy(new_compiler->metas_arena);

    yr_free(new_compiler);
  }

  return result;
}


void yr_compiler_destroy(
    YARA_COMPILER* compiler)
{
  int i;

  if (compiler->compiled_rules_arena != NULL)
    yr_arena_destroy(compiler->compiled_rules_arena);

  if (compiler->sz_arena != NULL)
    yr_arena_destroy(compiler->sz_arena);

  if (compiler->rules_arena != NULL)
    yr_arena_destroy(compiler->rules_arena);

  if (compiler->strings_arena != NULL)
    yr_arena_destroy(compiler->strings_arena);

  if (compiler->code_arena != NULL)
    yr_arena_destroy(compiler->code_arena);

  if (compiler->automaton_arena != NULL)
    yr_arena_destroy(compiler->automaton_arena);

  if (compiler->externals_arena != NULL)
    yr_arena_destroy(compiler->externals_arena);

  if (compiler->namespaces_arena != NULL)
    yr_arena_destroy(compiler->namespaces_arena);

  if (compiler->metas_arena != NULL)
    yr_arena_destroy(compiler->metas_arena);

  yr_hash_table_destroy(compiler->rules_table);

  for (i = 0; i < compiler->file_name_stack_ptr; i++)
    yr_free(compiler->file_name_stack[i]);

  yr_free(compiler);
}


int _yr_compiler_push_file(
    YARA_COMPILER* compiler,
    FILE* fh)
{
  if (compiler->file_stack_ptr < MAX_INCLUDE_DEPTH)
  {
    compiler->file_stack[compiler->file_stack_ptr] = fh;
    compiler->file_stack_ptr++;
    return ERROR_SUCCESS;
  }
  else
  {
    compiler->last_result = ERROR_INCLUDE_DEPTH_EXCEEDED;
    return ERROR_INCLUDE_DEPTH_EXCEEDED;
  }
}


FILE* _yr_compiler_pop_file(
    YARA_COMPILER* compiler)
{
  FILE* result = NULL;

  if (compiler->file_stack_ptr > 0)
  {
    compiler->file_stack_ptr--;
    result = compiler->file_stack[compiler->file_stack_ptr];
  }

  return result;
}

int yr_compiler_push_file_name(
    YARA_COMPILER* compiler,
    const char* file_name)
{
  int i;

  for (i = 0; i < compiler->file_name_stack_ptr; i++)
  {
    if (strcmp(file_name, compiler->file_name_stack[i]) == 0)
    {
      compiler->last_result = ERROR_INCLUDES_CIRCULAR_REFERENCE;
      return ERROR_INCLUDES_CIRCULAR_REFERENCE;
    }
  }

  if (compiler->file_name_stack_ptr < MAX_INCLUDE_DEPTH)
  {
    compiler->file_name_stack[compiler->file_name_stack_ptr] = yr_strdup(
        file_name);
    compiler->file_name_stack_ptr++;
    return ERROR_SUCCESS;
  }
  else
  {
    compiler->last_result = ERROR_INCLUDE_DEPTH_EXCEEDED;
    return ERROR_INCLUDE_DEPTH_EXCEEDED;
  }
}


void yr_compiler_pop_file_name(
    YARA_COMPILER* compiler)
{
  if (compiler->file_name_stack_ptr > 0)
  {
    compiler->file_name_stack_ptr--;
    yr_free(compiler->file_name_stack[compiler->file_name_stack_ptr]);
    compiler->file_name_stack[compiler->file_name_stack_ptr] = NULL;
  }
}


char* yr_compiler_get_current_file_name(
    YARA_COMPILER* context)
{
  if (context->file_name_stack_ptr > 0)
  {
    return context->file_name_stack[context->file_name_stack_ptr - 1];
  }
  else
  {
    return NULL;
  }
}


int _yr_compiler_set_namespace(
    YARA_COMPILER* compiler,
    const char* namespace)
{
  NAMESPACE* ns;
  char* ns_name;
  int result;
  int i;
  int found;


  ns = yr_arena_base_address(compiler->namespaces_arena);
  found = FALSE;

  for (i = 0; i < compiler->namespaces_count; i++)
  {
    if (strcmp(ns->name, namespace) == 0)
    {
      found = TRUE;
      break;
    }

    ns = yr_arena_next_address(
        compiler->namespaces_arena,
        ns,
        sizeof(NAMESPACE));
  }

  if (!found)
  {
    result = yr_arena_write_string(
        compiler->sz_arena,
        namespace,
        &ns_name);

    if (result == ERROR_SUCCESS)
      result = yr_arena_allocate_struct(
          compiler->namespaces_arena,
          sizeof(NAMESPACE),
          (void*) &ns,
          offsetof(NAMESPACE, name),
          EOL);

    if (result != ERROR_SUCCESS)
      return result;

    ns->name = ns_name;
    ns->flags = 0;
    compiler->namespaces_count++;
  }

  compiler->current_namespace = ns;
  return ERROR_SUCCESS;
}

int yr_compiler_add_file(
    YARA_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace)
{
  if (namespace != NULL)
    _yr_compiler_set_namespace(compiler, namespace);
  else
    _yr_compiler_set_namespace(compiler, "default");

  return yr_lex_parse_rules_file(rules_file, compiler);
}


int yr_compiler_add_string(
    YARA_COMPILER* compiler,
    const char* rules_string,
    const char* namespace)
{
  if (namespace != NULL)
    _yr_compiler_set_namespace(compiler, namespace);
  else
    _yr_compiler_set_namespace(compiler, "default");

  return yr_lex_parse_rules_string(rules_string, compiler);
}

int _yr_compiler_compile_rules(
  YARA_COMPILER* compiler)
{
  YARA_RULES_FILE_HEADER* rules_file_header;
  ARENA* arena;
  RULE null_rule;
  EXTERNAL_VARIABLE null_external;

  int8_t halt = HALT;
  int result;

  // Write halt instruction at the end of code.
  yr_arena_write_data(
      compiler->code_arena,
      &halt,
      sizeof(int8_t),
      NULL);

  // Write a null rule indicating the end.
  memset(&null_rule, 0xFA, sizeof(RULE));
  null_rule.flags = RULE_FLAGS_NULL;

  yr_arena_write_data(
      compiler->rules_arena,
      &null_rule,
      sizeof(RULE),
      NULL);

  // Write a null external the end.
  memset(&null_external, 0xFA, sizeof(EXTERNAL_VARIABLE));
  null_external.type = EXTERNAL_VARIABLE_TYPE_NULL;

  yr_arena_write_data(
      compiler->externals_arena,
      &null_external,
      sizeof(EXTERNAL_VARIABLE),
      NULL);

  // Create Aho-Corasick automaton's failure links.
  yr_ac_create_failure_links(
      compiler->automaton_arena,
      compiler->automaton);

  result = yr_arena_create(&arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_allocate_struct(
        arena,
        sizeof(YARA_RULES_FILE_HEADER),
        (void**) &rules_file_header,
        offsetof(YARA_RULES_FILE_HEADER, rules_list_head),
        offsetof(YARA_RULES_FILE_HEADER, externals_list_head),
        offsetof(YARA_RULES_FILE_HEADER, code_start),
        offsetof(YARA_RULES_FILE_HEADER, automaton),
        EOL);

  if (result == ERROR_SUCCESS)
  {
    rules_file_header->rules_list_head = yr_arena_base_address(
        compiler->rules_arena);

    rules_file_header->externals_list_head = yr_arena_base_address(
        compiler->externals_arena);

    rules_file_header->code_start = yr_arena_base_address(
        compiler->code_arena);

    rules_file_header->automaton = yr_arena_base_address(
        compiler->automaton_arena);
  }

  if (result == ERROR_SUCCESS)
    result = yr_arena_append(
        arena,
        compiler->automaton_arena);

  if (result == ERROR_SUCCESS)
  {
    compiler->automaton_arena = NULL;
    result = yr_arena_append(
        arena,
        compiler->code_arena);
  }

  if (result == ERROR_SUCCESS)
  {
    compiler->code_arena = NULL;
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
    compiler->compiled_rules_arena = arena;
    result = yr_arena_coalesce(arena);
  }

  return result;
}


int yr_compiler_get_rules(
    YARA_COMPILER* compiler,
    YARA_RULES** rules)
{
  YARA_RULES* yara_rules;
  YARA_RULES_FILE_HEADER* rules_file_header;

  int result = ERROR_SUCCESS;

  if (compiler->compiled_rules_arena == NULL)
     result = _yr_compiler_compile_rules(compiler);

  if (result != ERROR_SUCCESS)
    return result;

  yara_rules = yr_malloc(sizeof(YARA_RULES));

  if (yara_rules == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  result = yr_arena_duplicate(
      compiler->compiled_rules_arena,
      &yara_rules->arena);

  if (result == ERROR_SUCCESS)
  {
    rules_file_header = (YARA_RULES_FILE_HEADER*) yr_arena_base_address(
        yara_rules->arena);

    yara_rules->externals_list_head = NULL;
    yara_rules->rules_list_head = rules_file_header->rules_list_head;
    yara_rules->externals_list_head = rules_file_header->externals_list_head;
    yara_rules->automaton = rules_file_header->automaton;
    yara_rules->code_start = rules_file_header->code_start;
    yara_rules->matches_arena = NULL;

    *rules = yara_rules;
  }
  else
  {
    yr_free(yara_rules);
    *rules = NULL;
  }

  return result;
}


int yr_compiler_define_integer_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    int64_t value)
{
  EXTERNAL_VARIABLE* external;

  char* id;
  int result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &id);

  if (result == ERROR_SUCCESS)
    result = yr_arena_allocate_struct(
        compiler->externals_arena,
        sizeof(EXTERNAL_VARIABLE),
        (void**) &external,
        offsetof(EXTERNAL_VARIABLE, identifier),
        offsetof(EXTERNAL_VARIABLE, string),
        EOL);

  if (result == ERROR_SUCCESS)
  {
    external->type = EXTERNAL_VARIABLE_TYPE_INTEGER;
    external->identifier = id;
    external->integer = value;
    external->string = NULL;
  }

  compiler->externals_count++;
  compiler->last_result = result;
  return result;
}


int yr_compiler_define_boolean_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    int value)
{
  EXTERNAL_VARIABLE* external;

  char* id;
  int result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &id);

  if (result == ERROR_SUCCESS)
    result = yr_arena_allocate_struct(
        compiler->externals_arena,
        sizeof(EXTERNAL_VARIABLE),
        (void**) &external,
        offsetof(EXTERNAL_VARIABLE, identifier),
        offsetof(EXTERNAL_VARIABLE, string),
        EOL);

  if (result == ERROR_SUCCESS)
  {
    external->type = EXTERNAL_VARIABLE_TYPE_BOOLEAN;
    external->identifier = id;
    external->integer = value;
    external->string = NULL;
  }

  compiler->externals_count++;
  compiler->last_result = result;

  return result;
}


int yr_compiler_define_string_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    const char* value)
{
  EXTERNAL_VARIABLE* external;

  char* id;
  char* val;
  int result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &id);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_string(
      compiler->sz_arena,
      value,
      &val);

  if (result == ERROR_SUCCESS)
    result = yr_arena_allocate_struct(
        compiler->externals_arena,
        sizeof(EXTERNAL_VARIABLE),
        (void**) &external,
        offsetof(EXTERNAL_VARIABLE, identifier),
        offsetof(EXTERNAL_VARIABLE, string),
        EOL);

  if (result == ERROR_SUCCESS)
  {
    external->type = EXTERNAL_VARIABLE_TYPE_FIXED_STRING;
    external->identifier = id;
    external->integer = 0;
    external->string = val;
  }

  compiler->externals_count++;
  compiler->last_result = result;

  return result;
}


char* yr_compiler_get_error_message(
    YARA_COMPILER* compiler,
    char* buffer,
    int buffer_size)
{
  switch(compiler->last_error)
  {
    case ERROR_INSUFICIENT_MEMORY:
      snprintf(buffer, buffer_size, "not enough memory");
      break;
    case ERROR_DUPLICATE_RULE_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate rule identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATE_STRING_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate string identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATE_TAG_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate tag identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_DUPLICATE_META_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate metadata identifier \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_INVALID_CHAR_IN_HEX_STRING:
      snprintf(
          buffer,
          buffer_size,
          "invalid char in hex string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_MISMATCHED_BRACKET:
      snprintf(
          buffer,
          buffer_size,
          "mismatched bracket in string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_SKIP_AT_END:
      snprintf(
          buffer,
          buffer_size,
          "skip at the end of string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_INVALID_SKIP_VALUE:
      snprintf(
          buffer,
          buffer_size,
          "invalid skip in string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_UNPAIRED_NIBBLE:
      snprintf(
          buffer,
          buffer_size,
          "unpaired nibble in string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_CONSECUTIVE_SKIPS:
      snprintf(
          buffer,
          buffer_size,
          "two consecutive skips in string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_MISPLACED_WILDCARD_OR_SKIP:
      snprintf(
          buffer,
          buffer_size,
          "misplaced wildcard or skip at string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_MISPLACED_OR_OPERATOR:
      snprintf(
          buffer,
          buffer_size,
          "misplaced OR (|) operator at string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_NESTED_OR_OPERATION:
      snprintf(
          buffer,
          buffer_size,
          "nested OR (|) operator at string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_INVALID_OR_OPERATION_SYNTAX:
      snprintf(
          buffer,
          buffer_size,
          "invalid syntax at hex string \"%s\"",
          compiler->last_error_extra_info);
      break;
    case ERROR_SKIP_INSIDE_OR_OPERATION:
      snprintf(
          buffer,
          buffer_size,
          "skip inside an OR (|) operation at string \"%s\"",
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
    case ERROR_INCORRECT_VARIABLE_TYPE:
      snprintf(
          buffer,
          buffer_size,
          "external variable \"%s\" has an incorrect type for this operation",
          compiler->last_error_extra_info);
      break;
    case ERROR_MISPLACED_ANONYMOUS_STRING:
      snprintf(
          buffer,
          buffer_size,
          "wrong use of anonymous string");
      break;
    case ERROR_INVALID_REGULAR_EXPRESSION:
    case ERROR_SYNTAX_ERROR:
      snprintf(
          buffer,
          buffer_size,
          "%s",
          compiler->last_error_extra_info);
      break;
    case ERROR_INCLUDES_CIRCULAR_REFERENCE:
      snprintf(
          buffer,
          buffer_size,
          "include circular reference");
    case ERROR_INCLUDE_DEPTH_EXCEEDED:
      snprintf(buffer,
          buffer_size,
          "too many levels of included rules");
      break;
  }

  return buffer;
}