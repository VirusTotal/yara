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
#include <stdio.h>
#include <string.h>

#include <yara/utils.h>
#include <yara/compiler.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/object.h>
#include <yara/lexer.h>


int yr_compiler_create(
    YR_COMPILER** compiler)
{
  int result;
  YR_COMPILER* new_compiler;

  new_compiler = (YR_COMPILER*) yr_malloc(sizeof(YR_COMPILER));

  if (new_compiler == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  new_compiler->errors = 0;
  new_compiler->callback = NULL;
  new_compiler->last_error = ERROR_SUCCESS;
  new_compiler->last_error_line = 0;
  new_compiler->error_line = 0;
  new_compiler->last_result = ERROR_SUCCESS;
  new_compiler->file_stack_ptr = 0;
  new_compiler->file_name_stack_ptr = 0;
  new_compiler->current_rule_flags = 0;
  new_compiler->allow_includes = 1;
  new_compiler->loop_depth = 0;
  new_compiler->loop_for_of_mem_offset = -1;
  new_compiler->compiled_rules_arena = NULL;
  new_compiler->namespaces_count = 0;
  new_compiler->current_rule_strings = NULL;

  result = yr_hash_table_create(10007, &new_compiler->rules_table);

  if (result == ERROR_SUCCESS)
    result = yr_hash_table_create(10007, &new_compiler->objects_table);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->sz_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->rules_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->strings_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->code_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->re_code_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->automaton_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->externals_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->namespaces_arena);

  if (result == ERROR_SUCCESS)
    result = yr_arena_create(65536, 0, &new_compiler->metas_arena);

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
    yr_compiler_destroy(new_compiler);
  }

  return result;
}


void yr_compiler_destroy(
    YR_COMPILER* compiler)
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

  if (compiler->re_code_arena != NULL)
    yr_arena_destroy(compiler->re_code_arena);

  if (compiler->automaton_arena != NULL)
    yr_arena_destroy(compiler->automaton_arena);

  if (compiler->externals_arena != NULL)
    yr_arena_destroy(compiler->externals_arena);

  if (compiler->namespaces_arena != NULL)
    yr_arena_destroy(compiler->namespaces_arena);

  if (compiler->metas_arena != NULL)
    yr_arena_destroy(compiler->metas_arena);

  yr_hash_table_destroy(
      compiler->rules_table,
      NULL);

  yr_hash_table_destroy(
      compiler->objects_table,
      (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_object_destroy);

  for (i = 0; i < compiler->file_name_stack_ptr; i++)
    yr_free(compiler->file_name_stack[i]);

  yr_free(compiler);
}


void yr_compiler_set_callback(
    YR_COMPILER* compiler,
    YR_COMPILER_CALLBACK_FUNC callback)
{
  compiler->callback = callback;
}


int _yr_compiler_push_file(
    YR_COMPILER* compiler,
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
    YR_COMPILER* compiler)
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
    YR_COMPILER* compiler,
    const char* file_name)
{
  char* str;
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
    str = yr_strdup(file_name);

    if (str == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    compiler->file_name_stack[compiler->file_name_stack_ptr] = str;
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
    YR_COMPILER* compiler)
{
  if (compiler->file_name_stack_ptr > 0)
  {
    compiler->file_name_stack_ptr--;
    yr_free(compiler->file_name_stack[compiler->file_name_stack_ptr]);
    compiler->file_name_stack[compiler->file_name_stack_ptr] = NULL;
  }
}


char* yr_compiler_get_current_file_name(
    YR_COMPILER* context)
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
    YR_COMPILER* compiler,
    const char* namespace_)
{
  YR_NAMESPACE* ns;

  char* ns_name;
  int result;
  int i;
  int found;

  ns = yr_arena_base_address(compiler->namespaces_arena);
  found = FALSE;

  for (i = 0; i < compiler->namespaces_count; i++)
  {
    if (strcmp(ns->name, namespace_) == 0)
    {
      found = TRUE;
      break;
    }

    ns = yr_arena_next_address(
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
          (void*) &ns,
          offsetof(YR_NAMESPACE, name),
          EOL);

    if (result != ERROR_SUCCESS)
      return result;

    ns->name = ns_name;

    for (i = 0; i < MAX_THREADS; i++)
      ns->t_flags[i] = 0;

    compiler->namespaces_count++;
  }

  compiler->current_namespace = ns;
  return ERROR_SUCCESS;
}

int yr_compiler_add_file(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_)
{
  if (namespace_ != NULL)
    _yr_compiler_set_namespace(compiler, namespace_);
  else
    _yr_compiler_set_namespace(compiler, "default");

  return yr_lex_parse_rules_file(rules_file, compiler);
}


int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_)
{
  if (namespace_ != NULL)
    _yr_compiler_set_namespace(compiler, namespace_);
  else
    _yr_compiler_set_namespace(compiler, "default");

  return yr_lex_parse_rules_string(rules_string, compiler);
}

int _yr_compiler_compile_rules(
  YR_COMPILER* compiler)
{
  YARA_RULES_FILE_HEADER* rules_file_header = NULL;
  YR_ARENA* arena;
  YR_RULE null_rule;
  YR_EXTERNAL_VARIABLE null_external;

  int8_t halt = OP_HALT;
  int result;

  // Write halt instruction at the end of code.
  yr_arena_write_data(
      compiler->code_arena,
      &halt,
      sizeof(int8_t),
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

  // Create Aho-Corasick automaton's failure links.
  yr_ac_create_failure_links(
      compiler->automaton_arena,
      compiler->automaton);

  result = yr_arena_create(1024, 0, &arena);

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
    compiler->compiled_rules_arena = arena;
    result = yr_arena_coalesce(arena);
  }

  return result;
}


int yr_compiler_get_rules(
    YR_COMPILER* compiler,
    YR_RULES** rules)
{
  YR_RULES* yara_rules;
  YARA_RULES_FILE_HEADER* rules_file_header;

  *rules = NULL;

  if (compiler->compiled_rules_arena == NULL)
     FAIL_ON_ERROR(_yr_compiler_compile_rules(compiler));

  yara_rules = yr_malloc(sizeof(YR_RULES));

  if (yara_rules == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_arena_duplicate(compiler->compiled_rules_arena, &yara_rules->arena),
      yr_free(yara_rules));

  rules_file_header = (YARA_RULES_FILE_HEADER*) yr_arena_base_address(
      yara_rules->arena);

  yara_rules->externals_list_head = rules_file_header->externals_list_head;
  yara_rules->rules_list_head = rules_file_header->rules_list_head;
  yara_rules->automaton = rules_file_header->automaton;
  yara_rules->code_start = rules_file_header->code_start;
  yara_rules->tidx_mask = 0;

  #if WIN32
  yara_rules->mutex = CreateMutex(NULL, FALSE, NULL);
  #else
  pthread_mutex_init(&yara_rules->mutex, NULL);
  #endif

  *rules = yara_rules;

  return ERROR_SUCCESS;
}


int yr_compiler_define_integer_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int64_t value)
{
  YR_EXTERNAL_VARIABLE* external;
  YR_OBJECT* object;

  char* id;

  compiler->last_result = ERROR_SUCCESS;

  FAIL_ON_COMPILER_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &id));

  FAIL_ON_COMPILER_ERROR(yr_arena_allocate_struct(
      compiler->externals_arena,
      sizeof(YR_EXTERNAL_VARIABLE),
      (void**) &external,
      offsetof(YR_EXTERNAL_VARIABLE, identifier),
      offsetof(YR_EXTERNAL_VARIABLE, string),
      EOL));

  external->type = EXTERNAL_VARIABLE_TYPE_INTEGER;
  external->identifier = id;
  external->integer = value;
  external->string = NULL;

  FAIL_ON_COMPILER_ERROR(yr_object_from_external_variable(
      external,
      &object));

  FAIL_ON_COMPILER_ERROR(yr_hash_table_add(
      compiler->objects_table,
      external->identifier,
      NULL,
      (void*) object));

  return ERROR_SUCCESS;
}


int yr_compiler_define_boolean_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int value)
{
  return yr_compiler_define_integer_variable(
      compiler,
      identifier,
      value);
}


int yr_compiler_define_string_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    const char* value)
{
  YR_OBJECT* object;
  YR_EXTERNAL_VARIABLE* external;

  char* id = NULL;
  char* val = NULL;

  compiler->last_result = ERROR_SUCCESS;

  FAIL_ON_COMPILER_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &id));

  FAIL_ON_COMPILER_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      value,
      &val));

  FAIL_ON_COMPILER_ERROR(yr_arena_allocate_struct(
      compiler->externals_arena,
      sizeof(YR_EXTERNAL_VARIABLE),
      (void**) &external,
      offsetof(YR_EXTERNAL_VARIABLE, identifier),
      offsetof(YR_EXTERNAL_VARIABLE, string),
      EOL));

  external->type = EXTERNAL_VARIABLE_TYPE_STRING;
  external->identifier = id;
  external->integer = 0;
  external->string = val;

  FAIL_ON_COMPILER_ERROR(yr_object_from_external_variable(
      external,
      &object));

  FAIL_ON_COMPILER_ERROR(yr_hash_table_add(
      compiler->objects_table,
      external->identifier,
      NULL,
      (void*) object));

  return compiler->last_result;
}


char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size)
{
  switch(compiler->last_error)
  {
    case ERROR_INSUFICIENT_MEMORY:
      snprintf(buffer, buffer_size, "not enough memory");
      break;
    case ERROR_DUPLICATE_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate identifier \"%s\"",
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
    case ERROR_DUPLICATE_LOOP_IDENTIFIER:
      snprintf(
          buffer,
          buffer_size,
          "duplicate loop identifier \"%s\"",
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
    case ERROR_WRONG_TYPE:
      snprintf(
          buffer,
          buffer_size,
          "%s",
          compiler->last_error_extra_info);
      break;
    case ERROR_NOT_A_STRUCTURE:
      snprintf(
          buffer,
          buffer_size,
          "\"%s\" is not a structure",
          compiler->last_error_extra_info);
      break;
    case ERROR_NOT_AN_ARRAY:
      snprintf(
          buffer,
          buffer_size,
          "\"%s\" is not a array",
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
    case ERROR_INVALID_HEX_STRING:
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
    case ERROR_INTERNAL_FATAL_ERROR:
      snprintf(
          buffer,
          buffer_size,
          "internal fatal error");
      break;
  }

  return buffer;
}