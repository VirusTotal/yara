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

#include "exec.h"
#include "hash.h"
#include "mem.h"
#include "parser.h"
#include "utils.h"


#define todigit(x)  ((x) >='A'&& (x) <='F')? \
                    ((uint8_t) (x - 'A' + 10)) : \
                    ((uint8_t) (x - '0'))


int emit(
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


int emit_with_arg(
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


int emit_with_arg_reloc(
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


void emit_pushes_for_strings(
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
      emit_with_arg_reloc(yyscanner, PUSH, PTR_TO_UINT64(string), NULL);
      string->flags |= STRING_FLAGS_REFERENCED;
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(STRING));
  }
}


STRING* lookup_string(
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


EXTERNAL_VARIABLE* lookup_external_variable(
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

int new_hex_string(
    YARA_COMPILER* compiler,
    SIZED_STRING* charstr,
    uint8_t** new_string,
    uint8_t** new_mask,
    int32_t* length)
{
  int i;
  int skip_lo;
  int skip_hi;
  int skip_exact;
  int inside_or;
  int or_count;
  int result = ERROR_SUCCESS;
  char c, d;
  char* s;
  char* closing_bracket;
  uint8_t high_nibble = 0;
  uint8_t low_nibble = 0;
  uint8_t mask_high_nibble = 0;
  uint8_t mask_low_nibble = 0;
  uint8_t* hex;
  uint8_t* mask;
  uint8_t* hex_ptr;
  uint8_t* mask_ptr;

  hex_ptr = hex =  yr_malloc(charstr->length / 2);
  mask_ptr = mask = yr_malloc(charstr->length);

  if (hex == NULL || mask == NULL)
  {
    if (hex)
      yr_free(hex);

    if (mask)
      yr_free(mask);

    return ERROR_INSUFICIENT_MEMORY;
  }

  *length = 0;
  inside_or = FALSE;

  // Start iterating at 1 because at 0 is the opening curly brace.

  i = 1;

  // Iterate up to the character prior the closing curly brace.

  while (i < charstr->length - 1)
  {
    c = toupper(charstr->c_string[i]);

    if (isalnum(c) || (c == '?'))
    {
      d = toupper(charstr->c_string[i + 1]);

      if (!isalnum(d) && (d != '?'))
      {
        result = ERROR_UNPAIRED_NIBBLE;
        break;
      }

      if (c != '?')
      {
        high_nibble = todigit(c);
        mask_high_nibble = 0x0F;
      }
      else
      {
        high_nibble = 0;
        mask_high_nibble = 0;
      }

      if (d != '?')
      {
        low_nibble = todigit(d);
        mask_low_nibble = 0x0F;
      }
      else
      {
        low_nibble = 0;
        mask_low_nibble = 0;
      }

      *hex++ = (high_nibble << 4) | (low_nibble);
      *mask++ = (mask_high_nibble << 4) | (mask_low_nibble);

      (*length)++;

      i+=2;
    }
    else if (c == '(')
    {
      if (inside_or)
      {
        result = ERROR_NESTED_OR_OPERATION;
        break;
      }

      inside_or = TRUE;
      *mask++ = MASK_OR;
      i++;
    }
    else if (c == ')')
    {
      inside_or = FALSE;
      *mask++ = MASK_OR_END;
      i++;
    }
    else if (c == '|')
    {
      if (!inside_or)
      {
        result = ERROR_MISPLACED_OR_OPERATOR;
        break;
      }

      *mask++ = MASK_OR;
      i++;
    }
    else if (c == '[')
    {
      if (inside_or)
      {
        result = ERROR_SKIP_INSIDE_OR_OPERATION;
        break;
      }

      closing_bracket = strchr(charstr->c_string + i + 1, ']');

      if (closing_bracket == NULL)
      {
        result = ERROR_MISMATCHED_BRACKET;
        break;
      }
      else
      {
        s = closing_bracket + 1;

        while (*s == ' ')
          s++;  // Skip spaces.

        if (*s == '}')
        {
          // No skip instruction should exists at the end of the string.
          result = ERROR_SKIP_AT_END;
          break;
        }
        else if (*s == '[')
        {
          // Consecutive skip intructions are not allowed.
          result = ERROR_CONSECUTIVE_SKIPS;
          break;
        }
      }

      // Only decimal digits and '-' are allowed between brackets.

      for (s = charstr->c_string + i + 1; s < closing_bracket; s++)
      {
        if ((*s != '-') && (*s < '0' || *s > '9'))
        {
          result = ERROR_INVALID_SKIP_VALUE;
          break;
        }
      }

      skip_lo = atoi(charstr->c_string + i + 1);

      if (skip_lo < 0 || skip_lo > MASK_MAX_SKIP)
      {
        result = ERROR_INVALID_SKIP_VALUE;
        break;
      }

      skip_exact = 1;

      s = strchr(charstr->c_string + i + 1, '-');

      if (s != NULL && s < closing_bracket)
      {
        skip_hi = atoi(s + 1);

        if (skip_hi <= skip_lo || skip_hi > MASK_MAX_SKIP)
        {
          result = ERROR_INVALID_SKIP_VALUE;
          break;
        }

        skip_exact = 0;
      }

      if (skip_exact)
      {
        *mask++ = MASK_EXACT_SKIP;
        *mask++ = (unsigned char) skip_lo;
      }
      else
      {
        *mask++ = MASK_RANGE_SKIP;
        *mask++ = (unsigned char) skip_lo;
        *mask++ = (unsigned char) skip_hi;
      }

      i = (int) (closing_bracket - charstr->c_string + 1);

    }
    else if (c == ']')
    {
      result = ERROR_MISMATCHED_BRACKET;
      break;
    }
    else if (c == ' ' || c == '\n' || c == '\t')
    {
      i++;
    }
    else
    {
      result = ERROR_INVALID_CHAR_IN_HEX_STRING;
      break;
    }

  }

  *mask++ = MASK_END;

  // Wildcards or skip instructions are not allowed at the first
  // position the string.

  if (mask_ptr[0] != 0xFF)
  {
    result = ERROR_MISPLACED_WILDCARD_OR_SKIP;
  }

  // Check if OR syntax is correct.

  i = 0;
  or_count = 0;

  while (mask_ptr[i] != MASK_END)
  {
    if (mask_ptr[i] == MASK_OR)
    {
      or_count++;

      if (mask_ptr[i+1] == MASK_OR || mask_ptr[i+1] == MASK_OR_END)
      {
        result = ERROR_INVALID_OR_OPERATION_SYNTAX;
        break;
      }
    }
    else if (mask_ptr[i] == MASK_OR_END)
    {
      if (or_count <  2)
      {
        result = ERROR_INVALID_OR_OPERATION_SYNTAX;
        break;
      }

      or_count = 0;
    }

    i++;
  }

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        compiler->sz_arena,
        hex_ptr,
        *length,
        (void*) new_string);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        compiler->sz_arena,
        mask_ptr,
        i + 1,
        (void*) new_mask);

  yr_free(hex_ptr);
  yr_free(mask_ptr);

  return result;
}


STRING* reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    SIZED_STRING* str)
{
  int error_offset;
  STRING* string;
  YARA_COMPILER* compiler = yyget_extra(yyscanner);

  compiler->last_result = yr_arena_allocate_struct(
      compiler->strings_arena,
      sizeof(STRING),
      (void**) &string,
      offsetof(STRING, identifier),
      offsetof(STRING, string),
      offsetof(STRING, mask),
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
    flags |= STRING_FLAGS_ANONYMOUS;

  if (!(flags & STRING_FLAGS_WIDE))
    flags |= STRING_FLAGS_ASCII;

  string->flags = flags;
  string->mask = NULL;
  string->re.regexp = NULL;
  string->re.extra = NULL;
  string->matches_list_head = NULL;
  string->matches_list_tail = NULL;

  if (flags & STRING_FLAGS_HEXADECIMAL)
  {
    compiler->last_result = new_hex_string(
        compiler,
        str,
        &string->string,
        &string->mask,
        &string->length);
  }
  else
  {
    if (flags & STRING_FLAGS_REGEXP)
    {
      if (regex_compile(
          &string->re,
          str->c_string,
          flags & STRING_FLAGS_NO_CASE,
          compiler->last_error_extra_info,
          sizeof(compiler->last_error_extra_info),
          &error_offset) <= 0)
      {
        compiler->last_result = ERROR_INVALID_REGULAR_EXPRESSION;
      }
    }

    if (compiler->last_result == ERROR_SUCCESS)
    {
      compiler->last_result = yr_arena_write_data(
          compiler->sz_arena,
          str->c_string,
          str->length + 1, // +1 to include the null at the end
          (void*) &string->string);

      string->length = str->length;
    }
  }

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  // Add the string to Aho-Corasick automaton.

  compiler->last_result = yr_ac_add_string(
      compiler->automaton_arena,
      compiler->automaton,
      string);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  return string;
}


int reduce_rule_declaration(
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
      offsetof(RULE, namespace),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &rule->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = emit_with_arg_reloc(
      yyscanner,
      RULE_POP,
      PTR_TO_UINT64(rule),
      NULL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  rule->flags = flags | compiler->current_rule_flags;
  rule->tags = tags;
  rule->strings = strings;
  rule->metas = metas;
  rule->namespace = compiler->current_namespace;

  compiler->current_rule_flags = 0;
  compiler->current_rule_strings = NULL;

  yr_hash_table_add(
      compiler->rules_table,
      identifier,
      compiler->current_namespace->name,
      (void*) rule);

  return compiler->last_result;
}


int reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t instruction)
{
  STRING* string;
  YARA_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0)
  {
    if (compiler->inside_for > 0)
    {
      emit(yyscanner, PUSH_A, NULL);
      emit(yyscanner, instruction, NULL);
    }
    else
    {
      compiler->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
  }
  else
  {
    string = lookup_string(yyscanner, identifier);

    if (string != NULL)
    {
      emit_with_arg_reloc(
          yyscanner,
          PUSH,
          PTR_TO_UINT64(string),
          NULL);

      emit(yyscanner, instruction, NULL);

      string->flags |= STRING_FLAGS_REFERENCED;
    }
  }

  return compiler->last_result;
}


int reduce_external(
  yyscan_t yyscanner,
  const char* identifier,
  int8_t instruction)
{
  YARA_COMPILER* compiler = yyget_extra(yyscanner);
  EXTERNAL_VARIABLE* external;

  external = lookup_external_variable(yyscanner, identifier);

  if (external != NULL)
  {
    if (instruction == EXT_BOOL)
    {
      compiler->last_result = emit_with_arg_reloc(
          yyscanner,
          EXT_BOOL,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_INT &&
             external->type == EXTERNAL_VARIABLE_TYPE_INTEGER)
    {
      compiler->last_result = emit_with_arg_reloc(
          yyscanner,
          EXT_INT,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_STR &&
             external->type == EXTERNAL_VARIABLE_TYPE_STRING)
    {
      compiler->last_result = emit_with_arg_reloc(
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


META* reduce_meta_declaration(
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


