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

#include <string.h>

#include "arena.h"
#include "exec.h"
#include "exefiles.h"
#include "filemap.h"
#include "mem.h"
#include "utils.h"
#include "yara.h"


int _yr_scan_compare(
    uint8_t* str1,
    uint8_t* str2,
    int len)
{
    uint8_t* s1 = str1;
    uint8_t* s2 = str2;
    int i = 0;

    while (i < len && *s1++ == *s2++)
      i++;

    return ((i == len) ? i : 0);
}


int _yr_scan_icompare(
    uint8_t* str1,
    uint8_t* str2,
    int len)
{
    uint8_t* s1 = str1;
    uint8_t* s2 = str2;
    int i = 0;

    while (i < len && lowercase[*s1++] == lowercase[*s2++])
      i++;

    return ((i == len) ? i : 0);
}


int _yr_scan_wcompare(
    uint8_t* str1,
    uint8_t* str2,
    int len)
{
  uint8_t* s1 = str1;
  uint8_t* s2 = str2;
  int i = 0;

  while (i < len && *s1 == *s2)
  {
    s1++;
    s2+=2;
    i++;
  }

  return ((i == len) ? i * 2 : 0);
}


int _yr_scan_wicompare(
    uint8_t* str1,
    uint8_t* str2,
    int len)
{
  uint8_t* s1 = str1;
  uint8_t* s2 = str2;
  int i = 0;

  while (i < len && lowercase[*s1] == lowercase[*s2])
  {
    s1++;
    s2+=2;
    i++;
  }

  return ((i == len) ? i * 2 : 0);
}


int _yr_scan_verify_hex_match(
    uint8_t* buffer,
    size_t buffer_size,
    uint8_t* pattern,
    int32_t pattern_length,
    uint8_t* mask)
{
  size_t b, p, m;
  uint8_t distance;
  uint8_t delta;
  int match;
  int match_length;
  int longest_match;
  int matches;
  int i, tmp, tmp_b;

  b = 0;
  p = 0;
  m = 0;

  matches = 0;

  while (b < buffer_size && p < pattern_length)
  {
    if (mask[m] == MASK_EXACT_SKIP)
    {
      m++;
      distance = mask[m++];
      b += distance;
      matches += distance;
    }
    else if (mask[m] == MASK_RANGE_SKIP)
    {
      m++;
      distance = mask[m++];
      delta = mask[m++] - distance;
      b += distance;
      matches += distance;

      i = 0;

      while (i <= delta && b + i < buffer_size)
      {
        if ((buffer[b + i] & mask[m]) == pattern[p] || mask[m] == MASK_OR)
        {
          tmp = _yr_scan_verify_hex_match(
              buffer + b + i,
              buffer_size - b - i,
              pattern + p,
              pattern_length - p,
              mask + m);
        }
        else
        {
          tmp = 0;
        }

        if (tmp > 0)
          return b + i + tmp;

        i++;
      }

      break;
    }
    else if (mask[m] == MASK_OR)
    {
      longest_match = 0;

      while (mask[m] != MASK_OR_END)
      {
        tmp_b = b;
        match = TRUE;
        match_length = 0;
        m++;

        while (tmp_b < buffer_size &&
               mask[m] != MASK_OR &&
               mask[m] != MASK_OR_END)
        {
          if ((buffer[tmp_b] & mask[m]) != pattern[p])
            match = FALSE;

          if (match)
            match_length++;

          tmp_b++;
          m++;
          p++;
        }

        if (match && match_length > longest_match)
          longest_match = match_length;
      }

      m++;

      if (longest_match > 0)
      {
        b += longest_match;
        matches += longest_match;
      }
      else
      {
        matches = 0;
        break;
      }

    }
    else if ((buffer[b] & mask[m]) == pattern[p])
    {
      b++;
      m++;
      p++;
      matches++;
    }
    else  // do not match
    {
      matches = 0;
      break;
    }
  }

  // did not reach the end of pattern because buffer was too small
  if (p < pattern_length)
    matches = 0;

  return matches;
}

int _yr_scan_verify_regexp_match(
    uint8_t* buffer,
    size_t buffer_size,
    uint8_t* pattern,
    int32_t pattern_length,
    REGEXP re,
    int file_beginning)
{
  int result = 0;

  // if we are not at the beginning of the file, and
  // the pattern begins with ^, the string doesn't match
  if (file_beginning && pattern[0] == '^')
    return 0;

  result = regex_exec(&re, TRUE, (char*) buffer, buffer_size);

  if (result >= 0)
    return result;
  else
    return 0;
}


inline int _yr_scan_verify_string_match(
    STRING* string,
    uint8_t* buffer,
    size_t buffer_size,
    size_t negative_size)
{
  int match;
  int i, len;
  int is_wide_char;

  uint8_t tmp_buffer[512];
  uint8_t* tmp;

  if (STRING_IS_HEX(string))
  {
    return _yr_scan_verify_hex_match(
        buffer,
        buffer_size,
        string->string,
        string->length,
        string->mask);
  }
  else if (STRING_IS_REGEXP(string))
  {
    if (STRING_IS_WIDE(string))
    {
      i = 0;

      while (i < buffer_size - 1 &&
             buffer[i] >= 32 &&        // buffer[i] is a ...
             buffer[i] <= 126 &&       // ... printable character
             buffer[i + 1] == 0)
      {
        i += 2;
      }

      len = i/2;

      if (len > sizeof(tmp_buffer))
        tmp = yr_malloc(len);
      else
        tmp = tmp_buffer;

      i = 0;

      if (tmp != NULL)
      {
        while (i < len)
        {
          tmp[i] = buffer[i * 2];
          i++;
        }

        match = _yr_scan_verify_regexp_match(
            tmp,
            len,
            string->string,
            string->length,
            string->re,
            (negative_size > 2));

        if (len > sizeof(tmp_buffer))
          yr_free(tmp);

        return match * 2;
      }

    }
    else
    {
      return _yr_scan_verify_regexp_match(
          buffer,
          buffer_size,
          string->string,
          string->length,
          string->re,
          negative_size);
    }
  }

  if (STRING_IS_WIDE(string) && string->length * 2 <= buffer_size)
  {
    if (STRING_IS_NO_CASE(string))
    {
      match = _yr_scan_wicompare(
          string->string,
          buffer,
          string->length);
    }
    else
    {
      match = _yr_scan_wcompare(
          string->string,
          buffer,
          string->length);
    }

    if (match > 0 && STRING_IS_FULL_WORD(string))
    {
      if (negative_size >= 2)
      {
        is_wide_char = (buffer[-1] == 0 && isalphanum[(char) (buffer[-2])]);

        if (is_wide_char)
          match = 0;
      }

      if (string->length * 2 < buffer_size - 1)
      {
        is_wide_char = (isalphanum[(char) (buffer[string->length * 2])] && \
                        buffer[string->length * 2 + 1] == 0);

        if (is_wide_char)
          match = 0;
      }
    }

    if (match > 0)
      return match;
  }

  if (STRING_IS_ASCII(string) && string->length <= buffer_size)
  {
    if (STRING_IS_NO_CASE(string))
    {
      match = _yr_scan_icompare(
          string->string,
          buffer,
          string->length);
    }
    else
    {
      match = _yr_scan_compare(
          string->string,
          buffer,
          string->length);
    }

    if (match > 0 && STRING_IS_FULL_WORD(string))
    {
      if (negative_size >= 1 && isalphanum[(char) (buffer[-1])])
      {
        match = 0;
      }
      else if (string->length < buffer_size &&
               isalphanum[(char) (buffer[string->length])])
      {
        match = 0;
      }
    }

    return match;
  }

  return 0;
}


int _yr_scan_verify_match(
    AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t string_offset)
{
  MATCH* match;
  STRING* string;

  int32_t match_length;

  match_length = _yr_scan_verify_string_match(
      ac_match->string,
      data + string_offset,
      data_size - string_offset,
      string_offset);

  if (match_length > 0)
  {
    string = ac_match->string;
    string->flags |= STRING_FLAGS_FOUND;

    if (string->matches_list_tail != NULL &&
        string->matches_list_tail->last_offset == string_offset - 1)
    {
      string->matches_list_tail->last_offset = string_offset;
    }
    else
    {
      match = (MATCH*) yr_malloc(sizeof(MATCH));

      if (match == NULL)
        return ERROR_INSUFICIENT_MEMORY;

      match->data = (uint8_t*) yr_malloc(match_length);

      if (match->data != NULL)
      {
        match->first_offset = string_offset;
        match->last_offset = string_offset;
        match->length = match_length;
        match->next = NULL;

        memcpy(match->data, data + string_offset, match_length);

        if (string->matches_list_head == NULL)
          string->matches_list_head = match;

        if (string->matches_list_tail != NULL)
          string->matches_list_tail->next = match;

        string->matches_list_tail = match;
      }
      else
      {
        yr_free(match);
        return ERROR_INSUFICIENT_MEMORY;
      }

      match->first_offset = string_offset;
      match->last_offset = string_offset;
      match->length = match_length;
    }
  }

  return ERROR_SUCCESS;
}


int yr_rules_define_integer_variable(
    YARA_RULES* rules,
    const char* identifier,
    int64_t value)
{
  EXTERNAL_VARIABLE* external;

  return ERROR_SUCCESS;
}


int yr_rules_define_boolean_variable(
    YARA_RULES* rules,
    const char* identifier,
    int value)
{
  EXTERNAL_VARIABLE* external;

  return ERROR_SUCCESS;
}


int yr_rules_define_string_variable(
    YARA_RULES* rules,
    const char* identifier,
    const char* value)
{
  EXTERNAL_VARIABLE* external;

  return ERROR_SUCCESS;
}


void yr_rules_free_matches(
    YARA_RULES* rules)
{
  RULE* rule;
  STRING* string;
  MATCH* match;
  MATCH* next_match;

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    string = rule->strings;

    while (!STRING_IS_NULL(string))
    {
      string->flags &= ~STRING_FLAGS_FOUND;
      match = string->matches_list_head;

      while (match != NULL)
      {
        next_match = match->next;
        yr_free(match->data);
        yr_free(match);
        match = next_match;
      }

      string->matches_list_head = NULL;
      string->matches_list_tail = NULL;
      string++;
    }

    rule++;
  }
}


int yr_rules_scan_mem_block(
    YARA_RULES* rules,
    uint8_t* data,
    size_t data_size)
{

  AC_STATE* next_state;
  AC_MATCH* ac_match;
  AC_STATE* current_state;
  size_t i;
  int result;

  current_state = rules->automaton->root;
  i = 0;

  while (i < data_size)
  {
    ac_match = current_state->matches;

    while (ac_match != NULL)
    {
      result = _yr_scan_verify_match(
          ac_match,
          data,
          data_size,
          i - ac_match->backtrack);

      if (result != ERROR_SUCCESS)
        return result;

      ac_match = ac_match->next;
    }

    next_state = current_state->transitions[data[i]].state;

    while (next_state == NULL && current_state->depth > 0)
    {
      current_state = current_state->failure;
      next_state = current_state->transitions[data[i]].state;
    }

    if (next_state != NULL)
      current_state = next_state;

    i++;
  }

  ac_match = current_state->matches;

  while (ac_match != NULL)
  {
    result = _yr_scan_verify_match(
        ac_match,
        data,
        data_size,
        data_size - ac_match->backtrack);

    if (result != ERROR_SUCCESS)
      return result;

    ac_match = ac_match->next;
  }

  return ERROR_SUCCESS;
}


#include <time.h>

int yr_rules_scan_mem_blocks(
    YARA_RULES* rules,
    MEMORY_BLOCK* block,
    YARACALLBACK callback,
    void* user_data)
{
  RULE* rule;
  EVALUATION_CONTEXT context;

  char message[512];
  int result;

  context.file_size = block->size;
  context.mem_block = block;
  context.entry_point = UNDEFINED;

  clock_t start, end;

  start = clock();

  yr_rules_free_matches(rules);

  while (block != NULL)
  {
    if (context.entry_point == UNDEFINED)
    {
      if (rules->scanning_process_memory)
        context.entry_point = yr_get_entry_point_address(
            block->data,
            block->size,
            block->base);
      else
        context.entry_point = yr_get_entry_point_offset(
            block->data,
            block->size);
    }

    result = yr_rules_scan_mem_block(
        rules,
        block->data,
        block->size);

    if (result != ERROR_SUCCESS)
      return result;

    block = block->next;
  }

  result = yr_execute_code(rules, &context);

  if (result != ERROR_SUCCESS)
      return result;

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    if (rule->flags & RULE_FLAGS_GLOBAL &&
        !(rule->flags & RULE_FLAGS_MATCH))
    {
      rule->namespace->flags |= NAMESPACE_FLAGS_UNSATISFIED_GLOBAL;
    }

    rule++;
  }

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    if (rule->flags & RULE_FLAGS_MATCH &&
        !(rule->flags & RULE_FLAGS_PRIVATE) &&
        !(rule->namespace->flags & NAMESPACE_FLAGS_UNSATISFIED_GLOBAL))
    {
      switch (callback(rule, user_data))
      {
        case CALLBACK_ABORT:
          return ERROR_SUCCESS;

        case CALLBACK_ERROR:
          return ERROR_CALLBACK_ERROR;
      }
    }
    rule++;
  }

  end = clock();
  printf( "Scanning time: %f s\n", (float)(end - start) / CLOCKS_PER_SEC);

  return ERROR_SUCCESS;
}


int yr_rules_scan_mem(
    YARA_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YARACALLBACK callback,
    void* user_data)
{
  MEMORY_BLOCK block;

  block.data = buffer;
  block.size = buffer_size;
  block.base = 0;
  block.next = NULL;

  rules->scanning_process_memory = FALSE;

  return yr_rules_scan_mem_blocks(rules, &block, callback, user_data);
}


int yr_rules_scan_file(
    YARA_RULES* rules,
    const char* filename,
    YARACALLBACK callback,
    void* user_data)
{
  MAPPED_FILE mfile;
  int result;

  result = yr_filemap_map(filename, &mfile);

  if (result == ERROR_SUCCESS)
  {
    result = yr_rules_scan_mem(
        rules,
        mfile.data,
        mfile.size,
        callback,
        user_data);

    yr_filemap_unmap(&mfile);
  }

  return result;
}


int yr_rules_save(
    YARA_RULES* rules,
    const char* filename)
{
  return yr_arena_save(rules->arena, filename);
}


int yr_rules_load(
  const char* filename,
  YARA_RULES** rules)
{
  YARA_RULES* new_rules;
  YARA_RULES_FILE_HEADER* header;
  RULE* rule;
  STRING* string;

  int result;
  int error_offset;

  new_rules = yr_malloc(sizeof(YARA_RULES));

  if (new_rules == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  result = yr_arena_load(filename, &new_rules->arena);

  if (result != ERROR_SUCCESS)
  {
    yr_free(new_rules);
    return result;
  }

  header = (YARA_RULES_FILE_HEADER*) yr_arena_base_address(new_rules->arena);
  new_rules->automaton = header->automaton;
  new_rules->code_start = header->code_start;
  new_rules->externals_list_head = header->externals_list_head;
  new_rules->rules_list_head = header->rules_list_head;

  rule = new_rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    string = rule->strings;

    while (!STRING_IS_NULL(string))
    {
      string->re.regexp = NULL;
      string->re.extra = NULL;

      if (STRING_IS_REGEXP(string))
        regex_compile(&string->re,
            string->string,
            0,
            NULL,
            0,
            &error_offset);

      string++;
    }
    rule++;
  }

  *rules = new_rules;

  return ERROR_SUCCESS;
}


int yr_rules_destroy(
    YARA_RULES* rules)
{
  yr_rules_free_matches(rules);
  yr_arena_destroy(rules->arena);
  yr_free(rules);

  return ERROR_SUCCESS;
}
