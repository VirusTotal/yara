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

#include <assert.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "ahocorasick.h"
#include "arena.h"
#include "exec.h"
#include "exefiles.h"
#include "filemap.h"
#include "mem.h"
#include "proc.h"
#include "re.h"
#include "utils.h"
#include "yara.h"


typedef struct _CALLBACK_ARGS
{
  YR_STRING* string;
  YR_ARENA* matches_arena;
  int forward_matches;
  uint8_t* data;
  int data_size;
  int full_word;
  int tidx;

} CALLBACK_ARGS;


#define inline

inline int _yr_scan_compare(
    uint8_t* data,
    int data_size,
    uint8_t* string,
    int string_length)
{
  uint8_t* s1 = data;
  uint8_t* s2 = string;
  int i = 0;

  if (data_size < string_length)
    return 0;

  while (i < string_length && *s1++ == *s2++)
    i++;

  return ((i == string_length) ? i : 0);
}


inline int _yr_scan_icompare(
    uint8_t* data,
    int data_size,
    uint8_t* string,
    int string_length)
{
  uint8_t* s1 = data;
  uint8_t* s2 = string;
  int i = 0;

  if (data_size < string_length)
    return 0;

  while (i < string_length && lowercase[*s1++] == lowercase[*s2++])
    i++;

  return ((i == string_length) ? i : 0);
}


inline int _yr_scan_wcompare(
    uint8_t* data,
    int data_size,
    uint8_t* string,
    int string_length)
{
  uint8_t* s1 = data;
  uint8_t* s2 = string;
  int i = 0;

  if (data_size < string_length * 2)
    return 0;

  while (i < string_length && *s1 == *s2)
  {
    s1+=2;
    s2++;
    i++;
  }

  return ((i == string_length) ? i * 2 : 0);
}


inline int _yr_scan_wicompare(
    uint8_t* data,
    int data_size,
    uint8_t* string,
    int string_length)
{
  uint8_t* s1 = data;
  uint8_t* s2 = string;
  int i = 0;

  if (data_size < string_length * 2)
    return 0;

  while (i < string_length && lowercase[*s1] == lowercase[*s2])
  {
    s1+=2;
    s2++;
    i++;
  }

  return ((i == string_length) ? i * 2 : 0);
}


//
// _yr_scan_fast_hex_re_exec
//
// This function is a replacement for yr_re_exec in some particular cases of
// regular expressions where a faster algorithm can be used. These regular
// expressions are those derived from hex strings not containing OR (|)
// operations. The following hex strings would apply:
//
//   { 01 ?? 03 04 05 }
//   { 01 02 0? 04 04 }
//   { 01 02 [1] 04 05 }
//   { 01 02 [2-6] 04 06 }
//
// In order to match these strings we don't need to use the general case
// matching algorithm (yr_re_exec), instead we can take advance of the
// characteristics of the code generated for this kind of strings and do the
// matching in a faster way.
//

#define MAX_FAST_HEX_RE_STACK 300

int _yr_scan_fast_hex_re_exec(
    uint8_t* code,
    uint8_t* input,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args)
{
  uint8_t* code_stack[MAX_FAST_HEX_RE_STACK];
  uint8_t* input_stack[MAX_FAST_HEX_RE_STACK];
  int matches_stack[MAX_FAST_HEX_RE_STACK];

  int sp = 0;

  uint8_t* ip = code;
  uint8_t* current_input = input;
  uint8_t* next_input;
  uint8_t mask;
  uint8_t value;

  int i;
  int matches;
  int stop;
  int increment;

  increment = flags & RE_FLAGS_BACKWARDS ? -1 : 1;

  code_stack[sp] = code;
  input_stack[sp] = input;
  matches_stack[sp] = 0;
  sp++;

  while (sp > 0)
  {
    sp--;
    ip = code_stack[sp];
    current_input = input_stack[sp];
    matches = matches_stack[sp];
    stop = FALSE;

    while(!stop)
    {
      if (flags & RE_FLAGS_BACKWARDS)
      {
        if (current_input <= input - input_size)
          break;
      }
      else
      {
        if (current_input >= input + input_size)
          break;
      }

      switch(*ip)
      {
        case RE_OPCODE_LITERAL:
          if (*current_input == *(ip + 1))
          {
            matches++;
            current_input += increment;
            ip += 2;
          }
          else
          {
            stop = TRUE;
          }
          break;

        case RE_OPCODE_MASKED_LITERAL:
          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;
          if ((*current_input & mask) == value)
          {
            matches++;
            current_input += increment;
            ip += 3;
          }
          else
          {
            stop = TRUE;
          }
          break;

        case RE_OPCODE_ANY:
          matches++;
          current_input += increment;
          ip += 1;
          break;

        case RE_OPCODE_PUSH:
          for (i = *(uint16_t*)(ip + 1); i > 0; i--)
          {
            if (flags & RE_FLAGS_BACKWARDS)
            {
              next_input = current_input - i;
              if (next_input <= input - input_size)
                continue;
            }
            else
            {
              next_input = current_input + i;
              if (next_input >= input + input_size)
                continue;
            }

            if ( *(ip + 11) != RE_OPCODE_LITERAL ||
                (*(ip + 11) == RE_OPCODE_LITERAL &&
                 *(ip + 12) == *next_input))
            {
              assert(sp < MAX_FAST_HEX_RE_STACK);
              code_stack[sp] = ip + 11;
              input_stack[sp] = next_input;
              matches_stack[sp] = matches + i;
              sp++;
            }
          }
          ip += 11;
          break;

        default:
          assert(FALSE);
      }

      if (*ip == RE_OPCODE_MATCH)
      {
        if (flags & RE_FLAGS_EXHAUSTIVE)
        {
          callback(
            flags & RE_FLAGS_BACKWARDS ? current_input + 1 : input,
            matches,
            flags,
            callback_args);
          stop = TRUE;
        }
        else
        {
          return matches;
        }
      }
    }
  }

  return -1;
}


void _yr_scan_update_match_chain_length(
    int tidx,
    YR_STRING* string,
    YR_MATCH* match_to_update,
    int chain_length)
{
  YR_MATCH* match;
  size_t ending_offset;

  match_to_update->chain_length = chain_length;

  if (string->chained_to != NULL)
    match = string->chained_to->unconfirmed_matches[tidx].head;
  else
    match = NULL;

  while (match != NULL)
  {
    ending_offset = match->offset + match->length;

    if (ending_offset + string->chain_gap_max >= match_to_update->offset &&
        ending_offset + string->chain_gap_min <= match_to_update->offset)
    {
      _yr_scan_update_match_chain_length(
          tidx, string->chained_to, match, chain_length + 1);
    }

    match = match->next;
  }
}


void _yr_scan_add_match_to_list(
    YR_MATCH* match,
    YR_MATCHES* matches_list)
{
  YR_MATCH* insertion_point = matches_list->tail;

  while (insertion_point != NULL)
  {
    if (match->offset == insertion_point->offset)
    {
      insertion_point->length = match->length;
      return;
    }

    if (match->offset > insertion_point->offset)
      break;

    insertion_point = insertion_point->prev;
  }

  match->prev = insertion_point;

  if (insertion_point != NULL)
  {
    match->next = insertion_point->next;
    insertion_point->next = match;
  }
  else
  {
    match->next = matches_list->head;
    matches_list->head = match;
  }

  if (match->next != NULL)
    match->next->prev = match;
  else
    matches_list->tail = match;
}


void _yr_scan_remove_match_from_list(
    YR_MATCH* match,
    YR_MATCHES* matches_list)
{
  if (match->prev != NULL)
    match->prev->next = match->next;

  if (match->next != NULL)
    match->next->prev = match->prev;

  if (matches_list->head == match)
    matches_list->head = match->next;

  if (matches_list->tail == match)
    matches_list->tail = match->prev;

  match->next = NULL;
  match->prev = NULL;
}


int _yr_scan_handle_chained_matches(
    YR_ARENA* matches_arena,
    YR_STRING* matching_string,
    uint8_t* match_data,
    size_t match_offset,
    int32_t match_length,
    int tidx)
{
  YR_STRING* string;
  YR_MATCH* match;
  YR_MATCH* next_match;
  YR_MATCH* new_match;

  size_t lower_offset;
  size_t ending_offset;
  int32_t full_chain_length;

  int add_match = FALSE;
  int result;

  if (matching_string->chained_to == NULL)
  {
    add_match = TRUE;
  }
  else
  {
    if (matching_string->unconfirmed_matches[tidx].head != NULL)
      lower_offset = matching_string->unconfirmed_matches[tidx].head->offset;
    else
      lower_offset = match_offset;

    match = matching_string->chained_to->unconfirmed_matches[tidx].head;

    while (match != NULL)
    {
      next_match = match->next;
      ending_offset = match->offset + match->length;

      if (ending_offset + matching_string->chain_gap_max < lower_offset)
      {
        _yr_scan_remove_match_from_list(
            match, &matching_string->chained_to->unconfirmed_matches[tidx]);
      }
      else
      {
        if (ending_offset + matching_string->chain_gap_max >= match_offset &&
            ending_offset + matching_string->chain_gap_min <= match_offset)
        {
          add_match = TRUE;
          break;
        }
      }

      match = next_match;
    }
  }

  if (add_match)
  {
    if (STRING_IS_CHAIN_TAIL(matching_string))
    {
      match = matching_string->chained_to->unconfirmed_matches[tidx].head;

      while (match != NULL)
      {
        _yr_scan_update_match_chain_length(
            tidx, matching_string->chained_to, match, 1);

        match = match->next;
      }

      full_chain_length = 0;
      string = matching_string;

      while(string->chained_to != NULL)
      {
        full_chain_length++;
        string = string->chained_to;
      }

      // "string" points now to the head of the strings chain

      match = string->unconfirmed_matches[tidx].head;

      while (match != NULL)
      {
        next_match = match->next;

        if (match->chain_length == full_chain_length)
        {
          _yr_scan_remove_match_from_list(
              match, &string->unconfirmed_matches[tidx]);

          match->length = match_offset - match->offset + match_length;
          match->data = match_data - match_offset + match->offset;
          match->prev = NULL;
          match->next = NULL;

          _yr_scan_add_match_to_list(
              match, &string->matches[tidx]);
        }

        match = next_match;
      }
    }
    else
    {
      result = yr_arena_allocate_memory(
          matches_arena,
          sizeof(YR_MATCH),
          (void**) &new_match);

      if (result != ERROR_SUCCESS)
        return result;

      new_match->offset = match_offset;
      new_match->length = match_length;
      new_match->data = match_data;
      new_match->prev = NULL;
      new_match->next = NULL;

      _yr_scan_add_match_to_list(
          new_match,
          &matching_string->unconfirmed_matches[tidx]);
    }
  }

  return ERROR_SUCCESS;
}


int _yr_scan_match_callback(
    uint8_t* match_data,
    int32_t match_length,
    int flags,
    void* args)
{
  CALLBACK_ARGS* callback_args = args;

  YR_STRING* string = callback_args->string;
  YR_MATCH* new_match;

  int character_size;
  int result = ERROR_SUCCESS;
  int tidx = callback_args->tidx;

  size_t match_offset = match_data - callback_args->data;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;

  // match_length > 0 means that we have found some backward matching
  // but backward matching overlaps one character with forward matching,
  // we decrement match_length here to compensate that overlapping.

  if (match_length > 0)
    match_length -= character_size;

  // total match length is the sum of backward and forward matches.

  match_length = match_length + callback_args->forward_matches;

  if (callback_args->full_word)
  {
    if (flags & RE_FLAGS_WIDE)
    {
      if (match_offset >= 2 &&
          *(match_data - 1) == 0 &&
          isalnum(*(match_data - 2)))
        return ERROR_SUCCESS;

      if (match_offset + match_length + 1 < callback_args->data_size &&
          *(match_data + match_length + 1) == 0 &&
          isalnum(*(match_data + match_length)))
        return ERROR_SUCCESS;
    }
    else
    {
      if (match_offset >= 1 &&
          isalnum(*(match_data - 1)))
        return ERROR_SUCCESS;

      if (match_offset + match_length < callback_args->data_size &&
          isalnum(*(match_data + match_length)))
        return ERROR_SUCCESS;
    }
  }

  if (STRING_IS_CHAIN_PART(string))
  {
    result = _yr_scan_handle_chained_matches(
        callback_args->matches_arena,
        string,
        match_data,
        match_offset,
        match_length,
        tidx);
  }
  else
  {
    result = yr_arena_allocate_memory(
        callback_args->matches_arena,
        sizeof(YR_MATCH),
        (void**) &new_match);

    if (result == ERROR_SUCCESS)
    {
      new_match->offset = match_offset;
      new_match->length = match_length;
      new_match->data = match_data;
      new_match->prev = NULL;
      new_match->next = NULL;

      _yr_scan_add_match_to_list(
          new_match,
          &string->matches[tidx]);
    }
  }

  return result;
}


typedef int (*RE_EXEC_FUNC)(
    uint8_t* code,
    uint8_t* input,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args);


int _yr_scan_verify_re_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t offset,
    YR_ARENA* matches_arena)
{
  CALLBACK_ARGS callback_args;
  RE_EXEC_FUNC exec;

  int forward_matches = -1;
  int flags = 0;

  if (STRING_IS_FAST_HEX_REGEXP(ac_match->string))
    exec = _yr_scan_fast_hex_re_exec;
  else
    exec = yr_re_exec;

  if (STRING_IS_NO_CASE(ac_match->string))
    flags |= RE_FLAGS_NO_CASE;

  if (STRING_IS_HEX(ac_match->string))
    flags |= RE_FLAGS_DOT_ALL;

  if (STRING_IS_ASCII(ac_match->string))
  {
    forward_matches = exec(
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        flags,
        NULL,
        NULL);
  }

  if (STRING_IS_WIDE(ac_match->string) &&
      forward_matches < 0)
  {
    flags |= RE_FLAGS_WIDE;
    forward_matches = exec(
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        flags,
        NULL,
        NULL);
  }

  if (forward_matches < 0)
    return ERROR_SUCCESS;

  if (forward_matches == 0 && ac_match->backward_code == NULL)
    return ERROR_SUCCESS;

  callback_args.string = ac_match->string;
  callback_args.data = data;
  callback_args.data_size = data_size;
  callback_args.matches_arena = matches_arena;
  callback_args.forward_matches = forward_matches;
  callback_args.full_word = STRING_IS_FULL_WORD(ac_match->string);
  callback_args.tidx = yr_get_tidx();

  if (ac_match->backward_code != NULL)
  {
    exec(
        ac_match->backward_code,
        data + offset,
        offset + 1,
        flags | RE_FLAGS_BACKWARDS | RE_FLAGS_EXHAUSTIVE,
        _yr_scan_match_callback,
        (void*) &callback_args);
  }
  else
  {
    _yr_scan_match_callback(
        data + offset, 0, flags, &callback_args);
  }

  return ERROR_SUCCESS;
}


int _yr_scan_verify_literal_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t offset,
    YR_ARENA* matches_arena)
{
  int flags = 0;
  int forward_matches = 0;

  CALLBACK_ARGS callback_args;
  YR_STRING* string = ac_match->string;

  if (STRING_FITS_IN_ATOM(string))
  {
    if (STRING_IS_WIDE(string))
      forward_matches = string->length * 2;
    else
      forward_matches = string->length;
  }
  else if (STRING_IS_NO_CASE(string))
  {
    flags |= RE_FLAGS_NO_CASE;

    if (STRING_IS_ASCII(string))
    {
      forward_matches = _yr_scan_icompare(
          data + offset,
          data_size - offset,
          string->string,
          string->length);
    }

    if (STRING_IS_WIDE(string) && forward_matches == 0)
    {
      flags |= RE_FLAGS_WIDE;
      forward_matches = _yr_scan_wicompare(
          data + offset,
          data_size - offset,
          string->string,
          string->length);
    }
  }
  else
  {
    if (STRING_IS_ASCII(string))
    {
      forward_matches = _yr_scan_compare(
          data + offset,
          data_size - offset,
          string->string,
          string->length);
    }

    if (STRING_IS_WIDE(string) && forward_matches == 0)
    {
      flags |= RE_FLAGS_WIDE;
      forward_matches = _yr_scan_wcompare(
          data + offset,
          data_size - offset,
          string->string,
          string->length);
    }
  }

  if (forward_matches > 0)
  {
    if (STRING_IS_FULL_WORD(string))
    {
      if (flags & RE_FLAGS_WIDE)
      {
        if (offset >= 2 &&
            *(data + offset - 1) == 0 &&
            isalnum(*(data + offset - 2)))
          return ERROR_SUCCESS;

        if (offset + forward_matches + 1 < data_size &&
            *(data + offset + forward_matches + 1) == 0 &&
            isalnum(*(data + offset + forward_matches)))
          return ERROR_SUCCESS;
      }
      else
      {
        if (offset >= 1 &&
            isalnum(*(data + offset - 1)))
          return ERROR_SUCCESS;

        if (offset + forward_matches < data_size &&
            isalnum(*(data + offset + forward_matches)))
          return ERROR_SUCCESS;
      }
    }

    callback_args.string = string;
    callback_args.data = data;
    callback_args.data_size = data_size;
    callback_args.matches_arena = matches_arena;
    callback_args.forward_matches = forward_matches;
    callback_args.full_word = STRING_IS_FULL_WORD(string);
    callback_args.tidx = yr_get_tidx();

    _yr_scan_match_callback(
        data + offset, 0, flags, &callback_args);
  }

  return ERROR_SUCCESS;
}


inline int _yr_scan_verify_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t offset,
    YR_ARENA* matches_arena,
    int fast_scan_mode)
{
  YR_STRING* string = ac_match->string;

  if (data_size - offset <= 0)
    return ERROR_SUCCESS;

  if (fast_scan_mode &&
      STRING_IS_SINGLE_MATCH(string) &&
      STRING_FOUND(string))
    return ERROR_SUCCESS;

  if (STRING_IS_LITERAL(string))
  {
    FAIL_ON_ERROR(_yr_scan_verify_literal_match(
        ac_match, data, data_size, offset, matches_arena));
  }
  else
  {
    FAIL_ON_ERROR(_yr_scan_verify_re_match(
        ac_match, data, data_size, offset, matches_arena));
  }

  return ERROR_SUCCESS;
}


void _yr_rules_lock(
    YR_RULES* rules)
{
  #ifdef WIN32
  WaitForSingleObject(rules->mutex, INFINITE);
  #else
  pthread_mutex_lock(&rules->mutex);
  #endif
}


void _yr_rules_unlock(
    YR_RULES* rules)
{
  #ifdef WIN32
  ReleaseMutex(rules->mutex);
  #else
  pthread_mutex_unlock(&rules->mutex);
  #endif
}


int yr_rules_define_integer_variable(
    YR_RULES* rules,
    const char* identifier,
    int64_t value)
{
  YR_EXTERNAL_VARIABLE* external;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (strcmp(external->identifier, identifier) == 0)
    {
      external->integer = value;
      break;
    }

    external++;
  }

  return ERROR_SUCCESS;
}


int yr_rules_define_boolean_variable(
    YR_RULES* rules,
    const char* identifier,
    int value)
{
  YR_EXTERNAL_VARIABLE* external;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (strcmp(external->identifier, identifier) == 0)
    {
      external->integer = value;
      break;
    }

    external++;
  }

  return ERROR_SUCCESS;
}


int yr_rules_define_string_variable(
    YR_RULES* rules,
    const char* identifier,
    const char* value)
{
  YR_EXTERNAL_VARIABLE* external;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (strcmp(external->identifier, identifier) == 0)
    {
      if (external->type == EXTERNAL_VARIABLE_TYPE_MALLOC_STRING &&
          external->string != NULL)
      {
        yr_free(external->string);
      }

      external->type = EXTERNAL_VARIABLE_TYPE_MALLOC_STRING;
      external->string = yr_strdup(value);

      if (external->string == NULL)
        return ERROR_INSUFICIENT_MEMORY;
      else
        return ERROR_SUCCESS;
    }

    external++;
  }

  return ERROR_SUCCESS;
}


void _yr_rules_clean_matches(
    YR_RULES* rules)
{
  YR_RULE* rule;
  YR_STRING* string;

  int tidx = yr_get_tidx();

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    rule->t_flags[tidx] &= ~RULE_TFLAGS_MATCH;
    rule->ns->t_flags[tidx] &= ~NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL;
    string = rule->strings;

    while (!STRING_IS_NULL(string))
    {
      string->matches[tidx].head = NULL;
      string->matches[tidx].tail = NULL;
      string->unconfirmed_matches[tidx].head = NULL;
      string->unconfirmed_matches[tidx].tail = NULL;
      string++;
    }

    rule++;
  }
}


int yr_rules_scan_mem_block(
    YR_RULES* rules,
    uint8_t* data,
    size_t data_size,
    int fast_scan_mode,
    int timeout,
    time_t start_time,
    YR_ARENA* matches_arena)
{
  YR_AC_STATE* next_state;
  YR_AC_MATCH* ac_match;
  YR_AC_STATE* current_state;

  time_t current_time;
  size_t i;

  current_state = rules->automaton->root;
  i = 0;

  while (i < data_size)
  {
    ac_match = current_state->matches;

    while (ac_match != NULL)
    {
      if (ac_match->backtrack <= i)
      {
        _yr_scan_verify_match(
              ac_match,
              data,
              data_size,
              i - ac_match->backtrack,
              matches_arena,
              fast_scan_mode);
      }

      ac_match = ac_match->next;
    }

    next_state = yr_ac_next_state(current_state, data[i]);

    while (next_state == NULL && current_state->depth > 0)
    {
      current_state = current_state->failure;
      next_state = yr_ac_next_state(current_state, data[i]);
    }

    if (next_state != NULL)
      current_state = next_state;

    i++;

    if (timeout > 0 && i % 256 == 0)
    {
      current_time = time(NULL);

      if (difftime(current_time, start_time) > timeout)
        return ERROR_SCAN_TIMEOUT;
    }
  }

  ac_match = current_state->matches;

  while (ac_match != NULL)
  {
    if (ac_match->backtrack <= data_size)
    {
      _yr_scan_verify_match(
          ac_match,
          data,
          data_size,
          data_size - ac_match->backtrack,
          matches_arena,
          fast_scan_mode);
    }

    ac_match = ac_match->next;
  }

  return ERROR_SUCCESS;
}


int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK* block,
    int scanning_process_memory,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout)
{
  YR_RULE* rule;
  EVALUATION_CONTEXT context;
  YR_ARENA* matches_arena = NULL;

  time_t start_time;

  int message;
  int tidx;
  int result = ERROR_SUCCESS;

  context.file_size = block->size;
  context.mem_block = block;
  context.entry_point = UNDEFINED;

  tidx = yr_get_tidx();

  if (tidx == -1)
  {
    _yr_rules_lock(rules);

    tidx = rules->threads_count;

    if (tidx < MAX_THREADS)
      rules->threads_count++;
    else
      result = ERROR_TOO_MANY_SCAN_THREADS;

    _yr_rules_unlock(rules);

    if (result != ERROR_SUCCESS)
      return result;

    yr_set_tidx(tidx);
  }

  result = yr_arena_create(1024, 0, &matches_arena);

  if (result != ERROR_SUCCESS)
    goto _exit;

  start_time = time(NULL);

  while (block != NULL)
  {
    if (context.entry_point == UNDEFINED)
    {
      if (scanning_process_memory)
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
        block->size,
        fast_scan_mode,
        timeout,
        start_time,
        matches_arena);

    if (result != ERROR_SUCCESS)
      goto _exit;

    block = block->next;
  }

  result = yr_execute_code(rules, &context);

  if (result != ERROR_SUCCESS)
    goto _exit;

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    if (RULE_IS_GLOBAL(rule) && !(rule->t_flags[tidx] & RULE_TFLAGS_MATCH))
    {
      rule->ns->t_flags[tidx] |= NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL;
    }

    rule++;
  }

  rule = rules->rules_list_head;

  while (!RULE_IS_NULL(rule))
  {
    if (rule->t_flags[tidx] & RULE_TFLAGS_MATCH &&
        !(rule->ns->t_flags[tidx] & NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL))
    {
      message = CALLBACK_MSG_RULE_MATCHING;
    }
    else
    {
      message = CALLBACK_MSG_RULE_NOT_MATCHING;
    }

    if (!RULE_IS_PRIVATE(rule))
    {
      switch (callback(message, rule, user_data))
      {
        case CALLBACK_ABORT:
          result = ERROR_SUCCESS;
          goto _exit;

        case CALLBACK_ERROR:
          result = ERROR_CALLBACK_ERROR;
          goto _exit;
      }
    }

    rule++;
  }

  callback(CALLBACK_MSG_SCAN_FINISHED, NULL, user_data);

_exit:
  _yr_rules_clean_matches(rules);

  if (matches_arena != NULL)
    yr_arena_destroy(matches_arena);

  return result;
}


int yr_rules_scan_mem(
    YR_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout)
{
  YR_MEMORY_BLOCK block;

  block.data = buffer;
  block.size = buffer_size;
  block.base = 0;
  block.next = NULL;

  return yr_rules_scan_mem_blocks(
      rules,
      &block,
      FALSE,
      callback,
      user_data,
      fast_scan_mode,
      timeout);
}


int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout)
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
        user_data,
        fast_scan_mode,
        timeout);

    yr_filemap_unmap(&mfile);
  }

  return result;
}


int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout)
{
  YR_MEMORY_BLOCK* first_block;
  YR_MEMORY_BLOCK* next_block;
  YR_MEMORY_BLOCK* block;

  int result;

  result = yr_process_get_memory(pid, &first_block);

  if (result == ERROR_SUCCESS)
    result = yr_rules_scan_mem_blocks(
        rules,
        first_block,
        TRUE,
        callback,
        user_data,
        fast_scan_mode,
        timeout);

  block = first_block;

  while (block != NULL)
  {
    next_block = block->next;

    yr_free(block->data);
    yr_free(block);

    block = next_block;
  }

  return result;
}


int yr_rules_save(
    YR_RULES* rules,
    const char* filename)
{
  assert(rules->threads_count == 0);
  return yr_arena_save(rules->arena, filename);
}


int yr_rules_load(
  const char* filename,
  YR_RULES** rules)
{
  YR_RULES* new_rules;
  YARA_RULES_FILE_HEADER* header;
  YR_RULE* rule;

  int result;

  new_rules = yr_malloc(sizeof(YR_RULES));

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
  new_rules->threads_count = 0;

  #if WIN32
  new_rules->mutex = CreateMutex(NULL, FALSE, NULL);
  #else
  pthread_mutex_init(&new_rules->mutex, NULL);
  #endif

  rule = new_rules->rules_list_head;
  *rules = new_rules;

  return ERROR_SUCCESS;
}


int yr_rules_destroy(
    YR_RULES* rules)
{
  YR_EXTERNAL_VARIABLE* external;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (external->type == EXTERNAL_VARIABLE_TYPE_MALLOC_STRING)
      yr_free(external->string);

    external++;
  }

  yr_arena_destroy(rules->arena);
  yr_free(rules);

  return ERROR_SUCCESS;
}
