/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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
#include <stdlib.h>
#include <ctype.h>

#include <yara/globals.h>
#include <yara/limits.h>
#include <yara/utils.h>
#include <yara/re.h>
#include <yara/types.h>
#include <yara/error.h>
#include <yara/libyara.h>
#include <yara/scan.h>


typedef struct _CALLBACK_ARGS
{
  YR_STRING* string;
  YR_ARENA* matches_arena;

  uint8_t* data;
  size_t data_size;
  size_t data_base;

  int forward_matches;
  int full_word;
  int tidx;

} CALLBACK_ARGS;


int _yr_scan_compare(
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


int _yr_scan_icompare(
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


int _yr_scan_wcompare(
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


int _yr_scan_wicompare(
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
// See return values in yr_re_exec (re.c)
//

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

  if (flags & RE_FLAGS_BACKWARDS)
    input--;

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
      if (*ip == RE_OPCODE_MATCH)
      {
        if (flags & RE_FLAGS_EXHAUSTIVE)
        {
            callback(
               flags & RE_FLAGS_BACKWARDS ? current_input + 1 : input,
               matches,
               flags,
               callback_args);
            break;
        }
        else
        {
            return matches;
        }
      }

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

              if (sp >= MAX_FAST_HEX_RE_STACK)
                return -3;

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


int _yr_scan_add_match_to_list(
    YR_MATCH* match,
    YR_MATCHES* matches_list)
{
  YR_MATCH* insertion_point = matches_list->tail;

  if (matches_list->count == MAX_STRING_MATCHES)
    return ERROR_TOO_MANY_MATCHES;

  while (insertion_point != NULL)
  {
    if (match->offset == insertion_point->offset)
    {
      insertion_point->length = match->length;
      return ERROR_SUCCESS;
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

  matches_list->count++;

  if (match->next != NULL)
    match->next->prev = match;
  else
    matches_list->tail = match;

  return ERROR_SUCCESS;
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

  matches_list->count--;
  match->next = NULL;
  match->prev = NULL;
}


int _yr_scan_verify_chained_string_match(
    YR_ARENA* matches_arena,
    YR_STRING* matching_string,
    uint8_t* match_data,
    size_t match_base,
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
        ending_offset = match->offset + match->length;

        if (ending_offset + matching_string->chain_gap_max >= match_offset &&
            ending_offset + matching_string->chain_gap_min <= match_offset)
        {
          _yr_scan_update_match_chain_length(
              tidx, matching_string->chained_to, match, 1);
        }

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

          FAIL_ON_ERROR(_yr_scan_add_match_to_list(
              match, &string->matches[tidx]));
        }

        match = next_match;
      }
    }
    else
    {
      FAIL_ON_ERROR(yr_arena_allocate_memory(
          matches_arena,
          sizeof(YR_MATCH),
          (void**) &new_match));

      new_match->base = match_base;
      new_match->offset = match_offset;
      new_match->length = match_length;
      new_match->data = match_data;
      new_match->prev = NULL;
      new_match->next = NULL;

      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          &matching_string->unconfirmed_matches[tidx]));
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
  CALLBACK_ARGS* callback_args = (CALLBACK_ARGS*) args;

  YR_STRING* string = callback_args->string;
  YR_MATCH* new_match;

  int result = ERROR_SUCCESS;
  int tidx = callback_args->tidx;

  size_t match_offset = match_data - callback_args->data;

  // total match length is the sum of backward and forward matches.
  match_length += callback_args->forward_matches;

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
    result = _yr_scan_verify_chained_string_match(
        callback_args->matches_arena,
        string,
        match_data,
        callback_args->data_base,
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
      new_match->base = callback_args->data_base;
      new_match->offset = match_offset;
      new_match->length = match_length;
      new_match->data = match_data;
      new_match->prev = NULL;
      new_match->next = NULL;

      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          &string->matches[tidx]));
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
    size_t data_base,
    size_t offset,
    YR_ARENA* matches_arena)
{
  CALLBACK_ARGS callback_args;
  RE_EXEC_FUNC exec;

  int forward_matches = -1;
  int backward_matches = -1;
  int flags = 0;

  if (STRING_IS_FAST_HEX_REGEXP(ac_match->string))
    exec = _yr_scan_fast_hex_re_exec;
  else
    exec = yr_re_exec;

  if (STRING_IS_ASCII(ac_match->string))
  {
    forward_matches = exec(
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        offset > 0 ? flags | RE_FLAGS_NOT_AT_START : flags,
        NULL,
        NULL);
  }

  if (STRING_IS_WIDE(ac_match->string) && forward_matches == -1)
  {
    flags |= RE_FLAGS_WIDE;
    forward_matches = exec(
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        offset > 0 ? flags | RE_FLAGS_NOT_AT_START : flags,
        NULL,
        NULL);
  }

  switch(forward_matches)
  {
    case -1:
      return ERROR_SUCCESS;
    case -2:
      return ERROR_INSUFICIENT_MEMORY;
    case -3:
      return ERROR_INTERNAL_FATAL_ERROR;
  }

  if (forward_matches == 0 && ac_match->backward_code == NULL)
    return ERROR_SUCCESS;

  callback_args.string = ac_match->string;
  callback_args.data = data;
  callback_args.data_size = data_size;
  callback_args.data_base = data_base;
  callback_args.matches_arena = matches_arena;
  callback_args.forward_matches = forward_matches;
  callback_args.full_word = STRING_IS_FULL_WORD(ac_match->string);
  callback_args.tidx = yr_get_tidx();

  if (ac_match->backward_code != NULL)
  {
    backward_matches = exec(
        ac_match->backward_code,
        data + offset,
        offset,
        flags | RE_FLAGS_BACKWARDS | RE_FLAGS_EXHAUSTIVE,
        _yr_scan_match_callback,
        (void*) &callback_args);

    if (backward_matches == -2)
      return ERROR_INSUFICIENT_MEMORY;

    if (backward_matches == -3)
      return ERROR_INTERNAL_FATAL_ERROR;
  }
  else
  {
    FAIL_ON_ERROR(_yr_scan_match_callback(
        data + offset, 0, flags, &callback_args));
  }

  return ERROR_SUCCESS;
}


int _yr_scan_verify_literal_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t data_base,
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
      if (STRING_IS_WIDE(string))
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

    if (STRING_IS_WIDE(string))
      flags |= RE_FLAGS_WIDE;

    if (STRING_IS_NO_CASE(string))
      flags |= RE_FLAGS_NO_CASE;

    callback_args.string = string;
    callback_args.data = data;
    callback_args.data_size = data_size;
    callback_args.data_base = data_base;
    callback_args.matches_arena = matches_arena;
    callback_args.forward_matches = forward_matches;
    callback_args.full_word = STRING_IS_FULL_WORD(string);
    callback_args.tidx = yr_get_tidx();

    FAIL_ON_ERROR(_yr_scan_match_callback(
        data + offset, 0, flags, &callback_args));
  }

  return ERROR_SUCCESS;
}


int yr_scan_verify_match(
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t data_base,
    size_t offset,
    YR_ARENA* matches_arena,
    int flags)
{
  YR_STRING* string = ac_match->string;

  #ifdef PROFILING_ENABLED
  clock_t start = clock();
  #endif

  if (data_size - offset <= 0)
    return ERROR_SUCCESS;

  if (flags & SCAN_FLAGS_FAST_MODE &&
      STRING_IS_SINGLE_MATCH(string) &&
      STRING_FOUND(string))
    return ERROR_SUCCESS;

  if (STRING_IS_FIXED_OFFSET(string) &&
      string->fixed_offset != data_base + offset)
    return ERROR_SUCCESS;

  if (STRING_IS_LITERAL(string))
  {
    FAIL_ON_ERROR(_yr_scan_verify_literal_match(
        ac_match, data, data_size, data_base, offset, matches_arena));
  }
  else
  {
    FAIL_ON_ERROR(_yr_scan_verify_re_match(
        ac_match, data, data_size, data_base, offset, matches_arena));
  }

  #ifdef PROFILING_ENABLED
  string->clock_ticks += clock() - start;
  #endif

  return ERROR_SUCCESS;
}
