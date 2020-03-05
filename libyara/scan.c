/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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
#include <yara/stopwatch.h>



typedef struct _CALLBACK_ARGS
{
  YR_STRING* string;
  YR_SCAN_CONTEXT* context;

  const uint8_t* data;
  size_t data_size;
  uint64_t data_base;

  int forward_matches;
  int full_word;

} CALLBACK_ARGS;


static int _yr_scan_xor_compare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;
  uint8_t k = 0;

  size_t i = 0;

  if (data_size < string_length)
    return 0;

  // Calculate the xor key to compare with. *s1 is the start of the string we
  // matched on and *s2 is the "plaintext" string, so *s1 ^ *s2 is the key to
  // every *s2 as we compare.
  k = *s1 ^ *s2;

  while (i < string_length && *s1++ == ((*s2++) ^ k))
    i++;

  return (int) ((i == string_length) ? i : 0);
}

static int _yr_scan_xor_wcompare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;
  uint8_t k = 0;

  size_t i = 0;

  if (data_size < string_length * 2)
    return 0;

  // Calculate the xor key to compare with. *s1 is the start of the string we
  // matched on and *s2 is the "plaintext" string, so *s1 ^ *s2 is the key to
  // every *s2 as we compare.
  k = *s1 ^ *s2;

  while (i < string_length && *s1 == ((*s2) ^ k) && ((*(s1 + 1)) ^ k) == 0x00)
  {
    s1+=2;
    s2++;
    i++;
  }

  return (int) ((i == string_length) ? i * 2 : 0);
}


static int _yr_scan_compare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;

  size_t i = 0;

  if (data_size < string_length)
    return 0;

  while (i < string_length && *s1++ == *s2++)
    i++;

  return (int) ((i == string_length) ? i : 0);
}


static int _yr_scan_icompare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;

  size_t i = 0;

  if (data_size < string_length)
    return 0;

  while (i < string_length && yr_lowercase[*s1++] == yr_lowercase[*s2++])
    i++;

  return (int) ((i == string_length) ? i : 0);
}


static int _yr_scan_wcompare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;

  size_t i = 0;

  if (data_size < string_length * 2)
    return 0;

  while (i < string_length && *s1 == *s2 && *(s1 + 1) == 0x00)
  {
    s1+=2;
    s2++;
    i++;
  }

  return (int) ((i == string_length) ? i * 2 : 0);
}


static int _yr_scan_wicompare(
    const uint8_t* data,
    size_t data_size,
    uint8_t* string,
    size_t string_length)
{
  const uint8_t* s1 = data;
  const uint8_t* s2 = string;

  size_t i = 0;

  if (data_size < string_length * 2)
    return 0;

  while (i < string_length &&
         yr_lowercase[*s1] == yr_lowercase[*s2] &&
         *(s1 + 1) == 0x00)
  {
    s1+=2;
    s2++;
    i++;
  }

  return (int) ((i == string_length) ? i * 2 : 0);
}


static void _yr_scan_update_match_chain_length(
    YR_SCAN_CONTEXT* context,
    YR_STRING* string,
    YR_MATCH* match_to_update,
    int chain_length)
{
  YR_MATCH* match;

  if (match_to_update->chain_length == chain_length)
    return;

  match_to_update->chain_length = chain_length;

  if (string->chained_to == NULL)
    return;

  match = context->unconfirmed_matches[string->chained_to->idx].head;

  while (match != NULL)
  {
    int64_t ending_offset = match->offset + match->match_length;

    if (ending_offset + string->chain_gap_max >= match_to_update->offset &&
        ending_offset + string->chain_gap_min <= match_to_update->offset)
    {
      _yr_scan_update_match_chain_length(
          context, string->chained_to, match, chain_length + 1);
    }

    match = match->next;
  }
}


static int _yr_scan_add_match_to_list(
    YR_MATCH* match,
    YR_MATCHES* matches_list,
    int replace_if_exists)
{
  YR_MATCH* insertion_point = matches_list->tail;

  if (matches_list->count == YR_MAX_STRING_MATCHES)
    return ERROR_TOO_MANY_MATCHES;

  while (insertion_point != NULL)
  {
    if (match->offset == insertion_point->offset)
    {
      if (replace_if_exists)
      {
        insertion_point->match_length = match->match_length;
        insertion_point->data_length = match->data_length;
        insertion_point->data = match->data;
      }

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


static void _yr_scan_remove_match_from_list(
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

//
// _yr_scan_verify_chained_string_match
//
// Given a string that is part of a string chain and is matching at some
// point in the scanned data, this function determines if the whole string
// chain is also matching. For example, if the string S was splitted and
// converted in a chain S1 <- S2 <- S3 (see yr_re_ast_split_at_chaining_point),
// and a match for S3 was found, this functions finds out if there are matches
// for S1 and S2 that together with the match found for S3 conform a match for
// the whole S.
//
// Notice that this function operates in a non-greedy fashion. Matches found
// for S will be the shortest possible ones.
//

static int _yr_scan_verify_chained_string_match(
    YR_STRING* matching_string,
    YR_SCAN_CONTEXT* context,
    const uint8_t* match_data,
    uint64_t match_base,
    uint64_t match_offset,
    int32_t match_length)
{
  YR_STRING* string;
  YR_MATCH* match;
  YR_MATCH* next_match;
  YR_MATCH* new_match;

  uint64_t lowest_offset;
  uint64_t ending_offset;
  int32_t full_chain_length;

  bool add_match = false;

  if (matching_string->chained_to == NULL)
  {
    // The matching string is the head of the chain, this match should be
    // added to the list of unconfirmed matches. The match will remain
    // unconfirmed until all the strings in the chain are found with the
    // correct distances between them.
    add_match = true;
  }
  else
  {
    // If some unconfirmed match exists, the lowest possible offset where the
    // whole string chain can match is the offset of the first string in the
    // list of unconfirmed matches. Unconfirmed matches are sorted in ascending
    // offset order. If no unconfirmed match exists, the lowest possible offset
    // is the offset of the current match.
    match = context->unconfirmed_matches[matching_string->idx].head;

    if (match != NULL)
      lowest_offset = match->offset;
    else
      lowest_offset = match_offset;

    // Iterate over the list of unconfirmed matches for the string that
    // precedes the currently matching string. If we have a string chain like:
    // S1 <- S2 <- S3, and we just found a match for S2, we are iterating the
    // list of unconfirmed matches of S1.
    match = context->unconfirmed_matches[matching_string->chained_to->idx].head;

    while (match != NULL)
    {
      // Store match->next so that we can use it later for advancing in the
      // list, if _yr_scan_remove_match_from_list is called, match->next is
      // set to NULL, that's why we store its current value before that happens.
      next_match = match->next;

      // The unconfirmed match starts at match->offset and finishes at
      // ending_offset.
      ending_offset = match->offset + match->match_length;

      if (ending_offset + matching_string->chain_gap_max < lowest_offset)
      {
        // If the current match is too far away from the unconfirmed match,
        // remove the unconfirmed match from the list because it has been
        // negatively confirmed (i.e: we can be sure that this unconfirmed
        // match can't be an actual match)
        _yr_scan_remove_match_from_list(
            match,
            &context->unconfirmed_matches[matching_string->chained_to->idx]);
      }
      else if (ending_offset + matching_string->chain_gap_max >= match_offset &&
               ending_offset + matching_string->chain_gap_min <= match_offset)
      {
        // If the distance between the end of the unconfirmed match and the
        // start of the current match is within the range specified in the
        // regexp or hex string, this could be an actual match.
        add_match = true;
        break;
      }

      match = next_match;
    }
  }

  if (add_match)
  {
    uint32_t max_match_data;

    FAIL_ON_ERROR(yr_get_configuration(
        YR_CONFIG_MAX_MATCH_DATA,
        &max_match_data))

    if (STRING_IS_CHAIN_TAIL(matching_string))
    {
      // The matching string is the tail of the string chain. It must be
      // chained to some other string.
      assert(matching_string->chained_to != NULL);

      // Iterate over the list of unconfirmed matches of the preceding string
      // in the chain and update the chain_length field for each of them. This
      // is a recursive operation that will update the chain_length field for
      // every unconfirmed match in all the strings in the chain up to the head
      // of the chain.
      match = context->unconfirmed_matches[matching_string->chained_to->idx].head;

      while (match != NULL)
      {
        ending_offset = match->offset + match->match_length;

        if (ending_offset + matching_string->chain_gap_max >= match_offset &&
            ending_offset + matching_string->chain_gap_min <= match_offset)
        {
          _yr_scan_update_match_chain_length(
              context, matching_string->chained_to, match, 1);
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

      // "string" points now to the head of the strings chain.
      match = context->unconfirmed_matches[string->idx].head;

      // Iterate over the list of unconfirmed matches of the head of the chain,
      // and move to the list of confirmed matches those with a chain_length
      // equal to full_chain_length, which means that the whole chain has been
      // confirmed to match.
      while (match != NULL)
      {
        next_match = match->next;

        if (match->chain_length == full_chain_length)
        {
          _yr_scan_remove_match_from_list(
              match,
              &context->unconfirmed_matches[string->idx]);

          match->match_length = (int32_t) \
              (match_offset - match->offset + match_length);

          match->data_length = yr_min(match->match_length, max_match_data);

          match->data = yr_notebook_alloc(
              context->matches_notebook, match->data_length);

          if (match->data == NULL)
            return ERROR_INSUFFICIENT_MEMORY;

          memcpy(
              (void*) match->data,
              match_data - match_offset + match->offset,
              match->data_length);

          FAIL_ON_ERROR(_yr_scan_add_match_to_list(
              match,
              STRING_IS_PRIVATE(string) ?
                  &context->private_matches[string->idx] :
                  &context->matches[string->idx],
              false));
        }

        match = next_match;
      }
    }
    else // It's a part of a chain, but not the tail.
    {
      new_match = yr_notebook_alloc(context->matches_notebook, sizeof(YR_MATCH));

      if (new_match == NULL)
        return ERROR_INSUFFICIENT_MEMORY;

      new_match->base = match_base;
      new_match->offset = match_offset;
      new_match->match_length = match_length;
      new_match->chain_length = 0;
      new_match->prev = NULL;
      new_match->next = NULL;

      // A copy of the matching data is written to the matches_arena, the
      // amount of data copies is limited by YR_CONFIG_MAX_MATCH_DATA.
      new_match->data_length = yr_min(match_length, max_match_data);

      if (new_match->data_length > 0)
      {
        new_match->data = yr_notebook_alloc(
            context->matches_notebook, new_match->data_length);

        if (new_match->data == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        memcpy(
            (void*) new_match->data,
            match_data,
            new_match->data_length);
      }
      else
      {
        new_match->data = NULL;
      }

      // Add the match to the list of unconfirmed matches because the string
      // is part of a chain but not its tail, so we can't be sure the this is
      // an actual match until finding the remaining parts of the chain.
      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          &context->unconfirmed_matches[matching_string->idx],
          false));
    }
  }

  return ERROR_SUCCESS;
}


static int _yr_scan_match_callback(
    const uint8_t* match_data,
    int32_t match_length,
    int flags,
    void* args)
{
  CALLBACK_ARGS* callback_args = (CALLBACK_ARGS*) args;

  YR_STRING* string = callback_args->string;
  YR_MATCH* new_match;

  int result = ERROR_SUCCESS;

  size_t match_offset = match_data - callback_args->data;

  // total match length is the sum of backward and forward matches.
  match_length += callback_args->forward_matches;

  // make sure that match fits into the data.
  assert(match_offset + match_length <= callback_args->data_size);

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
        string,
        callback_args->context,
        match_data,
        callback_args->data_base,
        match_offset,
        match_length);
  }
  else
  {
    uint32_t max_match_data;

    FAIL_ON_ERROR(yr_get_configuration(
        YR_CONFIG_MAX_MATCH_DATA,
        &max_match_data));

    new_match = yr_notebook_alloc(
        callback_args->context->matches_notebook, sizeof(YR_MATCH));

    if (new_match == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    new_match->data_length = yr_min(match_length, max_match_data);

    if (new_match->data_length > 0)
    {
      new_match->data = yr_notebook_alloc(
          callback_args->context->matches_notebook, new_match->data_length);

      if (new_match->data == NULL)
        return ERROR_INSUFFICIENT_MEMORY;

      memcpy(
          (void*) new_match->data,
          match_data,
          new_match->data_length);
    }
    else
    {
      new_match->data = NULL;
    }

    if (result == ERROR_SUCCESS)
    {
      new_match->base = callback_args->data_base;
      new_match->offset = match_offset;
      new_match->match_length = match_length;
      new_match->prev = NULL;
      new_match->next = NULL;

      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          STRING_IS_PRIVATE(string) ?
             &callback_args->context->private_matches[string->idx] :
             &callback_args->context->matches[string->idx],
          STRING_IS_GREEDY_REGEXP(string)));
    }
  }

  return result;
}


typedef int (*RE_EXEC_FUNC)(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    const uint8_t* input,
    size_t input_forwards_size,
    size_t input_backwards_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    int* matches);


static int _yr_scan_verify_re_match(
    YR_SCAN_CONTEXT* context,
    YR_AC_MATCH* ac_match,
    const uint8_t* data,
    size_t data_size,
    uint64_t data_base,
    size_t offset)
{
  CALLBACK_ARGS callback_args;
  RE_EXEC_FUNC exec;

  int forward_matches = -1;
  int backward_matches = -1;
  int flags = 0;

  if (STRING_IS_GREEDY_REGEXP(ac_match->string))
    flags |= RE_FLAGS_GREEDY;

  if (STRING_IS_NO_CASE(ac_match->string))
    flags |= RE_FLAGS_NO_CASE;

  if (STRING_IS_DOT_ALL(ac_match->string))
    flags |= RE_FLAGS_DOT_ALL;

  if (STRING_IS_FAST_REGEXP(ac_match->string))
    exec = yr_re_fast_exec;
  else
    exec = yr_re_exec;

  if (STRING_IS_ASCII(ac_match->string) ||
      STRING_IS_BASE64(ac_match->string) ||
      STRING_IS_BASE64_WIDE(ac_match->string))
  {
    FAIL_ON_ERROR(exec(
        context,
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        offset,
        flags,
        NULL,
        NULL,
        &forward_matches));
  }

  if ((forward_matches == -1) &&
      (STRING_IS_WIDE(ac_match->string) &&
      !(STRING_IS_BASE64_WIDE(ac_match->string) || STRING_IS_BASE64_WIDE(ac_match->string))))
  {
    flags |= RE_FLAGS_WIDE;
    FAIL_ON_ERROR(exec(
        context,
        ac_match->forward_code,
        data + offset,
        data_size - offset,
        offset,
        flags,
        NULL,
        NULL,
        &forward_matches));
  }

  if (forward_matches == -1)
    return ERROR_SUCCESS;

  if (forward_matches == 0 && ac_match->backward_code == NULL)
    return ERROR_SUCCESS;

  callback_args.string = ac_match->string;
  callback_args.context = context;
  callback_args.data = data;
  callback_args.data_size = data_size;
  callback_args.data_base = data_base;
  callback_args.forward_matches = forward_matches;
  callback_args.full_word = STRING_IS_FULL_WORD(ac_match->string);

  if (ac_match->backward_code != NULL)
  {
    FAIL_ON_ERROR(exec(
        context,
        ac_match->backward_code,
        data + offset,
        data_size - offset,
        offset,
        flags | RE_FLAGS_BACKWARDS | RE_FLAGS_EXHAUSTIVE,
        _yr_scan_match_callback,
        (void*) &callback_args,
        &backward_matches));
  }
  else
  {
    FAIL_ON_ERROR(_yr_scan_match_callback(
        data + offset, 0, flags, &callback_args));
  }

  return ERROR_SUCCESS;
}


static int _yr_scan_verify_literal_match(
    YR_SCAN_CONTEXT* context,
    YR_AC_MATCH* ac_match,
    const uint8_t* data,
    size_t data_size,
    uint64_t data_base,
    size_t offset)
{
  int flags = 0;
  int forward_matches = 0;

  CALLBACK_ARGS callback_args;
  YR_STRING* string = ac_match->string;

  if (STRING_FITS_IN_ATOM(string))
  {
    forward_matches = ac_match->backtrack;
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

    if (STRING_IS_XOR(string) && forward_matches == 0)
    {
      if (STRING_IS_WIDE(string))
      {
        forward_matches = _yr_scan_xor_wcompare(
            data + offset,
            data_size - offset,
            string->string,
            string->length);
      }

      if (forward_matches == 0)
      {
        forward_matches = _yr_scan_xor_compare(
            data + offset,
            data_size - offset,
            string->string,
            string->length);
      }
    }

  }

  if (forward_matches == 0)
    return ERROR_SUCCESS;

  if (forward_matches == string->length * 2)
    flags |= RE_FLAGS_WIDE;

  if (STRING_IS_NO_CASE(string))
    flags |= RE_FLAGS_NO_CASE;

  callback_args.context = context;
  callback_args.string = string;
  callback_args.data = data;
  callback_args.data_size = data_size;
  callback_args.data_base = data_base;
  callback_args.forward_matches = forward_matches;
  callback_args.full_word = STRING_IS_FULL_WORD(string);

  FAIL_ON_ERROR(_yr_scan_match_callback(
      data + offset, 0, flags, &callback_args));

  return ERROR_SUCCESS;
}


int yr_scan_verify_match(
    YR_SCAN_CONTEXT* context,
    YR_AC_MATCH* ac_match,
    const uint8_t* data,
    size_t data_size,
    uint64_t data_base,
    size_t offset)
{
  YR_STRING* string = ac_match->string;

  int result;

  if (data_size - offset <= 0)
    return ERROR_SUCCESS;

  if (STRING_IS_DISABLED(string))
    return ERROR_SUCCESS;

  if (context->flags & SCAN_FLAGS_FAST_MODE &&
      STRING_IS_SINGLE_MATCH(string) &&
      context->matches[string->idx].head != NULL)
    return ERROR_SUCCESS;

  if (STRING_IS_FIXED_OFFSET(string) &&
      string->fixed_offset != data_base + offset)
    return ERROR_SUCCESS;

  #ifdef PROFILING_ENABLED
  uint64_t start_time = yr_stopwatch_elapsed_us(&context->stopwatch);
  #endif

  if (STRING_IS_LITERAL(string))
  {
    result = _yr_scan_verify_literal_match(
        context, ac_match, data, data_size, data_base, offset);
  }
  else
  {
    result = _yr_scan_verify_re_match(
        context, ac_match, data, data_size, data_base, offset);
  }

  #ifdef PROFILING_ENABLED
  uint64_t finish_time = yr_stopwatch_elapsed_us(&context->stopwatch);
  context->time_cost[string->rule_idx] += (finish_time - start_time);
  #endif

  if (result != ERROR_SUCCESS)
    context->last_error_string = string;

  return result;
}
