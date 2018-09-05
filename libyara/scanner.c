/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

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

#include <yara/ahocorasick.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/exefiles.h>
#include <yara/mem.h>
#include <yara/object.h>
#include <yara/proc.h>
#include <yara/scanner.h>
#include <yara/types.h>
#include <yara/libyara.h>

#include "exception.h"


static int _yr_scanner_scan_mem_block(
    YR_SCANNER* scanner,
    const uint8_t* block_data,
    YR_MEMORY_BLOCK* block)
{
  YR_RULES* rules = scanner->rules;
  YR_AC_TRANSITION_TABLE transition_table = rules->ac_transition_table;
  YR_AC_MATCH_TABLE match_table = rules->ac_match_table;

  YR_AC_MATCH* match;
  YR_AC_TRANSITION transition;

  size_t i = 0;
  uint32_t state = YR_AC_ROOT_STATE;
  uint16_t index;

  while (i < block->size)
  {
    match = match_table[state].match;

    if (i % 4096 == 0 && scanner->timeout > 0)
    {
      if (yr_stopwatch_elapsed_us(&scanner->stopwatch) > scanner->timeout)
        return ERROR_SCAN_TIMEOUT;
    }

    while (match != NULL)
    {
      if (match->backtrack <= i)
      {
        FAIL_ON_ERROR(yr_scan_verify_match(
            scanner,
            match,
            block_data,
            block->size,
            block->base,
            i - match->backtrack));
      }

      match = match->next;
    }

    index = block_data[i++] + 1;
    transition = transition_table[state + index];

    while (YR_AC_INVALID_TRANSITION(transition, index))
    {
      if (state != YR_AC_ROOT_STATE)
      {
        state = YR_AC_NEXT_STATE(transition_table[state]);
        transition = transition_table[state + index];
      }
      else
      {
        transition = 0;
        break;
      }
    }

    state = YR_AC_NEXT_STATE(transition);
  }

  match = match_table[state].match;

  while (match != NULL)
  {
    if (match->backtrack <= i)
    {
      FAIL_ON_ERROR(yr_scan_verify_match(
          scanner,
          match,
          block_data,
          block->size,
          block->base,
          i - match->backtrack));
    }

    match = match->next;
  }

  return ERROR_SUCCESS;
}


static void _yr_scanner_clean_matches(
    YR_SCANNER* scanner)
{
  YR_RULE* rule;
  YR_STRING** string;

  int tidx = scanner->tidx;

  yr_rules_foreach(scanner->rules, rule)
  {
    rule->t_flags[tidx] &= ~RULE_TFLAGS_MATCH;
    rule->ns->t_flags[tidx] &= ~NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL;
  }

  if (scanner->matching_strings_arena != NULL)
  {
    string = (YR_STRING**) yr_arena_base_address(
        scanner->matching_strings_arena);

    while (string != NULL)
    {
      (*string)->matches[tidx].count = 0;
      (*string)->matches[tidx].head = NULL;
      (*string)->matches[tidx].tail = NULL;
      (*string)->unconfirmed_matches[tidx].count = 0;
      (*string)->unconfirmed_matches[tidx].head = NULL;
      (*string)->unconfirmed_matches[tidx].tail = NULL;

      string = (YR_STRING**) yr_arena_next_address(
          scanner->matching_strings_arena,
          string,
          sizeof(YR_STRING*));
    }
  }
}


YR_API int yr_scanner_create(
    YR_RULES* rules,
    YR_SCANNER** scanner)
{
  YR_EXTERNAL_VARIABLE* external;
  YR_SCANNER* new_scanner;

  new_scanner = (YR_SCANNER*) yr_calloc(1, sizeof(YR_SCANNER));

  if (new_scanner == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_create(64, &new_scanner->objects_table),
      yr_scanner_destroy(new_scanner));

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    YR_OBJECT* object;

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_object_from_external_variable(external, &object),
        yr_scanner_destroy(new_scanner));

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_hash_table_add(
            new_scanner->objects_table,
            external->identifier,
            NULL,
            (void*) object),
        yr_scanner_destroy(new_scanner));

    external++;
  }

  new_scanner->rules = rules;
  new_scanner->tidx = -1;
  new_scanner->entry_point = UNDEFINED;

  *scanner = new_scanner;

  return ERROR_SUCCESS;
}


YR_API void yr_scanner_destroy(
    YR_SCANNER* scanner)
{
  RE_FIBER* fiber;
  RE_FIBER* next_fiber;

  fiber = scanner->re_fiber_pool.fibers.head;

  while (fiber != NULL)
  {
    next_fiber = fiber->next;
    yr_free(fiber);
    fiber = next_fiber;
  }

  if (scanner->objects_table != NULL)
  {
    yr_hash_table_destroy(
        scanner->objects_table,
        (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_object_destroy);
  }

  yr_free(scanner);
}


YR_API void yr_scanner_set_callback(
    YR_SCANNER* scanner,
    YR_CALLBACK_FUNC callback,
    void* user_data)
{
  scanner->callback = callback;
  scanner->user_data = user_data;
}


YR_API void yr_scanner_set_timeout(
    YR_SCANNER* scanner,
    int timeout)
{
  scanner->timeout = timeout * 1000000L;  // convert timeout to microseconds.
}


YR_API void yr_scanner_set_flags(
    YR_SCANNER* scanner,
    int flags)
{
  scanner->flags = flags;
}


YR_API int yr_scanner_define_integer_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int64_t value)
{
  YR_OBJECT* obj = (YR_OBJECT*) yr_hash_table_lookup(
      scanner->objects_table,
      identifier,
      NULL);

  if (obj == NULL)
    return ERROR_INVALID_ARGUMENT;

  if (obj->type != OBJECT_TYPE_INTEGER)
    return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

  return yr_object_set_integer(value, obj, NULL);
}


YR_API int yr_scanner_define_boolean_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int value)
{
  return yr_scanner_define_integer_variable(scanner, identifier, value);
}


YR_API int yr_scanner_define_float_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    double value)
{
  YR_OBJECT* obj = (YR_OBJECT*) yr_hash_table_lookup(
      scanner->objects_table,
      identifier,
      NULL);

  if (obj == NULL)
    return ERROR_INVALID_ARGUMENT;

  if (obj->type != OBJECT_TYPE_FLOAT)
    return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

  return yr_object_set_float(value, obj, NULL);
}


YR_API int yr_scanner_define_string_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    const char* value)
{
  YR_OBJECT* obj = (YR_OBJECT*) yr_hash_table_lookup(
      scanner->objects_table,
      identifier,
      NULL);

  if (obj == NULL)
    return ERROR_INVALID_ARGUMENT;

  if (obj->type != OBJECT_TYPE_STRING)
    return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

  return yr_object_set_string(value, strlen(value), obj, NULL);
}


YR_API int yr_scanner_scan_mem_blocks(
    YR_SCANNER* scanner,
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_RULES* rules;
  YR_RULE* rule;
  YR_MEMORY_BLOCK* block;

  int tidx = 0;
  int result = ERROR_SUCCESS;

  uint64_t elapsed_time;

  if (scanner->callback == NULL)
    return ERROR_CALLBACK_REQUIRED;

  scanner->iterator = iterator;
  rules = scanner->rules;
  block = iterator->first(iterator);

  if (block == NULL)
    return ERROR_SUCCESS;

  yr_mutex_lock(&rules->mutex);

  while (tidx < YR_MAX_THREADS && YR_BITARRAY_TEST(rules->tidx_mask, tidx))
  {
    tidx++;
  }

  if (tidx < YR_MAX_THREADS)
    YR_BITARRAY_SET(rules->tidx_mask, tidx);
  else
    result = ERROR_TOO_MANY_SCAN_THREADS;

  yr_mutex_unlock(&rules->mutex);

  if (result != ERROR_SUCCESS)
    return result;

  scanner->tidx = tidx;
  scanner->file_size = block->size;

  yr_set_tidx(tidx);

  result = yr_arena_create(1048576, 0, &scanner->matches_arena);

  if (result != ERROR_SUCCESS)
    goto _exit;

  result = yr_arena_create(4096, 0, &scanner->matching_strings_arena);

  if (result != ERROR_SUCCESS)
    goto _exit;

  yr_stopwatch_start(&scanner->stopwatch);

  while (block != NULL)
  {
    const uint8_t* data = block->fetch_data(block);

    // fetch may fail
    if (data == NULL)
    {
      block = iterator->next(iterator);
      continue;
    }

    if (scanner->entry_point == UNDEFINED)
    {
      YR_TRYCATCH(
        !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
        {
          if (scanner->flags & SCAN_FLAGS_PROCESS_MEMORY)
            scanner->entry_point = yr_get_entry_point_address(
                data,
                block->size,
                block->base);
          else
            scanner->entry_point = yr_get_entry_point_offset(
                data,
                block->size);
        },{});
    }

    YR_TRYCATCH(
      !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
      {
        result = _yr_scanner_scan_mem_block(
            scanner,
            data,
            block);
      },{
        result = ERROR_COULD_NOT_MAP_FILE;
      });

    if (result != ERROR_SUCCESS)
      goto _exit;

    block = iterator->next(iterator);
  }

  YR_TRYCATCH(
    !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
    {
      result = yr_execute_code(scanner);
    },{
      result = ERROR_COULD_NOT_MAP_FILE;
    });

  if (result != ERROR_SUCCESS)
    goto _exit;

  yr_rules_foreach(rules, rule)
  {
    int message;

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
      switch (scanner->callback(message, rule, scanner->user_data))
      {
        case CALLBACK_ABORT:
          result = ERROR_SUCCESS;
          goto _exit;

        case CALLBACK_ERROR:
          result = ERROR_CALLBACK_ERROR;
          goto _exit;
      }
    }
  }

  scanner->callback(CALLBACK_MSG_SCAN_FINISHED, NULL, scanner->user_data);

_exit:

  elapsed_time = yr_stopwatch_elapsed_us(&scanner->stopwatch);

  #ifdef PROFILING_ENABLED
  yr_rules_foreach(rules, rule)
  {
    #ifdef _WIN32
    InterlockedAdd64(&rule->time_cost, rule->time_cost_per_thread[tidx]);
    #else
    __sync_fetch_and_add(&rule->time_cost, rule->time_cost_per_thread[tidx]);
    #endif

    rule->time_cost_per_thread[tidx] = 0;
  }
  #endif

  _yr_scanner_clean_matches(scanner);

  if (scanner->matches_arena != NULL)
  {
    yr_arena_destroy(scanner->matches_arena);
    scanner->matches_arena = NULL;
  }

  if (scanner->matching_strings_arena != NULL)
  {
    yr_arena_destroy(scanner->matching_strings_arena);
    scanner->matching_strings_arena = NULL;
  }

  yr_mutex_lock(&rules->mutex);
  YR_BITARRAY_UNSET(rules->tidx_mask, tidx);
  rules->time_cost += elapsed_time;
  yr_mutex_unlock(&rules->mutex);

  yr_set_tidx(-1);

  return result;
}


static YR_MEMORY_BLOCK* _yr_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  return (YR_MEMORY_BLOCK*) iterator->context;
}


static YR_MEMORY_BLOCK* _yr_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  return NULL;
}


static const uint8_t* _yr_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  return (const uint8_t*) block->context;
}


YR_API int yr_scanner_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size)
{
  YR_MEMORY_BLOCK block;
  YR_MEMORY_BLOCK_ITERATOR iterator;

  block.size = buffer_size;
  block.base = 0;
  block.fetch_data = _yr_fetch_block_data;
  block.context = (void*) buffer;

  iterator.context = &block;
  iterator.first = _yr_get_first_block;
  iterator.next = _yr_get_next_block;

  return yr_scanner_scan_mem_blocks(scanner, &iterator);
}


YR_API int yr_scanner_scan_file(
    YR_SCANNER* scanner,
    const char* filename)
{
  YR_MAPPED_FILE mfile;

  int result = yr_filemap_map(filename, &mfile);

  if (result == ERROR_SUCCESS)
  {
    result = yr_scanner_scan_mem(scanner, mfile.data, mfile.size);
    yr_filemap_unmap(&mfile);
  }

  return result;
}


YR_API int yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    YR_FILE_DESCRIPTOR fd)
{
  YR_MAPPED_FILE mfile;

  int result = yr_filemap_map_fd(fd, 0, 0, &mfile);

  if (result == ERROR_SUCCESS)
  {
    result = yr_scanner_scan_mem(scanner, mfile.data, mfile.size);
    yr_filemap_unmap_fd(&mfile);
  }

  return result;
}


YR_API int yr_scanner_scan_proc(
    YR_SCANNER* scanner,
    int pid)
{
  YR_MEMORY_BLOCK_ITERATOR iterator;

  int result = yr_process_open_iterator(pid, &iterator);

  if (result == ERROR_SUCCESS)
  {
    int prev_flags = scanner->flags;
    scanner->flags |= SCAN_FLAGS_PROCESS_MEMORY;
    result = yr_scanner_scan_mem_blocks(scanner, &iterator);
    scanner->flags = prev_flags;
    yr_process_close_iterator(&iterator);
  }

  return result;
}


YR_API YR_STRING* yr_scanner_last_error_string(
    YR_SCANNER* scanner)
{
  return scanner->last_error_string;
}


YR_API YR_RULE* yr_scanner_last_error_rule(
    YR_SCANNER* scanner)
{
  if (scanner->last_error_string == NULL)
    return NULL;

  return scanner->last_error_string->rule;
}
