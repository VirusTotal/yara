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

#include <stdlib.h>
#include <yara/ahocorasick.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/exefiles.h>
#include <yara/libyara.h>
#include <yara/mem.h>
#include <yara/object.h>
#include <yara/proc.h>
#include <yara/scanner.h>
#include <yara/types.h>

#include "exception.h"

static int _yr_scanner_scan_mem_block(
    YR_SCANNER* scanner,
    const uint8_t* block_data,
    YR_MEMORY_BLOCK* block)
{
  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s(block_data=%p block->base=0x%" PRIx64 " block->size=%zu) {\n",
      __FUNCTION__,
      block_data,
      block->base,
      block->size);

  int result = ERROR_SUCCESS;

  YR_RULES* rules = scanner->rules;
  YR_AC_TRANSITION* transition_table = rules->ac_transition_table;
  uint32_t* match_table = rules->ac_match_table;

  YR_AC_MATCH* match;
  YR_AC_TRANSITION transition;

  size_t i = 0;
  uint32_t state = YR_AC_ROOT_STATE;
  uint16_t index;

  while (i < block->size)
  {
    if (i % 4096 == 0 && scanner->timeout > 0)
    {
      if (yr_stopwatch_elapsed_ns(&scanner->stopwatch) > scanner->timeout)
      {
        result = ERROR_SCAN_TIMEOUT;
        goto _exit;
      }
    }

#if 2 == YR_DEBUG_VERBOSITY
    if (0 != state)
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- match_table[state=%u]=%'u i=%'ld "
          "block_data=%p block->base=0x%" PRIx64 " // %s()\n",
          state,
          match_table[state],
          i,
          block_data,
          block->base,
          __FUNCTION__);
#endif

    if (match_table[state] != 0)
    {
      // If the entry corresponding to state N in the match table is zero, it
      // means that there's no match associated to the state. If it's non-zero,
      // its value is the 1-based index within ac_match_pool where the first
      // match resides.

      match = &rules->ac_match_pool[match_table[state] - 1];

      while (match != NULL)
      {
        if (match->backtrack <= i)
        {
          GOTO_EXIT_ON_ERROR(yr_scan_verify_match(
              scanner,
              match,
              block_data,
              block->size,
              block->base,
              i - match->backtrack));
        }

        match = match->next;
      }
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

  if (match_table[state] != 0)
  {
    match = &rules->ac_match_pool[match_table[state] - 1];

    while (match != NULL)
    {
      if (match->backtrack <= i)
      {
        GOTO_EXIT_ON_ERROR(yr_scan_verify_match(
            scanner,
            match,
            block_data,
            block->size,
            block->base,
            i - match->backtrack));
      }

      match = match->next;
    }
  }

_exit:

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "} = %d AKA %s // %s()\n",
      result,
      yr_debug_error_as_string(result),
      __FUNCTION__);

  return result;
}

static void _yr_scanner_clean_matches(YR_SCANNER* scanner)
{
  YR_DEBUG_FPRINTF(2, stderr, "- %s() {} \n", __FUNCTION__);

  memset(
      scanner->rule_matches_flags,
      0,
      sizeof(YR_BITMASK) * YR_BITMASK_SIZE(scanner->rules->num_rules));

  memset(
      scanner->ns_unsatisfied_flags,
      0,
      sizeof(YR_BITMASK) * YR_BITMASK_SIZE(scanner->rules->num_namespaces));

  memset(scanner->matches, 0, sizeof(YR_MATCHES) * scanner->rules->num_strings);

  memset(
      scanner->unconfirmed_matches,
      0,
      sizeof(YR_MATCHES) * scanner->rules->num_strings);
}

YR_API int yr_scanner_create(YR_RULES* rules, YR_SCANNER** scanner)
{
  YR_DEBUG_FPRINTF(2, stderr, "- %s() {} \n", __FUNCTION__);

  YR_EXTERNAL_VARIABLE* external;
  YR_SCANNER* new_scanner;

  new_scanner = (YR_SCANNER*) yr_calloc(1, sizeof(YR_SCANNER));

  if (new_scanner == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_create(64, &new_scanner->objects_table),
      yr_free(new_scanner));

  new_scanner->rules = rules;
  new_scanner->entry_point = YR_UNDEFINED;
  new_scanner->file_size = YR_UNDEFINED;
  new_scanner->canary = rand();

  // By default report both matching and non-matching rules.
  new_scanner->flags = SCAN_FLAGS_REPORT_RULES_MATCHING |
                       SCAN_FLAGS_REPORT_RULES_NOT_MATCHING;

  new_scanner->rule_matches_flags = (YR_BITMASK*) yr_calloc(
      sizeof(YR_BITMASK), YR_BITMASK_SIZE(rules->num_rules));

  new_scanner->ns_unsatisfied_flags = (YR_BITMASK*) yr_calloc(
      sizeof(YR_BITMASK), YR_BITMASK_SIZE(rules->num_namespaces));

  new_scanner->matches = (YR_MATCHES*) yr_calloc(
      rules->num_strings, sizeof(YR_MATCHES));

  new_scanner->unconfirmed_matches = (YR_MATCHES*) yr_calloc(
      rules->num_strings, sizeof(YR_MATCHES));

#ifdef YR_PROFILING_ENABLED
  new_scanner->profiling_info = yr_calloc(
      rules->num_rules, sizeof(YR_PROFILING_INFO));

  if (new_scanner->profiling_info == NULL)
  {
    yr_scanner_destroy(new_scanner);
    return ERROR_INSUFFICIENT_MEMORY;
  }
#else
  new_scanner->profiling_info = NULL;
#endif

  external = rules->ext_vars_table;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    YR_OBJECT* object;

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_object_from_external_variable(external, &object),
        // cleanup
        yr_scanner_destroy(new_scanner));

    FAIL_ON_ERROR_WITH_CLEANUP(yr_hash_table_add(
                                   new_scanner->objects_table,
                                   external->identifier,
                                   NULL,
                                   (void*) object),
                               // cleanup
                               yr_object_destroy(object);
                               yr_scanner_destroy(new_scanner));

    yr_object_set_canary(object, new_scanner->canary);
    external++;
  }

  *scanner = new_scanner;

  return ERROR_SUCCESS;
}

YR_API void yr_scanner_destroy(YR_SCANNER* scanner)
{
  YR_DEBUG_FPRINTF(2, stderr, "- %s() {} \n", __FUNCTION__);

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

#ifdef YR_PROFILING_ENABLED
  yr_free(scanner->profiling_info);
#endif

  yr_free(scanner->rule_matches_flags);
  yr_free(scanner->ns_unsatisfied_flags);
  yr_free(scanner->matches);
  yr_free(scanner->unconfirmed_matches);
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

YR_API void yr_scanner_set_timeout(YR_SCANNER* scanner, int timeout)
{
  // Convert timeout from seconds to nanoseconds.
  scanner->timeout = timeout * 1000000000ULL;
}

YR_API void yr_scanner_set_flags(YR_SCANNER* scanner, int flags)
{
  // For backward compatibility, if neither SCAN_FLAGS_REPORT_RULES_MATCHING
  // nor SCAN_FLAGS_REPORT_RULES_NOT_MATCHING are specified, both are assumed.

  if (!(flags & SCAN_FLAGS_REPORT_RULES_MATCHING) &&
      !(flags & SCAN_FLAGS_REPORT_RULES_NOT_MATCHING))
  {
    flags |= SCAN_FLAGS_REPORT_RULES_MATCHING |
             SCAN_FLAGS_REPORT_RULES_NOT_MATCHING;
  }

  scanner->flags = flags;
}

YR_API int yr_scanner_define_integer_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int64_t value)
{
  YR_OBJECT* obj = (YR_OBJECT*) yr_hash_table_lookup(
      scanner->objects_table, identifier, NULL);

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
      scanner->objects_table, identifier, NULL);

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
      scanner->objects_table, identifier, NULL);

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
  YR_DEBUG_FPRINTF(2, stderr, "+ %s() {\n", __FUNCTION__);

  YR_RULES* rules;
  YR_RULE* rule;
  YR_MEMORY_BLOCK* block;

  int i, result = ERROR_SUCCESS;

  if (scanner->callback == NULL)
  {
    result = ERROR_CALLBACK_REQUIRED;
    goto _exit;
  }

  scanner->iterator = iterator;
  rules = scanner->rules;

  if (iterator->last_error == ERROR_BLOCK_NOT_READY)
  {
    // The caller is invoking yr_scanner_scan_mem_blocks again because the
    // previous call returned ERROR_BLOCK_NOT_READY.
    block = iterator->next(iterator);
  }
  else
  {
    // Create the notebook that will hold the YR_MATCH structures representing
    // each match found. This notebook will also contain snippets of the
    // matching data (the "data" field in YR_MATCH points to the snippet
    // corresponding to the match). Each notebook's page can store up to 1024
    // matches.
    uint32_t max_match_data;

    FAIL_ON_ERROR(
        yr_get_configuration(YR_CONFIG_MAX_MATCH_DATA, &max_match_data));

    result = yr_notebook_create(
        1024 * (sizeof(YR_MATCH) + max_match_data), &scanner->matches_notebook);

    if (result != ERROR_SUCCESS)
      goto _exit;

    yr_stopwatch_start(&scanner->stopwatch);

    block = iterator->first(iterator);
  }

  while (block != NULL)
  {
    const uint8_t* data = block->fetch_data(block);

    // fetch_data may fail and return NULL.
    if (data == NULL)
    {
      block = iterator->next(iterator);
      continue;
    }

    if (scanner->entry_point == YR_UNDEFINED)
    {
      YR_TRYCATCH(
          !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
          {
            if (scanner->flags & SCAN_FLAGS_PROCESS_MEMORY)
              scanner->entry_point = yr_get_entry_point_address(
                  data, block->size, block->base);
            else
              scanner->entry_point = yr_get_entry_point_offset(
                  data, block->size);
          },
          {});
    }

    YR_TRYCATCH(
        !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
        { result = _yr_scanner_scan_mem_block(scanner, data, block); },
        { result = ERROR_COULD_NOT_MAP_FILE; });

    if (result != ERROR_SUCCESS)
      goto _exit;

    block = iterator->next(iterator);
  }

  result = iterator->last_error;

  if (result != ERROR_SUCCESS)
    goto _exit;

  // Ask the iterator for the file size.
  scanner->file_size = iterator->file_size(iterator);

  YR_TRYCATCH(
      !(scanner->flags & SCAN_FLAGS_NO_TRYCATCH),
      { result = yr_execute_code(scanner); },
      { result = ERROR_COULD_NOT_MAP_FILE; });

  if (result != ERROR_SUCCESS)
    goto _exit;

  for (i = 0, rule = rules->rules_table; !RULE_IS_NULL(rule); i++, rule++)
  {
    int message = 0;

    if (yr_bitmask_is_set(scanner->rule_matches_flags, i) &&
        yr_bitmask_is_not_set(scanner->ns_unsatisfied_flags, rule->ns->idx))
    {
      if (scanner->flags & SCAN_FLAGS_REPORT_RULES_MATCHING)
        message = CALLBACK_MSG_RULE_MATCHING;
    }
    else
    {
      if (scanner->flags & SCAN_FLAGS_REPORT_RULES_NOT_MATCHING)
        message = CALLBACK_MSG_RULE_NOT_MATCHING;
    }

    if (message != 0 && !RULE_IS_PRIVATE(rule))
    {
      switch (scanner->callback(scanner, message, rule, scanner->user_data))
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

  scanner->callback(
      scanner, CALLBACK_MSG_SCAN_FINISHED, NULL, scanner->user_data);

_exit:

  // If error is ERROR_BLOCK_NOT_READY we don't clean the matches and don't
  // destroy the notebook yet. ERROR_BLOCK_NOT_READY is not a permament error,
  // the caller can still call this function again for a retry.
  if (result != ERROR_BLOCK_NOT_READY)
  {
    _yr_scanner_clean_matches(scanner);

    if (scanner->matches_notebook != NULL)
    {
      yr_notebook_destroy(scanner->matches_notebook);
      scanner->matches_notebook = NULL;
    }
  }

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "} = %d AKA %s // %s()\n",
      result,
      yr_debug_error_as_string(result),
      __FUNCTION__);

  return result;
}

static YR_MEMORY_BLOCK* _yr_get_first_block(YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_MEMORY_BLOCK* result = (YR_MEMORY_BLOCK*) iterator->context;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "- %s() {} = %p // default iterator; single memory block, blocking\n",
      __FUNCTION__,
      result);

  iterator->last_error = ERROR_SUCCESS;

  return result;
}

static YR_MEMORY_BLOCK* _yr_get_next_block(YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_MEMORY_BLOCK* result = NULL;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "- %s() {} = %p // default iterator; single memory block, blocking\n",
      __FUNCTION__,
      result);

  iterator->last_error = ERROR_SUCCESS;

  return result;
}

static uint64_t _yr_get_file_size(YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  uint64_t file_size = ((YR_MEMORY_BLOCK*) iterator->context)->size;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "- %s() {} = %" PRIu64
      "  // default iterator; single memory block, blocking\n",
      __FUNCTION__,
      file_size);

  return file_size;
}

static const uint8_t* _yr_fetch_block_data(YR_MEMORY_BLOCK* block)
{
  return (const uint8_t*) block->context;
}

YR_API int yr_scanner_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size)
{
  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s(buffer=%p buffer_size=%zu) {\n",
      __FUNCTION__,
      buffer,
      buffer_size);

  YR_MEMORY_BLOCK block;
  YR_MEMORY_BLOCK_ITERATOR iterator;

  block.size = buffer_size;
  block.base = 0;
  block.fetch_data = _yr_fetch_block_data;
  block.context = (void*) buffer;

  iterator.context = &block;
  iterator.first = _yr_get_first_block;
  iterator.next = _yr_get_next_block;
  iterator.file_size = _yr_get_file_size;

  int result = yr_scanner_scan_mem_blocks(scanner, &iterator);

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "} = %d AKA %s // %s()\n",
      result,
      yr_debug_error_as_string(result),
      __FUNCTION__);

  return result;
}

YR_API int yr_scanner_scan_file(YR_SCANNER* scanner, const char* filename)
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

YR_API int yr_scanner_scan_fd(YR_SCANNER* scanner, YR_FILE_DESCRIPTOR fd)
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

YR_API int yr_scanner_scan_proc(YR_SCANNER* scanner, int pid)
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

YR_API YR_STRING* yr_scanner_last_error_string(YR_SCANNER* scanner)
{
  return scanner->last_error_string;
}

YR_API YR_RULE* yr_scanner_last_error_rule(YR_SCANNER* scanner)
{
  if (scanner->last_error_string == NULL)
    return NULL;

  return &scanner->rules->rules_table[scanner->last_error_string->rule_idx];
}

static int sort_by_cost_desc(
    const struct YR_RULE_PROFILING_INFO* r1,
    const struct YR_RULE_PROFILING_INFO* r2)
{
  if (r1->cost < r2->cost)
    return 1;

  if (r1->cost > r2->cost)
    return -1;

  return 0;
}

//
// yr_scanner_get_profiling_info
//
// Returns a pointer to an array of YR_RULE_PROFILING_INFO structures with
// information about the cost of each rule. The rules are sorted by cost
// in descending order and the last item in the array has rule == NULL.
// The caller is responsible for freeing the returned array by calling
// yr_free. Calling this function only makes sense if YR_PROFILING_ENABLED
// is defined, if not, the cost for each rule won't be computed, it will be
// set to 0 for all rules.
//
YR_API YR_RULE_PROFILING_INFO* yr_scanner_get_profiling_info(
    YR_SCANNER* scanner)
{
  YR_RULE_PROFILING_INFO* profiling_info = yr_malloc(
      (scanner->rules->num_rules + 1) * sizeof(YR_RULE_PROFILING_INFO));

  if (profiling_info == NULL)
    return NULL;

  for (uint32_t i = 0; i < scanner->rules->num_rules; i++)
  {
    profiling_info[i].rule = &scanner->rules->rules_table[i];
#ifdef YR_PROFILING_ENABLED
    profiling_info[i].cost = scanner->profiling_info[i].exec_time +
                             (scanner->profiling_info[i].atom_matches *
                              scanner->profiling_info[i].match_time) /
                                 YR_MATCH_VERIFICATION_PROFILING_RATE;
#else
    memset(&profiling_info[i], 0, sizeof(YR_RULE_PROFILING_INFO));
#endif
  }

  qsort(
      profiling_info,
      scanner->rules->num_rules,
      sizeof(YR_RULE_PROFILING_INFO),
      (int (*)(const void*, const void*)) sort_by_cost_desc);

  profiling_info[scanner->rules->num_rules].rule = NULL;
  profiling_info[scanner->rules->num_rules].cost = 0;

  return profiling_info;
}

YR_API void yr_scanner_reset_profiling_info(YR_SCANNER* scanner)
{
#ifdef YR_PROFILING_ENABLED
  memset(
      scanner->profiling_info,
      0,
      scanner->rules->num_rules * sizeof(YR_PROFILING_INFO));
#endif
}

YR_API int yr_scanner_print_profiling_info(YR_SCANNER* scanner)
{
  printf("\n===== PROFILING INFORMATION =====\n\n");

  YR_RULE_PROFILING_INFO* info = yr_scanner_get_profiling_info(scanner);

  if (info == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  YR_RULE_PROFILING_INFO* rpi = info;

  while (rpi->rule != NULL)
  {
    printf(
        "%10" PRIu64 " %s:%s: \n",
        rpi->cost,
        rpi->rule->ns->name,
        rpi->rule->identifier);

    rpi++;
  }

  printf("\n=================================\n");

  yr_free(info);

  return ERROR_SUCCESS;
}
