/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/exefiles.h>
#include <yara/filemap.h>
#include <yara/hash.h>
#include <yara/mem.h>
#include <yara/proc.h>
#include <yara/re.h>
#include <yara/utils.h>
#include <yara/object.h>
#include <yara/globals.h>
#include <yara/libyara.h>
#include <yara/scan.h>

#include "exception.h"


YR_API int yr_rules_define_integer_variable(
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
      if (external->type != EXTERNAL_VARIABLE_TYPE_INTEGER)
        return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

      external->value.i = value;
      return ERROR_SUCCESS;
    }

    external++;
  }

  return ERROR_INVALID_ARGUMENT;
}


YR_API int yr_rules_define_boolean_variable(
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
      if (external->type != EXTERNAL_VARIABLE_TYPE_BOOLEAN)
        return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

      external->value.i = value;
      return ERROR_SUCCESS;
    }

    external++;
  }

  return ERROR_INVALID_ARGUMENT;
}


YR_API int yr_rules_define_float_variable(
    YR_RULES* rules,
    const char* identifier,
    double value)
{
  YR_EXTERNAL_VARIABLE* external;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (strcmp(external->identifier, identifier) == 0)
    {
      if (external->type != EXTERNAL_VARIABLE_TYPE_FLOAT)
        return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

      external->value.f = value;
      return ERROR_SUCCESS;
    }

    external++;
  }

  return ERROR_INVALID_ARGUMENT;
}


YR_API int yr_rules_define_string_variable(
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
      if (external->type != EXTERNAL_VARIABLE_TYPE_STRING &&
          external->type != EXTERNAL_VARIABLE_TYPE_MALLOC_STRING)
        return ERROR_INVALID_EXTERNAL_VARIABLE_TYPE;

      if (external->type == EXTERNAL_VARIABLE_TYPE_MALLOC_STRING &&
          external->value.s != NULL)
      {
        yr_free(external->value.s);
      }

      external->type = EXTERNAL_VARIABLE_TYPE_MALLOC_STRING;
      external->value.s = yr_strdup(value);

      if (external->value.s == NULL)
        return ERROR_INSUFFICIENT_MEMORY;
      else
        return ERROR_SUCCESS;
    }

    external++;
  }

  return ERROR_INVALID_ARGUMENT;
}


void _yr_rules_clean_matches(
    YR_RULES* rules,
    YR_SCAN_CONTEXT* context)
{
  YR_RULE* rule;
  YR_STRING** string;

  int tidx = context->tidx;

  yr_rules_foreach(rules, rule)
  {
    rule->t_flags[tidx] &= ~RULE_TFLAGS_MATCH;
    rule->ns->t_flags[tidx] &= ~NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL;
  }

  if (context->matching_strings_arena != NULL)
  {
    string = (YR_STRING**) yr_arena_base_address(
        context->matching_strings_arena);

    while (string != NULL)
    {
      (*string)->matches[tidx].count = 0;
      (*string)->matches[tidx].head = NULL;
      (*string)->matches[tidx].tail = NULL;
      (*string)->unconfirmed_matches[tidx].count = 0;
      (*string)->unconfirmed_matches[tidx].head = NULL;
      (*string)->unconfirmed_matches[tidx].tail = NULL;

      string = (YR_STRING**) yr_arena_next_address(
          context->matching_strings_arena,
          string,
          sizeof(YR_STRING*));
    }
  }
}


#ifdef PROFILING_ENABLED
void yr_rules_print_profiling_info(
    YR_RULES* rules)
{
  YR_RULE* rule;
  YR_STRING* string;

  clock_t clock_ticks;

  printf("===== PROFILING INFORMATION =====\n");

  yr_rules_foreach(rules, rule)
  {
    clock_ticks = rule->clock_ticks;

    yr_rule_strings_foreach(rule, string)
    {
      clock_ticks += string->clock_ticks;
    }

    printf(
        "%s:%s: %li\n",
        rule->ns->name,
        rule->identifier,
        clock_ticks);
  }

  printf("================================\n");
}
#endif


int _yr_rules_scan_mem_block(
    YR_RULES* rules,
    uint8_t* block_data,
    YR_MEMORY_BLOCK* block,
    YR_SCAN_CONTEXT* context,
    int timeout,
    time_t start_time)
{
  YR_AC_TRANSITION_TABLE transition_table = rules->transition_table;
  YR_AC_MATCH_TABLE match_table = rules->match_table;

  YR_AC_MATCH* match;
  YR_AC_TRANSITION transition;

  size_t i = 0;
  uint32_t state = YR_AC_ROOT_STATE;
  uint16_t index;

  while (i < block->size)
  {
    match = match_table[state].match;

    while (match != NULL)
    {
      if (timeout > 0 && i % 4096 == 0)
      {
        if (difftime(time(NULL), start_time) > timeout)
          return ERROR_SCAN_TIMEOUT;
      }

      if (match->backtrack <= i)
      {
        FAIL_ON_ERROR(yr_scan_verify_match(
            context,
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
        state = transition_table[state] >> 32;
        transition = transition_table[state + index];
      }
      else
      {
        transition = 0;
        break;
      }
    }

    state = transition >> 32;

  }

  match = match_table[state].match;

  while (match != NULL)
  {
    if (match->backtrack <= i)
    {
      FAIL_ON_ERROR(yr_scan_verify_match(
          context,
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


YR_API int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_EXTERNAL_VARIABLE* external;
  YR_RULE* rule;
  YR_SCAN_CONTEXT context;
  YR_MEMORY_BLOCK* block;

  time_t start_time;

  int tidx = 0;
  int result = ERROR_SUCCESS;

  block = iterator->first(iterator);

  if (block == NULL)
    return ERROR_SUCCESS;

  yr_mutex_lock(&rules->mutex);

  while (tidx < MAX_THREADS && YR_BITARRAY_TEST(rules->tidx_mask, tidx))
  {
    tidx++;
  }

  if (tidx < MAX_THREADS)
    YR_BITARRAY_SET(rules->tidx_mask, tidx);
  else
    result = ERROR_TOO_MANY_SCAN_THREADS;

  yr_mutex_unlock(&rules->mutex);

  if (result != ERROR_SUCCESS)
    return result;

  context.tidx = tidx;
  context.flags = flags;
  context.callback = callback;
  context.user_data = user_data;
  context.file_size = block->size;
  context.iterator = iterator;
  context.entry_point = UNDEFINED;
  context.objects_table = NULL;
  context.matches_arena = NULL;
  context.matching_strings_arena = NULL;

  yr_set_tidx(tidx);

  result = yr_arena_create(1024, 0, &context.matches_arena);

  if (result != ERROR_SUCCESS)
    goto _exit;

  result = yr_arena_create(8, 0, &context.matching_strings_arena);

  if (result != ERROR_SUCCESS)
    goto _exit;

  result = yr_hash_table_create(64, &context.objects_table);

  if (result != ERROR_SUCCESS)
    goto _exit;

  external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    YR_OBJECT* object;

    result = yr_object_from_external_variable(
        external,
        &object);

    if (result == ERROR_SUCCESS)
      result = yr_hash_table_add(
          context.objects_table,
          external->identifier,
          NULL,
          (void*) object);

    if (result != ERROR_SUCCESS)
      goto _exit;

    external++;
  }

  start_time = time(NULL);

  while (block != NULL)
  {
    uint8_t* data = block->fetch_data(block);

    // fetch may fail
    if (data == NULL)
    {
      block = iterator->next(iterator);
      continue;
    }

    if (context.entry_point == UNDEFINED)
    {
      YR_TRYCATCH(
        !(flags & SCAN_FLAGS_NO_TRYCATCH),
        {
          if (flags & SCAN_FLAGS_PROCESS_MEMORY)
            context.entry_point = yr_get_entry_point_address(
                data,
                block->size,
                block->base);
          else
            context.entry_point = yr_get_entry_point_offset(
                data,
                block->size);
        },{});
    }

    YR_TRYCATCH(
      !(flags & SCAN_FLAGS_NO_TRYCATCH),
      {
        result = _yr_rules_scan_mem_block(
            rules,
            data,
            block,
            &context,
            timeout,
            start_time);
      },{
        result = ERROR_COULD_NOT_MAP_FILE;
      });

    if (result != ERROR_SUCCESS)
      goto _exit;

    block = iterator->next(iterator);
  }

  YR_TRYCATCH(
    !(flags & SCAN_FLAGS_NO_TRYCATCH),
    {
      result = yr_execute_code(
          rules,
          &context,
          timeout,
          start_time);
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
  }

  callback(CALLBACK_MSG_SCAN_FINISHED, NULL, user_data);

_exit:

  _yr_rules_clean_matches(rules, &context);

  if (context.matches_arena != NULL)
    yr_arena_destroy(context.matches_arena);

  if (context.matching_strings_arena != NULL)
    yr_arena_destroy(context.matching_strings_arena);

  if (context.objects_table != NULL)
    yr_hash_table_destroy(
        context.objects_table,
        (YR_HASH_TABLE_FREE_VALUE_FUNC) yr_object_destroy);

  yr_mutex_lock(&rules->mutex);
  YR_BITARRAY_UNSET(rules->tidx_mask, tidx);
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


static uint8_t* _yr_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  return (uint8_t*) block->context;
}


YR_API int yr_rules_scan_mem(
    YR_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_MEMORY_BLOCK block;
  YR_MEMORY_BLOCK_ITERATOR iterator;

  block.size = buffer_size;
  block.base = 0;
  block.fetch_data = _yr_fetch_block_data;
  block.context = buffer;

  iterator.context = &block;
  iterator.first = _yr_get_first_block;
  iterator.next = _yr_get_next_block;

  return yr_rules_scan_mem_blocks(
      rules,
      &iterator,
      flags,
      callback,
      user_data,
      timeout);
}


YR_API int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_MAPPED_FILE mfile;

  int result = yr_filemap_map(filename, &mfile);

  if (result == ERROR_SUCCESS)
  {
    result = yr_rules_scan_mem(
        rules,
        mfile.data,
        mfile.size,
        flags,
        callback,
        user_data,
        timeout);

    yr_filemap_unmap(&mfile);
  }

  return result;
}


YR_API int yr_rules_scan_fd(
    YR_RULES* rules,
    YR_FILE_DESCRIPTOR fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_MAPPED_FILE mfile;

  int result = yr_filemap_map_fd(fd, 0, 0, &mfile);

  if (result == ERROR_SUCCESS)
  {
    result = yr_rules_scan_mem(
        rules,
        mfile.data,
        mfile.size,
        flags,
        callback,
        user_data,
        timeout);

    yr_filemap_unmap_fd(&mfile);
  }

  return result;
}


YR_API int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_MEMORY_BLOCK_ITERATOR iterator;

  int result = yr_process_open_iterator(
      pid,
      &iterator);

  if (result == ERROR_SUCCESS)
  {
    result = yr_rules_scan_mem_blocks(
        rules,
        &iterator,
        flags | SCAN_FLAGS_PROCESS_MEMORY,
        callback,
        user_data,
        timeout);

    yr_process_close_iterator(&iterator);
  }

  return result;
}


YR_API int yr_rules_load_stream(
    YR_STREAM* stream,
    YR_RULES** rules)
{
  YARA_RULES_FILE_HEADER* header;
  YR_RULES* new_rules = (YR_RULES*) yr_malloc(sizeof(YR_RULES));

  if (new_rules == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_arena_load_stream(stream, &new_rules->arena),
      // cleanup
      yr_free(new_rules));

  header = (YARA_RULES_FILE_HEADER*)
      yr_arena_base_address(new_rules->arena);

  new_rules->code_start = header->code_start;
  new_rules->externals_list_head = header->externals_list_head;
  new_rules->rules_list_head = header->rules_list_head;
  new_rules->match_table = header->match_table;
  new_rules->transition_table = header->transition_table;
  memset(new_rules->tidx_mask, 0, sizeof(new_rules->tidx_mask));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_mutex_create(&new_rules->mutex),
      // cleanup
      yr_free(new_rules));

  *rules = new_rules;

  return ERROR_SUCCESS;
}


YR_API int yr_rules_load(
    const char* filename,
    YR_RULES** rules)
{
  int result;

  YR_STREAM stream;
  FILE* fh = fopen(filename, "rb");

  if (fh == NULL)
    return ERROR_COULD_NOT_OPEN_FILE;

  stream.user_data = fh;
  stream.read = (YR_STREAM_READ_FUNC) fread;

  result = yr_rules_load_stream(&stream, rules);

  fclose(fh);
  return result;
}


YR_API int yr_rules_save_stream(
    YR_RULES* rules,
    YR_STREAM* stream)
{
  int i;

  for (i = 0; i < YR_BITARRAY_NCHARS(MAX_THREADS); ++i)
    assert(rules->tidx_mask[i] == 0);

  return yr_arena_save_stream(rules->arena, stream);
}


YR_API int yr_rules_save(
    YR_RULES* rules,
    const char* filename)
{
  int result;

  YR_STREAM stream;
  FILE* fh = fopen(filename, "wb");

  if (fh == NULL)
    return ERROR_COULD_NOT_OPEN_FILE;

  stream.user_data = fh;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

  result = yr_rules_save_stream(rules, &stream);

  fclose(fh);
  return result;
}


YR_API int yr_rules_destroy(
    YR_RULES* rules)
{
  YR_EXTERNAL_VARIABLE* external = rules->externals_list_head;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    if (external->type == EXTERNAL_VARIABLE_TYPE_MALLOC_STRING)
      yr_free(external->value.s);

    external++;
  }

  yr_mutex_destroy(&rules->mutex);
  yr_arena_destroy(rules->arena);
  yr_free(rules);

  return ERROR_SUCCESS;
}
