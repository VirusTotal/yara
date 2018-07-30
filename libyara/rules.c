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
#include <ctype.h>

#include <yara/error.h>
#include <yara/filemap.h>
#include <yara/mem.h>
#include <yara/proc.h>
#include <yara/rules.h>
#include <yara/utils.h>
#include <yara/globals.h>
#include <yara/scan.h>
#include <yara/scanner.h>


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


#ifdef PROFILING_ENABLED
void yr_rules_print_profiling_info(
    YR_RULES* rules)
{
  YR_RULE* rule;

  printf("\n===== PROFILING INFORMATION =====\n\n");

  yr_rules_foreach(rules, rule)
  {
    printf(
        "%s:%s: %" PRIu64 " (%0.3f%%)\n",
        rule->ns->name,
        rule->identifier,
        rule->time_cost,
        (float) rule->time_cost / rules->time_cost * 100);
  }

  printf("\n=================================\n");
}
#endif


YR_API int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  YR_SCANNER* scanner;
  int result;

  FAIL_ON_ERROR(yr_scanner_create(rules, &scanner));

  yr_scanner_set_callback(scanner, callback, user_data);
  yr_scanner_set_timeout(scanner, timeout);
  yr_scanner_set_flags(scanner, flags);

  result = yr_scanner_scan_mem_blocks(scanner, iterator);

  yr_scanner_destroy(scanner);

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


YR_API int yr_rules_scan_mem(
    YR_RULES* rules,
    const uint8_t* buffer,
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
  block.context = (void*) buffer;

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
  new_rules->ac_match_table = header->ac_match_table;
  new_rules->ac_transition_table = header->ac_transition_table;
  new_rules->ac_tables_size = header->ac_tables_size;

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

  for (i = 0; i < YR_BITARRAY_NCHARS(YR_MAX_THREADS); ++i)
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


static int _uint32_cmp (
    const void * a,
    const void * b)
{
   return (*(uint32_t*) a - *(uint32_t*) b);
}

YR_API int yr_rules_get_stats(
    YR_RULES* rules,
    YR_RULES_STATS *stats)
{
  YR_RULE* rule;
  YR_STRING* string;

  uint32_t* match_list_lengths = (uint32_t*) yr_malloc(
      sizeof(uint32_t) * rules->ac_tables_size);

  float match_list_length_sum = 0;
  int i, c = 0;

  if (match_list_lengths == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  stats->ac_tables_size = rules->ac_tables_size;
  stats->ac_matches = 0;
  stats->rules = 0;
  stats->strings = 0;

  for (i = 0; i < rules->ac_tables_size; i++)
  {
    YR_AC_MATCH* match = rules->ac_match_table[i].match;

    int match_list_length = 0;

    while (match != NULL)
    {
      match_list_length++;
      stats->ac_matches++;
      match = match->next;
    }

    if (i == 0)
      stats->ac_root_match_list_length = match_list_length;

    match_list_length_sum += match_list_length;

    if (match_list_length > 0)
    {
      match_list_lengths[c] = match_list_length;
      c++;
    }
  }

  // sort match_list_lengths in increasing order for computing percentiles.
  qsort(match_list_lengths, c, sizeof(match_list_lengths[0]), _uint32_cmp);

  for (i = 0; i < 100; i++)
  {
    if (i < c)
      stats->top_ac_match_list_lengths[i] = match_list_lengths[c-i-1];
    else
      stats->top_ac_match_list_lengths[i] = 0;
  }

  stats->ac_average_match_list_length = match_list_length_sum / c;
  stats->ac_match_list_length_pctls[0] = match_list_lengths[0];
  stats->ac_match_list_length_pctls[100] = match_list_lengths[c-1];

  for (i = 1; i < 100; i++)
    stats->ac_match_list_length_pctls[i] = match_list_lengths[(c * i) / 100];

  yr_free(match_list_lengths);

  yr_rules_foreach(rules, rule)
  {
    stats->rules++;
    yr_rule_strings_foreach(rule, string)
      stats->strings++;
  }

  return ERROR_SUCCESS;
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

YR_API void yr_rule_disable(
    YR_RULE* rule)
{
  YR_STRING* string;

  rule->g_flags |= RULE_GFLAGS_DISABLED;

  yr_rule_strings_foreach(rule, string)
  {
    string->g_flags |= STRING_GFLAGS_DISABLED;
  }
}


YR_API void yr_rule_enable(
    YR_RULE* rule)
{
  YR_STRING* string;

  rule->g_flags &= ~RULE_GFLAGS_DISABLED;

  yr_rule_strings_foreach(rule, string)
  {
    string->g_flags &= ~STRING_GFLAGS_DISABLED;
  }
}
