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

#ifndef YR_RULES_H
#define YR_RULES_H

#include <yara/filemap.h>
#include <yara/scanner.h>
#include <yara/types.h>
#include <yara/utils.h>

#define CALLBACK_MSG_RULE_MATCHING     1
#define CALLBACK_MSG_RULE_NOT_MATCHING 2
#define CALLBACK_MSG_SCAN_FINISHED     3
#define CALLBACK_MSG_IMPORT_MODULE     4
#define CALLBACK_MSG_MODULE_IMPORTED   5
#define CALLBACK_MSG_TOO_MANY_MATCHES  6
#define CALLBACK_MSG_CONSOLE_LOG       7

#define CALLBACK_CONTINUE 0
#define CALLBACK_ABORT    1
#define CALLBACK_ERROR    2

#define yr_rule_tags_foreach(rule, tag_name)                         \
  for (tag_name = rule->tags; tag_name != NULL && *tag_name != '\0'; \
       tag_name += strlen(tag_name) + 1)

#define yr_rule_metas_foreach(rule, meta) \
  for (meta = rule->metas; meta != NULL;  \
       meta = META_IS_LAST_IN_RULE(meta) ? NULL : meta + 1)

#define yr_rule_strings_foreach(rule, string)  \
  for (string = rule->strings; string != NULL; \
       string = STRING_IS_LAST_IN_RULE(string) ? NULL : string + 1)

#define yr_string_matches_foreach(context, string, match)         \
  for (match = context->matches[string->idx].head; match != NULL; \
       match = match->next)                                       \
    /* private matches are skipped */                             \
    if (match->is_private)                                        \
    {                                                             \
      continue;                                                   \
    }                                                             \
    else /* user code block goes here */

#define yr_rules_foreach(rules, rule) \
  for (rule = rules->rules_table; !RULE_IS_NULL(rule); rule++)

YR_API int yr_rules_scan_mem_blocks(
    YR_RULES* rules,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

YR_API int yr_rules_scan_mem(
    YR_RULES* rules,
    const uint8_t* buffer,
    size_t buffer_size,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

YR_API int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

YR_API int yr_rules_scan_fd(
    YR_RULES* rules,
    YR_FILE_DESCRIPTOR fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

YR_API int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);

YR_API int yr_rules_save(YR_RULES* rules, const char* filename);

YR_API int yr_rules_save_stream(YR_RULES* rules, YR_STREAM* stream);

YR_API int yr_rules_load(const char* filename, YR_RULES** rules);

YR_API int yr_rules_load_stream(YR_STREAM* stream, YR_RULES** rules);

YR_API int yr_rules_destroy(YR_RULES* rules);

YR_API int yr_rules_define_integer_variable(
    YR_RULES* rules,
    const char* identifier,
    int64_t value);

YR_API int yr_rules_define_boolean_variable(
    YR_RULES* rules,
    const char* identifier,
    int value);

YR_API int yr_rules_define_float_variable(
    YR_RULES* rules,
    const char* identifier,
    double value);

YR_API int yr_rules_define_string_variable(
    YR_RULES* rules,
    const char* identifier,
    const char* value);

YR_API int yr_rules_get_stats(YR_RULES* rules, YR_RULES_STATS* stats);

YR_API void yr_rule_disable(YR_RULE* rule);

YR_API void yr_rule_enable(YR_RULE* rule);

int yr_rules_from_arena(YR_ARENA* arena, YR_RULES** rules);

#endif
