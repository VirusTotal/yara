/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#include <yara.h>
#include <stdio.h>

int err = 0;

#define CHECK_SIZE(expr,size)                          \
  do                                                   \
  {                                                    \
    printf("sizeof("#expr") = %lu ...", sizeof(expr)); \
    if (sizeof(expr) == size)                          \
    {                                                  \
      puts("ok");                                      \
    }                                                  \
    else                                               \
    {                                                  \
      printf("expected %d\n", size);                   \
      err = 1;                                         \
    }                                                  \
  } while (0);

#define CHECK_OFFSET(expr,offset,subexpr)             \
  do                                                  \
  {                                                   \
    printf("offsetof("#expr", "#subexpr") = %lu ...", \
           offsetof(expr, subexpr));                  \
    if (offsetof(expr, subexpr) == offset)            \
    {                                                 \
      puts("ok");                                     \
    }                                                 \
    else                                              \
    {                                                 \
      printf("expected %d\n", offset);                \
    }                                                 \
  } while (0)


int main (int argc, char **argv)
{
  CHECK_SIZE(YR_NAMESPACE, 4 * MAX_THREADS + 8);
  CHECK_OFFSET(YR_NAMESPACE, 4 * MAX_THREADS, name);

  CHECK_SIZE(YR_META, 32);
  CHECK_OFFSET(YR_META, 8,  integer);
  CHECK_OFFSET(YR_META, 16, identifier);
  CHECK_OFFSET(YR_META, 24, string);

  CHECK_SIZE(YR_MATCH, 48);
  CHECK_OFFSET(YR_MATCH, 8,  offset);
  CHECK_OFFSET(YR_MATCH, 16, length);
  CHECK_OFFSET(YR_MATCH, 24, data);
  CHECK_OFFSET(YR_MATCH, 24, chain_length);
  CHECK_OFFSET(YR_MATCH, 32, prev);
  CHECK_OFFSET(YR_MATCH, 40, next);

  CHECK_SIZE(YR_MATCHES, 24);
  CHECK_OFFSET(YR_MATCHES, 8,  head);
  CHECK_OFFSET(YR_MATCHES, 16, tail);

  CHECK_SIZE(YR_STRING, 48 + 2 * 24 /* YR_MATCHES */ * MAX_THREADS
#            ifdef PROFILING_ENABLED
             + 8
#            endif
             );
  CHECK_OFFSET(YR_STRING, 4,  length);
  CHECK_OFFSET(YR_STRING, 8,  identifier);
  CHECK_OFFSET(YR_STRING, 16, string);
  CHECK_OFFSET(YR_STRING, 24, chained_to);
  CHECK_OFFSET(YR_STRING, 32, chain_gap_min);
  CHECK_OFFSET(YR_STRING, 36, chain_gap_max);
  CHECK_OFFSET(YR_STRING, 40, fixed_offset);

  CHECK_SIZE(YR_RULE, 8 + 4 * MAX_THREADS + 40
#            ifdef PROFILING_ENABLED
             + 8
#            endif
             );
  CHECK_OFFSET(YR_RULE, 4,                        t_flags);
  CHECK_OFFSET(YR_RULE, 8 + 4 * MAX_THREADS,      identifier);
  CHECK_OFFSET(YR_RULE, 8 + 4 * MAX_THREADS + 8,  tags);
  CHECK_OFFSET(YR_RULE, 8 + 4 * MAX_THREADS + 16, metas);
  CHECK_OFFSET(YR_RULE, 8 + 4 * MAX_THREADS + 24, strings);
  CHECK_OFFSET(YR_RULE, 8 + 4 * MAX_THREADS + 32, ns);

  CHECK_SIZE(YR_EXTERNAL_VARIABLE, 24);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8,  value.i);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8,  value.f);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8,  value.s);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 16, identifier);

  CHECK_SIZE(YR_AC_MATCH, 40);
  CHECK_OFFSET(YR_AC_MATCH, 8,  string);
  CHECK_OFFSET(YR_AC_MATCH, 16, forward_code);
  CHECK_OFFSET(YR_AC_MATCH, 24, backward_code);
  CHECK_OFFSET(YR_AC_MATCH, 32, next);

  CHECK_SIZE(YR_AC_STATE, 40);
  CHECK_OFFSET(YR_AC_STATE, 8,  failure);
  CHECK_OFFSET(YR_AC_STATE, 16, first_child);
  CHECK_OFFSET(YR_AC_STATE, 24, siblings);
  CHECK_OFFSET(YR_AC_STATE, 32, matches);

  CHECK_SIZE(YR_AC_AUTOMATON, 32);

  CHECK_SIZE(YARA_RULES_FILE_HEADER, 48);
  CHECK_OFFSET(YARA_RULES_FILE_HEADER, 8,  rules_list_head);
  CHECK_OFFSET(YARA_RULES_FILE_HEADER, 16, externals_list_head);
  CHECK_OFFSET(YARA_RULES_FILE_HEADER, 24, code_start);
  CHECK_OFFSET(YARA_RULES_FILE_HEADER, 32, match_table);
  CHECK_OFFSET(YARA_RULES_FILE_HEADER, 40, transition_table);

  return err;
}
