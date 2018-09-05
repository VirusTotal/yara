/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#ifndef _UTIL_H
#define _UTIL_H

extern char compile_error[1024];
extern int warnings;

int compile_rule(
    char* string,
    YR_RULES** rules);


int count_matches(
    int message,
    void* message_data,
    void* user_data);


int do_nothing(
    int message,
    void* message_data,
    void* user_data);


int matches_blob(
    char* rule,
    uint8_t* blob,
    size_t len);


int matches_string(
    char* rule,
    char* string);


int capture_string(
    char* rule,
    char* string,
    char* expected_string);


int read_file(
    char* filename, char** buf);


#define assert_true_expr(expr)                                          \
  do {                                                                  \
    if (!(expr)) {                                                      \
      fprintf(stderr, "%s:%d: expression is not true\n",                \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_true_rule(rule, string)                                  \
  do {                                                                  \
    if (!matches_string(rule, string)) {                                \
      fprintf(stderr, "%s:%d: rule does not match (but should)\n",      \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_true_rule_blob_size(rule, blob, size)                    \
  do {                                                                  \
    if (!matches_blob(rule, (uint8_t*) (blob), size)) {                 \
      fprintf(stderr, "%s:%d: rule does not match (but should)\n",      \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_true_rule_blob(rule, blob)               \
  assert_true_rule_blob_size(rule, blob, sizeof(blob))

#define assert_true_rule_file(rule, filename)                           \
  do {                                                                  \
    char* buf;                                                          \
    size_t sz;                                                          \
    if ((sz = read_file(filename, &buf)) == -1) {                       \
      fprintf(stderr, "%s:%d: cannot read file '%s'\n",                 \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    if (!matches_blob(rule, (uint8_t*) (buf), sz)) {                    \
      fprintf(stderr, "%s:%d: rule does not match contents of"          \
              "'%s' (but should)\n",                                    \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    free(buf);                                                          \
  } while (0);

#define assert_false_rule(rule, string)                                 \
  do {                                                                  \
    if (matches_string(rule, string)) {                                 \
      fprintf(stderr, "%s:%d: rule matches (but shouldn't)\n",          \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_false_rule_blob_size(rule, blob, size)                   \
  do {                                                                  \
    if (matches_blob(rule, (uint8_t*) (blob), size)) {                  \
      fprintf(stderr, "%s:%d: rule matches (but shouldn't)\n",          \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_false_rule_blob(rule, blob)              \
  assert_false_rule_blob_size(rule, blob, sizeof(blob))

#define assert_false_rule_file(rule, filename)                          \
  do {                                                                  \
    char* buf;                                                          \
    size_t sz;                                                          \
    if ((sz = read_file(filename, &buf)) == -1) {                       \
      fprintf(stderr, "%s:%d: cannot read file '%s'\n",                 \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    if (matches_blob(rule, (uint8_t*) (buf), sz)) {                     \
      fprintf(stderr, "%s:%d: rule matches contents of"                 \
              "'%s' (but shouldn't)\n",                                 \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    free(buf);                                                          \
  } while (0);

#define assert_error(rule, error) do {                                  \
    YR_RULES* rules;                                                    \
    int result = compile_rule(rule, &rules);                            \
    if (result == ERROR_SUCCESS)                                        \
      yr_rules_destroy(rules);                                          \
    if (result != error) {                                              \
      fprintf(stderr, "%s:%d: expecting error %d but returned %d\n",    \
              __FILE__, __LINE__, error, result);                       \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_warnings(rule, w) do {                                   \
    YR_RULES* rules;                                                    \
    int result = compile_rule(rule, &rules);                            \
    if (result == ERROR_SUCCESS) {                                      \
      yr_rules_destroy(rules);                                          \
      if (warnings < w) {                                               \
        fprintf(stderr, "%s:%d: expecting warning\n",                   \
                __FILE__, __LINE__);                                    \
        exit(EXIT_FAILURE);                                             \
      }                                                                 \
    }                                                                   \
    else {                                                              \
      fprintf(stderr, "%s:%d: failed to compile << %s >>: %s\n",        \
              __FILE__, __LINE__, rule, compile_error);                 \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_no_warnings(rule) do {                                   \
    YR_RULES* rules;                                                    \
    int result = compile_rule(rule, &rules);                            \
    if (result == ERROR_SUCCESS) {                                      \
      yr_rules_destroy(rules);                                          \
      if (warnings > 0) {                                               \
        fprintf(stderr, "%s:%d: unexpected warning\n",                  \
                __FILE__, __LINE__);                                    \
        exit(EXIT_FAILURE);                                             \
      }                                                                 \
    }                                                                   \
    else {                                                              \
      fprintf(stderr, "%s:%d: failed to compile << %s >>: %s\n",        \
              __FILE__, __LINE__, rule, compile_error);                 \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_warning(rule) assert_warnings(rule, 1)


#define assert_true_regexp(regexp,string,expected) do {                 \
    if (!capture_string("rule test { strings: $a = /" regexp            \
                        "/ condition: $a }", string, expected)) {       \
      fprintf(stderr, "%s:%d: regexp does not match\n",                 \
              __FILE__, __LINE__);                                      \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_false_regexp(regexp,string)                              \
  assert_false_rule("rule test { strings: $a = /" regexp                \
                    "/ condition: $a }", string)

#define assert_regexp_syntax_error(regexp)                              \
  assert_error("rule test { strings: $a = /" regexp "/ condition: $a }",\
               ERROR_INVALID_REGULAR_EXPRESSION)

#endif /* _UTIL_H */
