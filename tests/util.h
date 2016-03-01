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

#ifndef _UTIL_H
#define _UTIL_H

extern char compile_error[1024];

YR_RULES* compile_rule(
    char* string);


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


#define assert_true_rule(rule, string)                                  \
  do {                                                                  \
    if (!matches_string(rule, string)) {                                \
      fprintf(stderr, "%s:%d: rule does not match (but should)\n",      \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_true_rule_blob(rule, blob)                               \
  do {                                                                  \
    if (!matches_blob(rule, (uint8_t*) (blob), sizeof(blob))) {         \
      fprintf(stderr, "%s:%d: rule does not match (but should)\n",      \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_false_rule(rule, string)                                 \
  do {                                                                  \
    if (matches_string(rule, string)) {                                 \
      fprintf(stderr, "%s:%d: rule matches (but shouldn't)\n",          \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_false_rule_blob(rule, blob)                              \
  do {                                                                  \
    if (matches_blob(rule, (uint8_t*) (blob), sizeof(blob))) {          \
      fprintf(stderr, "%s:%d: rule matches (but shouldn't)\n",          \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_syntax_correct(rule) do {                                \
    if (compile_rule(rule) == NULL) {                                   \
      fprintf(stderr, "%s:%d: rule << %s >> can't be compiled: %s\n",   \
              __FILE__, __LINE__, rule, compile_error);                 \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

#define assert_syntax_error(rule) do {                                  \
    if (compile_rule(rule) != NULL) {                                   \
      fprintf(stderr, "%s:%d: rule can be compiled (but shouldn't)\n",  \
              __FILE__, __LINE__);                                      \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);

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

#define assert_regexp_syntax_error(regexp)                      \
  assert_syntax_error("rule test { strings: $a = /" regexp      \
                      "/ condition: $a }")

#endif /* _UTIL_H */
