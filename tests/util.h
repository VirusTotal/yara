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

#include <yara.h>


#define TEXT_0063_BYTES     "[ 123456789 123456789 123456789 123456789 123456789 123456789 ]"
#define TEXT_0256_BYTES_001 "001" TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES "\n"
#define TEXT_0256_BYTES_002 "002" TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES "\n"
#define TEXT_0256_BYTES_003 "003" TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES "\n"
#define TEXT_0256_BYTES_004 "004" TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES TEXT_0063_BYTES "\n"
#define TEXT_1024_BYTES     TEXT_0256_BYTES_001 TEXT_0256_BYTES_002 TEXT_0256_BYTES_003 TEXT_0256_BYTES_004


extern char compile_error[1024];
extern int warnings;

// Default is 0 for production, which means use 1 block for contiguous memory.
// For testing, 1024 means split contiguous memory into max 1024 byte blocks.
// See https://github.com/VirusTotal/yara/issues/1356
extern uint64_t yr_test_mem_block_size;

// If yr_test_mem_block_size is non-zero, this specifies the bytes of the
// previous memory block to include in the current memory block.
extern uint64_t yr_test_mem_block_size_overlap;

// Decrement and if yr_test_mem_block_not_ready_if_zero is zero, pretend ERROR_BLOCK_NOT_READY.
extern int64_t yr_test_mem_block_not_ready_if_zero;
extern int64_t yr_test_mem_block_not_ready_if_zero_init_value;

// Counts calls to 'get first / next block' function for testing purposes.
extern uint64_t yr_test_count_get_block;


typedef struct YR_TEST_ITERATOR_CTX YR_TEST_ITERATOR_CTX;

struct YR_TEST_ITERATOR_CTX {
  const uint8_t* buffer;
  size_t buffer_size;
  YR_MEMORY_BLOCK current_block;
  void* proc_info;

  // Used by test iterator if buffer size not known in advance.
  size_t buffer_size_of_all_blocks;
};


extern int _yr_test_single_or_multi_block_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    YR_TEST_ITERATOR_CTX* context,
    int previous_calls);

extern void chdir_if_env_top_srcdir(void);

struct COUNTERS
{
  int rules_matching;
  int rules_not_matching;
};

int compile_rule(
    char* string,
    YR_RULES** rules);


typedef struct SCAN_CALLBACK_CTX SCAN_CALLBACK_CTX;

struct SCAN_CALLBACK_CTX {
  int matches;
  void* module_data;
  size_t module_data_size;
};


int _scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);


int count(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);


int do_nothing(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);


int matches_blob_uses_default_iterator;

int matches_blob(
    char* rule,
    uint8_t* blob,
    size_t blob_size,
    uint8_t* module_data,
    size_t module_data_size);


int matches_string(
    char* rule,
    char* string);


int capture_string(
    char* rule,
    char* string,
    char* expected_string);


int read_file(
    char* filename, char** buf);


typedef struct atom atom;

struct atom
{
  uint8_t length;
  uint8_t data[YR_MAX_ATOM_LENGTH];
};


void assert_re_atoms(
    char* re,
    int expected_atom_count,
    atom* expected_atoms);


void assert_hex_atoms(
    char* hex,
    int expected_atom_count,
    atom* expected_atoms);


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
    if (!matches_blob(rule, (uint8_t*) (blob), size, NULL, 0)) {        \
      fprintf(stderr, "%s:%d: rule does not match (but should)\n",      \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_true_rule_blob(rule, blob)                               \
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
    if (!matches_blob(rule, (uint8_t*) (buf), sz, NULL, 0)) {           \
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
    if (matches_blob(rule, (uint8_t*) (blob), size, NULL, 0)) {         \
      fprintf(stderr, "%s:%d: rule matches (but shouldn't)\n",          \
              __FILE__, __LINE__ );                                     \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
  } while (0);


#define assert_false_rule_blob(rule, blob)                              \
  assert_false_rule_blob_size(rule, blob, sizeof(blob))


#define assert_true_rule_module_data_file(rule, filename)               \
  do {                                                                  \
    char* buf;                                                          \
    size_t sz;                                                          \
    if ((sz = read_file(filename, &buf)) == -1) {                       \
      fprintf(stderr, "%s:%d: cannot read file '%s'\n",                 \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    if (!matches_blob(rule, NULL, 0, (uint8_t*) buf, sz)) {             \
      fprintf(stderr, "%s:%d: rule does not matches (but should)\n",    \
              __FILE__, __LINE__);                                      \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    free(buf);                                                          \
  } while (0);


#define assert_false_rule_file(rule, filename)                          \
  do {                                                                  \
    char* buf;                                                          \
    size_t sz;                                                          \
    if ((sz = read_file(filename, &buf)) == -1) {                       \
      fprintf(stderr, "%s:%d: cannot read file '%s'\n",                 \
              __FILE__, __LINE__, filename);                            \
      exit(EXIT_FAILURE);                                               \
    }                                                                   \
    if (matches_blob(rule, (uint8_t*) (buf), sz, NULL, 0)) {            \
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
