/*
Copyright (c) 2020. The YARA Authors. All Rights Reserved.

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

#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#if !defined(_WIN32) && !defined(__CYGWIN__)
#include <sys/wait.h>
#endif
#include <unistd.h>

#include <yara.h>
#include <yara/globals.h>
#include "blob.h"
#include "util.h"

#define PARALLEL_SCANS (3)

static void test_parallel_triple_scan(
    YR_RULES* rules,
    int expected_scan_complete_loops_0,
    int expected_scan_complete_loops_1,
    int expected_scan_complete_loops_2,
    char* text_0,
    char* text_1,
    char* text_2)
{
  YR_DEBUG_FPRINTF(
      1,
      stderr,
      "+ %s(%d, %d, %d) {\n",
      __FUNCTION__,
      expected_scan_complete_loops_0,
      expected_scan_complete_loops_1,
      expected_scan_complete_loops_2);

  YR_SCANNER* scanner[PARALLEL_SCANS];

  char* text[PARALLEL_SCANS];
  int scan_not_complete[PARALLEL_SCANS];
  int scan_complete_loops[PARALLEL_SCANS];

  YR_MEMORY_BLOCK_ITERATOR iterator[PARALLEL_SCANS];
  YR_TEST_ITERATOR_CTX iterator_ctx[PARALLEL_SCANS];

  SCAN_CALLBACK_CTX callback_ctx[PARALLEL_SCANS] = {
      [0].matches = 0,
      [0].module_data = NULL,
      [0].module_data_size = 0,
      [1].matches = 0,
      [1].module_data = NULL,
      [1].module_data_size = 0,
      [2].matches = 0,
      [2].module_data = NULL,
      [2].module_data_size = 0,
  };

  text[0] = text_0;
  text[1] = text_1;
  text[2] = text_2;

  YR_DEBUG_FPRINTF(
      1,
      stderr,
      "- before loop; create scanner instances // %s()\n",
      __FUNCTION__);

  for (int i = 0; i < PARALLEL_SCANS; i++)
  {
    scan_not_complete[i] = 1;
    scan_complete_loops[i] = 0;

    assert_true_expr(ERROR_SUCCESS == yr_scanner_create(rules, &scanner[i]));

    yr_scanner_set_flags(scanner[i], SCAN_FLAGS_NO_TRYCATCH);

    yr_scanner_set_callback(
        scanner[i], _scan_callback, (void*) &callback_ctx[i]);

    init_test_iterator(
        &iterator[i],
        &iterator_ctx[i],
        (const uint8_t*) text[i],
        strlen(text[i]));

    iterator_ctx[i].block_not_ready_frequency = 1;
  }

  int total_scans_not_complete;
  int loop = 0;

  do
  {
    total_scans_not_complete = 0;

    for (int i = 0; i < PARALLEL_SCANS; i++)
    {
      YR_DEBUG_FPRINTF(
          1,
          stderr,
          "- loop=%d i=%d callback_ctx[i].matches=%d"
          " scan_not_complete[i]=%d // %s()\n",
          loop,
          i,
          callback_ctx[i].matches,
          scan_not_complete[i],
          __FUNCTION__);

      if (scan_not_complete[i])
      {
        total_scans_not_complete++;

        int result = yr_scanner_scan_mem_blocks(scanner[i], &iterator[i]);

        if (result != ERROR_BLOCK_NOT_READY)
        {
          assert_true_expr(ERROR_SUCCESS == result);
          scan_not_complete[i] = 0;
          scan_complete_loops[i] = loop;
        }
      }
    }

    loop++;

  } while (total_scans_not_complete);

  YR_DEBUG_FPRINTF(
      1,
      stderr,
      "- after loop; destroy scanner instances // %s()\n",
      __FUNCTION__);

  for (int i = 0; i < PARALLEL_SCANS; i++)
  {
    yr_scanner_destroy(scanner[i]);
  }

  if ((callback_ctx[0].matches != 2) || (callback_ctx[1].matches != 2) ||
      (callback_ctx[2].matches != 2))
  {
    fprintf(
        stderr,
        "%s:%d: parallel triple scan matches %d,%d,%d but expected 2,2,2\n",
        __FILE__,
        __LINE__,
        callback_ctx[0].matches,
        callback_ctx[1].matches,
        callback_ctx[2].matches);
    exit(EXIT_FAILURE);
  }

  if ((scan_complete_loops[0] != expected_scan_complete_loops_0) ||
      (scan_complete_loops[1] != expected_scan_complete_loops_1) ||
      (scan_complete_loops[2] != expected_scan_complete_loops_2))
  {
    fprintf(
        stderr,
        "%s:%d: parallel triple scan looped %d,%d,%d but expected %d,%d,%d\n",
        __FILE__,
        __LINE__,
        scan_complete_loops[0],
        scan_complete_loops[1],
        scan_complete_loops[2],
        expected_scan_complete_loops_0,
        expected_scan_complete_loops_1,
        expected_scan_complete_loops_2);
    exit(EXIT_FAILURE);
  }

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

#define X0_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES "---- abc ---- xyz"

#define X0_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES \
  "---- abc ---- xyz" TEXT_1024_BYTES

#define X1_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES \
  TEXT_1024_BYTES "---- abc ---- xyz"

#define X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES \
  TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES

#define X2_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES \
  TEXT_1024_BYTES TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES

#define X3_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES \
  TEXT_1024_BYTES TEXT_1024_BYTES TEXT_1024_BYTES       \
      "---- abc ---- xyz" TEXT_1024_BYTES

static void test_parallel_strings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  // Compile one rule.

  char* rule = "rule test { strings: $a = \"a\" condition: $a } rule test2 { "
               "condition: filesize > 10 }";

  YR_RULES* rules;

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(
        stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  // Scan groups of 3 strings in "parallel" using the same rule. Algorithm:
  // - Scan 1st block of string 1, string 2, and string 3.
  // - Scan 2nd block of string 1, string 2, and string 3.
  // - And so on, until rule is fulfilled.
  // - Finally assert on match count, & expected # loops for each string.
  //
  // Note: In the real world subsequent blocks for a string must come in order,
  // but the strings themselves may be processed in any order, e.g.:
  // - Scan 1st block of string 2, string 1, and string 3.
  // - Scan 2nd block of string 3, string 2, and string 1.

  int expected_scan_complete_loops_1 = 1;
  int expected_scan_complete_loops_2 = 2;
  int expected_scan_complete_loops_3 = 3;
  int expected_scan_complete_loops_4 = 4;
  int expected_scan_complete_loops_5 = 5;

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_1,
      expected_scan_complete_loops_1,
      expected_scan_complete_loops_1,
      X0_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES,
      X0_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES,
      X0_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_2,
      expected_scan_complete_loops_2,
      expected_scan_complete_loops_2,
      X0_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X0_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X0_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_2,
      expected_scan_complete_loops_2,
      expected_scan_complete_loops_2,
      X1_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES,
      X1_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES,
      X1_TEXT_1024_BYTES__ABC_XYZ__X0_TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_3,
      expected_scan_complete_loops_3,
      expected_scan_complete_loops_3,
      X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_3,
      expected_scan_complete_loops_4,
      expected_scan_complete_loops_5,
      X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X2_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X3_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      expected_scan_complete_loops_5,
      expected_scan_complete_loops_4,
      expected_scan_complete_loops_3,
      X3_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X2_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES,
      X1_TEXT_1024_BYTES__ABC_XYZ__X1_TEXT_1024_BYTES);

  yr_rules_destroy(rules);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

// "Actually, a single block will contain the whole file's content in most
// cases, but you can't rely on that while writing your code. For very big files
// YARA could eventually split the file into two or more blocks, and your module
// should be prepared to handle that." [1]
//
// For testing two or more blocks with synchronous access, see the test-rules.c
// file. For testing two or more blocks with asynchronous access [2], this is
// the right file.
//
// [1]
// https://yara.readthedocs.io/en/stable/writingmodules.html#accessing-the-scanned-data
// [2] https://github.com/VirusTotal/yara/issues/1375

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();

  assert_true_expr(strlen(TEXT_1024_BYTES) == 1024);

  yr_test_mem_block_size = 1024;
  yr_test_mem_block_size_overlap = 256;

  assert(yr_test_mem_block_size_overlap <= yr_test_mem_block_size);

  YR_DEBUG_FPRINTF(
      1,
      stderr,
      "- // run tests: "
      "split data into blocks of max %" PRId64 " bytes "
      "(0 means single / unlimited block size; default) "
      "with %" PRId64 " bytes overlapping the previous block\n",
      yr_test_mem_block_size,
      yr_test_mem_block_size_overlap);

  yr_test_count_get_block = 0;

  test_parallel_strings();

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
