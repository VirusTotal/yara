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
#include <sys/wait.h>
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

  int scan_complete_loops[PARALLEL_SCANS];
  char* text[PARALLEL_SCANS];
  size_t len_text[PARALLEL_SCANS];

  YR_SCANNER* scanner_instance[PARALLEL_SCANS];

  int mem_block_not_ready_if_zero[PARALLEL_SCANS];
  int scan_not_complete[PARALLEL_SCANS];

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
    mem_block_not_ready_if_zero[i] =
        yr_test_mem_block_not_ready_if_zero_init_value;

    scan_not_complete[i] = 1;
    scan_complete_loops[i] = 0;
    len_text[i] = strlen(text[i]);
    iterator_ctx[i].buffer_size_of_all_blocks = len_text[i];

    int flags = SCAN_FLAGS_NO_TRYCATCH;
    YR_CALLBACK_FUNC callback = _scan_callback;
    void* user_data = &callback_ctx[i];
    int timeout = 0;

    // Note: yr_rules_scan_mem() incompatible with ERROR_BLOCK_NOT_READY
    // iterator return code,
    //       therefore create & configure scanner, but do not scan:
    assert_true_expr(
        ERROR_SUCCESS == yr_scanner_create(rules, &scanner_instance[i]));

    yr_scanner_set_callback(scanner_instance[i], callback, user_data);
    yr_scanner_set_timeout(scanner_instance[i], timeout);
    yr_scanner_set_flags(scanner_instance[i], flags);
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
          "- loop=%d i=%d strlen(text[i])=%ld callback_ctx[i].matches=%d"
          " scan_not_complete[i]=%d // %s()\n",
          loop,
          i,
          len_text[i],
          callback_ctx[i].matches,
          scan_not_complete[i],
          __FUNCTION__);

      if (scan_not_complete[i])
      {
        total_scans_not_complete++;

        yr_test_mem_block_not_ready_if_zero = mem_block_not_ready_if_zero[i];

        // Note: yr_scanner_scan_mem() incompatible with ERROR_BLOCK_NOT_READY
        // iterator return code, therefore use test
        // _yr_test_single_or_multi_block_scan_mem() instead:
        int scan_result = _yr_test_single_or_multi_block_scan_mem(
            scanner_instance[i],
            (uint8_t*) text[i],
            YR_DYNAMIC_BUFFER_SIZE,
            &iterator[i],
            &iterator_ctx[i],
            loop);

        if (ERROR_BLOCK_NOT_READY == scan_result)
        {
          // Come here due to test iterator returning ERROR_BLOCK_NOT_READY.
          mem_block_not_ready_if_zero[i] = yr_test_mem_block_not_ready_if_zero;
          continue;
        }

        assert_true_expr(ERROR_SUCCESS == scan_result);

        scan_not_complete[i] = 0;
        scan_complete_loops[i] = loop;
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
    // Note: yr_rules_scan_mem() incompatible with ERROR_BLOCK_NOT_READY return
    // code,
    //       therefore its teardown code is here instead:
    yr_scanner_destroy(scanner_instance[i]);
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

  // Scan groups of 3 text strings in "parallel" using the same rule. Algorithm:
  // - Scan block 1 of text string 1, scan block 1 of text string 2, scan block
  // 1 of text string 3.
  // - Scan block 2 of text string 1, scan block 2 of text string 2, scan block
  // 2 of text string 3.
  // - And so on, until rule is fulfilled.
  // - Finally assert on match count, and expected number of loops for each text
  // string.
  //
  // Note: In the real world subsequent blocks for a text string must come in
  // order, but the text strings themselves may be processed in any order, e.g.:
  // - Scan block 1 of text string 2, scan block 1 of text string 1, scan block
  // 1 of text string 3.
  // - Scan block 2 of text string 3, scan block 2 of text string 2, scan block
  // 2 of text string 1.

  yr_test_mem_block_not_ready_if_zero_init_value =
      2;  // get next block, but block block after :-)

  test_parallel_triple_scan(
      rules,
      /* loops: */ 1,
      1,
      1,
      "---- abc ---- xyz",
      "---- abc ---- xyz",
      "---- abc ---- xyz");

  test_parallel_triple_scan(
      rules,
      /* loops: */ 2,
      2,
      2,
      "---- abc ---- xyz" TEXT_1024_BYTES,
      "---- abc ---- xyz" TEXT_1024_BYTES,
      "---- abc ---- xyz" TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      /* loops: */ 2,
      2,
      2,
      TEXT_1024_BYTES "---- abc ---- xyz",
      TEXT_1024_BYTES "---- abc ---- xyz",
      TEXT_1024_BYTES "---- abc ---- xyz");

  test_parallel_triple_scan(
      rules,
      /* loops: */ 3,
      3,
      3,
      TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      /* loops: */ 3,
      4,
      5,
      TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES TEXT_1024_BYTES TEXT_1024_BYTES
      "---- abc ---- xyz" TEXT_1024_BYTES);

  test_parallel_triple_scan(
      rules,
      /* loops: */ 5,
      4,
      3,
      TEXT_1024_BYTES TEXT_1024_BYTES TEXT_1024_BYTES
      "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES,
      TEXT_1024_BYTES "---- abc ---- xyz" TEXT_1024_BYTES);

  yr_rules_destroy(rules);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

// "Actually, a single block will contain the whole file's content in most
// cases, but you
//  can't rely on that while writing your code. For very big files YARA could
//  eventually split the file into two or more blocks, and your module should be
//  prepared to handle that." [1]
//
// For testing two or more blocks with  synchronous access    , see the
// test-rules.c file. For testing two or more blocks with asynchronous access
// [2], this is the right file.
//
// [1]
// https://yara.readthedocs.io/en/stable/writingmodules.html#accessing-the-scanned-data
// [2] https://github.com/VirusTotal/yara/issues/1375

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  chdir_if_env_top_srcdir();

  yr_initialize();

  assert_true_expr(strlen(TEXT_1024_BYTES) == 1024);

  yr_test_mem_block_size = getenv("YR_TEST_MEM_BLOCK_SIZE")
                               ? atoi(getenv("YR_TEST_MEM_BLOCK_SIZE"))
                               : 1024;

  yr_test_mem_block_size_overlap = getenv("YR_TEST_MEM_BLOCK_SIZE_OVERLAP")
                                       ? atoi(getenv(
                                             "YR_TEST_MEM_BLOCK_SIZE_OVERLAP"))
                                       : 256;

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
