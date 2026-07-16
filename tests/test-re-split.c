/*
Copyright (c) 2019. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>
#include <string.h>
#include <yara.h>

#include "util.h"

static int re_match_callback(
    const uint8_t* match,
    int match_length,
    int flags,
    void* args)
{
  return 0;
}

// A compiled rule hand-crafted by a malicious actor can carry a regexp whose
// SPLIT instructions reference more distinct split ids than the compiler would
// ever emit (it caps them at RE_MAX_SPLIT_ID). _yr_re_fiber_sync tracks the
// executed split ids in an on-stack array of RE_MAX_SPLIT_ID entries, so such a
// stream must be rejected instead of writing past that array.
static void test_split_id_overflow(void)
{
  int count = RE_MAX_SPLIT_ID + 64;
  uint8_t code[(RE_MAX_SPLIT_ID + 64) * 4 + 1];

  // A run of SPLIT_A instructions, each with a distinct split id and a branch
  // that jumps to the trailing MATCH.
  for (int i = 0; i < count; i++)
  {
    int16_t offset = (int16_t) ((count - i) * 4);
    code[i * 4 + 0] = RE_OPCODE_SPLIT_A;
    code[i * 4 + 1] = (uint8_t) i;
    memcpy(code + i * 4 + 2, &offset, sizeof(offset));
  }
  code[count * 4] = RE_OPCODE_MATCH;

  YR_SCAN_CONTEXT context;
  memset(&context, 0, sizeof(context));

  uint8_t input[1] = {0};
  int matches = 0;

  int result = yr_re_exec(
      &context,
      code,
      input,
      sizeof(input),
      0,
      RE_FLAGS_SCAN,
      re_match_callback,
      NULL,
      &matches);

  assert(result == ERROR_INTERNAL_FATAL_ERROR);

  RE_FIBER* fiber = context.re_fiber_pool.fibers.head;

  while (fiber != NULL)
  {
    RE_FIBER* next = fiber->next;
    yr_free(fiber);
    fiber = next;
  }
}

// A compiled rule hand-crafted by a malicious actor can carry a regexp whose
// REPEAT_START instructions nest deeper than the fiber's repeat stack (which
// holds RE_MAX_STACK entries). _yr_re_fiber_sync pushes one entry per
// REPEAT_START onto that on-fiber stack, so such a stream must be rejected
// instead of writing past the stack.
static void test_repeat_stack_overflow(void)
{
  // Each REPEAT_START is the opcode byte followed by RE_REPEAT_ARGS, which is a
  // packed { uint16 min; uint16 max; int32 offset } (8 bytes).
  int instr_size = 1 + 8;
  int count = RE_MAX_STACK + 64;
  uint8_t code[(RE_MAX_STACK + 64) * (1 + 8) + 1];

  // A run of REPEAT_START instructions, each with a non-zero min so the split
  // branch is skipped and only the stack push is executed.
  for (int i = 0; i < count; i++)
  {
    uint8_t* p = code + i * instr_size;
    uint16_t min = 1;
    uint16_t max = 2;
    int32_t offset = 0;
    p[0] = RE_OPCODE_REPEAT_START_GREEDY;
    memcpy(p + 1, &min, sizeof(min));
    memcpy(p + 3, &max, sizeof(max));
    memcpy(p + 5, &offset, sizeof(offset));
  }
  code[count * instr_size] = RE_OPCODE_MATCH;

  YR_SCAN_CONTEXT context;
  memset(&context, 0, sizeof(context));

  uint8_t input[1] = {0};
  int matches = 0;

  int result = yr_re_exec(
      &context,
      code,
      input,
      sizeof(input),
      0,
      RE_FLAGS_SCAN,
      re_match_callback,
      NULL,
      &matches);

  assert(result == ERROR_INTERNAL_FATAL_ERROR);

  RE_FIBER* fiber = context.re_fiber_pool.fibers.head;

  while (fiber != NULL)
  {
    RE_FIBER* next = fiber->next;
    yr_free(fiber);
    fiber = next;
  }
}

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  RE_AST* re_ast;
  RE_AST* re_ast_remain;

  RE_ERROR re_error;

  int32_t min_gap;
  int32_t max_gap;

  yr_initialize();
  yr_re_parse_hex(
      "{ 01 02 03 04 [0-300] 05 06 07 08 [1-400] 09 0A 0B 0C }",
      &re_ast,
      &re_error);

  assert(re_ast != NULL);

  yr_re_ast_split_at_chaining_point(re_ast, &re_ast_remain, &min_gap, &max_gap);

  assert(re_ast != NULL);
  assert(re_ast_remain != NULL);
  assert(min_gap == 0);
  assert(max_gap == 300);

  yr_re_ast_destroy(re_ast);
  re_ast = re_ast_remain;

  yr_re_ast_split_at_chaining_point(re_ast, &re_ast_remain, &min_gap, &max_gap);

  assert(re_ast != NULL);
  assert(re_ast_remain != NULL);
  assert(min_gap == 1);
  assert(max_gap == 400);

  yr_re_ast_destroy(re_ast);
  re_ast = re_ast_remain;

  yr_re_ast_split_at_chaining_point(re_ast, &re_ast_remain, &min_gap, &max_gap);

  assert(re_ast != NULL);
  assert(re_ast_remain == NULL);

  yr_re_ast_destroy(re_ast);

  test_split_id_overflow();
  test_repeat_stack_overflow();

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
