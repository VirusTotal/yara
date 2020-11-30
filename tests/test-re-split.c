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
#include <yara.h>

#include "util.h"


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
  yr_finalize();

  YR_DEBUG_FPRINTF(1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
