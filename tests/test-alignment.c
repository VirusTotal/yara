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

#include <stdio.h>
#include <yara.h>
#include <yara/globals.h>

#undef NDEBUG
#include <assert.h>

#include "util.h"

#define CHECK_SIZE(expr, size)                           \
  do                                                     \
  {                                                      \
    printf("sizeof(" #expr ") = %zd ...", sizeof(expr)); \
    if (sizeof(expr) == size)                            \
    {                                                    \
      puts("ok");                                        \
    }                                                    \
    else                                                 \
    {                                                    \
      printf("expected %d\n", size);                     \
      return 1;                                          \
    }                                                    \
  } while (0);

#define CHECK_OFFSET(expr, offset, subexpr)            \
  do                                                   \
  {                                                    \
    printf(                                            \
        "offsetof(" #expr ", " #subexpr ") = %zd ...", \
        offsetof(expr, subexpr));                      \
    if (offsetof(expr, subexpr) == offset)             \
    {                                                  \
      puts("ok");                                      \
    }                                                  \
    else                                               \
    {                                                  \
      printf("expected %d\n", offset);                 \
      return 1;                                        \
    }                                                  \
  } while (0)

int main(int argc, char **argv)
{
  YR_DEBUG_INITIALIZE();

  CHECK_SIZE(YR_SUMMARY, 12);
  CHECK_OFFSET(YR_SUMMARY, 0, num_rules);
  CHECK_OFFSET(YR_SUMMARY, 4, num_strings);
  CHECK_OFFSET(YR_SUMMARY, 8, num_namespaces);

  CHECK_SIZE(SIZED_STRING, 9);
  CHECK_OFFSET(SIZED_STRING, 4, flags);
  CHECK_OFFSET(SIZED_STRING, 8, c_string);

  // The size of the following structures must be a multiple of 8 because they
  // are stored in arenas as an array. Each individual structure in the array
  // must be 8-byte aligned, so that it's safe to access its members in
  // platforms that have strict alignment requirements like ARM and Sparc.

  CHECK_SIZE(YR_NAMESPACE, 16);
  CHECK_OFFSET(YR_NAMESPACE, 0, name);
  CHECK_OFFSET(YR_NAMESPACE, 8, idx);

  CHECK_SIZE(YR_META, 32);
  CHECK_OFFSET(YR_META, 0, identifier);
  CHECK_OFFSET(YR_META, 8, string);
  CHECK_OFFSET(YR_META, 16, integer);
  CHECK_OFFSET(YR_META, 24, type);
  CHECK_OFFSET(YR_META, 28, flags);

  CHECK_SIZE(YR_STRING, 56);
  CHECK_OFFSET(YR_STRING, 0, flags);
  CHECK_OFFSET(YR_STRING, 4, idx);
  CHECK_OFFSET(YR_STRING, 8, fixed_offset);
  CHECK_OFFSET(YR_STRING, 16, rule_idx);
  CHECK_OFFSET(YR_STRING, 20, length);
  CHECK_OFFSET(YR_STRING, 24, string);
  CHECK_OFFSET(YR_STRING, 32, chained_to);
  CHECK_OFFSET(YR_STRING, 40, chain_gap_min);
  CHECK_OFFSET(YR_STRING, 44, chain_gap_max);
  CHECK_OFFSET(YR_STRING, 48, identifier);

  CHECK_SIZE(YR_RULE, 56);
  CHECK_OFFSET(YR_RULE, 0, flags);
  CHECK_OFFSET(YR_RULE, 4, num_atoms);
  CHECK_OFFSET(YR_RULE, 8, required_strings);
  CHECK_OFFSET(YR_RULE, 16, identifier);
  CHECK_OFFSET(YR_RULE, 24, tags);
  CHECK_OFFSET(YR_RULE, 32, metas);
  CHECK_OFFSET(YR_RULE, 40, strings);
  CHECK_OFFSET(YR_RULE, 48, ns);

  CHECK_SIZE(YR_EXTERNAL_VARIABLE, 24);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8, value.i);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8, value.f);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 8, value.s);
  CHECK_OFFSET(YR_EXTERNAL_VARIABLE, 16, identifier);

  CHECK_SIZE(YR_AC_MATCH, 40);
  CHECK_OFFSET(YR_AC_MATCH, 0, string);
  CHECK_OFFSET(YR_AC_MATCH, 8, forward_code);
  CHECK_OFFSET(YR_AC_MATCH, 16, backward_code);
  CHECK_OFFSET(YR_AC_MATCH, 24, next);
  CHECK_OFFSET(YR_AC_MATCH, 32, backtrack);

  return 0;
}
