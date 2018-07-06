/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

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

#include <yara.h>
#include "util.h"


#define PREV2QUALITY(p) (YR_MAX_ATOM_QUALITY - p)

void test_prevalence_quality()
{
  YR_ATOM_PREVALENCE_TABLE_ENTRY l1[] = {
    {{0x00, 0x00, 0x00, 0x00}, 1},
    {{0x00, 0x00, 0x00, 0x01}, 2},
    {{0x00, 0x00, 0x00, 0x02}, 3},
  };

  YR_ATOM_PREVALENCE_TABLE_ENTRY l2[] = {
    {{0x00, 0x00, 0x00, 0x00}, 1},
    {{0x00, 0x00, 0x00, 0x01}, 2},
    {{0x00, 0x00, 0x00, 0x02}, 3},
    {{0x00, 0x00, 0x00, 0x03}, 4},
  };

  uint8_t a0[] = {0x00, 0x00, 0x00, 0x00};
  uint8_t a1[] = {0x00, 0x00, 0x00, 0x01};
  uint8_t a2[] = {0x00, 0x00, 0x00, 0x02};
  uint8_t a3[] = {0x00, 0x00, 0x00, 0x03};

  YR_ATOMS_CONFIG c;

  c.get_atom_quality = yr_atoms_prevalence_quality;
  c.prevalence_table = l1;
  c.prevalence_table_entries = 3;

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a0, sizeof(a0)) == PREV2QUALITY(1));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a1, sizeof(a1)) == PREV2QUALITY(2));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a2, sizeof(a2)) == PREV2QUALITY(3));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a3, sizeof(3)) == YR_MAX_ATOM_QUALITY);

  c.prevalence_table = l2;
  c.prevalence_table_entries = 4;

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a0, sizeof(a0)) == PREV2QUALITY(1));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a1, sizeof(a1)) == PREV2QUALITY(2));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a2, sizeof(a2)) == PREV2QUALITY(3));

  assert_true_expr(
      yr_atoms_prevalence_quality(&c, a3, sizeof(a3)) == PREV2QUALITY(4));
}


int main(int argc, char** argv)
{
  test_prevalence_quality();
}
