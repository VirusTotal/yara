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


#include <yara/bitmask.h>
#include <yara.h>
#include "util.h"

#define BITMAP_SIZE 512


void assert_clear_all(YR_BITMASK* bitmask)
{
  for (int i = 0; i < BITMAP_SIZE; i++)
  {
    if (yr_bitmask_isset(bitmask, i))
    {
      fprintf(stderr, "bit %d is set and should not\n", i);
      exit(EXIT_FAILURE);
    }
  }
}

void test_set_clear()
{
  YR_BITMASK bitmask[YR_BITMASK_SIZE(BITMAP_SIZE)];

  yr_bitmask_clear_all(bitmask);

  assert_clear_all(bitmask);

  yr_bitmask_set(bitmask, 0);

  if (!yr_bitmask_isset(bitmask, 0))
    exit(EXIT_FAILURE);

  yr_bitmask_clear(bitmask, 0);

  if (yr_bitmask_isset(bitmask, 0))
    exit(EXIT_FAILURE);

  yr_bitmask_set(bitmask, BITMAP_SIZE-1);

  if (!yr_bitmask_isset(bitmask, BITMAP_SIZE-1))
    exit(EXIT_FAILURE);

  yr_bitmask_clear(bitmask, BITMAP_SIZE-1);

  if (yr_bitmask_isset(bitmask, BITMAP_SIZE-1))
    exit(EXIT_FAILURE);

  yr_bitmask_set(bitmask, 31);
  yr_bitmask_set(bitmask, 32);
  yr_bitmask_set(bitmask, 33);
  yr_bitmask_set(bitmask, 63);
  yr_bitmask_set(bitmask, 64);
  yr_bitmask_set(bitmask, 65);

  if (!yr_bitmask_isset(bitmask, 31))
    exit(EXIT_FAILURE);

  if (!yr_bitmask_isset(bitmask, 32))
    exit(EXIT_FAILURE);

  if (!yr_bitmask_isset(bitmask, 33))
    exit(EXIT_FAILURE);

  if (!yr_bitmask_isset(bitmask, 63))
    exit(EXIT_FAILURE);

  if (!yr_bitmask_isset(bitmask, 64))
    exit(EXIT_FAILURE);

  if (!yr_bitmask_isset(bitmask, 65))
    exit(EXIT_FAILURE);

  yr_bitmask_clear(bitmask, 31);
  yr_bitmask_clear(bitmask, 32);
  yr_bitmask_clear(bitmask, 33);
  yr_bitmask_clear(bitmask, 63);
  yr_bitmask_clear(bitmask, 64);
  yr_bitmask_clear(bitmask, 65);

  assert_clear_all(bitmask);
}


void test_collide()
{
  YR_BITMASK a[120];
  YR_BITMASK b[60];

  // Set all bits to 1, including padding, to make sure that
  // yr_bitmask_clear_all is working properly.

  memset(a, 0xFF, sizeof(a));
  memset(b, 0xFF, sizeof(b));

  yr_bitmask_clear_all(a);
  yr_bitmask_clear_all(b);

  if (yr_bitmask_collide(a, b, 120, 60))
    exit(EXIT_FAILURE);

  yr_bitmask_set(a, 0);
  yr_bitmask_set(a, 119);

  if (yr_bitmask_collide(a, b, 120, 60))
    exit(EXIT_FAILURE);

  // Now both bitmasks collide on bit 0.
  yr_bitmask_set(b, 0);

  if (!yr_bitmask_collide(a, b, 120, 60))
    exit(EXIT_FAILURE);

  yr_bitmask_clear(b, 0);

  // Bitmask A still has bit 119 set, but they don't collide because B is
  // shorter than 119 bits.
  if (yr_bitmask_collide(a, b, 120, 60))
    exit(EXIT_FAILURE);

  yr_bitmask_set(a, 59);
  yr_bitmask_set(b, 59);

  if (!yr_bitmask_collide(a, b, 120, 60))
    exit(EXIT_FAILURE);
}


int main(int argc, char** argv)
{
  test_set_clear();
  test_collide();
}
