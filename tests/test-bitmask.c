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


void test_find_non_colliding_offsets()
{
  uint64_t o;

  YR_BITMASK a[18];
  YR_BITMASK b[13];

  yr_bitmask_clear_all(a);
  yr_bitmask_clear_all(b);

  // Set even bits in A and odd bits in B.
  for (int i = 0; i < 13; i++)
  {
    if (i % 2 == 0)
      yr_bitmask_set(a, i);
    else
      yr_bitmask_set(b, i);
  }

  // A and B don't collide at offset 0.
  if (!yr_bitmask_find_non_colliding_offset(a, b, 18, 13, &o) || o != 0)
    exit(EXIT_FAILURE);

  // Set even bits and clear odd bits in B.
  for (int i = 0; i < 13; i++)
  {
    if (i % 2 == 0)
      yr_bitmask_set(b, i);
    else
      yr_bitmask_clear(b, i);
  }

  // A and B don't collide at offset 1.
  if (!yr_bitmask_find_non_colliding_offset(a, b, 18, 13, &o) || o != 1)
    exit(EXIT_FAILURE);

  yr_bitmask_clear_all(a);
  yr_bitmask_clear_all(b);

  // Set the following pattern in A:
  // 1 0 1 0   0 0 0 1   0 0 0 0   0 0 1 1   0 0
  yr_bitmask_set(a, 0);
  yr_bitmask_set(a, 2);
  yr_bitmask_set(a, 7);
  yr_bitmask_set(a, 14);
  yr_bitmask_set(a, 15);

  // Set B to:
  // 0 1 0 0   0 0 0 1   0 1 0 0  1
  yr_bitmask_set(b, 1);
  yr_bitmask_set(b, 7);
  yr_bitmask_set(b, 9);
  yr_bitmask_set(b, 12);

  // A and B don't collide at offset 4.
  if (!yr_bitmask_find_non_colliding_offset(a, b, 18, 13, &o) || o != 4)
    exit(EXIT_FAILURE);

  // Set the A to:
  // 1 0 1 0   0 0 0 1   0 0 0 0   0 0 1 1   1 0
  yr_bitmask_set(a, 16);

  // A can't accommodate B without colliding.
  if (yr_bitmask_find_non_colliding_offset(a, b, 18, 13, NULL))
    exit(EXIT_FAILURE);

  yr_bitmask_clear_all(a);
  yr_bitmask_clear_all(b);

  yr_bitmask_set(a, 0);
  yr_bitmask_set(a, 2);
  yr_bitmask_set(a, 3);

  yr_bitmask_set(b, 1);
  yr_bitmask_set(b, 3);

  // 1011 can't accommodate 0101.
  if (yr_bitmask_find_non_colliding_offset(a, b, 4, 4,  NULL))
    exit(EXIT_FAILURE);

  yr_bitmask_clear(a, 3);

  // 1010 can accommodate 0101 at offset 0.
  if (!yr_bitmask_find_non_colliding_offset(a, b, 4, 4, &o) || o != 0)
    exit(EXIT_FAILURE);

  // 1010 can accommodate 010 match at 0.
  if (!yr_bitmask_find_non_colliding_offset(a, b, 4, 3, &o) || o != 0)
    exit(EXIT_FAILURE);

  // A bitmask can not accommodate itself.
  if (yr_bitmask_find_non_colliding_offset(a, a, 4, 4, NULL))
    exit(EXIT_FAILURE);

  if (yr_bitmask_find_non_colliding_offset(a, a, 64, 64, NULL))
    exit(EXIT_FAILURE);

  if (yr_bitmask_find_non_colliding_offset(a, a, 200, 200, NULL))
    exit(EXIT_FAILURE);

  // A bitmask with an extra 0 at the end can accommodate the original one at
  // offset 1.
  if (!yr_bitmask_find_non_colliding_offset(a, a, 5, 4, &o) || o != 1)
    exit(EXIT_FAILURE);

  if (!yr_bitmask_find_non_colliding_offset(a, a, 65, 64, &o) || o != 1)
    exit(EXIT_FAILURE);

  if (!yr_bitmask_find_non_colliding_offset(a, a, 201, 200, &o) || o != 1)
    exit(EXIT_FAILURE);

}


int main(int argc, char** argv)
{
  test_set_clear();
  test_collide();
  test_find_non_colliding_offsets();
}
