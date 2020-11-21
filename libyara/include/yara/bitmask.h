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

#ifndef YR_BITMASK_H
#define YR_BITMASK_H

#include <yara/integers.h>

//
// Utility macros for working with bitmaps.
//
// Declare a bitmask of n bits:
//   YR_BITMASK my_bitmask[YR_BITMASK_SIZE(n)];
//
// Clear all bits:
//   yr_bitmask_clear_all(my_bitmask)
//
// Set bit n to 1:
//   yr_bitmask_set(my_bitmask, n)
//
// Clear bit n (set to 0):
//   yr_bitmask_clear(my_bitmask, n)
//
// Check if bit n is set:
//   yr_bitmask_is_set(my_bitmask, n)
//

#define YR_BITMASK unsigned long

#define YR_BITMASK_SLOT_BITS (sizeof(YR_BITMASK) * 8)
#define YR_BITMASK_SIZE(n)   (((n) / (YR_BITMASK_SLOT_BITS)) + 1)

#define yr_bitmask_set(bm, i)                                                \
  do                                                                         \
  {                                                                          \
    (bm)[(i) / YR_BITMASK_SLOT_BITS] |= 1UL << ((i) % YR_BITMASK_SLOT_BITS); \
  } while (0)

#define yr_bitmask_clear(bm, i)               \
  do                                          \
  {                                           \
    (bm)[(i) / YR_BITMASK_SLOT_BITS] &= ~(    \
        1UL << ((i) % YR_BITMASK_SLOT_BITS)); \
  } while (0)

#define yr_bitmask_clear_all(bm) memset(bm, 0, sizeof(bm))

#define yr_bitmask_is_set(bm, i) \
  ((bm)[(i) / YR_BITMASK_SLOT_BITS] & (1UL << ((i) % YR_BITMASK_SLOT_BITS)))

#define yr_bitmask_is_not_set(bm, i) (!yr_bitmask_is_set(bm, i))

#define yr_bitmask_print(bm)                         \
  {                                                  \
    int i;                                           \
    for (i = 0; i < sizeof(bm) / sizeof(bm[0]); i++) \
    {                                                \
      printf("%016lX\n", bm[i]);                     \
    }                                                \
  }

uint32_t yr_bitmask_find_non_colliding_offset(
    YR_BITMASK* a,
    YR_BITMASK* b,
    uint32_t len_a,
    uint32_t len_b,
    uint32_t* off_a);

#endif
