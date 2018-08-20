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

#include <assert.h>

#include <yara/utils.h>
#include <yara/bitmask.h>

//
// yr_bitmask_find_non_colliding_offset
//
// Finds the smaller offset within bitmask A where bitmask B can be accommodated
// without bit collisions. A collision occurs when bots bitmasks have a bit set
// to 1 at the same offset. This function assumes that the first bit in B is 1
// and do optimizations that rely on that.
//
// The function also receives a pointer to an uint32_t where the function stores
// a value that is used for speeding-up subsequent searches over the same
// bitmask A. When called for the first time with some bitmask A, the pointer
// must point to a zero-initialized uint32_t. In the next call the function uses
// the previously stored value for skiping over a portion of the A bitmask and
// updates the value.
//
// Args:
//    YR_BITMASK* a      - Bitmask A
//    YR_BITMASK* b      - Bitmask B
//    uint32_t len_a     - Length of bitmask A in bits
//    uint32_t len_b     - Length of bitmask B in bits
//    uint32_t* off_a    - Address of an uint32_t indicating the offset within
//                         bitmask A where to start searching. In the first call
//                         to it must point to a 0 value. This function updates
//                         the value to use it in subsequent calls.
// Returns:
//    The smaller offset within bitmask A where bitmask B can be put.
//

uint32_t yr_bitmask_find_non_colliding_offset(
    YR_BITMASK* a,
    YR_BITMASK* b,
    uint32_t len_a,
    uint32_t len_b,
    uint32_t* off_a)
{
  uint32_t i, j, k;

  // Ensure that the first bit of bitmask B is set, as this function does some
  // optimizations that rely on that.
  assert(yr_bitmask_isset(b, 0));

  // Skip all slots that are filled with 1s. It's safe to do that because the
  // first bit of B is 1, so we won't be able to accommodate B at any offset
  // within such slots.
  for (i = *off_a / YR_BITMASK_SLOT_BITS;
       i <= len_a / YR_BITMASK_SLOT_BITS && a[i] == -1L;
       i++);

  *off_a = i;

  for (; i <= len_a / YR_BITMASK_SLOT_BITS; i++)
  {
    // The slot is filled with 1s, we can safely skip it.
    if (a[i] == -1L)
      continue;

    for (j = 0; j <= yr_min(len_a, YR_BITMASK_SLOT_BITS - 1); j++)
    {
      bool found = true;

      for (k = 0; k <= len_b / YR_BITMASK_SLOT_BITS; k++)
      {
        YR_BITMASK m = b[k] << j;

        if (j > 0 && k > 0)
          m |= b[k - 1] >> (YR_BITMASK_SLOT_BITS - j);

        if ((i + k <= len_a / YR_BITMASK_SLOT_BITS) && (m & a[i + k]) != 0)
        {
          found = false;
          break ;
        }
      }

      if (found)
        return i * YR_BITMASK_SLOT_BITS + j;
    }
  }

  return len_a;
}
