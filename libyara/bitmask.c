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

#include <yara/utils.h>
#include <yara/bitmask.h>

//
// yr_bitmask_collide
//
// Returns FALSE if the result from ANDing bitmask A and B is zero, or TRUE
// if otherwise. Example:
//
//    A       :  0 0 0 1 0 0 0 0 1 0
//    B       :  0 0 1 0 0 1 0 1 0 1
//    A and B :  0 0 0 0 0 0 0 0 0 0   yr_bitmask_collide returns FALSE
//
//    A       :  0 0 0 1 0 0 0 0 1 0
//    B       :  0 0 1 1 0 1 0 1 0 1
//    A and B :  0 0 0 1 0 0 0 0 0 0   yr_bitmask_collide returns TRUE.
//
// If one bitmask longer the other, the shorter one is padded with zeroes.
//
// len_a and len_b are the lengths of bitmask A and B, in bits, *not* in bytes.
//

int yr_bitmask_collide(
    YR_BITMASK* a,
    YR_BITMASK* b,
    uint32_t len_a,
    uint32_t len_b)
{
  uint32_t max_len = yr_max(len_a, len_b);
  uint32_t i = 0;

  // The array containing the bitmask must have enough space to accommodate
  // all the bits. As the array size is multiple of sizeof(<array item type>)
  // the array usually has more bits than the bitmask. Those extra bits must be
  // set to zero. Notice that even if the bitmask's length is multiple of
  // sizeof(<array item type>) the array always have an extra item, so it's
  // to iterate up to (max_len / YR_BITMASK_SLOT_BITS) + 1.

  for (i = 0; i < (max_len / YR_BITMASK_SLOT_BITS) + 1; i++)
  {
    if ((a[i] & b[i]) != 0)
      return TRUE;
  }

  return FALSE;
}
