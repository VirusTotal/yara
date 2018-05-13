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
// yr_bitmask_find_non_colliding_offset
// 
// Finds the smaller offset within bitmask A where bitmask B can be accommodated 
// without bit collisions. A collision occurs when bots bitmasks have a bit set
// to one at the same offset. Bitmask B must have at least one bit set to one. 
//
// Args:
//    YR_BITMASK* a      - Bitmask A
//    YR_BITMASK* b      - Bitmask B
//    uint64_t len_a     - Length of bitmask A in bits
//    uint64_t len_b     - Length of bitmask B in bits
//    uint64_t* offset   - Address of an uint64_t where to put the offset if
//                         found.
// Returns:
//    TRUE if some non-colliding offset was found, FALSE if otherwise.
//

uint32_t yr_bitmask_find_non_colliding_offset(
    YR_BITMASK* a,
    YR_BITMASK* b,
    uint32_t len_a,
    uint32_t len_b,
    uint32_t* off_a)
{
  uint32_t i, j, k;

  for (i = *off_a / YR_BITMASK_SLOT_BITS; 
       i <= len_a / YR_BITMASK_SLOT_BITS && a[i] == 0xFFFFFFFFFFFFFFFFL; 
       i++);

  *off_a = i;
    
  for (; i <= len_a / YR_BITMASK_SLOT_BITS; i++)
  {
    if (a[i] == 0xFFFFFFFFFFFFFFFFL)
      continue;
  
    for (j = 0; j <= yr_min(len_a, YR_BITMASK_SLOT_BITS - 1); j++)
    {
      int found = TRUE;

      for (k = 0; k <= len_b / YR_BITMASK_SLOT_BITS; k++)
      {
        YR_BITMASK m = b[k] << j;
  
        if (j > 0 && k > 0)
          m |= b[k - 1] >> (YR_BITMASK_SLOT_BITS - j);
  
        if ((i + k <= len_a / YR_BITMASK_SLOT_BITS) && (m & a[i + k]) != 0)
        {
          found = FALSE;
          break ;
        }
      }

      if (found)
        return i * YR_BITMASK_SLOT_BITS + j;
    }
  }

  return len_a;
}
