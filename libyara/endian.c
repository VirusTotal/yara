/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

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

#include <yara/endian.h>

uint16_t _yr_bswap16(uint16_t x)
{
  return (x >> 8 | x << 8);
}

uint32_t _yr_bswap32(uint32_t x)
{
  return ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |
          (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24));
}

uint64_t _yr_bswap64(uint64_t x)
{
  return ((((x) & 0xff00000000000000ull) >> 56)
        | (((x) & 0x00ff000000000000ull) >> 40)
        | (((x) & 0x0000ff0000000000ull) >> 24)
        | (((x) & 0x000000ff00000000ull) >> 8)
        | (((x) & 0x00000000ff000000ull) << 8)
        | (((x) & 0x0000000000ff0000ull) << 24)
        | (((x) & 0x000000000000ff00ull) << 40)
        | (((x) & 0x00000000000000ffull) << 56));
}
