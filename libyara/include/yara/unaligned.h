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

#ifndef YR_UNALIGNED_H
#define YR_UNALIGNED_H

#include <yara/integers.h>

#pragma pack(push)
#pragma pack(1)

typedef struct
{
  uint16_t val;
} uint16_una_t;

typedef struct
{
  uint32_t val;
} uint32_una_t;

typedef struct
{
  uint64_t val;
} uint64_una_t;

typedef struct
{
  int16_t val;
} int16_una_t;

typedef struct
{
  int32_t val;
} int32_una_t;

typedef struct
{
  int64_t val;
} int64_una_t;

typedef struct
{
  char *val;
} charp_una_t;

#pragma pack(pop)

static inline uint16_t yr_unaligned_u16(const void *ptr)
{
  const uint16_una_t *tmp = (const uint16_una_t *) ptr;
  return tmp->val;
}

static inline uint32_t yr_unaligned_u32(const void *ptr)
{
  const uint32_una_t *tmp = (const uint32_una_t *) ptr;
  return tmp->val;
}

static inline uint64_t yr_unaligned_u64(const void *ptr)
{
  const uint64_una_t *tmp = (const uint64_una_t *) ptr;
  return tmp->val;
}

static inline uint16_t yr_unaligned_i16(const void *ptr)
{
  const int16_una_t *tmp = (const int16_una_t *) ptr;
  return tmp->val;
}

static inline uint32_t yr_unaligned_i32(const void *ptr)
{
  const int32_una_t *tmp = (const int32_una_t *) ptr;
  return tmp->val;
}

static inline uint64_t yr_unaligned_i64(const void *ptr)
{
  const int64_una_t *tmp = (const int64_una_t *) ptr;
  return tmp->val;
}

static inline char *yr_unaligned_char_ptr(const void *ptr)
{
  const charp_una_t *tmp = (const charp_una_t *) ptr;
  return tmp->val;
}

#endif
