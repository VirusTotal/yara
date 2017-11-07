/*
Copyright (c) 2007-2015. The YARA Authors. All Rights Reserved.

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

#ifndef YR_INTEGERS_H
#define YR_INTEGERS_H


#if ( defined( _MSC_VER ) && ( _MSC_VER < 1600 ) ) || ( defined( __BORLANDC__ ) && ( __BORLANDC__ <= 0x0560 ) )

#ifdef __cplusplus
extern "C" {
#endif

// Microsoft Visual Studio C++ before Visual Studio 2010 or earlier versions of
// the Borland C++ Builder do not support the (u)int#_t type definitions but
// have __int# definitions instead

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#ifdef __cplusplus
}
#endif


#ifndef INT8_MIN
#define INT8_MIN         (-127i8 - 1)
#endif

#ifndef INT8_MIN
#define INT16_MIN        (-32767i16 - 1)
#endif

#ifndef INT32_MIN
#define INT32_MIN        (-2147483647i32 - 1)
#endif

#ifndef INT64_MIN
#define INT64_MIN        (-9223372036854775807i64 - 1)
#endif

#ifndef INT8_MAX
#define INT8_MAX         127i8
#endif

#ifndef INT16_MAX
#define INT16_MAX        32767i16
#endif

#ifndef INT32_MAX
#define INT32_MAX        2147483647i32
#endif

#ifndef INT64_MAX
#define INT64_MAX        9223372036854775807i64
#endif

#ifndef UINT8_MAX
#define UINT8_MAX        0xffui8
#endif

#ifndef UINT16_MAX
#define UINT16_MAX       0xffffui16
#endif

#ifndef UINT32_MAX
#define UINT32_MAX       0xffffffffui32
#endif

#ifndef UINT64_MAX
#define UINT64_MAX       0xffffffffffffffffui64
#endif

#else

// Other "compilers" and later versions of Microsoft Visual Studio C++ and
// Borland C/C++ define the types in <stdint.h>

#include <stdint.h>

#endif

#endif
