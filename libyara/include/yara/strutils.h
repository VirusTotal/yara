/*
Copyright (c) 2007-2014. The YARA Authors. All Rights Reserved.

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

#ifndef YR_STRUTILS_H
#define YR_STRUTILS_H

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <yara/integers.h>

#if defined(_WIN32)

#if !defined(PRIu64)
#define PRIu64 "I64u"
#endif

#if !defined(PRIu32)
#define PRIu32 "I32u"
#endif

#if !defined(PRIx64)
#define PRIx64 "I64x"
#endif

#if !defined(PRId64)
#define PRId64 "I64d"
#endif

#if !defined(PRIi32)
#define PRIi32 "I32i"
#endif

#if !defined(PRIi64)
#define PRIi64 "I64i"
#endif

#if !defined(PRIo64)
#define PRIo64 "I64o"
#endif

#else
#include <inttypes.h>
#endif

// Cygwin already has these functions.
#if defined(_WIN32) && !defined(__CYGWIN__)
#if defined(_MSC_VER) && _MSC_VER < 1900

#if !defined(snprintf)
#define snprintf _snprintf
#endif

#endif
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#endif

uint64_t xtoi(const char* hexstr);

#if !HAVE_STRLCPY && !defined(strlcpy)
size_t strlcpy(char* dst, const char* src, size_t size);
#endif

#if !HAVE_STRLCAT && !defined(strlcat)
size_t strlcat(char* dst, const char* src, size_t size);
#endif

#if !HAVE_MEMMEM && !defined(memmem)
void* memmem(
    const void* haystack,
    size_t haystack_size,
    const void* needle,
    size_t needle_size);
#endif

int strnlen_w(const char* w_str);

int strcmp_w(const char* w_str, const char* str);

size_t strlcpy_w(char* dst, const char* w_src, size_t n);

#endif

int yr_isalnum(const uint8_t* s);

void yr_vasprintf(char** strp, const char* fmt, va_list ap);

void yr_asprintf(char** strp, const char* fmt, ...);
