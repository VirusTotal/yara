/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

#ifndef YR_GLOBALS_H
#define YR_GLOBALS_H

#include <yara/integers.h>
#include <yara/threading.h>

// Pre-computed tables for quickly converting a character to lowercase or to
// its alternative case (uppercase if it is a lowercase and vice versa). This
// tables are initialized by yr_initialize.
extern uint8_t yr_lowercase[256];
extern uint8_t yr_altercase[256];

// Thread-local storage (TLS) key used by the regexp and hex string parsers.
// Each thread calling yr_parse_re_string/yr_parse_hex_string stores a pointer
// to a jmp_buf struct used by setjmp/longjmp for recovering when a fatal error
// occurs in the parser.
extern YR_THREAD_STORAGE_KEY yr_yyfatal_trampoline_tls;

// Thread-local storage (TLS) key used by YR_TRYCATCH.
extern YR_THREAD_STORAGE_KEY yr_trycatch_trampoline_tls;

// When YARA is built with YR_DEBUG_VERBOSITY defined as larger than 0 it can
// print debug information to stdout.
#if 0 == YR_DEBUG_VERBOSITY

#define YR_DEBUG_INITIALIZE()
#define YR_DEBUG_FPRINTF(VERBOSITY, FORMAT, ...)

#else

// for getpid()
#include <sys/types.h>
#include <unistd.h>

extern double yr_debug_get_elapsed_seconds(void);

extern char* yr_debug_callback_message_as_string(int message);

extern char* yr_debug_error_as_string(int error);

// Default is 0 for production, which means be silent, else verbose.
extern uint64_t yr_debug_verbosity;

extern YR_TLS int yr_debug_indent;

extern const char yr_debug_spaces[];

extern size_t yr_debug_spaces_len;

#define YR_DEBUG_INITIALIZE()                                   \
  yr_debug_verbosity = getenv("YR_DEBUG_VERBOSITY")             \
                           ? atoi(getenv("YR_DEBUG_VERBOSITY")) \
                           : YR_DEBUG_VERBOSITY

#define YR_DEBUG_FPRINTF(VERBOSITY, STREAM, FORMAT, ...)       \
  if (yr_debug_verbosity >= VERBOSITY)                         \
  {                                                            \
    if (FORMAT[0] == '}')                                      \
    {                                                          \
      yr_debug_indent--;                                       \
    }                                                          \
    assert((2 * yr_debug_indent) >= 0);                        \
    assert((2 * yr_debug_indent) < (yr_debug_spaces_len - 2)); \
    fprintf(                                                   \
        STREAM,                                                \
        "%f %06u %.*s",                                        \
        yr_debug_get_elapsed_seconds(),                        \
        getpid(),                                              \
        (2 * yr_debug_indent),                                 \
        yr_debug_spaces);                                      \
    fprintf(STREAM, FORMAT, __VA_ARGS__);                      \
    if (FORMAT[0] == '+')                                      \
    {                                                          \
      yr_debug_indent++;                                       \
    }                                                          \
  }

#endif

#endif
