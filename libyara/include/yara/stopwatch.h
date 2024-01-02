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

#ifndef YR_STOPWATCH_H
#define YR_STOPWATCH_H

#include <time.h>
#include <yara/integers.h>

#if defined(_WIN32)

#include <windows.h>

typedef struct _YR_STOPWATCH
{
  LARGE_INTEGER frequency;
  LARGE_INTEGER start;

} YR_STOPWATCH;

#elif defined(__APPLE__) && defined(__MACH__)

#include <mach/mach_time.h>

typedef struct _YR_STOPWATCH
{
  mach_timebase_info_data_t timebase;
  uint64_t start;

} YR_STOPWATCH;

#else

#include <sys/time.h>

typedef struct _YR_STOPWATCH
{
  union
  {
    struct timeval tv_start;
    struct timespec ts_start;
  };

} YR_STOPWATCH;

#endif

// yr_stopwatch_start starts measuring time.
void yr_stopwatch_start(YR_STOPWATCH* stopwatch);

// yr_stopwatch_elapsed_ns returns the number of nanoseconds elapsed
// since the last call to yr_stopwatch_start.
uint64_t yr_stopwatch_elapsed_ns(YR_STOPWATCH* stopwatch);

#endif
