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

#include <time.h>

#include <yara/stopwatch.h>

#if defined(_WIN32)

void yr_stopwatch_start(
    YR_STOPWATCH* sw)
{
  QueryPerformanceFrequency(&sw->frequency);
  QueryPerformanceCounter(&sw->start);
}


uint64_t yr_stopwatch_elapsed_us(
    YR_STOPWATCH* sw)
{
  LARGE_INTEGER li;

  QueryPerformanceCounter(&li);

  return (li.QuadPart - sw->start.QuadPart) * 1000000L / sw->frequency.QuadPart;
}


#elif defined(__MACH__)

void yr_stopwatch_start(
    YR_STOPWATCH* sw)
{
  mach_timebase_info(&sw->timebase);
  sw->start = mach_absolute_time();
}


uint64_t yr_stopwatch_elapsed_us(
    YR_STOPWATCH* sw)
{
  uint64_t now;

  now = mach_absolute_time();
  return (now - sw->start) * sw->timebase.numer /
         (sw->timebase.denom * 1000ULL);
}


#elif defined(HAVE_CLOCK_GETTIME)

#define timespecsub(tsp, usp, vsp)                      \
do {                                                    \
  (vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;        \
  (vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;     \
  if ((vsp)->tv_nsec < 0) {                             \
    (vsp)->tv_sec--;                                    \
    (vsp)->tv_nsec += 1000000000L;                      \
  }                                                     \
} while (0)


void yr_stopwatch_start(
    YR_STOPWATCH* stopwatch)
{
  clock_gettime(CLOCK_MONOTONIC, &stopwatch->ts_start);
}


uint64_t yr_stopwatch_elapsed_us(
    YR_STOPWATCH* stopwatch)
{
  struct timespec ts_stop;
  struct timespec ts_elapsed;

  clock_gettime(CLOCK_MONOTONIC, &ts_stop);
  timespecsub(&ts_stop, &stopwatch->ts_start, &ts_elapsed);
  return ts_elapsed.tv_sec * 1000000L + ts_elapsed.tv_nsec / 1000;
}


#else

#include <sys/time.h>

#define timevalsub(tvp, uvp, vvp)                       \
do {                                                    \
  (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;        \
  (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;     \
  if ((vvp)->tv_usec < 0) {                             \
    (vvp)->tv_sec--;                                    \
    (vvp)->tv_usec += 1000000L;                         \
  }                                                     \
} while (0)


void yr_stopwatch_start(
    YR_STOPWATCH* stopwatch)
{
  gettimeofday(&stopwatch->tv_start, NULL);
}


uint64_t yr_stopwatch_elapsed_us(
    YR_STOPWATCH* stopwatch)
{
  struct timeval tv_stop;
  struct timeval tv_elapsed;

  gettimeofday(&tv_stop, NULL);
  timevalsub(&tv_stop, &stopwatch->tv_start, &tv_elapsed);
  return tv_elapsed.tv_sec * 1000000L + tv_elapsed.tv_usec;
}




#endif
