/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#include <fcntl.h>

#if !defined(_WIN32) && !defined(__CYGWIN__)
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <mach/mach_init.h>
#include <mach/task.h>
#else
#include <stdlib.h>
#endif

#include <time.h>
#include <yara/error.h>
#include "threading.h"

int cli_mutex_init(MUTEX* mutex)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  InitializeCriticalSection(mutex);
  return 0;
#else
  return pthread_mutex_init(mutex, NULL);
#endif
}

void cli_mutex_destroy(MUTEX* mutex)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  DeleteCriticalSection(mutex);
#else
  pthread_mutex_destroy(mutex);
#endif
}

void cli_mutex_lock(MUTEX* mutex)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  EnterCriticalSection(mutex);
#else
  pthread_mutex_lock(mutex);
#endif
}

void cli_mutex_unlock(MUTEX* mutex)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  LeaveCriticalSection(mutex);
#else
  pthread_mutex_unlock(mutex);
#endif
}

int cli_semaphore_init(SEMAPHORE* semaphore, int value)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  *semaphore = CreateSemaphore(NULL, value, 65535, NULL);
  if (*semaphore == NULL)
    return GetLastError();
#elif defined(__APPLE__)
  int result = semaphore_create(
      mach_task_self(), semaphore, SYNC_POLICY_FIFO, value);
  if (result != KERN_SUCCESS)
    return result;
#else
  *semaphore = malloc(sizeof(sem_t));
  if (*semaphore == NULL)
    return errno;
  return sem_init(*semaphore, 0, value);
#endif

  return 0;
}

void cli_semaphore_destroy(SEMAPHORE* semaphore)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  CloseHandle(*semaphore);
#elif defined(__APPLE__)
  semaphore_destroy(mach_task_self(), *semaphore);
#else
  sem_close(*semaphore);
  free(*semaphore);
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Wait for the semaphore, but stop waiting when the current time exceeds the
// given deadline. If deadline is in the past, exit immediately.
//
int cli_semaphore_wait(SEMAPHORE* semaphore, time_t deadline)
{
  unsigned int timeout = (unsigned int) (deadline - time(NULL));

  if (timeout <= 0)
    return ERROR_SCAN_TIMEOUT;

#if defined(_WIN32) || defined(__CYGWIN__)
  if (WaitForSingleObject(*semaphore, timeout * 1000) == WAIT_TIMEOUT)
    return ERROR_SCAN_TIMEOUT;
#elif defined(__APPLE__)
  mach_timespec_t ts;
  // semaphore_timedwait expects a timeout relative to the current time, not an
  // absolute timeout (deadline) as sem_timedwait does.
  ts.tv_sec = timeout;
  ts.tv_nsec = 0;
  if (semaphore_timedwait(*semaphore, ts) == KERN_OPERATION_TIMED_OUT)
    return ERROR_SCAN_TIMEOUT;
#else
  struct timespec ts;
  // sem_timedwait expects an absolute timeout (deadline), not a relative
  // timeout as semaphore_timedwait does.
  ts.tv_sec = deadline;
  ts.tv_nsec = 0;
  if (sem_timedwait(*semaphore, &ts) == -1 && errno == ETIMEDOUT)
    return ERROR_SCAN_TIMEOUT;
#endif
  return ERROR_SUCCESS;
}

void cli_semaphore_release(SEMAPHORE* semaphore)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  ReleaseSemaphore(*semaphore, 1, NULL);
#elif defined(__APPLE__)
  semaphore_signal(*semaphore);
#else
  sem_post(*semaphore);
#endif
}

int cli_create_thread(
    THREAD* thread,
    THREAD_START_ROUTINE start_routine,
    void* param)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  *thread = CreateThread(NULL, 0, start_routine, param, 0, NULL);
  if (*thread == NULL)
    return GetLastError();
  else
    return 0;
#else
  return pthread_create(thread, NULL, start_routine, param);
#endif
}

void cli_thread_join(THREAD* thread)
{
#if defined(_WIN32) || defined(__CYGWIN__)
  WaitForSingleObject(*thread, INFINITE);
#else
  pthread_join(*thread, NULL);
#endif
}
