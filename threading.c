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

#if defined(__FreeBSD__)
#include <stdlib.h>
#endif

#include "threading.h"


int mutex_init(
    MUTEX* mutex)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
    InitializeCriticalSection(mutex);
    return 0;
  #else
  return pthread_mutex_init(mutex, NULL);
  #endif
}

void mutex_destroy(
    MUTEX* mutex)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  DeleteCriticalSection(mutex);
  #else
  pthread_mutex_destroy(mutex);
  #endif
}


void mutex_lock(
    MUTEX* mutex)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  EnterCriticalSection(mutex);
  #else
  pthread_mutex_lock(mutex);
  #endif
}


void mutex_unlock(
    MUTEX* mutex)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  LeaveCriticalSection(mutex);
  #else
  pthread_mutex_unlock(mutex);
  #endif
}


int semaphore_init(
    SEMAPHORE* semaphore,
    int value)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  *semaphore = CreateSemaphore(NULL, value, 65535, NULL);
  if (*semaphore == NULL)
    return GetLastError();
  #elif defined(__FreeBSD__)
  *semaphore = malloc(sizeof(sem_t));
  if (*semaphore == NULL)
    return errno;
  return sem_init(*semaphore, 0, value);
  #else
  // Mac OS X doesn't support unnamed semaphores via sem_init, that's why
  // we use sem_open instead sem_init and immediately unlink the semaphore
  // from the name. More info at:
  //
  // http://stackoverflow.com/questions/1413785/sem-init-on-os-x
  //
  // Also create name for semaphore from PID because running multiple instances
  // of YARA at the same time can cause that sem_open() was called in two processes
  // simultaneously while neither of them had chance to call sem_unlink() yet.
  char name[20];
  snprintf(name, sizeof(name), "/yara.sem.%i", (int)getpid());
  *semaphore = sem_open(name, O_CREAT, S_IRUSR, value);

  if (*semaphore == SEM_FAILED)
    return errno;

  if (sem_unlink(name) != 0)
    return errno;
  #endif

  return 0;
}


void semaphore_destroy(
    SEMAPHORE* semaphore)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  CloseHandle(*semaphore);
  #elif defined(__FreeBSD__)
  sem_close(*semaphore);
  free(*semaphore);
  #else
  sem_close(*semaphore);
  #endif
}


void semaphore_wait(
    SEMAPHORE* semaphore)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  WaitForSingleObject(*semaphore, INFINITE);
  #else
  sem_wait(*semaphore);
  #endif
}


void semaphore_release(
    SEMAPHORE* semaphore)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  ReleaseSemaphore(*semaphore, 1, NULL);
  #else
  sem_post(*semaphore);
  #endif
}


int create_thread(
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


void thread_join(
    THREAD* thread)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  WaitForSingleObject(*thread, INFINITE);
  #else
  pthread_join(*thread, NULL);
  #endif
}
