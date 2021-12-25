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

#ifndef THREADING_H
#define THREADING_H

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <pthread.h>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <mach/semaphore.h>
#else
#include <semaphore.h>
#endif
#endif

#if defined(_WIN32) || defined(__CYGWIN__)

typedef HANDLE SEMAPHORE;
typedef CRITICAL_SECTION MUTEX;
typedef HANDLE THREAD;

typedef LPTHREAD_START_ROUTINE THREAD_START_ROUTINE;

#else

typedef pthread_mutex_t MUTEX;
typedef pthread_t THREAD;
typedef void* (*THREAD_START_ROUTINE)(void*);

#if defined(__APPLE__)
typedef semaphore_t SEMAPHORE;
#else
typedef sem_t* SEMAPHORE;
#endif

#endif

int cli_mutex_init(MUTEX* mutex);

void cli_mutex_destroy(MUTEX* mutex);

void cli_mutex_lock(MUTEX* mutex);

void cli_mutex_unlock(MUTEX* mutex);

int cli_semaphore_init(SEMAPHORE* semaphore, int value);

void cli_semaphore_destroy(SEMAPHORE* semaphore);

int cli_semaphore_wait(SEMAPHORE* semaphore, time_t abs_timeout);

void cli_semaphore_release(SEMAPHORE* semaphore);

int cli_create_thread(
    THREAD* thread,
    THREAD_START_ROUTINE start_routine,
    void* param);

void cli_thread_join(THREAD* thread);

#endif
