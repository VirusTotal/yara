/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#ifndef _THREADING_H
#define _THREADING_H

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <semaphore.h>
#endif

#ifdef WIN32

typedef HANDLE SEMAPHORE;
typedef HANDLE MUTEX;
typedef HANDLE THREAD;

typedef THREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

#else

typedef sem_t* SEMAPHORE;
typedef pthread_mutex_t MUTEX;
typedef pthread_t THREAD;
typedef void *(*THREAD_START_ROUTINE) (void *);

#endif

int mutex_init(
    MUTEX* mutex);

void mutex_lock(
    MUTEX* mutex);

void mutex_unlock(
    MUTEX* mutex);

void semaphore_init(
    SEMAPHORE* semaphore, 
    int value);

void semaphore_wait(
    SEMAPHORE* semaphore);

void semaphore_release(
    SEMAPHORE* semaphore);

int create_thread(
    THREAD* thread, 
    THREAD_START_ROUTINE start_routine,
    void* param);

void thread_join(
    THREAD* thread);

#endif