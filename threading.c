/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#include <fcntl.h>

#ifndef WIN32
#include <errno.h>
#endif

#include "threading.h"


int mutex_init(
    MUTEX* mutex)
{
  #ifdef WIN32
  *mutex = CreateMutex(NULL, FALSE, NULL);
  if (*mutex == NULL)
    return GetLastError();
  else
    return 0;
  #else
  return pthread_mutex_init(mutex, NULL);
  #endif
}

void mutex_destroy(
    MUTEX* mutex)
{
  #ifdef WIN32
  CloseHandle(*mutex);
  #else
  pthread_mutex_destroy(mutex);
  #endif
}


void mutex_lock(
    MUTEX* mutex)
{
  #ifdef WIN32
  WaitForSingleObject(*mutex, INFINITE);
  #else
  pthread_mutex_lock(mutex);
  #endif
}


void mutex_unlock(
    MUTEX* mutex)
{
  #ifdef WIN32
  ReleaseMutex(*mutex);
  #else
  pthread_mutex_unlock(mutex);
  #endif
}


int semaphore_init(
    SEMAPHORE* semaphore,
    int value)
{
  #ifdef WIN32
  *semaphore = CreateSemaphore(NULL, value, 65535, NULL);
  if (*semaphore == NULL)
    return GetLastError();
  #else
  // Mac OS X doesn't support unnamed semaphores via sem_init, that's why
  // we use sem_open instead sem_init and immediately unlink the semaphore
  // from the name. More info at:
  //
  // http://stackoverflow.com/questions/1413785/sem-init-on-os-x
  *semaphore = sem_open("/semaphore", O_CREAT, S_IRUSR, value);

  if (*semaphore == SEM_FAILED)
    return errno;

  if (sem_unlink("/semaphore") != 0)
    return errno;
  #endif

  return 0;
}


void semaphore_destroy(
    SEMAPHORE* semaphore)
{
  #ifdef WIN32
  CloseHandle(*semaphore);
  #else
  sem_close(*semaphore);
  #endif
}


void semaphore_wait(
    SEMAPHORE* semaphore)
{
  #ifdef WIN32
  WaitForSingleObject(*semaphore, INFINITE);
  #else
  sem_wait(*semaphore);
  #endif
}


void semaphore_release(
    SEMAPHORE* semaphore)
{
  #ifdef WIN32
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
  #ifdef WIN32
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
  #ifdef WIN32
  WaitForSingleObject(*thread, INFINITE);
  #else
  pthread_join(*thread, NULL);
  #endif
}




