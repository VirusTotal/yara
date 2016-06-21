/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <yara/error.h>
#include <yara/threading.h>

#if defined(_WIN32) || defined(__CYGWIN__)

YR_THREAD_ID yr_current_thread_id(void)
{
  return GetCurrentThreadId();
}


int yr_mutex_create(
    YR_MUTEX* mutex)
{
  *mutex = CreateMutex(NULL, FALSE, NULL);

  if (*mutex == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_destroy(
    YR_MUTEX* mutex)
{
  if (CloseHandle(*mutex) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_lock(
    YR_MUTEX* mutex)
{
  if (WaitForSingleObject(*mutex, INFINITE) == WAIT_FAILED)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_unlock(
    YR_MUTEX* mutex)
{
  if (ReleaseMutex(*mutex) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_create(
    YR_THREAD_STORAGE_KEY* storage)
{
  *storage = TlsAlloc();

  if (*storage == TLS_OUT_OF_INDEXES)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_destroy(
    YR_THREAD_STORAGE_KEY* storage)
{
  if (TlsFree(*storage) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_set_value(
    YR_THREAD_STORAGE_KEY* storage,
    void* value)
{
  if (TlsSetValue(*storage, value) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


void* yr_thread_storage_get_value(
    YR_THREAD_STORAGE_KEY* storage)
{
  return TlsGetValue(*storage);
}


#else  // POSIX implementation


YR_THREAD_ID yr_current_thread_id(void)
{
  return pthread_self();
}


int yr_mutex_create(
    YR_MUTEX* mutex)
{
  if (pthread_mutex_init(mutex, NULL) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_destroy(
    YR_MUTEX* mutex)
{
  if (pthread_mutex_destroy(mutex) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_lock(
    YR_MUTEX* mutex)
{
  if (pthread_mutex_lock(mutex) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_mutex_unlock(
    YR_MUTEX* mutex)
{
  if (pthread_mutex_unlock(mutex) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_create(
    YR_THREAD_STORAGE_KEY* storage)
{
  if (pthread_key_create(storage, NULL) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_destroy(
    YR_THREAD_STORAGE_KEY* storage)
{
  if (pthread_key_delete(*storage) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_set_value(
    YR_THREAD_STORAGE_KEY* storage,
    void* value)
{
  if (pthread_setspecific(*storage, value) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


void* yr_thread_storage_get_value(
    YR_THREAD_STORAGE_KEY* storage)
{
  return pthread_getspecific(*storage);
}

#endif
