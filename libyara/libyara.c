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

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <yara/error.h>
#include <yara/re.h>
#include <yara/modules.h>
#include <yara/mem.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/crypto.h>
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#define snprintf _snprintf
#endif


#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
DWORD tidx_key;
DWORD recovery_state_key;
#else
#include <pthread.h>
pthread_key_t tidx_key;
pthread_key_t recovery_state_key;
#endif

static int init_count = 0;

char lowercase[256];
char altercase[256];

#ifndef HAVE_PTHREAD
#ifdef _WIN32

typedef HANDLE pthread_mutex_t;

unsigned long pthread_self()
{
    return GetCurrentThreadId();
}

int pthread_mutex_init(pthread_mutex_t *mutex, void* attr)
{
    *mutex = CreateSemaphore(NULL, 1, 1, NULL);
    return *mutex == NULL;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    BOOL result;

    result = CloseHandle(*mutex);
    *mutex = NULL;
    return result == TRUE ? 0 : -1;
}

int pthread_mutex_lock(pthread_mutex_t mutex)
{
    return WaitForSingleObject(mutex, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
}

int pthread_mutex_unlock(pthread_mutex_t mutex)
{
    return ReleaseSemaphore(mutex, 1, NULL) == TRUE ? 0 : -1;
}
#endif
#endif

#ifdef HAVE_LIBCRYPTO
pthread_mutex_t *locks;

unsigned long pthreads_thread_id(void)
{
  return (unsigned long) pthread_self();
}

void locking_function(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&locks[n]);
  else
    pthread_mutex_unlock(&locks[n]);
}
#endif

//
// yr_initialize
//
// Should be called by main thread before using any other
// function from libyara.
//

YR_API int yr_initialize(void)
{
  int i;

  if (init_count > 0)
  {
    init_count++;
    return ERROR_SUCCESS;
  }

  for (i = 0; i < 256; i++)
  {
    if (i >= 'a' && i <= 'z')
      altercase[i] = i - 32;
    else if (i >= 'A' && i <= 'Z')
      altercase[i] = i + 32;
    else
      altercase[i] = i;

    lowercase[i] = tolower(i);
  }

  FAIL_ON_ERROR(yr_heap_alloc());

  #if defined(_WIN32) || defined(__CYGWIN__)
  tidx_key = TlsAlloc();
  recovery_state_key = TlsAlloc();
  #else
  pthread_key_create(&tidx_key, NULL);
  pthread_key_create(&recovery_state_key, NULL);
  #endif

  #ifdef HAVE_LIBCRYPTO
  locks = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  for (i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&locks[i], NULL);

  CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
  CRYPTO_set_locking_callback(locking_function);
  #endif

  FAIL_ON_ERROR(yr_re_initialize());
  FAIL_ON_ERROR(yr_modules_initialize());

  init_count++;

  return ERROR_SUCCESS;
}


//
// yr_finalize_thread
//
// Should be called by ALL threads using libyara before exiting.
//

YR_API void yr_finalize_thread(void)
{
  yr_re_finalize_thread();
}


//
// yr_finalize
//
// Should be called by main thread before exiting. Main thread doesn't
// need to explicitely call yr_finalize_thread because yr_finalize already
// calls it.
//

YR_API int yr_finalize(void)
{
  #ifdef HAVE_LIBCRYPTO
  int i;
  #endif

  yr_re_finalize_thread();

  if (--init_count > 0)
    return ERROR_SUCCESS;

  #ifdef HAVE_LIBCRYPTO
  for (i = 0; i < CRYPTO_num_locks(); i ++)
    pthread_mutex_destroy(&locks[i]);
  OPENSSL_free(locks);
  #endif

  #if defined(_WIN32) || defined(__CYGWIN__)
  TlsFree(tidx_key);
  TlsFree(recovery_state_key);
  #else
  pthread_key_delete(tidx_key);
  pthread_key_delete(recovery_state_key);
  #endif

  FAIL_ON_ERROR(yr_re_finalize());
  FAIL_ON_ERROR(yr_modules_finalize());
  FAIL_ON_ERROR(yr_heap_free());

  return ERROR_SUCCESS;
}

//
// _yr_set_tidx
//
// Set the thread index (tidx) for the current thread. The tidx is the index
// that will be used by the thread to access thread-specific data stored in
// YR_RULES structure.
//
// Args:
//    int tidx   - The zero-based tidx that will be associated to the current
//                 thread.
//

YR_API void yr_set_tidx(int tidx)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  TlsSetValue(tidx_key, (LPVOID) (tidx + 1));
  #else
  pthread_setspecific(tidx_key, (void*) (size_t) (tidx + 1));
  #endif
}


//
// _yr_get_tidx
//
// Get the thread index (tidx) for the current thread.
//
// Returns:
//    The tidx for the current thread or -1 if the current thread doesn't
//    have any tidx associated.
//

YR_API int yr_get_tidx(void)
{
  #if defined(_WIN32) || defined(__CYGWIN__)
  return (int) TlsGetValue(tidx_key) - 1;
  #else
  return (int) (size_t) pthread_getspecific(tidx_key) - 1;
  #endif
}
