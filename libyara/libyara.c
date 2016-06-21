/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <yara/error.h>
#include <yara/re.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/threading.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/crypto.h>
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#define snprintf _snprintf
#endif


YR_THREAD_STORAGE_KEY tidx_key;
YR_THREAD_STORAGE_KEY recovery_state_key;


static int init_count = 0;

static struct yr_config_var
{
  union
  {
    size_t   sz;
    uint32_t ui32;
    uint64_t ui64;
    char*    str;
  };

} yr_cfgs[YR_CONFIG_MAX];


char lowercase[256];
char altercase[256];


#ifdef HAVE_LIBCRYPTO

// The OpenSSL library requires some locks in order to be thread-safe. These
// locks are initialized in yr_initialize function.

YR_MUTEX *openssl_locks;


unsigned long thread_id(void)
{
  return (unsigned long) yr_current_thread_id();
}


void locking_function(
    int mode,
    int n,
    const char *file,
    int line)
{
  if (mode & CRYPTO_LOCK)
    yr_mutex_lock(&openssl_locks[n]);
  else
    yr_mutex_unlock(&openssl_locks[n]);
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
  uint32_t def_stack_size = DEFAULT_STACK_SIZE;
  int i;

  init_count++;

  if (init_count > 1)
    return ERROR_SUCCESS;

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
  FAIL_ON_ERROR(yr_thread_storage_create(&tidx_key));
  FAIL_ON_ERROR(yr_thread_storage_create(&recovery_state_key));

  #ifdef HAVE_LIBCRYPTO

  openssl_locks = (YR_MUTEX*) OPENSSL_malloc(
      CRYPTO_num_locks() * sizeof(YR_MUTEX));

  for (i = 0; i < CRYPTO_num_locks(); i++)
    yr_mutex_create(&openssl_locks[i]);

  CRYPTO_set_id_callback(thread_id);
  CRYPTO_set_locking_callback(locking_function);

  #endif

  FAIL_ON_ERROR(yr_re_initialize());
  FAIL_ON_ERROR(yr_modules_initialize());

  // Initialize default configuration options
  FAIL_ON_ERROR(yr_set_configuration(YR_CONFIG_STACK_SIZE, &def_stack_size));

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

  // yr_finalize shouldn't be called without calling yr_initialize first

  if (init_count == 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  yr_re_finalize_thread();

  init_count--;

  if (init_count > 0)
    return ERROR_SUCCESS;

  #ifdef HAVE_LIBCRYPTO

  for (i = 0; i < CRYPTO_num_locks(); i ++)
    yr_mutex_destroy(&openssl_locks[i]);

  OPENSSL_free(openssl_locks);

  #endif

  FAIL_ON_ERROR(yr_thread_storage_destroy(&tidx_key));
  FAIL_ON_ERROR(yr_thread_storage_destroy(&recovery_state_key));
  FAIL_ON_ERROR(yr_re_finalize());
  FAIL_ON_ERROR(yr_modules_finalize());
  FAIL_ON_ERROR(yr_heap_free());

  return ERROR_SUCCESS;
}

//
// yr_set_tidx
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
  yr_thread_storage_set_value(&tidx_key, (void*) (size_t) (tidx + 1));
}


//
// yr_get_tidx
//
// Get the thread index (tidx) for the current thread.
//
// Returns:
//    The tidx for the current thread or -1 if the current thread doesn't
//    have any tidx associated.
//

YR_API int yr_get_tidx(void)
{
  return (int) (size_t) yr_thread_storage_get_value(&tidx_key) - 1;
}


YR_API int yr_set_configuration(
    YR_CONFIG_NAME cfgname,
    void *src)
{
  if (src == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  switch (cfgname)
  { // lump all the cases using same types together in one cascade
    case YR_CONFIG_STACK_SIZE:
      yr_cfgs[cfgname].ui32 = *(uint32_t*) src;
      break;

    default:
      return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}


YR_API int yr_get_configuration(
    YR_CONFIG_NAME cfgname,
    void *dest)
{
  if (dest == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  switch (cfgname)
  { // lump all the cases using same types together in one cascade
    case YR_CONFIG_STACK_SIZE:
      *(uint32_t*) dest = yr_cfgs[cfgname].ui32;
      break;

    default:
      return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}
