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

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <yara/error.h>
#include <yara/re.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/threading.h>

#include "crypto.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#if !defined(_MSC_VER) || (defined(_MSC_VER) && (_MSC_VER < 1900))
#define snprintf _snprintf
#endif
#endif


YR_THREAD_STORAGE_KEY yr_tidx_key;
YR_THREAD_STORAGE_KEY yr_recovery_state_key;


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


char yr_lowercase[256];
char yr_altercase[256];


#if defined(HAVE_LIBCRYPTO) && OPENSSL_VERSION_NUMBER < 0x10100000L

// The OpenSSL library before version 1.1 requires some locks in order
// to be thread-safe. These locks are initialized in yr_initialize
// function.

static YR_MUTEX *openssl_locks;


static unsigned long _thread_id(void)
{
  return (unsigned long) yr_current_thread_id();
}


static void _locking_function(
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
  uint32_t def_max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;

  int i;

  init_count++;

  if (init_count > 1)
    return ERROR_SUCCESS;

  for (i = 0; i < 256; i++)
  {
    if (i >= 'a' && i <= 'z')
      yr_altercase[i] = i - 32;
    else if (i >= 'A' && i <= 'Z')
      yr_altercase[i] = i + 32;
    else
      yr_altercase[i] = i;

    yr_lowercase[i] = tolower(i);
  }

  FAIL_ON_ERROR(yr_heap_alloc());
  FAIL_ON_ERROR(yr_thread_storage_create(&yr_tidx_key));
  FAIL_ON_ERROR(yr_thread_storage_create(&yr_recovery_state_key));

  #if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L

  openssl_locks = (YR_MUTEX*) OPENSSL_malloc(
      CRYPTO_num_locks() * sizeof(YR_MUTEX));

  for (i = 0; i < CRYPTO_num_locks(); i++)
    yr_mutex_create(&openssl_locks[i]);

  CRYPTO_set_id_callback(_thread_id);
  CRYPTO_set_locking_callback(_locking_function);

  #elif defined(HAVE_WINCRYPT_H)

  if (!CryptAcquireContext(&yr_cryptprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  #elif defined(HAVE_COMMON_CRYPTO)

  ...

  #endif

  FAIL_ON_ERROR(yr_re_initialize());
  FAIL_ON_ERROR(yr_modules_initialize());

  // Initialize default configuration options
  FAIL_ON_ERROR(yr_set_configuration(
      YR_CONFIG_STACK_SIZE, &def_stack_size));
  FAIL_ON_ERROR(yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE, &def_max_strings_per_rule));

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
// need to explicitly call yr_finalize_thread because yr_finalize already
// calls it.
//

YR_API int yr_finalize(void)
{
  #if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L
  int i;
  #endif

  // yr_finalize shouldn't be called without calling yr_initialize first

  if (init_count == 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  yr_re_finalize_thread();

  init_count--;

  if (init_count > 0)
    return ERROR_SUCCESS;

  #if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L

  for (i = 0; i < CRYPTO_num_locks(); i ++)
    yr_mutex_destroy(&openssl_locks[i]);

  OPENSSL_free(openssl_locks);
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);

  #elif defined(HAVE_WINCRYPT_H)

  CryptReleaseContext(yr_cryptprov, 0);

  #endif

  FAIL_ON_ERROR(yr_thread_storage_destroy(&yr_tidx_key));
  FAIL_ON_ERROR(yr_thread_storage_destroy(&yr_recovery_state_key));
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
  yr_thread_storage_set_value(&yr_tidx_key, (void*) (size_t) (tidx + 1));
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
  return (int) (size_t) yr_thread_storage_get_value(&yr_tidx_key) - 1;
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
    case YR_CONFIG_MAX_STRINGS_PER_RULE:
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
    case YR_CONFIG_MAX_STRINGS_PER_RULE:
      *(uint32_t*) dest = yr_cfgs[cfgname].ui32;
      break;

    default:
      return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}
