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

#if defined(JEMALLOC)
#include <jemalloc/jemalloc.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <yara/error.h>
#include <yara/globals.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/re.h>
#include <yara/threading.h>

#include "crypto.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#if !defined(_MSC_VER) || (defined(_MSC_VER) && (_MSC_VER < 1900))
#define snprintf _snprintf
#endif
#endif

YR_THREAD_STORAGE_KEY yr_yyfatal_trampoline_tls;
YR_THREAD_STORAGE_KEY yr_trycatch_trampoline_tls;

static int init_count = 0;

static struct yr_config_var
{
  union
  {
    size_t sz;
    uint32_t ui32;
    uint64_t ui64;
    char *str;
  };

} yr_cfgs[YR_CONFIG_LAST];

// Global variables. See globals.h for their descriptions.

uint8_t yr_lowercase[256];
uint8_t yr_altercase[256];

#if 0 == YR_DEBUG_VERBOSITY

#else

uint64_t yr_debug_verbosity = YR_DEBUG_VERBOSITY;

#endif

#if defined(HAVE_LIBCRYPTO) && OPENSSL_VERSION_NUMBER < 0x10100000L

// The OpenSSL library before version 1.1 requires some locks in order
// to be thread-safe. These locks are initialized in yr_initialize
// function.

static YR_MUTEX *openssl_locks;

static void _thread_id(CRYPTO_THREADID *id)
{
  CRYPTO_THREADID_set_numeric(id, (unsigned long) yr_current_thread_id());
}

static void _locking_function(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    yr_mutex_lock(&openssl_locks[n]);
  else
    yr_mutex_unlock(&openssl_locks[n]);
}

#endif

#if defined(HAVE_WINCRYPT_H)

HCRYPTPROV yr_cryptprov;

#endif

////////////////////////////////////////////////////////////////////////////////
// Should be called by main thread before using any other
// function from libyara.
//
YR_API int yr_initialize(void)
{
  uint32_t def_stack_size = DEFAULT_STACK_SIZE;
  uint32_t def_max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
  uint32_t def_max_match_data = DEFAULT_MAX_MATCH_DATA;

  init_count++;

  if (init_count > 1)
    return ERROR_SUCCESS;

  // Initialize random number generator, as it is used for generating object
  // canaries.
  srand((unsigned) time(NULL));

  for (int i = 0; i < 256; i++)
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
  FAIL_ON_ERROR(yr_thread_storage_create(&yr_yyfatal_trampoline_tls));
  FAIL_ON_ERROR(yr_thread_storage_create(&yr_trycatch_trampoline_tls));

#if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L

  openssl_locks = (YR_MUTEX *) OPENSSL_malloc(
      CRYPTO_num_locks() * sizeof(YR_MUTEX));

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    yr_mutex_create(&openssl_locks[i]);

  CRYPTO_THREADID_set_callback(_thread_id);
  CRYPTO_set_locking_callback(_locking_function);

#elif defined(HAVE_WINCRYPT_H)

  if (!CryptAcquireContext(
          &yr_cryptprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
  {
    return ERROR_INTERNAL_FATAL_ERROR;
  }

#elif defined(HAVE_COMMON_CRYPTO)

  ...

#endif

  FAIL_ON_ERROR(yr_modules_initialize());

  // Initialize default configuration options

  FAIL_ON_ERROR(yr_set_configuration(YR_CONFIG_STACK_SIZE, &def_stack_size));

  FAIL_ON_ERROR(yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE, &def_max_strings_per_rule));

  FAIL_ON_ERROR(
      yr_set_configuration(YR_CONFIG_MAX_MATCH_DATA, &def_max_match_data));

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Should be called by main thread before exiting.
//
YR_API int yr_finalize(void)
{
#if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L
  int i;
#endif

  // yr_finalize shouldn't be called without calling yr_initialize first

  if (init_count == 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  init_count--;

  if (init_count > 0)
    return ERROR_SUCCESS;

#if defined HAVE_LIBCRYPTO && OPENSSL_VERSION_NUMBER < 0x10100000L

  for (i = 0; i < CRYPTO_num_locks(); i++) yr_mutex_destroy(&openssl_locks[i]);

  OPENSSL_free(openssl_locks);
  CRYPTO_THREADID_set_callback(NULL);
  CRYPTO_set_locking_callback(NULL);

#elif defined(HAVE_WINCRYPT_H)

  CryptReleaseContext(yr_cryptprov, 0);

#endif

  FAIL_ON_ERROR(yr_thread_storage_destroy(&yr_yyfatal_trampoline_tls));
  FAIL_ON_ERROR(yr_thread_storage_destroy(&yr_trycatch_trampoline_tls));
  FAIL_ON_ERROR(yr_modules_finalize());
  FAIL_ON_ERROR(yr_heap_free());

#if defined(JEMALLOC)
  malloc_stats_print(NULL, NULL, NULL);
  mallctl("prof.dump", NULL, NULL, NULL, 0);
#endif

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Sets a configuration option.
//
// This function receives a configuration name, as defined by the YR_CONFIG_NAME
// enum, and a pointer to the value being set. The type of the value depends on
// the configuration name.
//
// Args:
//   name: Any of the values defined by the YR_CONFIG_NAME enum. Possible values
//         are:
//              YR_CONFIG_STACK_SIZE             data type: uint32_t
//              YR_CONFIG_MAX_STRINGS_PER_RULE   data type: uint32_t
//              YR_CONFIG_MAX_MATCH_DATA         data type: uint32_t
//
//   src: Pointer to the value being set for the option.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INTERNAL_FATAL_ERROR
//
YR_API int yr_set_configuration(YR_CONFIG_NAME name, void *src)
{
  if (src == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  switch (name)
  {  // lump all the cases using same types together in one cascade
  case YR_CONFIG_STACK_SIZE:
  case YR_CONFIG_MAX_STRINGS_PER_RULE:
  case YR_CONFIG_MAX_MATCH_DATA:
    yr_cfgs[name].ui32 = *(uint32_t *) src;
    break;

  default:
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}

YR_API int yr_get_configuration(YR_CONFIG_NAME name, void *dest)
{
  if (dest == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  switch (name)
  {  // lump all the cases using same types together in one cascade
  case YR_CONFIG_STACK_SIZE:
  case YR_CONFIG_MAX_STRINGS_PER_RULE:
  case YR_CONFIG_MAX_MATCH_DATA:
    *(uint32_t *) dest = yr_cfgs[name].ui32;
    break;

  default:
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}
