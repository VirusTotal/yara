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

#if !(_WIN32 || __CYGWIN__)

#include <pthread.h>
#include <signal.h>

struct sigaction old_sigsegv_exception_handler;
struct sigaction old_sigbus_exception_handler;
int exception_handler_usecount = 0;
pthread_mutex_t exception_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

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

YR_TLS int yr_debug_indent = 0;

YR_TLS int yr_debug_stopwatch_unstarted = 1;

YR_TLS YR_STOPWATCH yr_debug_stopwatch;

const char yr_debug_spaces[] = "                " /* 16 spaces * 1 */
                               "                " /* 16 spaces * 2 */
                               "                " /* 16 spaces * 3 */
                               "                " /* 16 spaces * 4 */
                               "                " /* 16 spaces * 5 */
                               "                " /* 16 spaces * 6 */
                               "                " /* 16 spaces * 7 */
                               "                " /* 16 spaces * 8 */;

size_t yr_debug_spaces_len = sizeof(yr_debug_spaces);

double yr_debug_get_elapsed_seconds(void)
{
  if (yr_debug_stopwatch_unstarted)
  {
    yr_debug_stopwatch_unstarted = 0;
    yr_stopwatch_start(&yr_debug_stopwatch);
  }

  uint64_t elapsed_ns = yr_stopwatch_elapsed_ns(&yr_debug_stopwatch);

  double seconds = (double) elapsed_ns / 1000000000;

  return seconds;
}

char *yr_debug_callback_message_as_string(int message)
{
  char *s = "CALLBACK_MSG_?";
  switch (message)
  {  // clang-format off
  case CALLBACK_MSG_RULE_MATCHING    : s = "CALLBACK_MSG_RULE_MATCHING"    ; break;
  case CALLBACK_MSG_RULE_NOT_MATCHING: s = "CALLBACK_MSG_RULE_NOT_MATCHING"; break;
  case CALLBACK_MSG_SCAN_FINISHED    : s = "CALLBACK_MSG_SCAN_FINISHED"    ; break;
  case CALLBACK_MSG_IMPORT_MODULE    : s = "CALLBACK_MSG_IMPORT_MODULE"    ; break;
  case CALLBACK_MSG_MODULE_IMPORTED  : s = "CALLBACK_MSG_MODULE_IMPORTED"  ; break;
  }  // clang-format on
  return s;
}

char *yr_debug_error_as_string(int error)
{
  char *s = "ERROR_?";
  switch (error)
  {  // clang-format off
  case ERROR_SUCCESS                       : s = "ERROR_SUCCESS 0"                     ; break;
  case ERROR_INSUFFICIENT_MEMORY           : s = "ERROR_INSUFFICIENT_MEMORY"           ; break;
  case ERROR_COULD_NOT_ATTACH_TO_PROCESS   : s = "ERROR_COULD_NOT_ATTACH_TO_PROCESS"   ; break;
  case ERROR_COULD_NOT_OPEN_FILE           : s = "ERROR_COULD_NOT_OPEN_FILE"           ; break;
  case ERROR_COULD_NOT_MAP_FILE            : s = "ERROR_COULD_NOT_MAP_FILE"            ; break;
  case ERROR_INVALID_FILE                  : s = "ERROR_INVALID_FILE"                  ; break;
  case ERROR_CORRUPT_FILE                  : s = "ERROR_CORRUPT_FILE"                  ; break;
  case ERROR_UNSUPPORTED_FILE_VERSION      : s = "ERROR_UNSUPPORTED_FILE_VERSION"      ; break;
  case ERROR_INVALID_REGULAR_EXPRESSION    : s = "ERROR_INVALID_REGULAR_EXPRESSION"    ; break;
  case ERROR_INVALID_HEX_STRING            : s = "ERROR_INVALID_HEX_STRING"            ; break;
  case ERROR_SYNTAX_ERROR                  : s = "ERROR_SYNTAX_ERROR"                  ; break;
  case ERROR_LOOP_NESTING_LIMIT_EXCEEDED   : s = "ERROR_LOOP_NESTING_LIMIT_EXCEEDED"   ; break;
  case ERROR_DUPLICATED_LOOP_IDENTIFIER    : s = "ERROR_DUPLICATED_LOOP_IDENTIFIER"    ; break;
  case ERROR_DUPLICATED_IDENTIFIER         : s = "ERROR_DUPLICATED_IDENTIFIER"         ; break;
  case ERROR_DUPLICATED_TAG_IDENTIFIER     : s = "ERROR_DUPLICATED_TAG_IDENTIFIER"     ; break;
  case ERROR_DUPLICATED_META_IDENTIFIER    : s = "ERROR_DUPLICATED_META_IDENTIFIER"    ; break;
  case ERROR_DUPLICATED_STRING_IDENTIFIER  : s = "ERROR_DUPLICATED_STRING_IDENTIFIER"  ; break;
  case ERROR_UNREFERENCED_STRING           : s = "ERROR_UNREFERENCED_STRING"           ; break;
  case ERROR_UNDEFINED_STRING              : s = "ERROR_UNDEFINED_STRING"              ; break;
  case ERROR_UNDEFINED_IDENTIFIER          : s = "ERROR_UNDEFINED_IDENTIFIER"          ; break;
  case ERROR_MISPLACED_ANONYMOUS_STRING    : s = "ERROR_MISPLACED_ANONYMOUS_STRING"    ; break;
  case ERROR_INCLUDES_CIRCULAR_REFERENCE   : s = "ERROR_INCLUDES_CIRCULAR_REFERENCE"   ; break;
  case ERROR_INCLUDE_DEPTH_EXCEEDED        : s = "ERROR_INCLUDE_DEPTH_EXCEEDED"        ; break;
  case ERROR_WRONG_TYPE                    : s = "ERROR_WRONG_TYPE"                    ; break;
  case ERROR_EXEC_STACK_OVERFLOW           : s = "ERROR_EXEC_STACK_OVERFLOW"           ; break;
  case ERROR_SCAN_TIMEOUT                  : s = "ERROR_SCAN_TIMEOUT"                  ; break;
  case ERROR_CALLBACK_ERROR                : s = "ERROR_CALLBACK_ERROR"                ; break;
  case ERROR_INVALID_ARGUMENT              : s = "ERROR_INVALID_ARGUMENT"              ; break;
  case ERROR_TOO_MANY_MATCHES              : s = "ERROR_TOO_MANY_MATCHES"              ; break;
  case ERROR_INTERNAL_FATAL_ERROR          : s = "ERROR_INTERNAL_FATAL_ERROR"          ; break;
  case ERROR_NESTED_FOR_OF_LOOP            : s = "ERROR_NESTED_FOR_OF_LOOP"            ; break;
  case ERROR_INVALID_FIELD_NAME            : s = "ERROR_INVALID_FIELD_NAME"            ; break;
  case ERROR_UNKNOWN_MODULE                : s = "ERROR_UNKNOWN_MODULE"                ; break;
  case ERROR_NOT_A_STRUCTURE               : s = "ERROR_NOT_A_STRUCTURE"               ; break;
  case ERROR_NOT_INDEXABLE                 : s = "ERROR_NOT_INDEXABLE"                 ; break;
  case ERROR_NOT_A_FUNCTION                : s = "ERROR_NOT_A_FUNCTION"                ; break;
  case ERROR_INVALID_FORMAT                : s = "ERROR_INVALID_FORMAT"                ; break;
  case ERROR_TOO_MANY_ARGUMENTS            : s = "ERROR_TOO_MANY_ARGUMENTS"            ; break;
  case ERROR_WRONG_ARGUMENTS               : s = "ERROR_WRONG_ARGUMENTS"               ; break;
  case ERROR_WRONG_RETURN_TYPE             : s = "ERROR_WRONG_RETURN_TYPE"             ; break;
  case ERROR_DUPLICATED_STRUCTURE_MEMBER   : s = "ERROR_DUPLICATED_STRUCTURE_MEMBER"   ; break;
  case ERROR_EMPTY_STRING                  : s = "ERROR_EMPTY_STRING"                  ; break;
  case ERROR_DIVISION_BY_ZERO              : s = "ERROR_DIVISION_BY_ZERO"              ; break;
  case ERROR_REGULAR_EXPRESSION_TOO_LARGE  : s = "ERROR_REGULAR_EXPRESSION_TOO_LARGE"  ; break;
  case ERROR_TOO_MANY_RE_FIBERS            : s = "ERROR_TOO_MANY_RE_FIBERS"            ; break;
  case ERROR_COULD_NOT_READ_PROCESS_MEMORY : s = "ERROR_COULD_NOT_READ_PROCESS_MEMORY" ; break;
  case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE: s = "ERROR_INVALID_EXTERNAL_VARIABLE_TYPE"; break;
  case ERROR_REGULAR_EXPRESSION_TOO_COMPLEX: s = "ERROR_REGULAR_EXPRESSION_TOO_COMPLEX"; break;
  case ERROR_INVALID_MODULE_NAME           : s = "ERROR_INVALID_MODULE_NAME"           ; break;
  case ERROR_TOO_MANY_STRINGS              : s = "ERROR_TOO_MANY_STRINGS"              ; break;
  case ERROR_INTEGER_OVERFLOW              : s = "ERROR_INTEGER_OVERFLOW"              ; break;
  case ERROR_CALLBACK_REQUIRED             : s = "ERROR_CALLBACK_REQUIRED"             ; break;
  case ERROR_INVALID_OPERAND               : s = "ERROR_INVALID_OPERAND"               ; break;
  case ERROR_COULD_NOT_READ_FILE           : s = "ERROR_COULD_NOT_READ_FILE"           ; break;
  case ERROR_DUPLICATED_EXTERNAL_VARIABLE  : s = "ERROR_DUPLICATED_EXTERNAL_VARIABLE"  ; break;
  case ERROR_INVALID_MODULE_DATA           : s = "ERROR_INVALID_MODULE_DATA"           ; break;
  case ERROR_WRITING_FILE                  : s = "ERROR_WRITING_FILE"                  ; break;
  case ERROR_INVALID_MODIFIER              : s = "ERROR_INVALID_MODIFIER"              ; break;
  case ERROR_DUPLICATED_MODIFIER           : s = "ERROR_DUPLICATED_MODIFIER"           ; break;
  case ERROR_BLOCK_NOT_READY               : s = "ERROR_BLOCK_NOT_READY"               ; break;
  }  // clang-format on
  return s;
}

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
  YR_DEBUG_FPRINTF(2, stderr, "+ %s() {\n", __FUNCTION__);

  uint32_t def_stack_size = DEFAULT_STACK_SIZE;
  uint32_t def_max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
  uint32_t def_max_match_data = DEFAULT_MAX_MATCH_DATA;
  uint64_t def_max_process_memory_chunk = DEFAULT_MAX_PROCESS_MEMORY_CHUNK;

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

  FAIL_ON_ERROR(yr_set_configuration(
      YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, &def_max_process_memory_chunk));

  FAIL_ON_ERROR(
      yr_set_configuration(YR_CONFIG_MAX_MATCH_DATA, &def_max_match_data));

  YR_DEBUG_FPRINTF(2, stderr, "} // %s()\n", __FUNCTION__);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Should be called by main thread before exiting.
//
YR_API int yr_finalize(void)
{
  YR_DEBUG_FPRINTF(2, stderr, "+ %s() {\n", __FUNCTION__);

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

  YR_DEBUG_FPRINTF(2, stderr, "} // %s()\n", __FUNCTION__);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Set a configuration option.
//
// This function receives a configuration name, as defined by the YR_CONFIG_NAME
// enum, and a pointer to the value being set. The type of the value depends on
// the configuration name.
//
// The caller must ensure that the pointer passed to the function is the correct
// type. Using yr_set_configuration_uintXX is preferred, as those functions will
// perform the necessary type checking.
//
// Args:
//   name: Any of the values defined by the YR_CONFIG_NAME enum. Possible values
//         are:
//              YR_CONFIG_STACK_SIZE                data type: uint32_t
//              YR_CONFIG_MAX_STRINGS_PER_RULE      data type: uint32_t
//              YR_CONFIG_MAX_MATCH_DATA            data type: uint32_t
//              YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK  data type: uint64_t
//
//   src: Pointer to the value being set for the option.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
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

  case YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK:
    yr_cfgs[name].ui64 = *(uint64_t *) src;
    break;

  default:
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Set a configuration option.
//
// This function receives a configuration name, as defined by the YR_CONFIG_NAME
// and a value for the configuration being set. Only configuration names with
// type uint32_t will be accepted, if not ERROR_INVALID_ARGUMENT will be
// returned.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//
YR_API int yr_set_configuration_uint32(YR_CONFIG_NAME name, uint32_t value)
{
  switch (name)
  {
  // Accept only the configuration options that are of type uint32_t.
  case YR_CONFIG_STACK_SIZE:
  case YR_CONFIG_MAX_STRINGS_PER_RULE:
  case YR_CONFIG_MAX_MATCH_DATA:
    return yr_set_configuration(name, &value);
  default:
    return ERROR_INVALID_ARGUMENT;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Set a configuration option.
//
// See yr_set_configuration_uint32 for more details.
//
YR_API int yr_set_configuration_uint64(YR_CONFIG_NAME name, uint64_t value)
{
  switch (name)
  {
  case YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK:
    return yr_set_configuration(name, &value);
  default:
    return ERROR_INVALID_ARGUMENT;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Get a configuration option.
//
// This function receives a configuration name, as defined by the YR_CONFIG_NAME
// enum, and a pointer to the variable that will receive the value for that
// option. The type of the value depends on the configuration name.
//
// The caller must ensure that the pointer passed to the function is the correct
// type. Using yr_get_configuration_uintXX is preferred.
//
// Args:
//   name: Any of the values defined by the YR_CONFIG_NAME enum. Possible values
//         are:
//              YR_CONFIG_STACK_SIZE                data type: uint32_t
//              YR_CONFIG_MAX_STRINGS_PER_RULE      data type: uint32_t
//              YR_CONFIG_MAX_MATCH_DATA            data type: uint32_t
//              YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK  data type: uint64_t
//
//   dest: Pointer to a variable that will receive the value for the option.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//
YR_API int yr_get_configuration(YR_CONFIG_NAME name, void *dest)
{
  if (dest == NULL)
    return ERROR_INVALID_ARGUMENT;

  switch (name)
  {  // lump all the cases using same types together in one cascade
  case YR_CONFIG_STACK_SIZE:
  case YR_CONFIG_MAX_STRINGS_PER_RULE:
  case YR_CONFIG_MAX_MATCH_DATA:
    *(uint32_t *) dest = yr_cfgs[name].ui32;
    break;

  case YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK:
    *(uint64_t *) dest = yr_cfgs[name].ui64;
    break;

  default:
    return ERROR_INVALID_ARGUMENT;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Get a configuration option.
//
// This function receives a configuration name, as defined by the YR_CONFIG_NAME
// and a value for the configuration being set. Only configuration names with
// type uint32_t will be accepted, if not ERROR_INVALID_ARGUMENT will be
// returned.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//
YR_API int yr_get_configuration_uint32(YR_CONFIG_NAME name, uint32_t *dest)
{
  switch (name)
  {
  // Accept only the configuration options that are of type uint32_t.
  case YR_CONFIG_STACK_SIZE:
  case YR_CONFIG_MAX_STRINGS_PER_RULE:
  case YR_CONFIG_MAX_MATCH_DATA:
    return yr_get_configuration(name, (void *) dest);
  default:
    return ERROR_INVALID_ARGUMENT;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Get a configuration option.
//
// See yr_get_configuration_uint64 for more details.
//
YR_API int yr_get_configuration_uint64(YR_CONFIG_NAME name, uint64_t *value)
{
  switch (name)
  {
  case YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK:
    return yr_get_configuration(name, (void *) value);
  default:
    return ERROR_INVALID_ARGUMENT;
  }
}