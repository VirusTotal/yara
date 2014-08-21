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

#include <yara/mem.h>
#include <yara/re.h>
#include <yara/modules.h>


#ifdef _WIN32
#define snprintf _snprintf
#endif


#ifdef _WIN32
#include <windows.h>
DWORD tidx_key;
DWORD recovery_state_key;
#else
#include <pthread.h>
pthread_key_t tidx_key;
pthread_key_t recovery_state_key;
#endif


char lowercase[256];
char altercase[256];

//
// yr_initialize
//
// Should be called by main thread before using any other
// function from libyara.
//

void yr_initialize(void)
{
  int i;

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

  yr_heap_alloc();

  #ifdef _WIN32
  tidx_key = TlsAlloc();
  recovery_state_key = TlsAlloc();
  #else
  pthread_key_create(&tidx_key, NULL);
  pthread_key_create(&recovery_state_key, NULL);
  #endif

  yr_re_initialize();
  yr_modules_initialize();
}


//
// yr_finalize_thread
//
// Should be called by ALL threads using libyara before exiting.
//

void yr_finalize_thread(void)
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

void yr_finalize(void)
{
  yr_re_finalize_thread();

  #ifdef _WIN32
  TlsFree(tidx_key);
  TlsFree(recovery_state_key);
  #else
  pthread_key_delete(tidx_key);
  pthread_key_delete(recovery_state_key);
  #endif

  yr_re_finalize();
  yr_modules_finalize();
  yr_heap_free();
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

void yr_set_tidx(int tidx)
{
  #ifdef _WIN32
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

int yr_get_tidx(void)
{
  #ifdef _WIN32
  return (int) TlsGetValue(tidx_key) - 1;
  #else
  return (int) (size_t) pthread_getspecific(tidx_key) - 1;
  #endif
}
