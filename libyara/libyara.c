/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#include "mem.h"
#include "re.h"
#include "yara.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

#ifdef WIN32
#else
#include <pthread.h>
#endif

char lowercase[256];

#ifdef WIN32
DWORD key;
#else
pthread_key_t key;
#endif


void yr_initialize(void)
{
  int i;

  for (i = 0; i < 256; i++)
    lowercase[i] = tolower(i);

  yr_heap_alloc();
  
  #ifdef WIN32
  key = TlsAlloc();
  #else
  pthread_key_create(&key, NULL);
  #endif

  yr_re_initialize();

}

void yr_finalize(void)
{
  yr_heap_free();
  yr_re_finalize();
}

//
// _yr_set_tidx
//
// Set the thread index (tidx) for the current thread. The tidx is the index
// that will be used by the thread to access thread-specific data stored in
// YARA_RULES structure.
//
// Args:
//    int tidx   - The zero-based tidx that will be associated to the current
//                 thread.
//

void yr_set_tidx(int tidx)
{
  #ifdef WIN32
  TlsSetValue(key, (LPVOID) (tidx + 1));
  #else
  pthread_setspecific(key, (void*) (size_t) (tidx + 1));
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
  #ifdef WIN32
  return (int) TlsGetValue(key) - 1;
  #else
  return (int) (size_t) pthread_getspecific(key) - 1;
  #endif
}
