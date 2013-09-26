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
#include "yara.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

#ifdef WIN32
#else
#include <pthread.h>
#define PTHREADS
#endif

char isregexescapable[256];
char isregexhashable[256];
char isalphanum[256];
char lowercase[256];

pthread_key_t key;

void yr_initialize(void)
{
  int i;

  for (i = 0; i < 256; i++)
  {
  	lowercase[i] = tolower(i);
    isregexhashable[i] = isalnum(i);
   	isalphanum[i] = isalnum(i);
    isregexescapable[i] = FALSE;
  }

  // Add other characters that we can hash with for regexes.

  isregexhashable['"'] = TRUE;
  isregexhashable['\''] = TRUE;
  isregexhashable[','] = TRUE;
  isregexhashable[';'] = TRUE;
  isregexhashable[':'] = TRUE;
  isregexhashable['/'] = TRUE;
  isregexhashable['%'] = TRUE;
  isregexhashable['@'] = TRUE;
  isregexhashable['#'] = TRUE;
  isregexhashable['='] = TRUE;


  // Characters that are escaped in regexes.
  isregexescapable['['] = TRUE;
  isregexescapable['{'] = TRUE;
  isregexescapable['.'] = TRUE;
  isregexescapable['('] = TRUE;
  isregexescapable[')'] = TRUE;
  isregexescapable['.'] = TRUE;
  isregexescapable['?'] = TRUE;
  isregexescapable['^'] = TRUE;
  isregexescapable['*'] = TRUE;
  isregexescapable['+'] = TRUE;
  isregexescapable['$'] = TRUE;
  isregexescapable['|'] = TRUE;
  isregexescapable['\\'] = TRUE;

  yr_heap_alloc();
  
  #ifdef PTHREADS
  pthread_key_create(&key, NULL);
  #endif

}

void yr_finalize(void)
{
  yr_heap_free();
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
    //TODO: implement this
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
  return (int) (size_t) pthread_getspecific(key) - 1;
}
