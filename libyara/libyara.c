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


char isregexescapable[256];
char isregexhashable[256];
char isalphanum[256];
char lowercase[256];


void yr_initialize()
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
}


void yr_finalize()
{
  yr_heap_free();
}







