/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

#include <ctype.h>
#include <string.h>
#include <yara/globals.h>
#include <yara/mem.h>
#include <yara/sizedstr.h>
#include <yara/types.h>

//
// ss_compare returns:
//     0 if s1 == s2
//    -1 if s1 < s2
//     1 if s1 > s2
//
int ss_compare(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  size_t i = 0;

  while (s1->length > i &&
         s2->length > i &&
         s1->c_string[i] == s2->c_string[i])
  {
    i++;
  }

  if (i == s1->length && i == s2->length)
    return 0;
  else if (i == s1->length)
    return -1;
  else if (i == s2->length)
    return 1;
  else if (s1->c_string[i] < s2->c_string[i])
    return -1;
  else
    return 1;
}

//
// ss_icompare is the case-insensitive version of ss_compare.
//
int ss_icompare(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  size_t i = 0;

  while (s1->length > i &&
         s2->length > i &&
         yr_lowercase[(uint8_t) s1->c_string[i]] ==
         yr_lowercase[(uint8_t) s2->c_string[i]])
  {
    i++;
  }

  if (i == s1->length && i == s2->length)
    return 0;
  else if (i == s1->length)
    return -1;
  else if (i == s2->length)
    return 1;
  else if (s1->c_string[i] < s2->c_string[i])
    return -1;
  else
    return 1;
}


//
// ss_contains returns true if the sized string s1 contains s2.
//
bool ss_contains(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  return memmem(s1->c_string, s1->length,
                s2->c_string, s2->length) != NULL;
}


//
// ss_icontains is the case-insensitive version of ss_contains.
//
bool ss_icontains(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  if (s1->length < s2->length)
    return false;

  for (uint32_t i = 0; i < s1->length - s2->length + 1; i++)
  {
    uint32_t j = 0;

    for (j = 0; j < s2->length; j++)
      if (yr_lowercase[(uint8_t) s1->c_string[i + j]] !=
          yr_lowercase[(uint8_t) s2->c_string[j]])
        break;

    if (j == s2->length)
      return true;
  }

  return false;
}


//
// ss_startswith returns true if the sized string s1 starts with s2.
//
bool ss_startswith(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  if (s1->length < s2->length)
    return false;

  for (uint32_t i = 0; i < s2->length; i++)
  {
    if (s1->c_string[i] != s2->c_string[i])
      return false;
  }

  return true;
}


//
// ss_istartswith is the case-insensitive version of ss_startswith
//
bool ss_istartswith(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  if (s1->length < s2->length)
    return false;

  for (uint32_t i = 0; i < s2->length; i++)
  {
    if (yr_lowercase[(uint8_t) s1->c_string[i]] !=
        yr_lowercase[(uint8_t) s2->c_string[i]])
      return false;
  }

  return true;
}


//
// ss_endswith returns true if the sized string s1 ends with s2.
//
bool ss_endswith(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  if (s1->length < s2->length)
    return false;

  for (uint32_t i = 0; i < s2->length; i++)
  {
    if (s1->c_string[s1->length - s2->length + i] != s2->c_string[i])
      return false;
  }

  return true;
}


bool ss_iendswith(
    SIZED_STRING* s1,
    SIZED_STRING* s2)
{
  if (s1->length < s2->length)
    return false;

  for (uint32_t i = 0; i < s2->length; i++)
  {
    if (yr_lowercase[(uint8_t) s1->c_string[s1->length - s2->length + i]] !=
        yr_lowercase[(uint8_t) s2->c_string[i]])
      return false;
  }

  return true;
}



SIZED_STRING* ss_dup(
    SIZED_STRING* s)
{
  SIZED_STRING* result = (SIZED_STRING*) yr_malloc(
      sizeof(SIZED_STRING) + s->length);

  if (result == NULL)
    return NULL;

  result->length = s->length;
  result->flags = s->flags;

  memcpy(result->c_string, s->c_string, s->length + 1);

  return result;
}


SIZED_STRING* ss_new(
    const char* s)
{
  SIZED_STRING* result;

  int length = strlen(s);

  result = (SIZED_STRING*) yr_malloc(sizeof(SIZED_STRING) + length);

  if (result == NULL)
    return NULL;

  result->length = length;
  result->flags = 0;

  // Copy the string and the null terminator.
  strcpy(result->c_string, s);

  return result;
}

//
// Convert a SIZED_STRING to a wide version. It is up to the caller to free
// the returned string.
//

SIZED_STRING* ss_convert_to_wide(
    SIZED_STRING* s)
{
  SIZED_STRING* wide = (SIZED_STRING*) yr_malloc(
      sizeof(SIZED_STRING) + s->length * 2);

  if (wide == NULL)
    return NULL;

  for (size_t i = 0; i < s->length; i++)
  {
    wide->c_string[i * 2] = s->c_string[i];
    wide->c_string[i * 2 + 1] = '\x00';
  }

  wide->length = s->length * 2;
  wide->flags = s->flags | STRING_FLAGS_WIDE;

  return wide;
}
