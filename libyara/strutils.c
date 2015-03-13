/*
Copyright (c) 2007-2014. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>
#include <string.h>

#include <yara/strutils.h>

#include "config.h"

uint64_t xtoi(
    const char* hexstr)
{
  int l = strlen(hexstr);
  uint64_t r = 0;

  for (int i = 0; i < l; i++)
  {
    switch (hexstr[i])
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        r |= ((uint64_t)(hexstr[i] - '0')) << ((l - i - 1) * 4);
        break;
      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f':
        r |= ((uint64_t)(hexstr[i] - 'a' + 10)) << ((l - i - 1) * 4);
        break;
      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F':
        r |= ((uint64_t)(hexstr[i] - 'A' + 10)) << ((l - i - 1) * 4);
        break;
      default:
        i = l;  // force loop exit
    }
  }

  return r;
}

/*

strlcpy and strlcat are defined in FreeBSD and OpenBSD,
the following implementations were taken from OpenBSD.

*/

#if !HAVE_STRLCPY

size_t strlcpy(
    char* dst,
    const char* src,
    size_t size)
{
  register char* d = dst;
  register const char* s = src;
  register size_t n = size;

  // Copy as many bytes as will fit

  if (n != 0 && --n != 0)
  {
    do
    {
      if ((*d++ = *s++) == 0)
        break;

    } while (--n != 0);
  }

  // Not enough room in dst, add NUL and traverse rest of src

  if (n == 0)
  {
    if (size != 0)
      *d = '\0';    // NULL-terminate dst

    while (*s++);
  }

  return (s - src - 1);  // count does not include NULL
}

#endif


#if !HAVE_STRLCAT

size_t strlcat(
    char* dst,
    const char* src,
    size_t size)
{
  register char* d = dst;
  register const char* s = src;
  register size_t n = size;
  size_t dlen;

  // Find the end of dst and adjust bytes left but don't go past end

  while (n-- != 0 && *d != '\0') d++;

  dlen = d - dst;
  n = size - dlen;

  if (n == 0)
    return(dlen + strlen(s));

  while (*s != '\0')
  {
    if (n != 1)
    {
      *d++ = *s;
      n--;
    }
    s++;
  }

  *d = '\0';

  return (dlen + (s - src));  // count does not include NULL
}

#endif


int strnlen_w(
    const char* w_str)
{
  int len = 0;

  while (w_str[0] || w_str[1])
  {
    w_str += 2;
    len += 1;
  }

  return len;
}


int strcmp_w(
    const char* w_str,
    const char* str)
{
  while (*str != 0 && w_str[0] == *str && w_str[1] == 0)
  {
    w_str += 2;
    str += 1;
  }

  // Higher-order byte of wide char non-zero? -> w_str is larger than str

  if (w_str[1] != 0)
    return 1;

  return w_str[0] - *str;
}


size_t strlcpy_w(
    char* dst,
    const char* w_src,
    size_t n)
{
  register char* d = dst;
  register const char* s = w_src;

  while (n > 1 && *s != 0)
  {
    *d = *s;
    d += 1;
    n -= 1;
    s += 2;
  }

  while (*s) s += 2;

  *d = '\0';

  return (s - w_src) / 2;
}


#if !HAVE_MEMMEM
void* memmem(
    const void *haystack,
    size_t haystack_size,
    const void *needle,
    size_t needle_size)
{
  char *sp = (char *) haystack;
  char *pp = (char *) needle;
  char *eos = sp + haystack_size - needle_size;

  if (haystack == NULL || haystack_size == 0 ||
      needle == NULL || needle_size == 0)
    return NULL;

  while (sp <= eos)
  {
    if (*sp == *pp && memcmp(sp, pp, needle_size) == 0)
      return sp;

    sp++;
  }

  return NULL;
}
#endif
