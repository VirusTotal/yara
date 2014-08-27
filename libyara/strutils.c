/*
Copyright (c) 2007. The YARA Authors. All Rights Reserved.

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

uint64_t xtoi(const char* hexstr)
{
  int l = strlen(hexstr);
  uint64_t r = 0;

  for (int i = 0; i < l; i++)
  {
    switch(hexstr[i])
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

size_t strlcpy(char *dst, const char *src, size_t size)
{
  register char *d = dst;
  register const char *s = src;
  register size_t n = size;

  /* Copy as many bytes as will fit */

  if (n != 0 && --n != 0)
  {
    do
    {
      if ((*d++ = *s++) == 0)
        break;

    } while (--n != 0);
  }

  /* Not enough room in dst, add NUL and traverse rest of src */

  if (n == 0)
  {
    if (size != 0)
      *d = '\0';    /* NUL-terminate dst */

    while (*s++);
  }

  return(s - src - 1);  /* count does not include NUL */
}

#endif


#if !HAVE_STRLCAT

size_t strlcat(char *dst, const char *src, size_t size)
{
  register char *d = dst;
  register const char *s = src;
  register size_t n = size;
  size_t dlen;

  /* Find the end of dst and adjust bytes left but don't go past end */

  while (n-- != 0 && *d != '\0')
    d++;

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

  return(dlen + (s - src));  /* count does not include NUL */
}

#endif
