/*
Copyright (c) 2022. The YARA Authors. All Rights Reserved.

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

#include <stdarg.h>
#include <string.h>
#include <yara/mem.h>
#include <yara/simple_str.h>
#include <yara/types.h>

static bool sstr_vappendf(SIMPLE_STR* ss, const char* fmt, va_list va)
{
  va_list va2;
  // Create copy because list will get consumed when getting the final length
  va_copy(va2, va);

  int size = vsnprintf(NULL, 0, fmt, va);
  if (size < 0)
    return false;

  if (ss->cap < ss->len + size + 1)
  {
    uint32_t new_size = (ss->len + size) * 2 + 64;
    char* tmp = yr_realloc(ss->str, new_size);
    if (!tmp)
      return false;

    ss->str = tmp;
    ss->cap = new_size;
  }

  ss->len += vsnprintf(ss->str + ss->len, ss->cap, fmt, va2);

  va_end(va2);
  return true;
}

SIMPLE_STR* sstr_new(const char* s)
{
  SIMPLE_STR* ss = yr_calloc(1, sizeof(SIMPLE_STR));
  if (!ss)
    return NULL;

  if (s)
  {
    uint32_t slen = strlen(s);
    ss->str = yr_malloc(slen + 1);
    if (!ss->str)
    {
      yr_free(ss);
      return NULL;
    }
    ss->len = slen;
    ss->cap = slen;
    memcpy(ss->str, s, slen + 1);
  }

  return ss;
}

SIMPLE_STR* sstr_newf(const char* fmt, ...)
{
  SIMPLE_STR* ss = sstr_new(NULL);
  if (!ss)
    return NULL;

  va_list va;
  va_start(va, fmt);
  bool ret = sstr_vappendf(ss, fmt, va);
  va_end(va);

  if (ret)
    return ss;

  sstr_free(ss);

  return NULL;
}

void sstr_free(SIMPLE_STR* ss)
{
  if (ss)
  {
    yr_free(ss->str);
    yr_free(ss);
  }
}

bool sstr_appendf(SIMPLE_STR* ss, const char* fmt, ...)
{
  va_list vlist;
  va_start(vlist, fmt);
  bool ret = sstr_vappendf(ss, fmt, vlist);
  va_end(vlist);

  return ret;
}

char* sstr_move(SIMPLE_STR* ss)
{
  char* ret = ss->str;
  ss->str = NULL;
  ss->len = 0;
  ss->cap = 0;

  return ret;
}
