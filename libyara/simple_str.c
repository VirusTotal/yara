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
