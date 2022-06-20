#ifndef _SIMPLESTR_H
#define _SIMPLESTR_H

#include <yara/types.h>

/* Simple dynamic string implementation for more readable/maintainable code
   Can be further optimized */
typedef struct _SIMPLE_STR
{
  uint32_t len;
  uint32_t cap;
  char* str;
} SIMPLE_STR, *PSIMPLE_STR;

SIMPLE_STR* sstr_new(const char* s);
SIMPLE_STR* sstr_newf(const char* fmt, ...);
void sstr_free(SIMPLE_STR* ss);
bool sstr_appendf(SIMPLE_STR* ss, const char* fmt, ...);
char* sstr_move(SIMPLE_STR* ss);

#endif