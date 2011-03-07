/*
Copyright(c) 2011, Google, Inc. [mjwiacek@google.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#ifndef _REGEX_H 
#define _REGEX_H

#include "yara.h"

#ifdef __cplusplus
extern "C" {
#endif

void regex_free(REGEXP* regex);
int regex_exec(REGEXP* regex, const char *buffer, size_t buffer_size);
int regex_compile(REGEXP* output,
                  const char* pattern,
                  int anchored,
                  int case_insensitive,
                  const char** error_message,
                  int* error_offset);

#ifdef __cplusplus
}
#endif

#endif
