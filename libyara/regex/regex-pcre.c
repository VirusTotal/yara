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

#include "regex.h"
#include <pcre.h>
#include <string.h>
#include "../yara.h"


int regex_exec(REGEXP* regex, const char *buffer, size_t buffer_size) {
  
  int ovector[3];
  int result = -1;
  char *s;
	
  if (!regex || buffer_size == 0)
    return 0;

  result = pcre_exec((pcre*)regex->regexp,       /* the compiled pattern */
                     (pcre_extra*)regex->extra,  /* extra data */
                     (char*) buffer,    /* the subject string */
                     buffer_size,       /* the length of the subject */
                     0,                 /* start at offset 0 in the subject */
                     0,                 /* default options */
                     ovector,           /* output vector for substring information */
                     sizeof(ovector));  /* number of elements in the output vector */
  if (result >= 0) {
    result = pcre_get_substring(
        (char*) buffer, ovector, 1, 0, (const char**) &s);
    if (result != PCRE_ERROR_NOMEMORY && result != PCRE_ERROR_NOSUBSTRING) {
      pcre_free_substring(s);
      return result;
    }
  }
  return -1;
}


void regex_free(REGEXP* regex) {
  if (!regex)
    return;

  if (regex->regexp) {
    pcre_free((pcre*)regex->regexp);
    regex->regexp = NULL;
  }

  if (regex->extra) {
    pcre_free((pcre_extra*)regex->extra);
    regex->extra = NULL;
  }
}


int regex_compile(REGEXP* output,
                  const char* pattern,
                  int anchored,
                  int case_insensitive,
                  char* error_message,
                  size_t error_message_size,
                  int* error_offset) {
  
  int pcre_options = 0;
  char *pcre_error = NULL;
					  
  if (!output || !pattern)
    return 0;

  memset(output, '\0', sizeof(REGEXP));

  if (anchored)
    pcre_options |= PCRE_ANCHORED;
  if (case_insensitive)
    pcre_options |= PCRE_CASELESS;

  output->regexp = (pcre*) pcre_compile(
      pattern, pcre_options, (const char **)&pcre_error, error_offset, NULL);
  if (output->regexp != NULL) {
    output->extra = (pcre_extra *)pcre_study(
        output->regexp, 0, (const char **)error_message);
  } else {
    if (error_message && error_message_size) {
      strncpy(error_message, pcre_error, error_message_size - 1);
      error_message[error_message_size - 1] = '\0';
    }
    // TODO: Handle fatal error here, consistently with how yara would.
    return 0;
  }

  return 1;
}
