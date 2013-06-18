/*
Copyright(c) 2011, Google, Inc. [mjwiacek@google.com].

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

#include <pcre.h>
#include <string.h>

#include "regex.h"

int yr_regex_exec(
    REGEXP* regex,
    int anchored,
    const char *buffer,
    size_t buffer_size)
{
  int ovector[3];
  int result = -1;
  int options = 0;
  char *s;

  if (!regex || buffer_size == 0)
      return 0;

  if (anchored)
    options = PCRE_ANCHORED;

  result = pcre_exec(
      (pcre*)regex->regexp,         // the compiled pattern
      (pcre_extra*)regex->extra,    // extra data
      (char*) buffer,               // the subject string
      buffer_size,                  // the length of the subject
      0,                            // start at offset 0 in the subject
      options,                      // options */
      ovector,                      // output vector for substring information
      sizeof(ovector)/sizeof(int)); // number of elements in the output vector

  if (result >= 0)
  {
    result = pcre_get_substring(
        (char*) buffer,
        ovector,
        1,
        0,
        (const char**) &s);

    if (result != PCRE_ERROR_NOMEMORY && result != PCRE_ERROR_NOSUBSTRING)
    {
      pcre_free_substring(s);
      return result;
    }
  }

  return -1;
}


void yr_regex_free(
    REGEXP* regex)
{
  if (!regex)
    return;

  if (regex->regexp)
  {
    pcre_free((pcre*)regex->regexp);
    regex->regexp = NULL;
  }

  if (regex->extra)
  {
    pcre_free((pcre_extra*)regex->extra);
    regex->extra = NULL;
  }
}


int yr_regex_compile(
    REGEXP* output,
    const char* pattern,
    int case_insensitive,
    char* error_message,
    size_t error_message_size,
    int* error_offset)
{
  int pcre_options = 0;
  char *pcre_error = NULL;

  if (!output || !pattern)
    return 0;

  memset(output, '\0', sizeof(REGEXP));

  if (case_insensitive)
    pcre_options |= PCRE_CASELESS;

  output->regexp = (pcre*) pcre_compile(
      pattern,
      pcre_options,
      (const char **) &pcre_error,
      error_offset,
      NULL);

  if (output->regexp != NULL)
  {
    output->extra = (pcre_extra *) pcre_study(
        output->regexp,
        0,
        (const char **) &pcre_error);
  }
  else
  {
    if (error_message && error_message_size)
    {
      strncpy(error_message, pcre_error, error_message_size - 1);
      error_message[error_message_size - 1] = '\0';
    }

    // TODO: Handle fatal error here, consistently with how yara would.
    return 0;
  }

  return 1;
}


int yr_regex_get_first_bytes(
    REGEXP* regex,
    uint8_t* table)
{
  unsigned char* t;

  int i;
  int b;
  int result;
  int count = 0;

  result = pcre_fullinfo(
      regex->regexp,
      regex->extra,
      PCRE_INFO_FIRSTTABLE,
      &t);

  if (result == 0 && t != NULL)
  {
    for (i = 0; i < 256; i++)
    {
      if (t[i / 8] & (1 << i % 8))
      {
        table[count] = i;
        count++;
      }
    }
  }

  result = pcre_fullinfo(
      regex->regexp,
      regex->extra,
      PCRE_INFO_FIRSTBYTE,
      &b);

  if (result == 0 && b > 0)
  {
    table[count] = b;
    count++;
  }

  return count;
}
