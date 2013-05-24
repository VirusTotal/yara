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


#include <string.h>
#include <re2/re2.h>
#include <re2/stringpiece.h>

#include "regex.h"

int regex_exec(
    REGEXP* regex,
    int anchored,
    const char *buffer,
    size_t buffer_size)
{
  if (!regex || buffer_size == 0)
    return 0;

  re2::StringPiece data(buffer, buffer_size);
  re2::StringPiece substring;
  re2::RE2::Anchor anchor = re2::RE2::UNANCHORED;

  if (anchored)
    anchor = re2::RE2::ANCHOR_START;

  re2::RE2* re_ptr = (re2::RE2*) regex->regexp;

  if (re_ptr->Match(data, 0, data.size(), anchor, &substring, 1))
    return substring.size();

  return -1;
}


void regex_free(REGEXP* regex)
{
  if (!regex)
    return;

  if (regex->regexp)
  {
    delete (re2::RE2*) regex->regexp;
    regex->regexp = NULL;
  }
}


int regex_compile(
    REGEXP* output,
    const char* pattern,
    int case_insensitive,
    char* error_message,
    size_t error_message_size,
    int* error_offset)
{
  if (!output || !pattern)
    return 0;

  memset(output, '\0', sizeof(REGEXP));

  RE2::Options options;
  options.set_log_errors(false);
  options.set_encoding(RE2::Options::EncodingLatin1);

  if (case_insensitive)
    options.set_case_sensitive(false);

  re2::StringPiece string_piece_pattern(pattern);
  output->regexp = (void *) new RE2(string_piece_pattern, options);

  if (output->regexp == NULL)
  {
    // TODO: Handle fatal error here, consistently with how yara would.
    return 0;
  }

  re2::RE2* re_ptr = (re2::RE2*)output->regexp;

  if (!re_ptr->ok())
  {
    if (error_message && error_message_size)
    {
      strncpy(error_message, re_ptr->error().c_str(), error_message_size - 1);
      error_message[error_message_size - 1] = '\0';
    }

    *error_offset = re_ptr->error().find(pattern);
    delete re_ptr;
    output->regexp = NULL;
    return 0;
  }

  return 1;
}

int regex_get_first_bytes(
    REGEXP* regex,
    unsigned char* table)
{
  return 0;
}
