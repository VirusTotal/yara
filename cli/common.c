/*
Copyright (c) 2017-2021. The YARA Authors. All Rights Reserved.

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

#if defined(_WIN32)
#include <io.h>

// In Visual C++ use _taccess_s, in MinGW use _access_s.
#if defined(_MSC_VER)
#define access _taccess_s
#else
#define access _access_s
#endif

#else  // not _WIN32
#include <unistd.h>
#endif

#include <stdbool.h>
#include <yara.h>

#include "common.h"
#include "unicode.h"

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }

#if defined(_UNICODE)
char* unicode_to_ansi(const char_t* str)
{
  if (str == NULL)
    return NULL;

  int str_len = WideCharToMultiByte(
      CP_ACP, WC_NO_BEST_FIT_CHARS, str, -1, NULL, 0, NULL, NULL);

  char* str_utf8 = (char*) malloc(str_len);

  WideCharToMultiByte(
      CP_ACP, WC_NO_BEST_FIT_CHARS, str, -1, str_utf8, str_len, NULL, NULL);

  return str_utf8;
}
#endif

bool compile_files(YR_COMPILER* compiler, int argc, const char_t** argv)
{
  for (int i = 0; i < argc - 1; i++)
  {
    FILE* rule_file;
    const char_t* ns;
    const char_t* file_name;
    char_t* colon = NULL;
    int errors;

    if (access(argv[i], 0) != 0)
    {
      // A file with the name specified by the command-line argument wasn't
      // found, it may be because the name is prefixed with a namespace, so
      // lets try to find the colon that separates the namespace from the
      /// actual file name.
      colon = (char_t*) _tcschr(argv[i], ':');
    }

    // The namespace delimiter must be a colon not followed by a backslash,
    // as :\ is the separator for a drive letter in Windows.
    if (colon && *(colon + 1) != '\\')
    {
      file_name = colon + 1;
      *colon = '\0';
      ns = argv[i];
    }
    else
    {
      file_name = argv[i];
      ns = NULL;
    }

    if (_tcscmp(file_name, _T("-")) == 0)
      rule_file = stdin;
    else
      rule_file = _tfopen(file_name, _T("r"));

    if (rule_file == NULL)
    {
      _ftprintf(stderr, _T("error: could not open file: %s\n"), file_name);
      return false;
    }

#if defined(_UNICODE)
    char* file_name_mb = unicode_to_ansi(file_name);
    char* ns_mb = unicode_to_ansi(ns);

    errors = yr_compiler_add_file(compiler, rule_file, ns_mb, file_name_mb);

    free(file_name_mb);
    free(ns_mb);
#else
    errors = yr_compiler_add_file(compiler, rule_file, ns, file_name);
#endif

    fclose(rule_file);

    if (errors > 0)
      return false;
  }

  return true;
}

int define_external_variables(
    char** ext_vars,
    YR_RULES* rules,
    YR_COMPILER* compiler)
{
  int result = ERROR_SUCCESS;

  for (int i = 0; ext_vars[i] != NULL; i++)
  {
    char* equal_sign = strchr(ext_vars[i], '=');

    if (!equal_sign)
    {
      fprintf(stderr, "error: wrong syntax for `-d` option.\n");
      return ERROR_SUCCESS;
    }

    // Replace the equal sign with null character to split the external
    // variable definition (i.e: myvar=somevalue) in two strings: identifier
    // and value.

    *equal_sign = '\0';

    char* value = equal_sign + 1;
    char* identifier = ext_vars[i];

    if (is_float(value))
    {
      if (rules != NULL)
        result = yr_rules_define_float_variable(rules, identifier, atof(value));

      if (compiler != NULL)
        result = yr_compiler_define_float_variable(
            compiler, identifier, atof(value));
    }
    else if (is_integer(value))
    {
      if (rules != NULL)
        result = yr_rules_define_integer_variable(
            rules, identifier, atoi(value));

      if (compiler != NULL)
        result = yr_compiler_define_integer_variable(
            compiler, identifier, atoi(value));
    }
    else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
    {
      if (rules != NULL)
        result = yr_rules_define_boolean_variable(
            rules, identifier, strcmp(value, "true") == 0);

      if (compiler != NULL)
        result = yr_compiler_define_boolean_variable(
            compiler, identifier, strcmp(value, "true") == 0);
    }
    else
    {
      if (rules != NULL)
        result = yr_rules_define_string_variable(rules, identifier, value);

      if (compiler != NULL)
        result = yr_compiler_define_string_variable(
            compiler, identifier, value);
    }
  }

  return result;
}

bool is_integer(const char* str)
{
  if (*str == '-')
    str++;

  if (*str == '\0')
    return false;

  while (*str)
  {
    if (!isdigit(*str))
      return false;
    str++;
  }

  return true;
}

bool is_float(const char* str)
{
  bool has_dot = false;

  if (*str == '-')  // skip the minus sign if present
    str++;

  if (*str == '.')  // float can't start with a dot
    return false;

  while (*str)
  {
    if (*str == '.')
    {
      if (has_dot)  // two dots, not a float
        return false;

      has_dot = true;
    }
    else if (!isdigit(*str))
    {
      return false;
    }

    str++;
  }

  return has_dot;  // to be float must contain a dot
}
