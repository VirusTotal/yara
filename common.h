/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

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


#ifndef COMMON_H
#define COMMON_H

#define exit_with_code(code) { result = code; goto _exit; }


int compile_files(
    YR_COMPILER* compiler,
    int argc,
    const char** argv)
{
  for (int i = 0; i < argc - 1; i++)
  {
    const char* ns;
    const char* file_name;
    char* colon = (char*) strchr(argv[i], ':');
    int errors;

    // Namespace delimiter must be a colon not followed by a slash or backslash
    if (colon && *(colon + 1) != '\\' && *(colon + 1) != '/')
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

    FILE* rule_file = fopen(file_name, "r");

    if (rule_file == NULL)
    {
      fprintf(stderr, "error: could not open file: %s\n", file_name);
      return FALSE;
    }

    errors = yr_compiler_add_file(compiler, rule_file, ns, file_name);

    fclose(rule_file);

    if (errors > 0)
      return FALSE;
  }

  return TRUE;
}


int is_integer(const char *str)
{
  if (*str == '-')
    str++;

  while(*str)
  {
    if (!isdigit(*str))
      return FALSE;
    str++;
  }

  return TRUE;
}


int is_float(const char *str)
{
  int has_dot = FALSE;

  if (*str == '-')      // skip the minus sign if present
    str++;

  if (*str == '.')      // float can't start with a dot
    return FALSE;

  while(*str)
  {
    if (*str == '.')
    {
      if (has_dot)      // two dots, not a float
        return FALSE;

      has_dot = TRUE;
    }
    else if (!isdigit(*str))
    {
      return FALSE;
    }

    str++;
  }

  return has_dot; // to be float must contain a dot
}

#endif