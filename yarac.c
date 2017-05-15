/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#ifndef _WIN32

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

#else

#include <windows.h>

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <yara.h>

#include "args.h"


#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#define MAX_ARGS_EXT_VAR   32


typedef struct COMPILER_RESULTS
{
  int errors;
  int warnings;

} COMPILER_RESULTS;


static char* ext_vars[MAX_ARGS_EXT_VAR + 1];
static int ignore_warnings = FALSE;
static int show_version = FALSE;
static int show_help = FALSE;
static int fail_on_warnings = FALSE;


#define USAGE_STRING \
    "Usage: yarac [OPTION]... [NAMESPACE:]SOURCE_FILE... OUTPUT_FILE"

args_option_t options[] =
{
  OPT_STRING_MULTI('d', NULL, &ext_vars, MAX_ARGS_EXT_VAR,
      "define external variable", "VAR=VALUE"),

  OPT_BOOLEAN('w', "no-warnings", &ignore_warnings,
      "disable warnings"),

  OPT_BOOLEAN(0, "fail-on-warnings", &fail_on_warnings,
      "fail on warnings"),

  OPT_BOOLEAN('v', "version", &show_version,
      "show version information"),

  OPT_BOOLEAN('h', "help", &show_help,
      "show this help and exit"),

  OPT_END()
};


int is_numeric(
    const char *str)
{
  while(*str)
  {
    if (!isdigit(*str))
      return 0;
    str++;
  }

  return 1;
}


void report_error(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
  }
  else if (!ignore_warnings)
  {
    COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*) user_data;
    compiler_results->warnings++;

    fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
  }
}


int define_external_variables(
    YR_COMPILER* compiler)
{
  for (int i = 0; ext_vars[i] != NULL; i++)
  {
    char* equal_sign = strchr(ext_vars[i], '=');

    if (!equal_sign)
    {
      fprintf(stderr, "error: wrong syntax for `-d` option.\n");
      return FALSE;
    }

    // Replace the equal sign with null character to split the external
    // variable definition (i.e: myvar=somevalue) in two strings: identifier
    // and value.

    *equal_sign = '\0';

    char* identifier = ext_vars[i];
    char* value = equal_sign + 1;

    if (is_numeric(value))
    {
      yr_compiler_define_integer_variable(
          compiler,
          identifier,
          atoi(value));
    }
    else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
    {
      yr_compiler_define_boolean_variable(
          compiler,
          identifier,
          strcmp(value, "true") == 0);
    }
    else
    {
      yr_compiler_define_string_variable(
          compiler,
          identifier,
          value);
    }
  }

  return TRUE;
}


#define exit_with_code(code) { result = code; goto _exit; }


int main(
    int argc,
    const char** argv)
{
  COMPILER_RESULTS cr;

  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

  int result;

  argc = args_parse(options, argc, argv);

  if (show_version)
  {
    printf("%s\n", YR_VERSION);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf("%s\n\n", USAGE_STRING);

    args_print_usage(options, 35);
    printf("\nSend bug reports and suggestions to: vmalvarez@virustotal.com\n");

    return EXIT_SUCCESS;
  }

  if (argc < 2)
  {
    fprintf(stderr, "yarac: wrong number of arguments\n");
    fprintf(stderr, "%s\n\n", USAGE_STRING);
    fprintf(stderr, "Try `--help` for more options\n");

    exit_with_code(EXIT_FAILURE);
  }

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
    exit_with_code(EXIT_FAILURE);

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    exit_with_code(EXIT_FAILURE);

  if (!define_external_variables(compiler))
    exit_with_code(EXIT_FAILURE);

  cr.errors = 0;
  cr.warnings = 0;

  yr_compiler_set_callback(compiler, report_error, &cr);

  for (int i = 0; i < argc - 1; i++)
  {
    const char* ns;
    const char* file_name;
    char* colon = (char*) strchr(argv[i], ':');

    if (colon)
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

    if (rule_file != NULL)
    {
      cr.errors = yr_compiler_add_file(
          compiler, rule_file, ns, file_name);

      fclose(rule_file);

      if (cr.errors) // errors during compilation
        exit_with_code(EXIT_FAILURE);

      if (fail_on_warnings && cr.warnings > 0)
        exit_with_code(EXIT_FAILURE);
    }
    else
    {
      fprintf(stderr, "error: could not open file: %s\n", file_name);
    }
  }

  result = yr_compiler_get_rules(compiler, &rules);

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: %d\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  result = yr_rules_save(rules, argv[argc - 1]);

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: %d\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  result = EXIT_SUCCESS;

_exit:

  if (compiler != NULL)
    yr_compiler_destroy(compiler);

  if (rules != NULL)
    yr_rules_destroy(rules);

  yr_finalize();

  return result;
}
