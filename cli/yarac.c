/*
Copyright (c) 2013-2021. The YARA Authors. All Rights Reserved.

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

#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#else

#include <windows.h>

#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#include "args.h"
#include "common.h"

#define MAX_ARGS_EXT_VAR 32

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }

typedef struct COMPILER_RESULTS
{
  int errors;
  int warnings;

} COMPILER_RESULTS;

static char* atom_quality_table;
static char* ext_vars[MAX_ARGS_EXT_VAR + 1];
static bool ignore_warnings = false;
static bool show_version = false;
static bool show_help = false;
static bool strict_escape = false;
static bool fail_on_warnings = false;
static long max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;

#define USAGE_STRING \
  "Usage: yarac [OPTION]... [NAMESPACE:]SOURCE_FILE... OUTPUT_FILE"

args_option_t options[] = {
    OPT_STRING(
        0,
        _T("atom-quality-table"),
        &atom_quality_table,
        _T("path to a file with the atom quality table"),
        _T("FILE")),

    OPT_STRING_MULTI(
        'd',
        _T("define"),
        &ext_vars,
        MAX_ARGS_EXT_VAR,
        _T("define external variable"),
        _T("VAR=VALUE")),

    OPT_BOOLEAN(
        0,
        _T("fail-on-warnings"),
        &fail_on_warnings,
        _T("fail on warnings")),

    OPT_BOOLEAN('h', _T("help"), &show_help, _T("show this help and exit")),

    OPT_BOOLEAN(
        'E',
        _T("strict-escape"),
        &strict_escape,
        _T("warn on unknown escape sequences")),

    OPT_LONG(
        0,
        _T("max-strings-per-rule"),
        &max_strings_per_rule,
        _T("set maximum number of strings per rule (default=10000)"),
        _T("NUMBER")),

    OPT_BOOLEAN(
        'w',
        _T("no-warnings"),
        &ignore_warnings,
        _T("disable warnings")),

    OPT_BOOLEAN(
        'v',
        _T("version"),
        &show_version,
        _T("show version information")),

    OPT_END(),
};

static void report_error(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  char* msg_type;

  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    msg_type = "error";
  }
  else if (!ignore_warnings)
  {
    COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*) user_data;
    compiler_results->warnings++;
    msg_type = "warning";
  }
  else
  {
    return;
  }

  if (rule != NULL)
  {
    fprintf(
        stderr,
        "%s: rule \"%s\" in %s(%d): %s\n",
        msg_type,
        rule->identifier,
        file_name,
        line_number,
        message);
  }
  else
  {
    fprintf(
        stderr, "%s: %s(%d): %s\n", msg_type, file_name, line_number, message);
  }
}

int _tmain(int argc, const char_t** argv)
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

    args_print_usage(options, 40);
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

  if (yr_initialize() != ERROR_SUCCESS)
    exit_with_code(EXIT_FAILURE);

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    exit_with_code(EXIT_FAILURE);

  if (define_external_variables(ext_vars, NULL, compiler) != ERROR_SUCCESS)
    exit_with_code(EXIT_FAILURE);

  if (atom_quality_table != NULL)
  {
    result = yr_compiler_load_atom_quality_table(
        compiler, atom_quality_table, 0);

    if (result != ERROR_SUCCESS)
    {
      fprintf(stderr, "error loading atom quality table\n");
      exit_with_code(EXIT_FAILURE);
    }
  }

  cr.errors = 0;
  cr.warnings = 0;

  yr_set_configuration_uint32(
      YR_CONFIG_MAX_STRINGS_PER_RULE, max_strings_per_rule);

  yr_compiler_set_callback(compiler, report_error, &cr);

  if (strict_escape)
    compiler->strict_escape = true;
  else
    compiler->strict_escape = false;

  if (!compile_files(compiler, argc, argv))
    exit_with_code(EXIT_FAILURE);

  if (cr.errors > 0)
    exit_with_code(EXIT_FAILURE);

  if (fail_on_warnings && cr.warnings > 0)
    exit_with_code(EXIT_FAILURE);

  result = yr_compiler_get_rules(compiler, &rules);

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: %d\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  // Not using yr_rules_save because it does not have support for unicode
  // file names. Instead use open _tfopen for openning the file and
  // yr_rules_save_stream for writing the rules to it.

  FILE* fh = _tfopen(argv[argc - 1], _T("wb"));

  if (fh != NULL)
  {
    YR_STREAM stream;

    stream.user_data = fh;
    stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

    result = yr_rules_save_stream(rules, &stream);

    fclose(fh);
  }

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

  args_free(options);

  return result;
}
