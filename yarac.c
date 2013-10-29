/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#ifndef WIN32

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

#else

#include <windows.h>
#include "getopt.h"

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#include "config.h"
#include "REVISION"

#ifndef MAX_PATH
#define MAX_PATH 255
#endif


void show_help()
{
  printf("usage:  yarac [OPTION]... [RULE_FILE]... OUTPUT_FILE\n");
  printf("options:\n");
  printf("  -d <identifier>=<value>   define external variable.\n");
  printf("  -v                        show version information.\n");
  printf("\nReport bugs to: <%s>\n", PACKAGE_BUGREPORT);
}


int is_numeric(
    const char *str)
{
  while(*str)
  {
    if(!isdigit(*str++))
      return 0;
  }

  return 1;
}


int process_cmd_line(
    YARA_COMPILER* compiler,
    int argc,
    char const* argv[])
{
  char* equal_sign;
  char* value;
  char c;
  opterr = 0;

  while ((c = getopt (argc, (char**) argv, "vd:")) != -1)
  {
    switch (c)
    {
      case 'v':
        printf("%s (rev:%s)\n", PACKAGE_STRING, REVISION);
        return 0;

      case 'd':
        equal_sign = strchr(optarg, '=');

        if (equal_sign != NULL)
        {
          *equal_sign = '\0';
          value = equal_sign + 1;

          if (is_numeric(value))
          {
            yr_compiler_define_integer_variable(
                compiler,
                optarg,
                atol(value));
          }
          else if (strcmp(value, "true") == 0  || strcmp(value, "false") == 0)
          {
            yr_compiler_define_boolean_variable(
                compiler,
                optarg,
                strcmp(value, "true") == 0);
          }
          else
          {
            yr_compiler_define_string_variable(
                compiler,
                optarg,
                value);
          }
        }
        break;

      case '?':

        if (isprint(optopt))
        {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        }
        else
        {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
        }
        return 0;

      default:
        abort();
    }
  }

  return 1;
}


void report_error(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
    fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
  else
    fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
}


int main(
    int argc,
    char const* argv[])
{
  int i, errors;

  YARA_COMPILER* compiler;
  YARA_RULES* rules;
  FILE* rule_file;

  clock_t start, end;

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    return 0;

  if (!process_cmd_line(compiler, argc, argv))
  {
    yr_compiler_destroy(compiler);
    return 0;
  }

  if (argc == 1 || optind == argc)
  {
    yr_compiler_destroy(compiler);
    show_help();
    return 0;
  }

  compiler->error_report_function = report_error;

  start = clock();

  for (i = optind; i < argc - 1; i++)
  {
    rule_file = fopen(argv[i], "r");

    if (rule_file != NULL)
    {
      yr_compiler_push_file_name(compiler, argv[i]);

      errors = yr_compiler_add_file(compiler, rule_file, NULL);

      fclose(rule_file);

      if (errors) // errors during compilation
      {
        yr_compiler_destroy(compiler);
        return 0;
      }
    }
    else
    {
      fprintf(stderr, "could not open file: %s\n", argv[i]);
    }
  }

  yr_compiler_get_rules(compiler, &rules);

  end = clock();

  printf( "Compiling time: %f s\n", (float)(end - start) / CLOCKS_PER_SEC);

  yr_rules_save(rules, argv[argc - 1]);

  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);

  return 1;
}

