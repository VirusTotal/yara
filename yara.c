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

#ifdef _MSC_VER
#define snprintf _snprintf
#endif


int recursive_search = FALSE;
int show_tags = FALSE;
int show_specified_tags = FALSE;
int show_specified_rules = FALSE;
int show_strings = FALSE;
int show_meta = FALSE;
int fast_scan = FALSE;
int negate = FALSE;
int count = 0;
int limit = 0;


typedef struct _TAG
{
  char* identifier;
  struct _TAG* next;

} TAG;


typedef struct _IDENTIFIER
{
  char* name;
  struct _IDENTIFIER* next;

} IDENTIFIER;


#define EXTERNAL_TYPE_INTEGER   1
#define EXTERNAL_TYPE_BOOLEAN   2
#define EXTERNAL_TYPE_STRING    3

typedef struct _EXTERNAL
{
  char type;
  char*  name;
  union {
    char* string;
    int integer;
    int boolean;
  };
  struct _EXTERNAL* next;

} EXTERNAL;


TAG* specified_tags_list = NULL;
IDENTIFIER* specified_rules_list = NULL;
EXTERNAL* externals_list = NULL;

#define USAGE \
"usage:  yara [OPTION]... RULES_FILE FILE | PID\n"\
"options:\n"\
"  -t <tag>                 only print rules tagged as <tag>.\n"\
"  -i <identifier>          only print rules named <identifier>.\n"\
"  -n                       only print not satisfied rules (negate).\n"\
"  -g                       print tags.\n"\
"  -m                       print metadata.\n"\
"  -s                       print matching strings.\n"\
"  -l <number>              abort scanning after matching <number> rules.\n"\
"  -d <identifier>=<value>  define external variable.\n"\
"  -r                       recursively search directories.\n"\
"  -v                       show version information.\n"

void show_help()
{
  printf(USAGE);
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


#ifdef WIN32

int is_directory(
    const char* path)
{
  if (GetFileAttributes(path) & FILE_ATTRIBUTE_DIRECTORY)
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

int scan_dir(
    const char* dir,
    int recursive,
    YARA_RULES* rules,
    YARACALLBACK callback)
{
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;

  char full_path[MAX_PATH];
  static char path_and_mask[MAX_PATH];

  int result = ERROR_SUCCESS;

  snprintf(path_and_mask, sizeof(path_and_mask), "%s\\*", dir);

  hFind = FindFirstFile(path_and_mask, &FindFileData);

  if (hFind != INVALID_HANDLE_VALUE)
  {
    do
    {
      snprintf(full_path, sizeof(full_path), "%s\\%s",
               dir, FindFileData.cFileName);

      if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      {
        result = yr_rules_scan_file(
            rules,
            full_path,
            callback,
            full_path,
            TRUE);
      }
      else if (recursive && FindFileData.cFileName[0] != '.' )
      {
        result = scan_dir(full_path, recursive, rules, callback);
      }

      if (result != ERROR_SUCCESS)
        break;

    } while (FindNextFile(hFind, &FindFileData));

    FindClose(hFind);
  }

  return result;
}

#else

int is_directory(
    const char* path)
{
  struct stat st;

  if (stat(path,&st) == 0)
  {
    return S_ISDIR(st.st_mode);
  }

  return 0;
}

int scan_dir(
    const char* dir,
    int recursive,
    YARA_RULES* rules,
    YARACALLBACK callback)
{
  DIR *dp;
  struct dirent *de;
  struct stat st;
  char full_path[MAX_PATH];

  int result = ERROR_SUCCESS;

  dp = opendir(dir);

  if (dp)
  {
    de = readdir(dp);

    while (de)
    {
      snprintf(full_path, sizeof(full_path), "%s/%s", dir, de->d_name);

      int err = stat(full_path,&st);

      if (err == 0)
      {
        if(S_ISREG(st.st_mode))
        {
          result = yr_rules_scan_file(
              rules,
              full_path,
              callback,
              full_path,
              fast_scan);
        }
        else if(recursive && S_ISDIR(st.st_mode) && de->d_name[0] != '.')
        {
          result = scan_dir(full_path, recursive, rules, callback);
        }

        if (result != ERROR_SUCCESS)
          break;
      }

      de = readdir(dp);
    }

    closedir(dp);
  }

  return result;
}

#endif

void print_string(
    unsigned char* data,
    unsigned int length,
    int unicode)
{
  unsigned int i;
  char* str;

  str = (char*) (data);

  for (i = 0; i < length; i++)
  {
    if (str[i] >= 32 && str[i] <= 126)
    {
      printf("%c",str[i]);
    }
    else
    {
      printf("\\x%02x", str[i]);
    }

    if (unicode) i++;
  }

  printf("\n");
}

void print_hex_string(
    unsigned char* data,
    unsigned int length)
{
  unsigned int i;

  for (i = 0; i < length; i++)
  {
    printf("%02X ", data[i]);
  }

  printf("\n");
}


int callback(RULE* rule, void* data)
{
  TAG* tag;
  IDENTIFIER* identifier;
  STRING* string;
  MATCH* match;
  META* meta;

  char* tag_name;
  size_t tag_length;
  int rule_match;
  int string_found;
  int show = TRUE;

  if (show_specified_tags)
  {
    show = FALSE;
    tag = specified_tags_list;

    while (tag != NULL)
    {
      tag_name = rule->tags;
      tag_length = tag_name != NULL ? strlen(tag_name) : 0;

      while (tag_length > 0)
      {
        if (strcmp(tag_name, tag->identifier) == 0)
        {
          show = TRUE;
          break;
        }

        tag_name += tag_length + 1;
        tag_length = strlen(tag_name);
      }

      tag = tag->next;
    }
  }

  if (show_specified_rules)
  {
    show = FALSE;
    identifier = specified_rules_list;

    while (identifier != NULL)
    {
      if (strcmp(identifier->name, rule->identifier) == 0)
      {
        show = TRUE;
        break;
      }

      identifier = identifier->next;
    }
  }

  rule_match = (rule->flags & RULE_FLAGS_MATCH);

  show = show && ((!negate && rule_match) || (negate && !rule_match));

  if (show)
  {
    printf("%s ", rule->identifier);

    if (show_tags)
    {
      printf("[");

      tag_name = rule->tags;
      tag_length = tag_name != NULL ? strlen(tag_name) : 0;

      while (tag_length > 0)
      {
        printf("%s", tag_name);
        tag_name += tag_length + 1;
        tag_length = strlen(tag_name);

        if (tag_length > 0)
          printf(",");
      }

      printf("] ");
    }

    // Show meta-data.

    if (show_meta)
    {
      meta = rule->metas;

      printf("[");

      while(!META_IS_NULL(meta))
      {
        if (meta->type == META_TYPE_INTEGER)
          printf("%s=%d", meta->identifier, meta->integer);
        else if (meta->type == META_TYPE_BOOLEAN)
          printf("%s=%s", meta->identifier, meta->integer ? "true" : "false");
        else
          printf("%s=\"%s\"", meta->identifier, meta->string);

        meta++;

        if (!META_IS_NULL(meta))
          printf(",");
      }

      printf("] ");
    }

    printf("%s\n", (char*) data);

    // Show matched strings.

    if (show_strings)
    {
      string = rule->strings;

      while (!STRING_IS_NULL(string))
      {
        string_found = string->flags & STRING_FLAGS_FOUND;

        if (string_found)
        {
          match = string->matches_list_head;

          while (match != NULL)
          {
            printf("0x%zx:%s: ", match->first_offset, string->identifier);

            if (STRING_IS_HEX(string))
            {
              print_hex_string(match->data, match->length);
            }
            else if (STRING_IS_WIDE(string))
            {
              print_string(match->data, match->length, TRUE);
            }
            else
            {
              print_string(match->data, match->length, FALSE);
            }

            match = match->next;
          }
        }

        string++;
      }
    }
  }

  if (rule_match)
    count++;

  if (limit != 0 && count >= limit)
    return CALLBACK_ABORT;

  return CALLBACK_CONTINUE;
}


int process_cmd_line(
    int argc,
    char const* argv[])
{
  char* equal_sign;
  char* value;
  int c;

  TAG* tag;
  IDENTIFIER* identifier;
  EXTERNAL* external;

  opterr = 0;

  while ((c = getopt (argc, (char**) argv, "rnsvgml:t:i:d:f")) != -1)
  {
    switch (c)
    {
      case 'v':
        printf("%s (rev:%s)\n", PACKAGE_STRING, REVISION);
        return 0;

      case 'r':
        recursive_search = TRUE;
        break;

      case 'g':
        show_tags = TRUE;
        break;

      case 'm':
        show_meta = TRUE;
        break;

      case 's':
        show_strings = TRUE;
        break;

      case 'f':
        fast_scan = TRUE;
        break;

      case 'n':
        negate = TRUE;
        break;

      case 't':
        show_specified_tags = TRUE;
        tag = malloc(sizeof(TAG));

        if (tag != NULL)
        {
          tag->identifier = optarg;
          tag->next = specified_tags_list;
          specified_tags_list = tag;
        }
        else
        {
          fprintf (stderr, "Not enough memory.\n", optopt);
          return 0;
        }
        break;

      case 'i':
        show_specified_rules = TRUE;
        identifier = malloc(sizeof(IDENTIFIER));

        if (identifier != NULL)
        {
          identifier->name = optarg;
          identifier->next = specified_rules_list;
          specified_rules_list = identifier;
        }
        else
        {
          fprintf (stderr, "Not enough memory.\n", optopt);
          return 0;
        }
        break;

      case 'd':
        equal_sign = strchr(optarg, '=');
        external = malloc(sizeof(EXTERNAL));

        if (external != NULL)
        {
          external->name = optarg;
          external->next = externals_list;
          externals_list = external;
        }
        else
        {
          fprintf (stderr, "Not enough memory.\n", optopt);
          return 0;
        }

        if (equal_sign != NULL)
        {
          *equal_sign = '\0';
          value = equal_sign + 1;

          if (is_numeric(value))
          {
            external->type = EXTERNAL_TYPE_INTEGER;
            external->integer = atoi(value);
          }
          else if (strcmp(value, "true") == 0  || strcmp(value, "false") == 0)
          {
            external->type = EXTERNAL_TYPE_BOOLEAN;
            external->boolean = strcmp(value, "true") == 0;
          }
          else
          {
            external->type = EXTERNAL_TYPE_STRING;
            external->string = value;
          }
        }
        break;

      case 'l':
        limit = atoi(optarg);
        break;

      case '?':

        if (optopt == 't')
        {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        }
        else if (isprint (optopt))
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


void cleanup()
{
  IDENTIFIER* identifier;
  IDENTIFIER* next_identifier;
  TAG* tag;
  TAG* next_tag;
  EXTERNAL* external;
  EXTERNAL* next_external;

  tag = specified_tags_list;

  while(tag != NULL)
  {
    next_tag = tag->next;
    free(tag);
    tag = next_tag;
  }

  external = externals_list;

  while(external != NULL)
  {
    next_external = external->next;
    free(external);
    external = next_external;
  }

  identifier = specified_rules_list;

  while(identifier != NULL)
  {
    next_identifier = identifier->next;
    free(identifier);
    identifier = next_identifier;
  }
}


int main(
    int argc,
    char const* argv[])
{
  YARA_COMPILER* compiler;
  YARA_RULES* rules;
  FILE* rule_file;
  EXTERNAL* external;

  int pid;
  int errors;
  int result;

  if (!process_cmd_line(argc, argv))
    return 0;

  if (argc == 1 || optind == argc)
  {
    show_help();
    return 0;
  }

  yr_initialize();

  if (yr_rules_load(argv[optind], &rules) == ERROR_SUCCESS)
  {
    external = externals_list;

    while (external != NULL)
    {
      switch (external->type)
      {
        case EXTERNAL_TYPE_INTEGER:
          yr_rules_define_integer_variable(
              rules,
              external->name,
              external->integer);
          break;

        case EXTERNAL_TYPE_BOOLEAN:
          yr_rules_define_boolean_variable(
              rules,
              external->name,
              external->boolean);
          break;

        case EXTERNAL_TYPE_STRING:
          yr_rules_define_string_variable(
              rules,
              external->name,
              external->string);
          break;
      }
      external = external->next;
    }
  }
  else
  {
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
      return 0;

    external = externals_list;

    while (external != NULL)
    {
      switch (external->type)
      {
        case EXTERNAL_TYPE_INTEGER:
          yr_compiler_define_integer_variable(
              compiler,
              external->name,
              external->integer);
          break;

        case EXTERNAL_TYPE_BOOLEAN:
          yr_compiler_define_boolean_variable(
              compiler,
              external->name,
              external->boolean);
          break;

        case EXTERNAL_TYPE_STRING:
          yr_compiler_define_string_variable(
              compiler,
              external->name,
              external->string);
          break;
      }
      external = external->next;
    }

    compiler->error_report_function = report_error;
    rule_file = fopen(argv[optind], "r");

    if (rule_file != NULL)
    {
      yr_compiler_push_file_name(compiler, argv[optind]);

      errors = yr_compiler_add_file(compiler, rule_file, NULL);

      fclose(rule_file);

      if (errors == 0)
        yr_compiler_get_rules(compiler, &rules);

      yr_compiler_destroy(compiler);

      if (errors > 0)
      {
        yr_finalize();
        return 0;
      }
    }
    else
    {
      fprintf(stderr, "could not open file: %s\n", argv[optind]);
      return 0;
    }
  }

  if (is_numeric(argv[argc - 1]))
  {
    pid = atoi(argv[argc - 1]);
    result = yr_rules_scan_proc(
        rules,
        pid,
        callback,
        (void*) argv[argc - 1],
        fast_scan);
  }
  else if (is_directory(argv[argc - 1]))
  {
    result = scan_dir(
        argv[argc - 1],
        recursive_search,
        rules,
        callback);
  }
  else
  {
    result = yr_rules_scan_file(
        rules,
        argv[argc - 1],
        callback,
        (void*) argv[argc - 1],
        fast_scan);
  }

  switch (result)
  {
    case ERROR_SUCCESS:
      break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      fprintf(stderr, "can not attach to process (try running as root)\n");
      break;
    case ERROR_INSUFICIENT_MEMORY:
      fprintf(stderr, "not enough memory\n");
      break;
    default:
      fprintf(stderr, "internal error: %d\n", result);
      break;
  }

  yr_rules_destroy(rules);
  yr_finalize();
  cleanup();

  return 1;
}

