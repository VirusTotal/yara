/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

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
#include <inttypes.h>

#else

#include <windows.h>
#include "getopt.h"

#define PRIx64 "llx"

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <yara.h>

#include "threading.h"
#include "config.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define USAGE \
"usage:  yara [OPTION]... RULES_FILE FILE | PID\n"\
"options:\n"\
"  -t <tag>                 only print rules tagged as <tag>.\n"\
"  -i <identifier>          only print rules named <identifier>.\n"\
"  -n                       only print not satisfied rules (negate).\n"\
"  -g                       print tags.\n"\
"  -m                       print metadata.\n"\
"  -s                       print matching strings.\n"\
"  -l <number>              abort scanning after matching a number rules.\n"\
"  -a <seconds>             abort scanning after a number of seconds has elapsed.\n"\
"  -d <identifier>=<value>  define external variable.\n"\
"  -r                       recursively search directories.\n"\
"  -f                       fast matching mode.\n"\
"  -w                       disable warnings.\n"\
"  -v                       show version information.\n"

#define EXTERNAL_TYPE_INTEGER   1
#define EXTERNAL_TYPE_BOOLEAN   2
#define EXTERNAL_TYPE_STRING    3

#define ERROR_COULD_NOT_CREATE_THREAD  100

#ifndef MAX_PATH
#define MAX_PATH 255
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#define strdup _strdup
#endif

#define MAX_QUEUED_FILES 64


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


typedef struct _QUEUED_FILE {

  char* path;

} QUEUED_FILE;


int recursive_search = FALSE;
int show_tags = FALSE;
int show_specified_tags = FALSE;
int show_specified_rules = FALSE;
int show_strings = FALSE;
int show_warnings = TRUE;
int show_meta = FALSE;
int fast_scan = FALSE;
int negate = FALSE;
int count = 0;
int limit = 0;
int timeout = 0;
int threads = 8;


TAG* specified_tags_list = NULL;
IDENTIFIER* specified_rules_list = NULL;
EXTERNAL* externals_list = NULL;


// file_queue is size-limited queue stored as a circular array, files are
// removed from queue_head position and new files are added at queue_tail
// position. The array has room for one extra element to avoid queue_head
// being equal to queue_tail in a full queue. The only situation where
// queue_head == queue_tail is when queue is empty.

QUEUED_FILE file_queue[MAX_QUEUED_FILES + 1];

int queue_head;
int queue_tail;

SEMAPHORE used_slots;
SEMAPHORE unused_slots;

MUTEX queue_mutex;
MUTEX output_mutex;


void file_queue_init()
{
  queue_tail = 0;
  queue_head = 0;

  mutex_init(&queue_mutex);
  semaphore_init(&used_slots, 0);
  semaphore_init(&unused_slots, MAX_QUEUED_FILES);
}


void file_queue_destroy()
{
  mutex_destroy(&queue_mutex);
  semaphore_destroy(&unused_slots);
  semaphore_destroy(&used_slots);
}


void file_queue_finish()
{
  int i;

  for (i = 0; i < MAX_THREADS; i++)
    semaphore_release(&used_slots);
}


void file_queue_put(
    const char* file_path)
{
  semaphore_wait(&unused_slots);
  mutex_lock(&queue_mutex);

  file_queue[queue_tail].path = strdup(file_path);
  queue_tail = (queue_tail + 1) % (MAX_QUEUED_FILES + 1);

  mutex_unlock(&queue_mutex);
  semaphore_release(&used_slots);
}


char* file_queue_get()
{
  char* result;

  semaphore_wait(&used_slots);
  mutex_lock(&queue_mutex);

  if (queue_head == queue_tail) // queue is empty
  {
    result = NULL;
  }
  else
  {
    result = file_queue[queue_head].path;
    queue_head = (queue_head + 1) % (MAX_QUEUED_FILES + 1);
  }

  mutex_unlock(&queue_mutex);
  semaphore_release(&unused_slots);

  return result;
}


#ifdef WIN32

int is_directory(
    const char* path)
{
  if (GetFileAttributes(path) & FILE_ATTRIBUTE_DIRECTORY)
    return TRUE;
  else
    return FALSE;
}

void scan_dir(
    const char* dir,
    int recursive,
    YR_RULES* rules,
    YR_CALLBACK_FUNC callback)
{
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;

  char full_path[MAX_PATH];
  static char path_and_mask[MAX_PATH];

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
        file_queue_put(full_path);
      }
      else if (recursive && FindFileData.cFileName[0] != '.' )
      {
        scan_dir(full_path, recursive, rules, callback);
      }

    } while (FindNextFile(hFind, &FindFileData));

    FindClose(hFind);
  }
}

#else

int is_directory(
    const char* path)
{
  struct stat st;

  if (stat(path,&st) == 0)
    return S_ISDIR(st.st_mode);

  return 0;
}

void scan_dir(
    const char* dir,
    int recursive,
    YR_RULES* rules,
    YR_CALLBACK_FUNC callback)
{
  DIR *dp;
  struct dirent *de;
  struct stat st;
  char full_path[MAX_PATH];

  dp = opendir(dir);

  if (dp)
  {
    de = readdir(dp);

    while (de)
    {
      snprintf(full_path, sizeof(full_path), "%s/%s", dir, de->d_name);

      int err = lstat(full_path, &st);

      if (err == 0)
      {
        if(S_ISREG(st.st_mode))
        {
          file_queue_put(full_path);
        }
        else if(recursive &&
                S_ISDIR(st.st_mode) &&
                !S_ISLNK(st.st_mode) &&
                de->d_name[0] != '.')
        {
          scan_dir(full_path, recursive, rules, callback);
        }
      }

      de = readdir(dp);
    }

    closedir(dp);
  }
}

#endif

void print_string(
    uint8_t* data,
    int length)
{
  int i;
  char* str;

  str = (char*) (data);

  for (i = 0; i < length; i++)
  {
    if (str[i] >= 32 && str[i] <= 126)
      printf("%c", str[i]);
    else
      printf("\\x%02X", (uint8_t) str[i]);
  }

  printf("\n");
}

void print_hex_string(
    uint8_t* data,
    int length)
{
  int i;

  for (i = 0; i < length; i++)
    printf("%02X ", (uint8_t) data[i]);

  printf("\n");
}


void print_scanning_error(int error)
{
  switch (error)
  {
    case ERROR_SUCCESS:
      break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      fprintf(stderr, "can not attach to process (try running as root)\n");
      break;
    case ERROR_INSUFICIENT_MEMORY:
      fprintf(stderr, "not enough memory\n");
      break;
    case ERROR_SCAN_TIMEOUT:
      fprintf(stderr, "scanning timed out\n");
      break;
    case ERROR_COULD_NOT_OPEN_FILE:
      fprintf(stderr, "could not open file\n");
      break;
    case ERROR_ZERO_LENGTH_FILE:
      fprintf(stderr, "zero length file\n");
      break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
      fprintf(stderr, "rules were compiled with a newer version of YARA.\n");
      break;
    case ERROR_CORRUPT_FILE:
      fprintf(stderr, "corrupt compiled rules file.\n");
      break;
    default:
      fprintf(stderr, "internal error: %d\n", error);
      break;
  }
}


void print_compiler_error(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
  }
  else
  {
    if (show_warnings)
      fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
  }
}


int handle_message(int message, YR_RULE* rule, void* data)
{
  TAG* tag;
  IDENTIFIER* identifier;
  YR_STRING* string;
  YR_MATCH* match;
  YR_META* meta;

  char* tag_name;
  size_t tag_length;
  int is_matching;
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

  is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

  show = show && ((!negate && is_matching) || (negate && !is_matching));

  if (show)
  {
    mutex_lock(&output_mutex);
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
        string_found = STRING_FOUND(string);

        if (string_found)
        {
          match = STRING_MATCHES(string).head;

          while (match != NULL)
          {
            printf("0x%" PRIx64 ":%s: ", match->first_offset, string->identifier);

            if (STRING_IS_HEX(string))
            {
              print_hex_string(match->data, match->length);
            }
            else
            {
              print_string(match->data, match->length);
            }

            match = match->next;
          }
        }

        string++;
      }
    }

    mutex_unlock(&output_mutex);
  }

  if (is_matching)
    count++;

  if (limit != 0 && count >= limit)
    return CALLBACK_ABORT;

  return CALLBACK_CONTINUE;
}


int callback(int message, YR_RULE* rule, void* data)
{
  switch(message)
  {
    case CALLBACK_MSG_RULE_MATCHING:
    case CALLBACK_MSG_RULE_NOT_MATCHING:
      return handle_message(message, rule, data);
  }

  return CALLBACK_ERROR;
}

#ifdef WIN32
DWORD WINAPI scanning_thread(LPVOID param)
#else
void* scanning_thread(void* param)
#endif
{
  YR_RULES* rules = (YR_RULES*) param;
  char* file_path;
  int result;

  file_path = file_queue_get();

  while (file_path != NULL)
  {
    result = yr_rules_scan_file(
        rules,
        file_path,
        callback,
        file_path,
        fast_scan,
        timeout);

    if (result != ERROR_SUCCESS)
    {
      mutex_lock(&output_mutex);
      fprintf(stderr, "Error scanning %s: ", file_path);
      print_scanning_error(result);
      mutex_unlock(&output_mutex);
    }

    free(file_path);
    file_path = file_queue_get();
  }

  yr_finalize_thread();

  return 0;
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

  while ((c = getopt (argc, (char**) argv, "wrnsvgma:l:t:i:d:f")) != -1)
  {
    switch (c)
    {
      case 'v':
        printf("%s\n", PACKAGE_STRING);
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

      case 'w':
        show_warnings = FALSE;
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
          fprintf(stderr, "Not enough memory.\n");
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
          fprintf(stderr, "Not enough memory.\n");
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
          fprintf(stderr, "Not enough memory.\n");
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

      case 'a':
        timeout = atoi(optarg);
        break;

      case '?':
        if (optopt == 't')
        {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        }
        else if (isprint(optopt))
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


void show_help()
{
  printf(USAGE);
  printf("\nReport bugs to: <%s>\n", PACKAGE_BUGREPORT);
}


int main(
    int argc,
    char const* argv[])
{
  YR_COMPILER* compiler;
  YR_RULES* rules;
  FILE* rule_file;
  EXTERNAL* external;

  int pid;
  int i;
  int errors;
  int result;

  THREAD thread[MAX_THREADS];

  if (!process_cmd_line(argc, argv))
    return 0;

  if (argc == 1 || optind == argc)
  {
    show_help();
    cleanup();
    return 0;
  }

  yr_initialize();

  result = yr_rules_load(argv[optind], &rules);

  if (result == ERROR_UNSUPPORTED_FILE_VERSION ||
      result == ERROR_CORRUPT_FILE)
  {
    print_scanning_error(result);
    yr_finalize();
    cleanup();
    return 0;
  }

  if (result == ERROR_SUCCESS)
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
    {
      yr_finalize();
      cleanup();
      return 0;
    }

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

    compiler->error_report_function = print_compiler_error;
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
        cleanup();
        return 0;
      }
    }
    else
    {
      fprintf(stderr, "could not open file: %s\n", argv[optind]);
      yr_finalize();
      cleanup();
      return 0;
    }
  }

  mutex_init(&output_mutex);

  if (is_numeric(argv[argc - 1]))
  {
    pid = atoi(argv[argc - 1]);
    result = yr_rules_scan_proc(
        rules,
        pid,
        callback,
        (void*) argv[argc - 1],
        fast_scan,
        timeout);

    if (result != ERROR_SUCCESS)
      print_scanning_error(result);
  }
  else if (is_directory(argv[argc - 1]))
  {
    file_queue_init();

    for (i = 0; i < threads; i++)
    {
      if (create_thread(&thread[i], scanning_thread, (void*) rules) != 0)
        return ERROR_COULD_NOT_CREATE_THREAD;
    }

    scan_dir(
        argv[argc - 1],
        recursive_search,
        rules,
        callback);

    file_queue_finish();

    // Wait for scan threads to finish
    for (i = 0; i < threads; i++)
      thread_join(&thread[i]);

    file_queue_destroy();
  }
  else
  {
    result = yr_rules_scan_file(
        rules,
        argv[argc - 1],
        callback,
        (void*) argv[argc - 1],
        fast_scan,
        timeout);

    if (result != ERROR_SUCCESS)
    {
      fprintf(stderr, "Error scanning %s: ", argv[argc - 1]);
      print_scanning_error(result);
    }
  }

  yr_rules_destroy(rules);
  yr_finalize();

  mutex_destroy(&output_mutex);
  cleanup();

  return 1;
}

