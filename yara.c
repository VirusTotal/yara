/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#ifndef _WIN32

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


#define USAGE \
"usage:  yara [OPTION]... RULES_FILE FILE | PID\n"\
"options:\n"\
"  -t <tag>                 only print rules tagged as <tag>.\n"\
"  -i <identifier>          only print rules named <identifier>.\n"\
"  -n                       only print not satisfied rules (negate).\n"\
"  -g                       print tags.\n"\
"  -m                       print metadata.\n"\
"  -s                       print matching strings.\n"\
"  -p <number>              use the specified <number> of threads to scan a directory.\n"\
"  -l <number>              abort scanning after matching a number rules.\n"\
"  -a <seconds>             abort scanning after a number of seconds has elapsed.\n"\
"  -d <identifier>=<value>  define external variable.\n"\
"  -x <module>=<file>       pass file's content as extra data to module.\n"\
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

#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
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


typedef struct _MODULE_DATA
{
  const char* module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA* next;

} MODULE_DATA;


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
MODULE_DATA* modules_data_list = NULL;


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


int file_queue_init()
{
  int result;

  queue_tail = 0;
  queue_head = 0;

  result = mutex_init(&queue_mutex);

  if (result != 0)
    return result;

  result = semaphore_init(&used_slots, 0);

  if (result != 0)
    return result;

 return semaphore_init(&unused_slots, MAX_QUEUED_FILES);
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


#ifdef _WIN32

int is_directory(
    const char* path)
{
  DWORD attributes = GetFileAttributes(path);

  if (attributes != INVALID_FILE_ATTRIBUTES &&
	  attributes & FILE_ATTRIBUTE_DIRECTORY)
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

  for (i = 0; i < min(32, length); i++)
    printf("%02X ", (uint8_t) data[i]);

  if (length > 32)
    printf("...");

  printf("\n");
}


void print_scanner_error(int error)
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

  const char* tag_name;

  int is_matching;
  int show = TRUE;

  if (show_specified_tags)
  {
    show = FALSE;
    tag = specified_tags_list;

    while (tag != NULL)
    {
      yr_rule_tags_foreach(rule, tag_name)
      {
        if (strcmp(tag_name, tag->identifier) == 0)
        {
          show = TRUE;
          break;
        }
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

      yr_rule_tags_foreach(rule, tag_name)
      {
        // print a comma except for the first tag
        if (tag_name != rule->tags)
          printf(",");

        printf("%s", tag_name);
      }

      printf("] ");
    }

    // Show meta-data.

    if (show_meta)
    {
      printf("[");

      yr_rule_metas_foreach(rule, meta)
      {
        if (meta != rule->metas)
          printf(",");

        if (meta->type == META_TYPE_INTEGER)
          printf("%s=%d", meta->identifier, meta->integer);
        else if (meta->type == META_TYPE_BOOLEAN)
          printf("%s=%s", meta->identifier, meta->integer ? "true" : "false");
        else
          printf("%s=\"%s\"", meta->identifier, meta->string);
      }

      printf("] ");
    }

    printf("%s\n", (char*) data);

    // Show matched strings.

    if (show_strings)
    {
      yr_rule_strings_foreach(rule, string)
      {
        yr_string_matches_foreach(string, match)
        {
          printf("0x%" PRIx64 ":%s: ",
              match->base + match->offset,
              string->identifier);

          if (STRING_IS_HEX(string))
            print_hex_string(match->data, match->length);
          else
            print_string(match->data, match->length);
        }
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


int callback(int message, void* message_data, void* user_data)
{
  YR_MODULE_IMPORT* mi;
  MODULE_DATA* module_data;

  switch(message)
  {
    case CALLBACK_MSG_RULE_MATCHING:
    case CALLBACK_MSG_RULE_NOT_MATCHING:
      return handle_message(message, (YR_RULE*) message_data, user_data);

    case CALLBACK_MSG_IMPORT_MODULE:
      mi = (YR_MODULE_IMPORT*) message_data;

      module_data = modules_data_list;

      while (module_data != NULL)
      {
        if (strcmp(module_data->module_name, mi->module_name) == 0)
        {
          mi->module_data = module_data->mapped_file.data;
          mi->module_data_size = module_data->mapped_file.size;
          break;
        }

        module_data = module_data->next;
      }

      return CALLBACK_CONTINUE;
  }

  return CALLBACK_ERROR;
}

#ifdef _WIN32
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
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        file_path,
        timeout);

    if (result != ERROR_SUCCESS)
    {
      mutex_lock(&output_mutex);
      fprintf(stderr, "Error scanning %s: ", file_path);
      print_scanner_error(result);
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
  MODULE_DATA* module_data;
  MODULE_DATA* next_module_data;

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

  module_data = modules_data_list;

  while(module_data != NULL)
  {
    next_module_data = module_data->next;

    yr_filemap_unmap(&module_data->mapped_file);

    free((void*) module_data->module_name);
    free((void*) module_data);

    module_data = next_module_data;
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
  MODULE_DATA* module_data;

  opterr = 0;

  while ((c = getopt (argc, (char**) argv, "wrnsvgma:l:t:i:d:x:p:f")) != -1)
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
        tag = (TAG*) malloc(sizeof(TAG));

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
        identifier = (IDENTIFIER*) malloc(sizeof(IDENTIFIER));

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
        external = (EXTERNAL*) malloc(sizeof(EXTERNAL));

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

      case 'x':

        equal_sign = strchr(optarg, '=');

        if (equal_sign == NULL)
        {
          fprintf(stderr, "Wrong syntax for -x modifier.\n");
          return 0;
        }

        module_data = (MODULE_DATA*) malloc(sizeof(MODULE_DATA));

        if (module_data != NULL)
          module_data->module_name = strdup(optarg);

        if (module_data == NULL || module_data->module_name == NULL)
        {
          if (module_data != NULL)
            free(module_data);

          fprintf(stderr, "Not enough memory.\n");
          return 0;
        }

        *equal_sign = '\0';
        value = equal_sign + 1;

        if (yr_filemap_map(value, &module_data->mapped_file) != ERROR_SUCCESS)
        {
          free(module_data);
          fprintf(stderr, "Could not open file \"%s\".\n", value);
          return 0;
        }

        module_data->next = modules_data_list;
        modules_data_list = module_data;

        break;

      case 'l':
        limit = atoi(optarg);
        break;

      case 'a':
        timeout = atoi(optarg);
        break;

      case 'p':
        threads = atoi(optarg);
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
    return EXIT_FAILURE;

  if (argc == 1 || optind == argc)
  {
    show_help();
    cleanup();
    return EXIT_FAILURE;
  }

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "initialization error: %d\n", result);
    cleanup();
    return EXIT_FAILURE;
  }

  result = yr_rules_load(argv[optind], &rules);

  if (result != ERROR_SUCCESS &&
      result != ERROR_INVALID_FILE)
  {
    print_scanner_error(result);
    yr_finalize();
    cleanup();
    return EXIT_FAILURE;
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
      return EXIT_FAILURE;
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

    yr_compiler_set_callback(compiler, print_compiler_error);

    rule_file = fopen(argv[optind], "r");

    if (rule_file == NULL)
    {
      fprintf(stderr, "could not open file: %s\n", argv[optind]);
      yr_compiler_destroy(compiler);
      yr_finalize();
      cleanup();
      return EXIT_FAILURE;
    }

    errors = yr_compiler_add_file(compiler, rule_file, NULL, argv[optind]);

    fclose(rule_file);

    if (errors > 0)
    {
      yr_compiler_destroy(compiler);
      yr_finalize();
      cleanup();
      return EXIT_FAILURE;
    }

    result = yr_compiler_get_rules(compiler, &rules);

    yr_compiler_destroy(compiler);

    if (result != ERROR_SUCCESS)
    {
      yr_finalize();
      cleanup();
      return EXIT_FAILURE;
    }
  }

  mutex_init(&output_mutex);

  if (is_numeric(argv[argc - 1]))
  {
    pid = atoi(argv[argc - 1]);
    result = yr_rules_scan_proc(
        rules,
        pid,
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        (void*) argv[argc - 1],
        timeout);

    if (result != ERROR_SUCCESS)
      print_scanner_error(result);
  }
  else if (is_directory(argv[argc - 1]))
  {
    if (file_queue_init() != 0)
      print_scanner_error(ERROR_INTERNAL_FATAL_ERROR);

    for (i = 0; i < threads; i++)
    {
      if (create_thread(&thread[i], scanning_thread, (void*) rules) != 0)
      {
        print_scanner_error(ERROR_COULD_NOT_CREATE_THREAD);
        return EXIT_FAILURE;
      }
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
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        (void*) argv[argc - 1],
        timeout);

    if (result != ERROR_SUCCESS)
    {
      fprintf(stderr, "Error scanning %s: ", argv[argc - 1]);
      print_scanner_error(result);
    }
  }

  #ifdef PROFILING_ENABLED
  yr_rules_print_profiling_info(rules);
  #endif

  yr_rules_destroy(rules);
  yr_finalize();

  mutex_destroy(&output_mutex);
  cleanup();

  return EXIT_SUCCESS;
}
