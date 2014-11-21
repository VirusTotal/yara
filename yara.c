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

#define PRIx64 "llx"

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <argparse/argparse.h>
#include <yara.h>

#include "threading.h"
#include "config.h"


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


typedef struct _MODULE_DATA
{
  const char* module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA* next;

} MODULE_DATA;


typedef struct _QUEUED_FILE {

  char* path;

} QUEUED_FILE;


#define MAX_ARGS_TAG            32
#define MAX_ARGS_IDENTIFIER     32
#define MAX_ARGS_EXT_VAR        32
#define MAX_ARGS_MODULE_DATA    32

char* tags[MAX_ARGS_TAG + 1];
char* identifiers[MAX_ARGS_IDENTIFIER + 1];
char* ext_vars[MAX_ARGS_EXT_VAR + 1];
char* modules_data[MAX_ARGS_EXT_VAR + 1];

int recursive_search = FALSE;
int show_tags = FALSE;
int show_specified_tags = FALSE;
int show_specified_rules = FALSE;
int show_strings = FALSE;
int show_meta = FALSE;
int ignore_warnings = FALSE;
int fast_scan = FALSE;
int negate = FALSE;
int count = 0;
int limit = 0;
int timeout = 0;
int threads = 8;


static const char *const usage[] = {
   "yara [OPTION]... RULES_FILE FILE | DIRECTORY | PID",
   NULL,
};


struct argparse_option options[] =
{
  OPT_STRING_MULTI('t', "tag", &tags, MAX_ARGS_TAG,
      "only print rules tagged as <tag>.", "<tag>"),

  OPT_STRING_MULTI('i', "identifier", &identifiers, MAX_ARGS_IDENTIFIER,
      "only print rules named <identifier>.", "<identifier>"),

  OPT_BOOLEAN('n', "negate", &negate,
      "only print not satisfied rules (negate)", NULL),

  OPT_BOOLEAN('g', "print-tags", &show_tags,
      "print tags"),

  OPT_BOOLEAN('m', "print-meta", &show_meta,
      "print metadata"),

  OPT_BOOLEAN('s', "print-strings", &show_strings,
      "print matching strings"),

  OPT_INTEGER('p', "threads", &threads,
      "use the specified number of threads to scan a directory", "<number>"),

  OPT_INTEGER('l', "max-rules", &limit,
      "abort scanning after matching a number rules", "<number>"),

  OPT_STRING_MULTI('d', NULL, &ext_vars, MAX_ARGS_EXT_VAR,
      "define external variable", "<identifier>=<value>"),

  OPT_STRING_MULTI('x', NULL, &modules_data, MAX_ARGS_MODULE_DATA,
      "pass file's content as extra data to module", "<module>=<file>"),

  OPT_INTEGER('a', "timeout", &timeout,
      "abort scanning after matching a number of  rules", "<number>"),

  OPT_BOOLEAN('r', "recursive", &recursive_search,
      "recursively search directories"),

  OPT_BOOLEAN('f', "fast-scan", &fast_scan,
      "fast matching mode"),

  OPT_BOOLEAN('w', "no-warnings", &ignore_warnings,
      "disable warnings"),

  OPT_HELP(),
  OPT_END()
};


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

MODULE_DATA* modules_data_list = NULL;


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
  static char path_and_mask[MAX_PATH];

  snprintf(path_and_mask, sizeof(path_and_mask), "%s\\*", dir);

  WIN32_FIND_DATA FindFileData;
  HANDLE hFind = FindFirstFile(path_and_mask, &FindFileData);

  if (hFind != INVALID_HANDLE_VALUE)
  {
    do
    {
      char full_path[MAX_PATH];

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
  DIR* dp = opendir(dir);

  if (dp)
  {
    struct dirent* de = readdir(dp);

    while (de)
    {
      char full_path[MAX_PATH];
      struct stat st;

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
  char* str = (char*) (data);

  for (int i = 0; i < length; i++)
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
  for (int i = 0; i < min(32, length); i++)
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
    if (!ignore_warnings)
      fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
  }
}


int handle_message(int message, YR_RULE* rule, void* data)
{
  const char* tag;
  int show = TRUE;

  if (tags[0] != NULL)
  {
    // The user specified one or more -t <tag> arguments, let's show this rule
    // only if it's tagged with some of the specified tags.

    show = FALSE;

    for (int i = 0; !show && tags[i] != NULL; i++)
    {
      yr_rule_tags_foreach(rule, tag)
      {
        if (strcmp(tag, tags[i]) == 0)
        {
          show = TRUE;
          break;
        }
      }
    }
  }

  if (identifiers[0] != NULL)
  {
    // The user specified one or more -i <identifier> arguments, let's show
    // this rule only if it's identifier is among of the provided ones.

    show = FALSE;

    for (int i = 0; !show && identifiers[i] != NULL; i++)
    {
      if (strcmp(identifiers[i], rule->identifier) == 0)
      {
        show = TRUE;
        break;
      }
    }
  }

  int is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

  show = show && ((!negate && is_matching) || (negate && !is_matching));

  if (show)
  {
    mutex_lock(&output_mutex);
    printf("%s ", rule->identifier);

    if (show_tags)
    {
      printf("[");

      yr_rule_tags_foreach(rule, tag)
      {
        // print a comma except for the first tag
        if (tag != rule->tags)
          printf(",");

        printf("%s", tag);
      }

      printf("] ");
    }

    // Show meta-data.

    if (show_meta)
    {
      YR_META* meta;

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
      YR_STRING* string;

      yr_rule_strings_foreach(rule, string)
      {
        YR_MATCH* match;

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
  char* file_path = file_queue_get();

  while (file_path != NULL)
  {
    int result = yr_rules_scan_file(
        rules,
        file_path,
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        file_path,
        timeout);

    if (result != ERROR_SUCCESS)
    {
      mutex_lock(&output_mutex);
      fprintf(stderr, "error scanning %s: ", file_path);
      print_scanner_error(result);
      mutex_unlock(&output_mutex);
    }

    free(file_path);
    file_path = file_queue_get();
  }

  yr_finalize_thread();

  return 0;
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


int define_external_variables(
    YR_RULES* rules,
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
      if (rules != NULL)
        yr_rules_define_integer_variable(
            rules,
            identifier,
            atoi(value));

      if (compiler != NULL)
        yr_compiler_define_integer_variable(
            compiler,
            identifier,
            atoi(value));
    }
    else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
    {
      if (rules != NULL)
        yr_rules_define_boolean_variable(
            rules,
            identifier,
            strcmp(value, "true") == 0);

      if (compiler != NULL)
        yr_compiler_define_boolean_variable(
            compiler,
            identifier,
            strcmp(value, "true") == 0);
    }
    else
    {
      if (rules != NULL)
        yr_rules_define_string_variable(
            rules,
            identifier,
            value);

      if (compiler != NULL)
        yr_compiler_define_string_variable(
            compiler,
            identifier,
            value);
    }
  }

  return TRUE;
}


int load_modules_data()
{
  for (int i = 0; modules_data[i] != NULL; i++)
  {
    char* equal_sign = strchr(modules_data[i], '=');

    if (!equal_sign)
    {
      fprintf(stderr, "error: wrong syntax for `-x` option.\n");
      return FALSE;
    }

    *equal_sign = '\0';

    MODULE_DATA* module_data = (MODULE_DATA*) malloc(sizeof(MODULE_DATA));

    if (module_data != NULL)
    {
      module_data->module_name = modules_data[i];

      int result = yr_filemap_map(equal_sign + 1, &module_data->mapped_file);

      if (result != ERROR_SUCCESS)
      {
        free(module_data);
        fprintf(stderr, "error: could not open file \"%s\".\n", equal_sign + 1);
        return FALSE;
      }

      module_data->next = modules_data_list;
      modules_data_list = module_data;
    }
  }

  return TRUE;
}


void unload_modules_data()
{
  MODULE_DATA* module_data = modules_data_list;

  while(module_data != NULL)
  {
    MODULE_DATA* next_module_data = module_data->next;

    yr_filemap_unmap(&module_data->mapped_file);
    free(module_data);

    module_data = next_module_data;
  }

  modules_data_list = NULL;
}


#define exit_with_code(code) { result = code; goto _exit; }

int main(
    int argc,
    const char** argv)
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

  struct argparse argparse;
  int result;

  argparse_init(&argparse, options, usage, 0);

  argc = argparse_parse(&argparse, argc, argv);

  if (argc != 2)
  {
    // After parsing the command-line options we expect two additional
    // arguments, the rules file and the target file, directory or pid to
    // be scanned.

    fprintf(stderr, "error: wrong number of arguments\n");
    argparse_usage(&argparse);
    return EXIT_FAILURE;
  }

  if (!load_modules_data())
    exit_with_code(EXIT_FAILURE);

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: initialization error (%d)\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  // Try to load the rules file as a binary file containing
  // compiled rules first

  result = yr_rules_load(argv[0], &rules);

  // Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
  // if we are passing the rules in source form, if result is
  // different from those exit with error.

  if (result != ERROR_SUCCESS &&
      result != ERROR_INVALID_FILE)
  {
    print_scanner_error(result);
    exit_with_code(EXIT_FAILURE);
  }

  if (result == ERROR_SUCCESS)
  {
    if (!define_external_variables(rules, NULL))
      exit_with_code(EXIT_FAILURE);
  }
  else
  {
    // Rules file didn't contain compiled rules, let's handle it
    // as a text file containing rules in source form.

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
      exit_with_code(EXIT_FAILURE);

    if (!define_external_variables(NULL, compiler))
      exit_with_code(EXIT_FAILURE);

    yr_compiler_set_callback(compiler, print_compiler_error);

    FILE* rule_file = fopen(argv[0], "r");

    if (rule_file == NULL)
    {
      fprintf(stderr, "error: could not open file: %s\n", argv[0]);
      exit_with_code(EXIT_FAILURE);
    }

    int errors = yr_compiler_add_file(compiler, rule_file, NULL, argv[0]);

    fclose(rule_file);

    if (errors > 0)
      exit_with_code(EXIT_FAILURE);

    result = yr_compiler_get_rules(compiler, &rules);

    yr_compiler_destroy(compiler);

    compiler = NULL;

    if (result != ERROR_SUCCESS)
      exit_with_code(EXIT_FAILURE);
  }

  mutex_init(&output_mutex);

  if (is_numeric(argv[1]))
  {
    int pid = atoi(argv[1]);

    result = yr_rules_scan_proc(
        rules,
        pid,
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        (void*) argv[1],
        timeout);

    if (result != ERROR_SUCCESS)
    {
      print_scanner_error(result);
      exit_with_code(EXIT_FAILURE);
    }
  }
  else if (is_directory(argv[1]))
  {
    if (file_queue_init() != 0)
    {
      print_scanner_error(ERROR_INTERNAL_FATAL_ERROR);
      exit_with_code(EXIT_FAILURE);
    }

    THREAD thread[MAX_THREADS];

    for (int i = 0; i < threads; i++)
    {
      if (create_thread(&thread[i], scanning_thread, (void*) rules) != 0)
      {
        print_scanner_error(ERROR_COULD_NOT_CREATE_THREAD);
        exit_with_code(EXIT_FAILURE);
      }
    }

    scan_dir(
        argv[1],
        recursive_search,
        rules,
        callback);

    file_queue_finish();

    // Wait for scan threads to finish
    for (int i = 0; i < threads; i++)
      thread_join(&thread[i]);

    file_queue_destroy();
  }
  else
  {
    result = yr_rules_scan_file(
        rules,
        argv[1],
        fast_scan ? SCAN_FLAGS_FAST_MODE : 0,
        callback,
        (void*) argv[1],
        timeout);

    if (result != ERROR_SUCCESS)
    {
      fprintf(stderr, "error scanning %s: ", argv[1]);
      print_scanner_error(result);
      exit_with_code(EXIT_FAILURE);
    }
  }

  #ifdef PROFILING_ENABLED
  yr_rules_print_profiling_info(rules);
  #endif

  result = EXIT_SUCCESS;

_exit:

  unload_modules_data();

  if (compiler != NULL)
    yr_compiler_destroy(compiler);

  if (rules != NULL)
    yr_rules_destroy(rules);

  yr_finalize();

  return result;
}
