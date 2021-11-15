/*
Copyright (c) 2007-2021. The YARA Authors. All Rights Reserved.

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

#if !defined(_WIN32) && !defined(__CYGWIN__)

// for getline(3)
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#else

#include <fcntl.h>
#include <io.h>
#include <windows.h>

#define PRIx64 "I64x"
#define PRId64 "I64d"

#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yara.h>

#include "args.h"
#include "common.h"
#include "threading.h"
#include "unicode.h"

#define ERROR_COULD_NOT_CREATE_THREAD 100

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef min
#define min(x, y) ((x < y) ? (x) : (y))
#endif

#define MAX_ARGS_TAG         32
#define MAX_ARGS_IDENTIFIER  32
#define MAX_ARGS_EXT_VAR     32
#define MAX_ARGS_MODULE_DATA 32
#define MAX_QUEUED_FILES     64

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }

typedef struct _MODULE_DATA
{
  const char* module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA* next;

} MODULE_DATA;

typedef struct _CALLBACK_ARGS
{
  const char_t* file_path;
  int current_count;

} CALLBACK_ARGS;

#define MAX_ARGS_TAG         32
#define MAX_ARGS_IDENTIFIER  32
#define MAX_ARGS_EXT_VAR     32
#define MAX_ARGS_MODULE_DATA 32

static char* tags[MAX_ARGS_TAG + 1];
static char* identifiers[MAX_ARGS_IDENTIFIER + 1];

static bool show_module_data = false;
static bool show_tags = false;
static bool show_stats = false;
static bool show_strings = false;
static bool show_string_length = false;
static bool show_meta = false;
static bool show_namespace = false;
static bool show_version = false;
static bool show_help = false;
static bool ignore_warnings = false;
static bool fast_scan = false;
static bool negate = false;
static bool print_count_only = false;
static bool fail_on_warnings = false;
static int total_count = 0;
static int limit = 0;
static int timeout = 1000000;
static int stack_size = DEFAULT_STACK_SIZE;
static int max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;

#define USAGE_STRING \
  "Usage: yara [OPTION]... [NAMESPACE:]COMPILED_RULES_FILE... FILE"

args_option_t options[] = {

    OPT_BOOLEAN(
        'c',
        _T("count"),
        &print_count_only,
        _T("print only number of matches")),

    OPT_BOOLEAN(
        0,
        _T("fail-on-warnings"),
        &fail_on_warnings,
        _T("fail on warnings")),

    OPT_BOOLEAN('f', _T("fast-scan"), &fast_scan, _T("fast matching mode")),

    OPT_BOOLEAN('h', _T("help"), &show_help, _T("show this help and exit")),

    OPT_STRING_MULTI(
        'i',
        _T("identifier"),
        &identifiers,
        MAX_ARGS_IDENTIFIER,
        _T("print only rules named IDENTIFIER"),
        _T("IDENTIFIER")),

    OPT_INTEGER(
        'l',
        _T("max-rules"),
        &limit,
        _T("abort scanning after matching a NUMBER of rules"),
        _T("NUMBER")),

    OPT_INTEGER(
        0,
        _T("max-strings-per-rule"),
        &max_strings_per_rule,
        _T("set maximum number of strings per rule (default=10000)"),
        _T("NUMBER")),

    OPT_BOOLEAN(
        'n',
        _T("negate"),
        &negate,
        _T("print only not satisfied rules (negate)"),
        NULL),

    OPT_BOOLEAN(
        'w',
        _T("no-warnings"),
        &ignore_warnings,
        _T("disable warnings")),

    OPT_BOOLEAN('m', _T("print-meta"), &show_meta, _T("print metadata")),

    OPT_BOOLEAN(
        'D',
        _T("print-module-data"),
        &show_module_data,
        _T("print module data")),

    OPT_BOOLEAN(
        'e',
        _T("print-namespace"),
        &show_namespace,
        _T("print rules' namespace")),

    OPT_BOOLEAN(
        'S',
        _T("print-stats"),
        &show_stats,
        _T("print rules' statistics")),

    OPT_BOOLEAN(
        's',
        _T("print-strings"),
        &show_strings,
        _T("print matching strings")),

    OPT_BOOLEAN(
        'L',
        _T("print-string-length"),
        &show_string_length,
        _T("print length of matched strings")),

    OPT_BOOLEAN('g', _T("print-tags"), &show_tags, _T("print tags")),

    OPT_INTEGER(
        'k',
        _T("stack-size"),
        &stack_size,
        _T("set maximum stack size (default=16384)"),
        _T("SLOTS")),

    OPT_STRING_MULTI(
        't',
        _T("tag"),
        &tags,
        MAX_ARGS_TAG,
        _T("print only rules tagged as TAG"),
        _T("TAG")),

    OPT_INTEGER(
        'a',
        _T("timeout"),
        &timeout,
        _T("abort scanning after the given number of SECONDS"),
        _T("SECONDS")),

    OPT_BOOLEAN(
        'v',
        _T("version"),
        &show_version,
        _T("show version information")),

    OPT_END(),
};

#if defined(_WIN32) || defined(__CYGWIN__)

static int scan_file(YR_SCANNER* scanner, const char_t* filename)
{
  YR_FILE_DESCRIPTOR fd = CreateFile(
      filename,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  uint32_t len = 0;
  uint32_t read = 0;
  GetFileSize(fd, &len);
  int result = 0;
  if (len)
  {
    uint8_t* data = malloc(len);
	if (data)
	{
        ReadFile(fd, data, len, &read, NULL);

        result = yr_scanner_scan_mem(scanner, data, len);

        free(data);
    }
  }
  CloseHandle(fd);

  return result;
}

#else

static int scan_file(YR_SCANNER* scanner, const char_t* filename)
{
  YR_FILE_DESCRIPTOR fd = open(filename, O_RDONLY);

  if (fd == -1)
    return ERROR_COULD_NOT_OPEN_FILE;

  int result = yr_scanner_scan_fd(scanner, fd);

  close(fd);

  return result;
}

#endif

static void print_string(const uint8_t* data, int length)
{
  for (int i = 0; i < length; i++)
  {
    if (data[i] >= 32 && data[i] <= 126)
      _tprintf(_T("%c"), data[i]);
    else
      _tprintf(_T("\\x%02X"), data[i]);
  }
}

static char cescapes[] = {
    0, 0, 0, 0, 0, 0, 0, 'a', 'b', 't', 'n', 'v', 'f', 'r', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0, 0,
};

static void print_escaped(const uint8_t* data, size_t length)
{
  for (size_t i = 0; i < length; i++)
  {
    switch (data[i])
    {
    case '\"':
    case '\'':
    case '\\':
      _tprintf(_T("\\%" PF_C), data[i]);
      break;

    default:
      if (data[i] >= 127)
        _tprintf(_T("\\%03o"), data[i]);
      else if (data[i] >= 32)
        _tprintf(_T("%" PF_C), data[i]);
      else if (cescapes[data[i]] != 0)
        _tprintf(_T("\\%" PF_C), cescapes[data[i]]);
      else
        _tprintf(_T("\\%03o"), data[i]);
    }
  }
}

static void print_hex_string(const uint8_t* data, int length)
{
  for (int i = 0; i < min(64, length); i++)
    _tprintf(_T("%s%02X"), (i == 0 ? _T("") : _T(" ")), data[i]);

  if (length > 64)
    _tprintf(_T(" ..."));
}

static void print_error(int error)
{
  switch (error)
  {
  case ERROR_SUCCESS:
    break;
  case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
    fprintf(stderr, "can not attach to process (try running as root)\n");
    break;
  case ERROR_INSUFFICIENT_MEMORY:
    fprintf(stderr, "not enough memory\n");
    break;
  case ERROR_SCAN_TIMEOUT:
    fprintf(stderr, "scanning timed out\n");
    break;
  case ERROR_COULD_NOT_OPEN_FILE:
    fprintf(stderr, "could not open file\n");
    break;
  case ERROR_UNSUPPORTED_FILE_VERSION:
    fprintf(stderr, "rules were compiled with a different version of YARA\n");
    break;
  case ERROR_INVALID_FILE:
    fprintf(stderr, "invalid compiled rules file.\n");
    break;
  case ERROR_CORRUPT_FILE:
    fprintf(stderr, "corrupt compiled rules file.\n");
    break;
  case ERROR_EXEC_STACK_OVERFLOW:
    fprintf(
        stderr,
        "stack overflow while evaluating condition "
        "(see --stack-size argument) \n");
    break;
  case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
    fprintf(stderr, "invalid type for external variable\n");
    break;
  case ERROR_TOO_MANY_MATCHES:
    fprintf(stderr, "too many matches\n");
    break;
  default:
    fprintf(stderr, "error: %d\n", error);
    break;
  }
}

static void print_scanner_error(YR_SCANNER* scanner, int error)
{
  YR_RULE* rule = yr_scanner_last_error_rule(scanner);
  YR_STRING* string = yr_scanner_last_error_string(scanner);

  if (rule != NULL && string != NULL)
  {
    fprintf(
        stderr,
        "string \"%s\" in rule \"%s\" caused ",
        string->identifier,
        rule->identifier);
  }
  else if (rule != NULL)
  {
    fprintf(stderr, "rule \"%s\" caused ", rule->identifier);
  }

  print_error(error);
}

static int handle_message(
    YR_SCAN_CONTEXT* context,
    int message,
    YR_RULE* rule,
    void* data)
{
  const char* tag;
  bool show = true;

  if (tags[0] != NULL)
  {
    // The user specified one or more -t <tag> arguments, let's show this rule
    // only if it's tagged with some of the specified tags.

    show = false;

    for (int i = 0; !show && tags[i] != NULL; i++)
    {
      yr_rule_tags_foreach(rule, tag)
      {
        if (strcmp(tag, tags[i]) == 0)
        {
          show = true;
          break;
        }
      }
    }
  }

  if (identifiers[0] != NULL)
  {
    // The user specified one or more -i <identifier> arguments, let's show
    // this rule only if it's identifier is among of the provided ones.

    show = false;

    for (int i = 0; !show && identifiers[i] != NULL; i++)
    {
      if (strcmp(identifiers[i], rule->identifier) == 0)
      {
        show = true;
        break;
      }
    }
  }

  bool is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

  show = show && ((!negate && is_matching) || (negate && !is_matching));

  if (show && !print_count_only)
  {
    if (show_namespace)
      _tprintf(_T("%" PF_S ":"), rule->ns->name);

    _tprintf(_T("%" PF_S " "), rule->identifier);

    if (show_tags)
    {
      _tprintf(_T("["));

      yr_rule_tags_foreach(rule, tag)
      {
        // print a comma except for the first tag
        if (tag != rule->tags)
          _tprintf(_T(","));

        _tprintf(_T("%" PF_S), tag);
      }

      _tprintf(_T("] "));
    }

    // Show meta-data.

    if (show_meta)
    {
      YR_META* meta;

      _tprintf(_T("["));

      yr_rule_metas_foreach(rule, meta)
      {
        if (meta != rule->metas)
          _tprintf(_T(","));

        if (meta->type == META_TYPE_INTEGER)
        {
          _tprintf(_T("%" PF_S " =%" PRId64), meta->identifier, meta->integer);
        }
        else if (meta->type == META_TYPE_BOOLEAN)
        {
          _tprintf(
              _T("%" PF_S "=%" PF_S),
              meta->identifier,
              meta->integer ? "true" : "false");
        }
        else
        {
          _tprintf(_T("%" PF_S "=\""), meta->identifier);
          print_escaped((uint8_t*) (meta->string), strlen(meta->string));
          _tprintf(_T("\""));
        }
      }

      _tprintf(_T("] "));
    }

    _tprintf(_T("%s\n"), ((CALLBACK_ARGS*) data)->file_path);

    // Show matched strings.

    if (show_strings || show_string_length)
    {
      YR_STRING* string;

      yr_rule_strings_foreach(rule, string)
      {
        YR_MATCH* match;

        yr_string_matches_foreach(context, string, match)
        {
          if (show_string_length)
            _tprintf(
                _T("0x%" PRIx64 ":%d:%" PF_S),
                match->base + match->offset,
                match->data_length,
                string->identifier);
          else
            _tprintf(
                _T("0x%" PRIx64 ":%" PF_S),
                match->base + match->offset,
                string->identifier);

          if (show_strings)
          {
            _tprintf(_T(": "));

            if (STRING_IS_HEX(string))
              print_hex_string(match->data, match->data_length);
            else
              print_string(match->data, match->data_length);
          }

          _tprintf(_T("\n"));
        }
      }
    }
  }

  if (is_matching)
  {
    ((CALLBACK_ARGS*) data)->current_count++;
    total_count++;
  }

  if (limit != 0 && total_count >= limit)
    return CALLBACK_ABORT;

  return CALLBACK_CONTINUE;
}

static int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  YR_STRING* string;
  YR_RULE* rule;
  YR_OBJECT* object;

  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
  case CALLBACK_MSG_RULE_NOT_MATCHING:
    return handle_message(context, message, (YR_RULE*) message_data, user_data);

  case CALLBACK_MSG_IMPORT_MODULE:
    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_MODULE_IMPORTED:

    if (show_module_data)
    {
      object = (YR_OBJECT*) message_data;

#if defined(_WIN32)
      // In Windows restore stdout to normal text mode as yr_object_print_data
      // calls printf which is not supported in UTF-8 mode.
      _setmode(_fileno(stdout), _O_TEXT);
#endif

      yr_object_print_data(object, 0, 1);
      printf("\n");

#if defined(_WIN32)
      // Go back to UTF-8 mode.
      _setmode(_fileno(stdout), _O_U8TEXT);
#endif
    }

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_TOO_MANY_MATCHES:
    if (ignore_warnings)
      return CALLBACK_CONTINUE;

    string = (YR_STRING*) message_data;
    rule = &context->rules->rules_table[string->rule_idx];

    fprintf(
        stderr,
        "warning: rule \"%s\": too many matches for %s, results for this rule "
        "may be incorrect\n",
        rule->identifier,
        string->identifier);

    if (fail_on_warnings)
      return CALLBACK_ERROR;

    return CALLBACK_CONTINUE;
  }

  return CALLBACK_ERROR;
}

int _tmain(int argc, const char_t** argv)
{
  YR_RULES* rules = NULL;
  YR_SCANNER* scanner = NULL;

  bool arg_is_dir = false;
  int flags = 0;
  int result;

  argc = args_parse(options, argc, argv);

  if (show_version)
  {
    printf("%s\n", YR_VERSION);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf(
        "YARA %s, the pattern matching swiss army knife.\n"
        "%s\n\n"
        "Mandatory arguments to long options are mandatory for "
        "short options too.\n\n",
        YR_VERSION,
        USAGE_STRING);

    args_print_usage(options, 43);
    printf(
        "\nSend bug reports and suggestions to: vmalvarez@virustotal.com.\n");

    return EXIT_SUCCESS;
  }

  if (argc < 2)
  {
    // After parsing the command-line options we expect two additional
    // arguments, the rules file and the target file, directory or pid to
    // be scanned.

    fprintf(stderr, "yara: wrong number of arguments\n");
    fprintf(stderr, "%s\n\n", USAGE_STRING);
    fprintf(stderr, "Try `--help` for more options\n");

    return EXIT_FAILURE;
  }

#if defined(_WIN32) && defined(_UNICODE)
  // In Windows set stdout to UTF-8 mode.
  if (_setmode(_fileno(stdout), _O_U8TEXT) == -1)
  {
    return EXIT_FAILURE;
  }
#endif

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: initialization error (%d)\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
  yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);

  // Try to load the rules file as a binary file containing
  // compiled rules first

  {
    // When a binary file containing compiled rules is provided, yara accepts
    // only two arguments, the compiled rules file and the target to be scanned.

    if (argc != 2)
    {
      fprintf(
          stderr,
          "error: can't accept multiple rules files if one of them is in "
          "compiled form.\n");
      exit_with_code(EXIT_FAILURE);
    }

    // Not using yr_rules_load because it does not have support for unicode
    // file names. Instead use open _tfopen for openning the file and
    // yr_rules_load_stream for loading the rules from it.

    FILE* fh = _tfopen(argv[0], _T("rb"));

    if (fh != NULL)
    {
      YR_STREAM stream;

      stream.user_data = fh;
      stream.read = (YR_STREAM_READ_FUNC) fread;

      result = yr_rules_load_stream(&stream, &rules);

      fclose(fh);
    }
    else
    {
      result = ERROR_COULD_NOT_OPEN_FILE;
    }
  }

  if (result != ERROR_SUCCESS)
  {
    print_error(result);
    exit_with_code(EXIT_FAILURE);
  }

  if (fast_scan)
    flags |= SCAN_FLAGS_FAST_MODE;


  {
    CALLBACK_ARGS user_data = {argv[argc - 1], 0};

    result = yr_scanner_create(rules, &scanner);

    if (result != ERROR_SUCCESS)
    {
      _ftprintf(stderr, _T("error: %d\n"), result);
      exit_with_code(EXIT_FAILURE);
    }

    yr_scanner_set_callback(scanner, callback, &user_data);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);

    // Assume the last argument is a file first. This assures we try to process
    // files that start with numbers first.
    result = scan_file(scanner, argv[argc - 1]);

    if (result != ERROR_SUCCESS)
    {
      _ftprintf(stderr, _T("error scanning %s: "), argv[argc - 1]);
      print_scanner_error(scanner, result);
      exit_with_code(EXIT_FAILURE);
    }

    if (print_count_only)
      _tprintf(_T("%d\n"), user_data.current_count);

  }

  result = EXIT_SUCCESS;

_exit:

  if (scanner != NULL)
    yr_scanner_destroy(scanner);

  if (rules != NULL)
    yr_rules_destroy(rules);

  yr_finalize();

  args_free(options);

  return result;
}
