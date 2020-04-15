/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <yara.h>
#include "util.h"

//
// Global variables used in test cases.
//

// Message for the latest compiler error
char compile_error[1024];

// Number of warnings produced by the last call to compile_rule
int warnings;


//
// A YR_CALLBACK_FUNC that counts the number of matching and non-matching rules
// during a scan. user_data must point to a COUNTERS structure.
//
int count(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  switch (message)
  {
    case CALLBACK_MSG_RULE_MATCHING:
      (*(struct COUNTERS*) user_data).rules_matching++;
      break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
      (*(struct COUNTERS*) user_data).rules_not_matching++;

  }
  return CALLBACK_CONTINUE;
}


int count_non_matches(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_NOT_MATCHING)
  {
    (*(int*) user_data)++;
  }

  return CALLBACK_CONTINUE;
}

//
// A YR_CALLBACK_FUNC that does nothing.
//
int do_nothing(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}


static void _compiler_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_WARNING)
    (*((int*) user_data))++;

  snprintf(
      compile_error,
      sizeof(compile_error),
      "line %d: %s",
      line_number,
      message);
}


int compile_rule(
    char* string,
    YR_RULES** rules)
{
  YR_COMPILER* compiler = NULL;
  int result = ERROR_SUCCESS;

  compile_error[0] = '\0';
  warnings = 0;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    goto _exit;
  }

  yr_compiler_set_callback(compiler, _compiler_callback, &warnings);

  if (yr_compiler_add_string(compiler, string, NULL) != 0)
  {
    result = compiler->last_error;
    goto _exit;
  }

  result = yr_compiler_get_rules(compiler, rules);

_exit:
  yr_compiler_destroy(compiler);
  return result;
}


typedef struct SCAN_CALLBACK_CTX SCAN_CALLBACK_CTX;

struct SCAN_CALLBACK_CTX {
  int matches;
  void* module_data;
  size_t module_data_size;
};

static int _scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  SCAN_CALLBACK_CTX* ctx =  (SCAN_CALLBACK_CTX*) user_data;
  YR_MODULE_IMPORT* mi;

  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
    ctx->matches++;
    break;
  case CALLBACK_MSG_IMPORT_MODULE:
    mi = (YR_MODULE_IMPORT*) message_data;
    mi->module_data = ctx->module_data;
    mi->module_data_size = ctx->module_data_size;
    break;
  }

  return CALLBACK_CONTINUE;
}


int matches_blob(
    char* rule,
    uint8_t* blob,
    size_t blob_size,
    uint8_t* module_data,
    size_t module_data_size)
{
  YR_RULES* rules;

  if (blob == NULL)
  {
    blob = (uint8_t*) "dummy";
    blob_size = 5;
  }

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  SCAN_CALLBACK_CTX ctx = {
    .matches = 0,
    .module_data = module_data,
    .module_data_size = module_data_size,
  };

  int scan_result = yr_rules_scan_mem(
      rules, blob, blob_size, SCAN_FLAGS_NO_TRYCATCH, _scan_callback, &ctx, 0);

  if (scan_result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error: %d\n", scan_result);
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  return ctx.matches;
}


int matches_string(
    char* rule,
    char* string)
{
  size_t len = 0;

  if (string != NULL)
    len = strlen(string);

  return matches_blob(rule, (uint8_t*) string, len, NULL, 0);
}

typedef struct
{
  char* expected;
  int found;

} find_string_t;


static int capture_matches(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    find_string_t* f = (find_string_t*) user_data;

    YR_RULE* rule = (YR_RULE*) message_data;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string)
    {
      YR_MATCH* match;

      yr_string_matches_foreach(context, string, match)
      {
        if (strlen(f->expected) == match->data_length &&
            strncmp(f->expected, (char*)(match->data), match->data_length) == 0)
        {
          f->found++;
        }
      }
    }
  }

  return CALLBACK_CONTINUE;
}


typedef struct
{
  int number;
  int found;
  char* expected[14];

} check_string_t;

static int new_capture_matches(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  check_string_t* f = (check_string_t*) user_data;
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    YR_RULE* rule = (YR_RULE*) message_data;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string)
    {
      YR_MATCH* match;

      yr_string_matches_foreach(context, string, match)
      {
        if (f->found < f->number)
        {
          if (strlen(f->expected[f->found]) != match->data_length ||
            strncmp(f->expected[f->found], (char*)(match->data), match->data_length) != 0)
          {
            f->found = 0;
            return CALLBACK_CONTINUE;
          }
        }
        f->found++;
      }
    }
    if (f->found != f->number)
    {
      f->found = 0;
      return CALLBACK_CONTINUE;
    }
  }
  return CALLBACK_CONTINUE;
}


int capture_string(
    char* rule,
    char* string,
    char* expected_string)
{
  YR_RULES* rules;

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  find_string_t f;

  f.found = 0;
  f.expected = expected_string;

  if (yr_rules_scan_mem(rules, (uint8_t*)string, strlen(string), 0,
                        capture_matches, &f, 0) != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error\n");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  return f.found;
}


int capture_strings(
    char* rule,
    char* string,
    char* expected_strings[],
    int number)
{
  YR_RULES* rules;

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  check_string_t f;

  f.found = 0;
  f.number = number;
  int i = 0;
  for (i = 0; i < number; i++)
    f.expected[i] = expected_strings[i];

  if (yr_rules_scan_mem(rules, (uint8_t*)string, strlen(string), 0,
                        new_capture_matches, &f, 0) != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error\n");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);
  return f.found;
}


int read_file(
    char* filename,
    char** buf)
{
  int fd;

  if ((fd = open(filename, O_RDONLY)) < 0)
    return -1;

  size_t sz = lseek(fd, 0, SEEK_END);
  int rc = -1;

  if (sz == -1)
    goto _exit;

  if (lseek(fd, 0, SEEK_SET) != 0)
    goto _exit;

  if ((*buf = malloc(sz)) == NULL)
    goto _exit;

  if ((rc = read(fd, *buf, sz)) != sz)
  {
    rc = -1;
    free(*buf);
  }

_exit:
  close(fd);
  return rc;
}


int _assert_atoms(
    RE_AST* re_ast,
    int expected_atom_count,
    atom* expected_atoms)
{
  YR_ATOMS_CONFIG c;
  YR_ATOM_LIST_ITEM* atoms;
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* next_atom;

  int min_atom_quality;
  int exit_code;
  YR_MODIFIER modifier;
  modifier.flags = 0;

  c.get_atom_quality = yr_atoms_heuristic_quality;

  yr_atoms_extract_from_re(&c, re_ast, modifier, &atoms, &min_atom_quality);

  atom = atoms;

  exit_code = EXIT_SUCCESS;
  while (atom != NULL)
  {
    if (expected_atom_count == 0)
    {
      exit_code = EXIT_FAILURE;
      break;
    }

    if (atom->atom.length != expected_atoms->length ||
       memcmp(atom->atom.bytes, expected_atoms->data, atom->atom.length) != 0)
    {
      exit_code = EXIT_FAILURE;
      break;
    }

    expected_atoms++;
    expected_atom_count--;
    atom = atom->next;
  }

  atom = atoms;
  while (atom != NULL)
  {
    next_atom = atom->next;
    yr_free(atom);
    atom = next_atom;
  }

  return exit_code;
}


void assert_re_atoms(
    char* re,
    int expected_atom_count,
    atom* expected_atoms)
{
  RE_AST* re_ast;
  RE_ERROR re_error;

  int exit_code;

  yr_re_parse(re, &re_ast, &re_error);
  exit_code = _assert_atoms(re_ast, expected_atom_count, expected_atoms);

  if (re_ast != NULL)
    yr_re_ast_destroy(re_ast);

  if (exit_code != EXIT_SUCCESS)
    exit(exit_code);
}


void assert_hex_atoms(
    char* hex,
    int expected_atom_count,
    atom* expected_atoms)
{
  RE_AST* re_ast;
  RE_ERROR re_error;

  int exit_code;

  yr_re_parse_hex(hex, &re_ast, &re_error);
  exit_code = _assert_atoms(re_ast, expected_atom_count, expected_atoms);

  if (re_ast != NULL)
    yr_re_ast_destroy(re_ast);

  if (exit_code != EXIT_SUCCESS)
    exit(exit_code);
}
