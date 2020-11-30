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

#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <yara.h>
#include <yara/globals.h>
#include <yara/proc.h>

//
// Global variables used in test cases.
//

// Message for the latest compiler error
char compile_error[1024];

// Number of warnings produced by the last call to compile_rule
int warnings;

uint64_t yr_test_mem_block_size = 0;
uint64_t yr_test_mem_block_size_overlap = 0;
int64_t yr_test_mem_block_not_ready_if_zero = -1;
int64_t yr_test_mem_block_not_ready_if_zero_init_value = -1;
uint64_t yr_test_count_get_block = 0;

static uint64_t _yr_test_single_block_file_size(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) iterator->context;
  return context->current_block.size;
}

static YR_MEMORY_BLOCK* _yr_test_single_block_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) iterator->context;

  context->current_block.size = context->buffer_size;
  YR_MEMORY_BLOCK* result = &context->current_block;

  yr_test_count_get_block++;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} = %p // test iterator; single memory block, non-blocking\n",
      __FUNCTION__,
      result);

  return result;
}

static YR_MEMORY_BLOCK* _yr_test_single_block_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_MEMORY_BLOCK* result = NULL;

  yr_test_count_get_block++;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} = %p // test iterator; single memory block, non-blocking\n",
      __FUNCTION__,
      result);

  return result;
}

static const uint8_t* _yr_test_single_block_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) block->context;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} = %p // test iterator; single memory block, non-blocking\n",
      __FUNCTION__,
      context->buffer);

  return context->buffer;
}

static uint64_t _yr_test_multi_block_file_size(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) iterator->context;
  return context->buffer_size;
}

static YR_MEMORY_BLOCK* _yr_test_multi_block_get_next_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) iterator->context;

  YR_MEMORY_BLOCK* result;
  uint64_t overlap;

  yr_test_count_get_block++;
  yr_test_mem_block_not_ready_if_zero--;

  iterator->last_error = ERROR_SUCCESS;

  if (yr_test_mem_block_not_ready_if_zero == 0)
  {
    overlap = 0;
    result = NULL;
    yr_test_mem_block_not_ready_if_zero =
        yr_test_mem_block_not_ready_if_zero_init_value;
    iterator->last_error = ERROR_BLOCK_NOT_READY;
  }
  else if (0 == context->current_block.size)
  {
    overlap = 0;
    context->current_block.size = (context->buffer_size <
                                   yr_test_mem_block_size)
                                      ? context->buffer_size
                                      : yr_test_mem_block_size;
    result = &context->current_block;
  }
  else
  {
    overlap = yr_test_mem_block_size_overlap;
    context->current_block.base += (0 == context->current_block.base) ? 0
                                                                      : overlap;
    context->current_block.base += (context->current_block.base <
                                    context->buffer_size)
                                       ? yr_test_mem_block_size
                                       : 0;

    result = (context->current_block.base < context->buffer_size)
                 ? &context->current_block
                 : NULL;

    context->current_block.size =
        ((context->buffer_size - context->current_block.base) <
         yr_test_mem_block_size)
            ? context->buffer_size - context->current_block.base + overlap
            : yr_test_mem_block_size + overlap;

    context->current_block.base -= overlap;

    if (result == NULL)
    {
      // never report block not ready because end of blocks
      yr_test_mem_block_not_ready_if_zero = -1;
    }
  }

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} = %p // "
      ".base=(0x%" PRIx64 " or %" PRId64 ") of "
      "(0x%lx or %'lu) .size=%'lu, both including %" PRId64
      " block overlap%s\n",
      __FUNCTION__,
      result,
      context->current_block.base,
      context->current_block.base,
      context->buffer_size,
      context->buffer_size,
      context->current_block.size,
      overlap,
      overlap ? "" : " (note: 1st block overlap always 0)");

  return result;
}

static YR_MEMORY_BLOCK* _yr_test_multi_block_get_first_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} // wrapping _yr_test_multi_block_get_next_block()\n",
      __FUNCTION__);

  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) iterator->context;
  context->current_block.base = 0;
  context->current_block.size = 0;

  return _yr_test_multi_block_get_next_block(iterator);
}

static const uint8_t* _yr_test_multi_block_fetch_block_data(
    YR_MEMORY_BLOCK* block)
{
  YR_TEST_ITERATOR_CTX* context = (YR_TEST_ITERATOR_CTX*) block->context;

#if YR_DEBUG_VERBOSITY > 0
  uint64_t overlap = context->current_block.base > 0
                         ? yr_test_mem_block_size_overlap
                         : 0;
#endif
  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s() {} = %p = %p + 0x%" PRIx64 " base including %" PRId64
      " overlap%s\n",
      __FUNCTION__,
      context->buffer + context->current_block.base - overlap,
      context->buffer,
      context->current_block.base,
      overlap,
      overlap ? "" : " (note: 1st block overlap always 0)");

  return context->buffer + context->current_block.base;
}

int _yr_test_single_or_multi_block_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    YR_TEST_ITERATOR_CTX* iterator_ctx,
    int previous_calls)
{
  int result;

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s(buffer=%p buffer_size=%zu previous_calls=%d) {"
      " // yr_test_mem_block_size=%" PRId64 "\n",
      __FUNCTION__,
      buffer,
      buffer_size,
      previous_calls,
      yr_test_mem_block_size);

  if (previous_calls)
  {
    // Come here to skip initialization of iterator and context
  }
  else
  {
    // Come here for initialization of iterator and context

    iterator_ctx->buffer = buffer;
    iterator_ctx->buffer_size = buffer_size;
    iterator_ctx->current_block.base = 0;
    iterator_ctx->current_block.size = 0;
    iterator_ctx->current_block.context = iterator_ctx;

    iterator->context = iterator_ctx;
    iterator->last_error = ERROR_SUCCESS;

    if (yr_test_mem_block_size)
    {
      // Come here for callbacks which dish up the buffer as multi blocks
      iterator_ctx->current_block.fetch_data =
          _yr_test_multi_block_fetch_block_data;
      iterator->first = _yr_test_multi_block_get_first_block;
      iterator->next = _yr_test_multi_block_get_next_block;
      iterator->file_size = _yr_test_multi_block_file_size;
    }
    else
    {
      // Come here for callbacks which dish up the buffer as a single block
      iterator_ctx->current_block.fetch_data =
          _yr_test_single_block_fetch_block_data;
      iterator->first = _yr_test_single_block_get_first_block;
      iterator->next = _yr_test_single_block_get_next_block;
      iterator->file_size = _yr_test_single_block_file_size;
    }
  }

  result = yr_scanner_scan_mem_blocks(scanner, iterator);

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "} = %d AKA %s // %s()\n",
      result,
      ERROR_SUCCESS == result
          ? "ERROR_SUCCESS"
          : ERROR_INSUFFICIENT_MEMORY == result
                ? "ERROR_INSUFFICIENT_MEMORY"
                : ERROR_BLOCK_NOT_READY == result ? "ERROR_BLOCK_NOT_READY"
                                                  : "ERROR_?",
      __FUNCTION__);

  return result;
}

void chdir_if_env_top_srcdir(void)
{
  char* top_srcdir = getenv("TOP_SRCDIR");
  if (top_srcdir)
  {
    int result = chdir(top_srcdir);
    assert_true_expr(0 == result);
  }
}

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

int compile_rule(char* string, YR_RULES** rules)
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

int _scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "+ %s(message=%d AKA %s) {}\n",
      __FUNCTION__,
      message,
      message == CALLBACK_MSG_RULE_MATCHING
          ? "CALLBACK_MSG_RULE_MATCHING"
          : message == CALLBACK_MSG_RULE_NOT_MATCHING
                ? "CALLBACK_MSG_RULE_NOT_MATCHING"
                : message == CALLBACK_MSG_SCAN_FINISHED
                      ? "CALLBACK_MSG_SCAN_FINISHED"
                      : message == CALLBACK_MSG_IMPORT_MODULE
                            ? "CALLBACK_MSG_IMPORT_MODULE"
                            : message == CALLBACK_MSG_MODULE_IMPORTED
                                  ? "CALLBACK_MSG_MODULE_IMPORTED"
                                  : "CALLBACK_MSG_?");

  SCAN_CALLBACK_CTX* ctx = (SCAN_CALLBACK_CTX*) user_data;
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

int matches_blob_uses_default_iterator = 1;

int matches_blob(
    char* rule,
    uint8_t* blob,
    size_t blob_size,
    uint8_t* module_data,
    size_t module_data_size)
{
  YR_DEBUG_FPRINTF(
      2, stderr, "+ %s(blob_size=%zu) {\n", __FUNCTION__, blob_size);

  YR_RULES* rules;

  if (blob == NULL)
  {
    blob = (uint8_t*) "dummy";
    blob_size = 5;
  }

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(
        stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  SCAN_CALLBACK_CTX ctx = {
      .matches = 0,
      .module_data = module_data,
      .module_data_size = module_data_size,
  };

  int flags = SCAN_FLAGS_NO_TRYCATCH;
  YR_CALLBACK_FUNC callback = _scan_callback;
  void* user_data = &ctx;
  int timeout = 0;
  int scan_result;

  if (matches_blob_uses_default_iterator)
  {
    // Call   yr_rules_scan_mem()                      <- Create & config
    // scanner, and calls  yr_scanner_scan_mem()                    <- Create
    // default iterator, and calls  yr_scanner_scan_mem_blocks()             <-
    // Scan

    scan_result = yr_rules_scan_mem(
        rules, blob, blob_size, flags, callback, user_data, timeout);
  }
  else
  {
    // Call   yr_scanner_create()                      <- Create scanner
    // Call   yr_scanner_set_*()                       <- Config scanner
    // Call  _yr_test_single_or_multi_block_scan_mem() <- Create test iterator,
    // and calls  yr_scanner_scan_mem_blocks()             <- Scan Call
    // yr_scanner_destroy()                     <- Destroy scanner

    YR_SCANNER* scanner;

    assert_true_expr(ERROR_SUCCESS == yr_scanner_create(rules, &scanner));

    yr_scanner_set_callback(scanner, callback, user_data);
    yr_scanner_set_timeout(scanner, timeout);
    yr_scanner_set_flags(scanner, flags);

    YR_MEMORY_BLOCK_ITERATOR iterator;
    YR_TEST_ITERATOR_CTX iterator_ctx;
    int previous_calls = 0;

    scan_result = _yr_test_single_or_multi_block_scan_mem(
        scanner, blob, blob_size, &iterator, &iterator_ctx, previous_calls);

    yr_scanner_destroy(scanner);
  }

  if (scan_result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: scan_result: %d\n", scan_result);
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  YR_DEBUG_FPRINTF(
      2, stderr, "} = %u AKA ctx.matches // %s()\n", ctx.matches, __FUNCTION__);

  return ctx.matches;
}

int matches_string(char* rule, char* string)
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
            strncmp(f->expected, (char*) (match->data), match->data_length) ==
                0)
        {
          f->found++;
        }
      }
    }
  }

  return CALLBACK_CONTINUE;
}

int capture_string(char* rule, char* string, char* expected_string)
{
  YR_RULES* rules;

  if (compile_rule(rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(
        stderr, "failed to compile rule << %s >>: %s\n", rule, compile_error);
    exit(EXIT_FAILURE);
  }

  find_string_t f;

  f.found = 0;
  f.expected = expected_string;

  if (yr_rules_scan_mem(
          rules,
          (uint8_t*) string,
          strlen(string),
          0,
          capture_matches,
          &f,
          0) != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error\n");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  return f.found;
}

int read_file(char* filename, char** buf)
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

int _assert_atoms(RE_AST* re_ast, int expected_atom_count, atom* expected_atoms)
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

void assert_re_atoms(char* re, int expected_atom_count, atom* expected_atoms)
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

void assert_hex_atoms(char* hex, int expected_atom_count, atom* expected_atoms)
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
