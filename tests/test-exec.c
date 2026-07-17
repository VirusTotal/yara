/*
Copyright (c) 2024. The YARA Authors. All Rights Reserved.

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
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#include "util.h"

// A growable buffer used to back a YR_STREAM so the compiled rules can be
// serialized, tampered with and loaded again without touching the disk.
typedef struct
{
  uint8_t* data;
  size_t size;
  size_t pos;
  size_t cap;
} MEM_STREAM;

static size_t mem_write(const void* ptr, size_t size, size_t count, void* ud)
{
  MEM_STREAM* b = (MEM_STREAM*) ud;
  size_t n = size * count;

  if (b->pos + n > b->cap)
  {
    b->cap = (b->pos + n) * 2 + 1024;
    b->data = realloc(b->data, b->cap);
  }

  memcpy(b->data + b->pos, ptr, n);
  b->pos += n;

  if (b->pos > b->size)
    b->size = b->pos;

  return count;
}

static size_t mem_read(void* ptr, size_t size, size_t count, void* ud)
{
  MEM_STREAM* b = (MEM_STREAM*) ud;

  if (b->pos + size * count > b->size)
    count = (b->size - b->pos) / size;

  memcpy(ptr, b->data + b->pos, size * count);
  b->pos += size * count;

  return count;
}

static int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}

// OP_PUSH_RULE carries the index of the referenced rule as an 8-byte operand
// taken straight from the compiled-rules bytecode. yr_execute_code used it to
// index rules_table[] without any bounds check, while the sibling OP_MATCH_RULE
// already validated the same index against the rules arena. A compiled rule
// hand-crafted so that the OP_PUSH_RULE operand points past the rules table
// makes the scan read out of bounds. The index must be rejected.
static void test_push_rule_index_overflow(void)
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;
  YR_RULES* loaded = NULL;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  // Rule "b" references rule "a" in its condition, which is emitted as an
  // OP_PUSH_RULE (opcode 27 = 0x1B) carrying a's rule index (0) as an 8-byte
  // operand.
  if (yr_compiler_add_string(
          compiler,
          "rule a { condition: true }\nrule b { condition: a }",
          NULL) != 0)
    exit(EXIT_FAILURE);

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  MEM_STREAM buffer = {0};
  YR_STREAM out = {.user_data = &buffer, .read = mem_read, .write = mem_write};

  if (yr_rules_save_stream(rules, &out) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  // Find the OP_PUSH_RULE for rule "a" (opcode 0x1B followed by an 8-byte zero
  // index) and bump the index to a value far past the rules table.
  int tampered = 0;

  for (size_t i = 0; i + 9 < buffer.size; i++)
  {
    if (buffer.data[i] == 0x1B && buffer.data[i + 1] == 0x00 &&
        buffer.data[i + 2] == 0x00 && buffer.data[i + 3] == 0x00 &&
        buffer.data[i + 4] == 0x00 && buffer.data[i + 5] == 0x00 &&
        buffer.data[i + 6] == 0x00 && buffer.data[i + 7] == 0x00 &&
        buffer.data[i + 8] == 0x00)
    {
      buffer.data[i + 1] = 0xFF;
      buffer.data[i + 2] = 0xFF;
      buffer.data[i + 3] = 0xFF;
      buffer.data[i + 4] = 0xFF;
      tampered = 1;
      break;
    }
  }

  assert(tampered);

  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);

  buffer.pos = 0;
  YR_STREAM in = {.user_data = &buffer, .read = mem_read, .write = mem_write};

  if (yr_rules_load_stream(&in, &loaded) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  uint8_t data[16] = {0};

  // Without the bounds check this scan reads rules_table past its end. The
  // out-of-range index must be detected and reported instead.
  int result = yr_rules_scan_mem(
      loaded, data, sizeof(data), 0, scan_callback, NULL, 0);

  assert(result == ERROR_INTERNAL_FATAL_ERROR);

  yr_rules_destroy(loaded);
  free(buffer.data);
}

int main(int argc, char** argv)
{
  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  test_push_rule_index_overflow();

  yr_finalize();

  YR_DEBUG_FPRINTF(1, stderr, "} // %s() in %s\n", __FUNCTION__, argv[0]);

  return 0;
}
