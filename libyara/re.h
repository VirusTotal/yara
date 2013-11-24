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

#ifndef _RE_H
#define _RE_H

#include "yara.h"

#define RE_NODE_LITERAL             1
#define RE_NODE_MASKED_LITERAL      2
#define RE_NODE_ANY                 3
#define RE_NODE_CONCAT              4
#define RE_NODE_ALT                 5
#define RE_NODE_RANGE               6
#define RE_NODE_STAR                7
#define RE_NODE_PLUS                8
#define RE_NODE_CLASS               9
#define RE_NODE_WORD_CHAR           10
#define RE_NODE_NON_WORD_CHAR       11
#define RE_NODE_SPACE               12
#define RE_NODE_NON_SPACE           13
#define RE_NODE_DIGIT               14
#define RE_NODE_NON_DIGIT           15


#define RE_OPCODE_ANY               0xA0
#define RE_OPCODE_LITERAL           0xA1
#define RE_OPCODE_MASKED_LITERAL    0xA2
#define RE_OPCODE_LITERAL_STRING    0xA3
#define RE_OPCODE_CLASS             0xA4
#define RE_OPCODE_WORD_CHAR         0xA5
#define RE_OPCODE_NON_WORD_CHAR     0xA6
#define RE_OPCODE_SPACE             0xA7
#define RE_OPCODE_NON_SPACE         0xA8
#define RE_OPCODE_DIGIT             0xA9
#define RE_OPCODE_NON_DIGIT         0xAA
#define RE_OPCODE_MATCH             0xAB

#define RE_OPCODE_SPLIT_A           0xB0
#define RE_OPCODE_SPLIT_B           0xB1
#define RE_OPCODE_PUSH              0xB2
#define RE_OPCODE_POP               0xB3
#define RE_OPCODE_JNZ               0xB4
#define RE_OPCODE_JUMP              0xB5


#define RE_FLAGS_START_ANCHORED           0x01
#define RE_FLAGS_END_ANCHORED             0x02
#define RE_FLAGS_LITERAL_STRING           0x04
#define RE_FLAGS_FAST_HEX_REGEXP          0x08
#define RE_FLAGS_BACKWARDS                0x10
#define RE_FLAGS_EXHAUSTIVE               0x20
#define RE_FLAGS_WIDE                     0x40
#define RE_FLAGS_NO_CASE                  0x80
#define RE_FLAGS_SCAN                     0x100
#define RE_FLAGS_DOT_ALL                  0x200


typedef struct RE RE;
typedef struct RE_NODE RE_NODE;


#define CHAR_IN_CLASS(chr, cls)  \
    ((cls)[(chr) / 8] & 1 << ((chr) % 8))


struct RE_NODE
{
  int type;

  union {
    int value;
    int count;
    int start;
  };

  union {
    int mask;
    int end;
  };

  int greedy;

  uint8_t* class_vector;

  RE_NODE* left;
  RE_NODE* right;

  void* forward_code;
  void* backward_code;
};


struct RE {

  uint32_t flags;
  RE_NODE* root_node;

  const char* error_message;
  int error_code;

  uint8_t* literal_string;

  int literal_string_len;
  int literal_string_max;
};


typedef void RE_MATCH_CALLBACK_FUNC(
    uint8_t* match,
    int match_length,
    int flags,
    void* args);


int yr_re_create(
    RE** re);


int yr_re_compile(
    const char* re_string,
    RE** re);


int yr_re_compile_hex(
    const char* hex_string,
    RE** re);


RE_NODE* yr_re_node_create(
    int type,
    RE_NODE* left,
    RE_NODE* right);


void yr_re_destroy(
  RE* re);


void yr_re_print(
    RE* re);


int yr_re_emit_code(
    RE* re,
    YR_ARENA* arena);

int yr_re_exec(
    uint8_t* code,
    uint8_t* input,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args);

int yr_re_initialize();

int yr_re_finalize();

int yr_re_finalize_thread();

#endif
