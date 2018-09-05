/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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


/*

This module implements a regular expressions engine based on Thompson's
algorithm as described by Russ Cox in http://swtch.com/~rsc/regexp/regexp2.html.

What the article names a "thread" has been named a "fiber" in this code, in
order to avoid confusion with operating system threads.

*/

#include <assert.h>
#include <string.h>

#include <yara/limits.h>
#include <yara/globals.h>
#include <yara/utils.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/threading.h>
#include <yara/re_lexer.h>
#include <yara/hex_lexer.h>


#define EMIT_BACKWARDS                  0x01
#define EMIT_DONT_SET_FORWARDS_CODE     0x02
#define EMIT_DONT_SET_BACKWARDS_CODE    0x04

#ifndef INT16_MAX
#define INT16_MAX              (32767)
#endif


typedef uint8_t RE_SPLIT_ID_TYPE;


typedef struct _RE_REPEAT_ARGS
{
  uint16_t  min;
  uint16_t  max;
  int32_t   offset;

} RE_REPEAT_ARGS;


typedef struct _RE_REPEAT_ANY_ARGS
{
  uint16_t   min;
  uint16_t   max;

} RE_REPEAT_ANY_ARGS;


typedef struct _RE_EMIT_CONTEXT {

  YR_ARENA*         arena;
  RE_SPLIT_ID_TYPE  next_split_id;

} RE_EMIT_CONTEXT;


#define CHAR_IN_CLASS(cls, chr)  \
  ((cls)[(chr) / 8] & 1 << ((chr) % 8))


static bool _yr_re_is_char_in_class(
    RE_CLASS* re_class,
    uint8_t chr,
    int case_insensitive)
{
  int result = CHAR_IN_CLASS(re_class->bitmap, chr);

  if (case_insensitive)
    result |= CHAR_IN_CLASS(re_class->bitmap, yr_altercase[chr]);

  if (re_class->negated)
    result = !result;

  return result;
}


static bool _yr_re_is_word_char(
    const uint8_t* input,
    uint8_t character_size)
{
  int result = ((isalnum(*input) || (*input) == '_'));

  if (character_size == 2)
    result = result && (*(input + 1) == 0);

  return result;
}


RE_NODE* yr_re_node_create(
    int type,
    RE_NODE* left,
    RE_NODE* right)
{
  RE_NODE* result = (RE_NODE*) yr_malloc(sizeof(RE_NODE));

  if (result != NULL)
  {
    result->type = type;
    result->left = left;
    result->right = right;
    result->greedy = true;
    result->forward_code = NULL;
    result->backward_code = NULL;
  }

  return result;
}


void yr_re_node_destroy(
    RE_NODE* node)
{
  if (node->left != NULL)
    yr_re_node_destroy(node->left);

  if (node->right != NULL)
    yr_re_node_destroy(node->right);

  if (node->type == RE_NODE_CLASS)
    yr_free(node->re_class);

  yr_free(node);
}


int yr_re_ast_create(
    RE_AST** re_ast)
{
  *re_ast = (RE_AST*) yr_malloc(sizeof(RE_AST));

  if (*re_ast == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  (*re_ast)->flags = 0;
  (*re_ast)->levels = 0;
  (*re_ast)->root_node = NULL;

  return ERROR_SUCCESS;
}


void yr_re_ast_destroy(
    RE_AST* re_ast)
{
  if (re_ast->root_node != NULL)
    yr_re_node_destroy(re_ast->root_node);

  yr_free(re_ast);
}


//
// yr_re_parse
//
// Parses a regexp but don't emit its code. A further call to
// yr_re_emit_code is required to get the code.
//

int yr_re_parse(
    const char* re_string,
    RE_AST** re_ast,
    RE_ERROR* error)
{
  return yr_parse_re_string(re_string, re_ast, error);
}


//
// yr_re_parse_hex
//
// Parses a hex string but don't emit its code. A further call to
// yr_re_emit_code is required to get the code.
//

int yr_re_parse_hex(
    const char* hex_string,
    RE_AST** re_ast,
    RE_ERROR* error)
{
  return yr_parse_hex_string(hex_string, re_ast, error);
}


//
// yr_re_compile
//
// Parses the regexp and emit its code to the provided code_arena.
//

int yr_re_compile(
    const char* re_string,
    int flags,
    YR_ARENA* code_arena,
    RE** re,
    RE_ERROR* error)
{
  RE_AST* re_ast;
  RE _re;

  FAIL_ON_ERROR(yr_arena_reserve_memory(
      code_arena, sizeof(int64_t) + RE_MAX_CODE_SIZE));

  FAIL_ON_ERROR(yr_re_parse(re_string, &re_ast, error));

  _re.flags = flags;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_arena_write_data(
          code_arena,
          &_re,
          sizeof(_re),
          (void**) re),
      yr_re_ast_destroy(re_ast));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_re_ast_emit_code(re_ast, code_arena, false),
      yr_re_ast_destroy(re_ast));

  yr_re_ast_destroy(re_ast);

  return ERROR_SUCCESS;
}


//
// yr_re_match
//
// Verifies if the target string matches the pattern
//
// Args:
//    YR_SCAN_CONTEXT* context  - Scan context
//    RE* re                    -  A pointer to a compiled regexp
//    char* target              -  Target string
//
// Returns:
//    See return codes for yr_re_exec


int yr_re_match(
    YR_SCAN_CONTEXT* context,
    RE* re,
    const char* target)
{
  int result;

  yr_re_exec(
      context,
      re->code,
      (uint8_t*) target,
      strlen(target),
      0,
      re->flags | RE_FLAGS_SCAN,
      NULL,
      NULL,
      &result);

  return result;
}


//
// yr_re_ast_extract_literal
//
// Verifies if the provided regular expression is just a literal string
// like "abc", "12345", without any wildcard, operator, etc. In that case
// returns the string as a SIZED_STRING, or returns NULL if otherwise.
//
// The caller is responsible for deallocating the returned SIZED_STRING by
// calling yr_free.
//

SIZED_STRING* yr_re_ast_extract_literal(
    RE_AST* re_ast)
{
  SIZED_STRING* string;
  RE_NODE* node = re_ast->root_node;

  int i, length = 0;

  while (node != NULL)
  {
    length++;

    if (node->type == RE_NODE_LITERAL)
      break;

    if (node->type != RE_NODE_CONCAT)
      return NULL;

    if (node->right == NULL ||
        node->right->type != RE_NODE_LITERAL)
      return NULL;

    node = node->left;
  }

  string = (SIZED_STRING*) yr_malloc(sizeof(SIZED_STRING) + length);

  if (string == NULL)
    return NULL;

  string->length = length;
  node = re_ast->root_node;

  // The root node is the end of the string. So let's fill it up backwards.
  for (i = length - 1; i > 0; i--)
  {
    string->c_string[i] = node->right->value;
    node = node->left;
  }

  if (length > 0)
    string->c_string[0] = node->value;

  assert(node == NULL || node->type == RE_NODE_LITERAL);

  return string;
}


int _yr_re_node_contains_dot_star(
    RE_NODE* re_node)
{
  if ((re_node->type == RE_NODE_STAR || re_node->type == RE_NODE_PLUS) &&
      re_node->left->type == RE_NODE_ANY)
    return true;

  if (re_node->left != NULL && _yr_re_node_contains_dot_star(re_node->left))
    return true;

  if (re_node->right != NULL && _yr_re_node_contains_dot_star(re_node->right))
    return true;

  return false;
}


int yr_re_ast_contains_dot_star(
    RE_AST* re_ast)
{
  return _yr_re_node_contains_dot_star(re_ast->root_node);
}


//
// yr_re_ast_split_at_chaining_point
//
// In some cases splitting a regular expression in two is more efficient that
// having a single regular expression. This happens when the regular expression
// contains a large repetition of any character, for example: /foo.{0,1000}bar/
// In this case the regexp is split in /foo/ and /bar/ where /bar/ is "chained"
// to /foo/. This means that /foo/ and /bar/ are handled as individual regexps
// and when both matches YARA verifies if the distance between the matches
// complies with the {0,1000} restriction.

// This function traverses the regexp's tree looking for nodes where the regxp
// should be split. It expects a left-unbalanced tree where the right child of
// a RE_NODE_CONCAT can't be another RE_NODE_CONCAT. A RE_NODE_CONCAT must be
// always the left child of its parent if the parent is also a RE_NODE_CONCAT.
//

int yr_re_ast_split_at_chaining_point(
    RE_AST* re_ast,
    RE_AST** result_re_ast,
    RE_AST** remainder_re_ast,
    int32_t* min_gap,
    int32_t* max_gap)
{
  RE_NODE* node = re_ast->root_node;
  RE_NODE* child = re_ast->root_node->left;
  RE_NODE* parent = NULL;

  int result;

  *result_re_ast = re_ast;
  *remainder_re_ast = NULL;
  *min_gap = 0;
  *max_gap = 0;

  while (child != NULL && child->type == RE_NODE_CONCAT)
  {
    if (child->right != NULL &&
        child->right->type == RE_NODE_RANGE_ANY &&
        child->right->greedy == false &&
        (child->right->start > YR_STRING_CHAINING_THRESHOLD ||
         child->right->end > YR_STRING_CHAINING_THRESHOLD))
    {
      result = yr_re_ast_create(remainder_re_ast);

      if (result != ERROR_SUCCESS)
        return result;

      (*remainder_re_ast)->root_node = child->left;
      (*remainder_re_ast)->flags = re_ast->flags;

      child->left = NULL;

      if (parent != NULL)
        parent->left = node->right;
      else
        (*result_re_ast)->root_node = node->right;

      node->right = NULL;

      *min_gap = child->right->start;
      *max_gap = child->right->end;

      yr_re_node_destroy(node);

      return ERROR_SUCCESS;
    }

    parent = node;
    node = child;
    child = child->left;
  }

  return ERROR_SUCCESS;
}


int _yr_emit_inst(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    uint8_t** instruction_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  *code_size = sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint8(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    uint8_t argument,
    uint8_t** instruction_addr,
    uint8_t** argument_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &argument,
      sizeof(uint8_t),
      (void**) argument_addr));

  *code_size = 2 * sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint16(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    uint16_t argument,
    uint8_t** instruction_addr,
    uint16_t** argument_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &argument,
      sizeof(uint16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint16_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint32(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    uint32_t argument,
    uint8_t** instruction_addr,
    uint32_t** argument_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &argument,
      sizeof(uint32_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint32_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_int16(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    int16_t argument,
    uint8_t** instruction_addr,
    int16_t** argument_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &argument,
      sizeof(int16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(int16_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_struct(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    void* structure,
    size_t structure_size,
    uint8_t** instruction_addr,
    void** argument_addr,
    size_t* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      structure,
      structure_size,
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + structure_size;

  return ERROR_SUCCESS;
}


int _yr_emit_split(
    RE_EMIT_CONTEXT* emit_context,
    uint8_t opcode,
    int16_t argument,
    uint8_t** instruction_addr,
    int16_t** argument_addr,
    size_t* code_size)
{
  assert(opcode == RE_OPCODE_SPLIT_A || opcode == RE_OPCODE_SPLIT_B);

  if (emit_context->next_split_id == RE_MAX_SPLIT_ID)
    return ERROR_REGULAR_EXPRESSION_TOO_COMPLEX;

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &emit_context->next_split_id,
      sizeof(RE_SPLIT_ID_TYPE),
      NULL));

  emit_context->next_split_id++;

  FAIL_ON_ERROR(yr_arena_write_data(
      emit_context->arena,
      &argument,
      sizeof(int16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(RE_SPLIT_ID_TYPE) + sizeof(int16_t);

  return ERROR_SUCCESS;
}


static int _yr_re_emit(
    RE_EMIT_CONTEXT* emit_context,
    RE_NODE* re_node,
    int flags,
    uint8_t** code_addr,
    size_t* code_size)
{
  size_t branch_size;
  size_t split_size;
  size_t inst_size;
  size_t jmp_size;

  bool emit_split;
  bool emit_repeat;
  bool emit_prolog;
  bool emit_epilog;

  RE_REPEAT_ARGS repeat_args;
  RE_REPEAT_ARGS* repeat_start_args_addr;
  RE_REPEAT_ANY_ARGS repeat_any_args;

  RE_NODE* left;
  RE_NODE* right;

  int16_t* split_offset_addr = NULL;
  int16_t* jmp_offset_addr = NULL;
  uint8_t* instruction_addr = NULL;

  *code_size = 0;

  switch(re_node->type)
  {
  case RE_NODE_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint8(
        emit_context,
        RE_OPCODE_LITERAL,
        re_node->value,
        &instruction_addr,
        NULL,
        code_size));
    break;

  case RE_NODE_MASKED_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint16(
        emit_context,
        RE_OPCODE_MASKED_LITERAL,
        re_node->mask << 8 | re_node->value,
        &instruction_addr,
        NULL,
        code_size));
    break;

  case RE_NODE_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_WORD_CHAR,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_NON_WORD_CHAR,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_WORD_BOUNDARY:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_WORD_BOUNDARY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_WORD_BOUNDARY:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_NON_WORD_BOUNDARY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_SPACE,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_NON_SPACE,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_DIGIT,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_NON_DIGIT,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_ANY:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_ANY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_CLASS:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_CLASS,
        &instruction_addr,
        code_size));

    FAIL_ON_ERROR(yr_arena_write_data(
        emit_context->arena,
        re_node->re_class,
        sizeof(*re_node->re_class),
        NULL));

    *code_size += sizeof(*re_node->re_class);
    break;

  case RE_NODE_ANCHOR_START:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_MATCH_AT_START,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_ANCHOR_END:

    FAIL_ON_ERROR(_yr_emit_inst(
        emit_context,
        RE_OPCODE_MATCH_AT_END,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_CONCAT:

    if (flags & EMIT_BACKWARDS)
    {
      left = re_node->right;
      right = re_node->left;
    }
    else
    {
      left = re_node->left;
      right = re_node->right;
    }

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        left,
        flags,
        &instruction_addr,
        &branch_size));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        right,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    break;

  case RE_NODE_PLUS:

    // Code for e+ looks like:
    //
    //          L1: code for e
    //              split L1, L2
    //          L2:

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        re_node->left,
        flags,
        &instruction_addr,
        &branch_size));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_emit_split(
        emit_context,
        re_node->greedy ? RE_OPCODE_SPLIT_B : RE_OPCODE_SPLIT_A,
        -((int16_t) branch_size),
        NULL,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;
    break;

  case RE_NODE_STAR:

    // Code for e* looks like:
    //
    //          L1: split L1, L2
    //              code for e
    //              jmp L1
    //          L2:

    FAIL_ON_ERROR(_yr_emit_split(
        emit_context,
        re_node->greedy ? RE_OPCODE_SPLIT_A : RE_OPCODE_SPLIT_B,
        0,
        &instruction_addr,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        re_node->left,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        emit_context,
        RE_OPCODE_JUMP,
        -((uint16_t)(branch_size + split_size)),
        NULL,
        &jmp_offset_addr,
        &jmp_size));

    *code_size += jmp_size;

    if (split_size + branch_size + jmp_size >= INT16_MAX)
      return ERROR_REGULAR_EXPRESSION_TOO_LARGE;

    // Update split offset.
    *split_offset_addr = (int16_t) (split_size + branch_size + jmp_size);
    break;

  case RE_NODE_ALT:

    // Code for e1|e2 looks like:
    //
    //              split L1, L2
    //          L1: code for e1
    //              jmp L3
    //          L2: code for e2
    //          L3:

    // Emit a split instruction with offset set to 0 temporarily. Offset
    // will be updated after we know the size of the code generated for
    // the left node (e1).

    FAIL_ON_ERROR(_yr_emit_split(
        emit_context,
        RE_OPCODE_SPLIT_A,
        0,
        &instruction_addr,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        re_node->left,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        emit_context,
        RE_OPCODE_JUMP,
        0,
        NULL,
        &jmp_offset_addr,
        &jmp_size));

    *code_size += jmp_size;

    if (split_size + branch_size + jmp_size >= INT16_MAX)
      return ERROR_REGULAR_EXPRESSION_TOO_LARGE;

    // Update split offset.
    *split_offset_addr = (int16_t) (split_size + branch_size + jmp_size);

    FAIL_ON_ERROR(_yr_re_emit(
        emit_context,
        re_node->right,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    if (branch_size + jmp_size >= INT16_MAX)
      return ERROR_REGULAR_EXPRESSION_TOO_LARGE;

    // Update offset for jmp instruction.
    *jmp_offset_addr = (int16_t) (branch_size + jmp_size);
    break;

  case RE_NODE_RANGE_ANY:

    repeat_any_args.min = re_node->start;
    repeat_any_args.max = re_node->end;

    FAIL_ON_ERROR(_yr_emit_inst_arg_struct(
        emit_context,
        re_node->greedy ?
            RE_OPCODE_REPEAT_ANY_GREEDY :
            RE_OPCODE_REPEAT_ANY_UNGREEDY,
        &repeat_any_args,
        sizeof(repeat_any_args),
        &instruction_addr,
        NULL,
        &inst_size));

    *code_size += inst_size;
    break;

  case RE_NODE_RANGE:

    // Code for e{n,m} looks like:
    //
    //            code for e              ---   prolog
    //            repeat_start n, m, L1   --+
    //        L0: code for e                |   repeat
    //            repeat_end n, m, L0     --+
    //        L1: split L2, L3            ---   split
    //        L2: code for e              ---   epilog
    //        L3:
    //
    // Not all sections (prolog, repeat, split and epilog) are generated in all
    // cases, it depends on the values of n and m. The following table shows
    // which sections are generated for the first few values of n and m.
    //
    //        n,m   prolog  repeat      split  epilog
    //                      (min,max)
    //        ---------------------------------------
    //        0,0     -       -           -      -
    //        0,1     -       -           X      X
    //        0,2     -       0,1         X      X
    //        0,3     -       0,2         X      X
    //        0,M     -       0,M-1       X      X
    //
    //        1,1     X       -           -      -
    //        1,2     X       -           X      X
    //        1,3     X       0,1         X      X
    //        1,4     X       1,2         X      X
    //        1,M     X       1,M-2       X      X
    //
    //        2,2     X       -           -      X
    //        2,3     X       1,1         X      X
    //        2,4     X       1,2         X      X
    //        2,M     X       1,M-2       X      X
    //
    //        3,3     X       1,1         -      X
    //        3,4     X       2,2         X      X
    //        3,M     X       2,M-2       X      X
    //
    //        4,4     X       2,2         -      X
    //        4,5     X       3,3         X      X
    //        4,M     X       3,M-2       X      X
    //
    // The code can't consists simply in the repeat section, the prolog and
    // epilog are required because we can't have atoms pointing to code inside
    // the repeat loop. Atoms' forwards_code will point to code in the prolog
    // and backwards_code will point to code in the epilog (or in prolog if
    // epilog wasn't generated, like in n=1,m=1)

    emit_prolog = re_node->start > 0;
    emit_repeat = re_node->end > re_node->start + 1 || re_node->end > 2;
    emit_split = re_node->end > re_node->start;
    emit_epilog = re_node->end > re_node->start || re_node->end > 1;

    if (emit_prolog)
    {
      FAIL_ON_ERROR(_yr_re_emit(
          emit_context,
          re_node->left,
          flags,
          &instruction_addr,
          &branch_size));

       *code_size += branch_size;
    }

    if (emit_repeat)
    {
      repeat_args.min = re_node->start;
      repeat_args.max = re_node->end;

      if (emit_prolog)
      {
        repeat_args.max--;
        repeat_args.min--;
      }

      if (emit_split)
      {
        repeat_args.max--;
      }
      else
      {
        repeat_args.min--;
        repeat_args.max--;
      }

      repeat_args.offset = 0;

      FAIL_ON_ERROR(_yr_emit_inst_arg_struct(
          emit_context,
          re_node->greedy ?
              RE_OPCODE_REPEAT_START_GREEDY :
              RE_OPCODE_REPEAT_START_UNGREEDY,
          &repeat_args,
          sizeof(repeat_args),
          emit_prolog ? NULL : &instruction_addr,
          (void**) &repeat_start_args_addr,
          &inst_size));

      *code_size += inst_size;

      FAIL_ON_ERROR(_yr_re_emit(
          emit_context,
          re_node->left,
          flags | EMIT_DONT_SET_FORWARDS_CODE | EMIT_DONT_SET_BACKWARDS_CODE,
          NULL,
          &branch_size));

      *code_size += branch_size;

      repeat_start_args_addr->offset = (int32_t)(2 * inst_size + branch_size);
      repeat_args.offset = -((int32_t) branch_size);

      FAIL_ON_ERROR(_yr_emit_inst_arg_struct(
          emit_context,
          re_node->greedy ?
              RE_OPCODE_REPEAT_END_GREEDY :
              RE_OPCODE_REPEAT_END_UNGREEDY,
          &repeat_args,
          sizeof(repeat_args),
          NULL,
          NULL,
          &inst_size));

      *code_size += inst_size;
    }

    if (emit_split)
    {
      FAIL_ON_ERROR(_yr_emit_split(
          emit_context,
          re_node->greedy ?
              RE_OPCODE_SPLIT_A :
              RE_OPCODE_SPLIT_B,
          0,
          NULL,
          &split_offset_addr,
          &split_size));

      *code_size += split_size;
    }

    if (emit_epilog)
    {
      FAIL_ON_ERROR(_yr_re_emit(
          emit_context,
          re_node->left,
          emit_prolog ? flags | EMIT_DONT_SET_FORWARDS_CODE : flags,
          emit_prolog || emit_repeat ? NULL : &instruction_addr,
          &branch_size));

      *code_size += branch_size;
    }

    if (emit_split)
    {
      if (split_size + branch_size >= INT16_MAX)
        return ERROR_REGULAR_EXPRESSION_TOO_LARGE;

      *split_offset_addr = (int16_t) (split_size + branch_size);
    }

    break;
  }

  if (flags & EMIT_BACKWARDS)
  {
    if (!(flags & EMIT_DONT_SET_BACKWARDS_CODE))
      re_node->backward_code = instruction_addr + *code_size;
  }
  else
  {
    if (!(flags & EMIT_DONT_SET_FORWARDS_CODE))
      re_node->forward_code = instruction_addr;
  }

  if (code_addr != NULL)
    *code_addr = instruction_addr;

  return ERROR_SUCCESS;
}


int yr_re_ast_emit_code(
    RE_AST* re_ast,
    YR_ARENA* arena,
    int backwards_code)
{
  RE_EMIT_CONTEXT emit_context;

  size_t code_size;
  size_t total_size;

  // Ensure that we have enough contiguous memory space in the arena to
  // contain the regular expression code. The code can't span over multiple
  // non-contiguous pages.

  FAIL_ON_ERROR(yr_arena_reserve_memory(arena, RE_MAX_CODE_SIZE));

  // Emit code for matching the regular expressions forwards.

  total_size = 0;
  emit_context.arena = arena;
  emit_context.next_split_id = 0;

  FAIL_ON_ERROR(_yr_re_emit(
      &emit_context,
      re_ast->root_node,
      backwards_code ? EMIT_BACKWARDS : 0,
      NULL,
      &code_size));

  total_size += code_size;

  FAIL_ON_ERROR(_yr_emit_inst(
      &emit_context,
      RE_OPCODE_MATCH,
      NULL,
      &code_size));

  total_size += code_size;

  if (total_size > RE_MAX_CODE_SIZE)
    return ERROR_REGULAR_EXPRESSION_TOO_LARGE;

  return ERROR_SUCCESS;
}


static int _yr_re_fiber_create(
    RE_FIBER_POOL* fiber_pool,
    RE_FIBER** new_fiber)
{
  RE_FIBER* fiber;

  if (fiber_pool->fibers.head != NULL)
  {
    fiber = fiber_pool->fibers.head;
    fiber_pool->fibers.head = fiber->next;

    if (fiber_pool->fibers.tail == fiber)
      fiber_pool->fibers.tail = NULL;
  }
  else
  {
    if (fiber_pool->fiber_count == RE_MAX_FIBERS)
      return ERROR_TOO_MANY_RE_FIBERS;

    fiber = (RE_FIBER*) yr_malloc(sizeof(RE_FIBER));

    if (fiber == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    fiber_pool->fiber_count++;
  }

  fiber->ip = NULL;
  fiber->sp = -1;
  fiber->rc = -1;
  fiber->next = NULL;
  fiber->prev = NULL;

  *new_fiber = fiber;

  return ERROR_SUCCESS;
}


//
// _yr_re_fiber_append
//
// Appends 'fiber' to 'fiber_list'
//

static void _yr_re_fiber_append(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER* fiber)
{
  assert(fiber->prev == NULL);
  assert(fiber->next == NULL);

  fiber->prev = fiber_list->tail;

  if (fiber_list->tail != NULL)
    fiber_list->tail->next = fiber;

  fiber_list->tail = fiber;

  if (fiber_list->head == NULL)
    fiber_list->head = fiber;

  assert(fiber_list->tail->next == NULL);
  assert(fiber_list->head->prev == NULL);
}


//
// _yr_re_fiber_exists
//
// Verifies if a fiber with the same properties (ip, rc, sp, and stack values)
// than 'target_fiber' exists in 'fiber_list'. The list is iterated from
// the start until 'last_fiber' (inclusive). Fibers past 'last_fiber' are not
// taken into account.
//

static int _yr_re_fiber_exists(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER* target_fiber,
    RE_FIBER* last_fiber)
{
  RE_FIBER* fiber = fiber_list->head;

  int equal_stacks;
  int i;

  if (last_fiber == NULL)
    return false;

  while (fiber != last_fiber->next)
  {
    if (fiber->ip == target_fiber->ip &&
        fiber->sp == target_fiber->sp &&
        fiber->rc == target_fiber->rc)
    {
      equal_stacks = true;

      for (i = 0; i <= fiber->sp; i++)
      {
        if (fiber->stack[i] != target_fiber->stack[i])
        {
          equal_stacks = false;
          break;
        }
      }

      if (equal_stacks)
        return true;
    }

    fiber = fiber->next;
  }

  return false;
}


//
// _yr_re_fiber_split
//
// Clones a fiber in fiber_list and inserts the cloned fiber just after.
// the original one. If fiber_list is:
//
//   f1 -> f2 -> f3 -> f4
//
// Splitting f2 will result in:
//
//   f1 -> f2 -> cloned f2 -> f3 -> f4
//

static int _yr_re_fiber_split(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_POOL* fiber_pool,
    RE_FIBER* fiber,
    RE_FIBER** new_fiber)
{
  int32_t i;

  FAIL_ON_ERROR(_yr_re_fiber_create(fiber_pool, new_fiber));

  (*new_fiber)->sp = fiber->sp;
  (*new_fiber)->ip = fiber->ip;
  (*new_fiber)->rc = fiber->rc;

  for (i = 0; i <= fiber->sp; i++)
    (*new_fiber)->stack[i] = fiber->stack[i];

  (*new_fiber)->next = fiber->next;
  (*new_fiber)->prev = fiber;

  if (fiber->next != NULL)
    fiber->next->prev = *new_fiber;

  fiber->next = *new_fiber;

  if (fiber_list->tail == fiber)
    fiber_list->tail = *new_fiber;

  assert(fiber_list->tail->next == NULL);
  assert(fiber_list->head->prev == NULL);

  return ERROR_SUCCESS;
}


//
// _yr_re_fiber_kill
//
// Kills a given fiber by removing it from the fiber list and putting it
// in the fiber pool.
//

static RE_FIBER* _yr_re_fiber_kill(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_POOL* fiber_pool,
    RE_FIBER* fiber)
{
  RE_FIBER* next_fiber = fiber->next;

  if (fiber->prev != NULL)
    fiber->prev->next = next_fiber;

  if (next_fiber != NULL)
    next_fiber->prev = fiber->prev;

  if (fiber_pool->fibers.tail != NULL)
    fiber_pool->fibers.tail->next = fiber;

  if (fiber_list->tail == fiber)
    fiber_list->tail = fiber->prev;

  if (fiber_list->head == fiber)
    fiber_list->head = next_fiber;

  fiber->next = NULL;
  fiber->prev = fiber_pool->fibers.tail;
  fiber_pool->fibers.tail = fiber;

  if (fiber_pool->fibers.head == NULL)
    fiber_pool->fibers.head = fiber;

  return next_fiber;
}


//
// _yr_re_fiber_kill_tail
//
// Kills all fibers from the given one up to the end of the fiber list.
//

static void _yr_re_fiber_kill_tail(
  RE_FIBER_LIST* fiber_list,
  RE_FIBER_POOL* fiber_pool,
  RE_FIBER* fiber)
{
  RE_FIBER* prev_fiber = fiber->prev;

  if (prev_fiber != NULL)
    prev_fiber->next = NULL;

  fiber->prev = fiber_pool->fibers.tail;

  if (fiber_pool->fibers.tail != NULL)
    fiber_pool->fibers.tail->next = fiber;

  fiber_pool->fibers.tail = fiber_list->tail;
  fiber_list->tail = prev_fiber;

  if (fiber_list->head == fiber)
    fiber_list->head = NULL;

  if (fiber_pool->fibers.head == NULL)
    fiber_pool->fibers.head = fiber;
}


//
// _yr_re_fiber_kill_all
//
// Kills all fibers in the fiber list.
//

static void _yr_re_fiber_kill_all(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_POOL* fiber_pool)
{
  if (fiber_list->head != NULL)
    _yr_re_fiber_kill_tail(fiber_list, fiber_pool, fiber_list->head);
}


//
// _yr_re_fiber_sync
//
// Executes a fiber until reaching an "matching" instruction. A "matching"
// instruction is one that actually reads a byte from the input and performs
// some matching. If the fiber reaches a split instruction, the new fiber is
// also synced.
//

static int _yr_re_fiber_sync(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_POOL* fiber_pool,
    RE_FIBER* fiber_to_sync)
{
  // A array for keeping track of which split instructions has been already
  // executed. Each split instruction within a regexp has an associated ID
  // between 0 and RE_MAX_SPLIT_ID. Keeping track of executed splits is
  // required to avoid infinite loops in regexps like (a*)* or (a|)*

  RE_SPLIT_ID_TYPE splits_executed[RE_MAX_SPLIT_ID];
  RE_SPLIT_ID_TYPE splits_executed_count = 0;
  RE_SPLIT_ID_TYPE split_id, splits_executed_idx;

  int split_already_executed;

  RE_REPEAT_ARGS* repeat_args;
  RE_REPEAT_ANY_ARGS* repeat_any_args;

  RE_FIBER* fiber;
  RE_FIBER* last;
  RE_FIBER* next;
  RE_FIBER* branch_a;
  RE_FIBER* branch_b;

  fiber = fiber_to_sync;
  last = fiber_to_sync->next;

  while (fiber != last)
  {
    uint8_t opcode = *fiber->ip;

    switch (opcode)
    {
      case RE_OPCODE_SPLIT_A:
      case RE_OPCODE_SPLIT_B:

        split_id = *(RE_SPLIT_ID_TYPE*)(fiber->ip + 1);
        split_already_executed = false;

        for (splits_executed_idx = 0;
             splits_executed_idx < splits_executed_count;
             splits_executed_idx++)
        {
          if (split_id == splits_executed[splits_executed_idx])
          {
            split_already_executed = true;
            break;
          }
        }

        if (split_already_executed)
        {
          fiber = _yr_re_fiber_kill(fiber_list, fiber_pool, fiber);
        }
        else
        {
          branch_a = fiber;

          FAIL_ON_ERROR(_yr_re_fiber_split(
              fiber_list, fiber_pool, branch_a, &branch_b));

          // With RE_OPCODE_SPLIT_A the current fiber continues at the next
          // instruction in the stream (branch A), while the newly created
          // fiber starts at the address indicated by the instruction (branch B)
          // RE_OPCODE_SPLIT_B has the opposite behavior.

          if (opcode == RE_OPCODE_SPLIT_B)
            yr_swap(branch_a, branch_b, RE_FIBER*);

          // Branch A continues at the next instruction

          branch_a->ip += (sizeof(RE_SPLIT_ID_TYPE) + 3);

          // Branch B adds the offset encoded in the opcode to its instruction
          // pointer.

          branch_b->ip += *(int16_t*)(
              branch_b->ip
              + 1  // opcode size
              + sizeof(RE_SPLIT_ID_TYPE));

          splits_executed[splits_executed_count] = split_id;
          splits_executed_count++;
        }

        break;

      case RE_OPCODE_REPEAT_START_GREEDY:
      case RE_OPCODE_REPEAT_START_UNGREEDY:

        repeat_args = (RE_REPEAT_ARGS*)(fiber->ip + 1);
        assert(repeat_args->max > 0);
        branch_a = fiber;

        if (repeat_args->min == 0)
        {
          FAIL_ON_ERROR(_yr_re_fiber_split(
              fiber_list, fiber_pool, branch_a, &branch_b));

          if (opcode == RE_OPCODE_REPEAT_START_UNGREEDY)
            yr_swap(branch_a, branch_b, RE_FIBER*);

          branch_b->ip += repeat_args->offset;
        }

        branch_a->stack[++branch_a->sp] = 0;
        branch_a->ip += (1 + sizeof(RE_REPEAT_ARGS));
        break;

      case RE_OPCODE_REPEAT_END_GREEDY:
      case RE_OPCODE_REPEAT_END_UNGREEDY:

        repeat_args = (RE_REPEAT_ARGS*)(fiber->ip + 1);
        fiber->stack[fiber->sp]++;

        if (fiber->stack[fiber->sp] < repeat_args->min)
        {
          fiber->ip += repeat_args->offset;
          break;
        }

        branch_a = fiber;

        if (fiber->stack[fiber->sp] < repeat_args->max)
        {
          FAIL_ON_ERROR(_yr_re_fiber_split(
              fiber_list, fiber_pool, branch_a, &branch_b));

          if (opcode == RE_OPCODE_REPEAT_END_GREEDY)
            yr_swap(branch_a, branch_b, RE_FIBER*);

          branch_a->sp--;
          branch_b->ip += repeat_args->offset;
        }

        branch_a->ip += (1 + sizeof(RE_REPEAT_ARGS));
        break;

      case RE_OPCODE_REPEAT_ANY_GREEDY:
      case RE_OPCODE_REPEAT_ANY_UNGREEDY:

        repeat_any_args = (RE_REPEAT_ANY_ARGS*)(fiber->ip + 1);

        // If repetition counter (rc) is -1 it means that we are reaching this
        // instruction from the previous one in the instructions stream. In
        // this case let's initialize the counter to 0 and start looping.

        if (fiber->rc == -1)
          fiber->rc = 0;

        if (fiber->rc < repeat_any_args->min)
        {
          // Increase repetition counter and continue with next fiber. The
          // instruction pointer for this fiber is not incremented yet, this
          // fiber spins in this same instruction until reaching the minimum
          // number of repetitions.

          fiber->rc++;
          fiber = fiber->next;
        }
        else if (fiber->rc < repeat_any_args->max)
        {
          // Once the minimum number of repetitions are matched one fiber
          // remains spinning in this instruction until reaching the maximum
          // number of repetitions while new fibers are created. New fibers
          // start executing at the next instruction.

          next = fiber->next;
          branch_a = fiber;

          FAIL_ON_ERROR(_yr_re_fiber_split(
              fiber_list, fiber_pool, branch_a, &branch_b));

          if (opcode == RE_OPCODE_REPEAT_ANY_UNGREEDY)
            yr_swap(branch_a, branch_b, RE_FIBER*);

          branch_a->rc++;
          branch_b->ip += (1 + sizeof(RE_REPEAT_ANY_ARGS));
          branch_b->rc = -1;

          FAIL_ON_ERROR(_yr_re_fiber_sync(
              fiber_list, fiber_pool, branch_b));

          fiber = next;
        }
        else
        {
          // When the maximum number of repetitions is reached the fiber keeps
          // executing at the next instruction. The repetition counter is set
          // to -1 indicating that we are not spinning in a repeat instruction
          // anymore.

          fiber->ip += (1 + sizeof(RE_REPEAT_ANY_ARGS));
          fiber->rc = -1;
        }

        break;

      case RE_OPCODE_JUMP:
        fiber->ip += *(int16_t*)(fiber->ip + 1);
        break;

      default:
        fiber = fiber->next;
    }
  }

  return ERROR_SUCCESS;
}


//
// yr_re_exec
//
// Executes a regular expression. The specified regular expression will try to
// match the data starting at the address specified by "input". The "input"
// pointer can point to any address inside a memory buffer. Arguments
// "input_forwards_size" and "input_backwards_size" indicate how many bytes
// can be accesible starting at "input" and going forwards and backwards
// respectively.
//
//   <--- input_backwards_size -->|<----------- input_forwards_size -------->
//  |--------  memory buffer  -----------------------------------------------|
//                                ^
//                              input
//
// Args:
//   YR_SCAN_CONTEXT *context         - Scan context.
//   const uint8_t* code              - Regexp code be executed
//   const uint8_t* input             - Pointer to input data
//   size_t input_forwards_size       - Number of accessible bytes starting at
//                                      "input" and going forwards.
//   size_t input_backwards_size      - Number of accessible bytes starting at
//                                      "input" and going backwards
//   int flags                        - Flags:
//      RE_FLAGS_SCAN
//      RE_FLAGS_BACKWARDS
//      RE_FLAGS_EXHAUSTIVE
//      RE_FLAGS_WIDE
//      RE_FLAGS_NO_CASE
//      RE_FLAGS_DOT_ALL
//   RE_MATCH_CALLBACK_FUNC callback  - Callback function
//   void* callback_args              - Callback argument
//   int*  matches                    - Pointer to an integer receiving the
//                                      number of matching bytes. Notice that
//                                      0 means a zero-length match, while no
//                                      matches is -1.
// Returns:
//    ERROR_SUCCESS or any other error code.

int yr_re_exec(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    const uint8_t* input_data,
    size_t input_forwards_size,
    size_t input_backwards_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    int* matches)
{
  const uint8_t* input;
  const uint8_t* ip;

  uint8_t mask;
  uint8_t value;
  uint8_t character_size;

  RE_FIBER_LIST fibers;
  RE_FIBER* fiber;
  RE_FIBER* next_fiber;

  int bytes_matched;
  int max_bytes_matched;
  int match;
  int input_incr;
  int kill;
  int action;

  #define ACTION_NONE       0
  #define ACTION_CONTINUE   1
  #define ACTION_KILL       2
  #define ACTION_KILL_TAIL  3

  #define prolog { \
      if ((bytes_matched >= max_bytes_matched) || \
          (character_size == 2 && *(input + 1) != 0)) \
      { \
        action = ACTION_KILL; \
        break; \
      } \
    }

  if (matches != NULL)
    *matches = -1;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;

  input = input_data;
  input_incr = character_size;

  if (flags & RE_FLAGS_BACKWARDS)
  {
    max_bytes_matched = (int) yr_min(input_backwards_size, RE_SCAN_LIMIT);
    input -= character_size;
    input_incr = -input_incr;
  }
  else
  {
    max_bytes_matched = (int) yr_min(input_forwards_size, RE_SCAN_LIMIT);
  }

  // Round down max_bytes_matched to a multiple of character_size, this way if
  // character_size is 2 and max_bytes_matched is odd we are ignoring the
  // extra byte which can't match anyways.

  max_bytes_matched = max_bytes_matched - max_bytes_matched % character_size;
  bytes_matched = 0;

  FAIL_ON_ERROR(_yr_re_fiber_create(&context->re_fiber_pool, &fiber));

  fiber->ip = code;
  fibers.head = fiber;
  fibers.tail = fiber;

  FAIL_ON_ERROR_WITH_CLEANUP(
      _yr_re_fiber_sync(&fibers, &context->re_fiber_pool, fiber),
      _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));

  while (fibers.head != NULL)
  {
    fiber = fibers.head;

    while (fiber != NULL)
    {
      next_fiber = fiber->next;

      if (_yr_re_fiber_exists(&fibers, fiber, fiber->prev))
        _yr_re_fiber_kill(&fibers, &context->re_fiber_pool, fiber);

      fiber = next_fiber;
    }

    fiber = fibers.head;

    while (fiber != NULL)
    {
      ip = fiber->ip;
      action = ACTION_NONE;

      switch (*ip)
      {
        case RE_OPCODE_ANY:
          prolog;
          match = (flags & RE_FLAGS_DOT_ALL) || (*input != 0x0A);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_REPEAT_ANY_GREEDY:
        case RE_OPCODE_REPEAT_ANY_UNGREEDY:
          prolog;
          match = (flags & RE_FLAGS_DOT_ALL) || (*input != 0x0A);
          action = match ? ACTION_NONE : ACTION_KILL;

          // The instruction pointer is not incremented here. The current fiber
          // spins in this instruction until reaching the required number of
          // repetitions. The code controlling the number of repetitions is in
          // _yr_re_fiber_sync.

          break;

        case RE_OPCODE_LITERAL:
          prolog;
          if (flags & RE_FLAGS_NO_CASE)
            match = yr_lowercase[*input] == yr_lowercase[*(ip + 1)];
          else
            match = (*input == *(ip + 1));
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 2;
          break;

        case RE_OPCODE_MASKED_LITERAL:
          prolog;
          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;

          // We don't need to take into account the case-insensitive
          // case because this opcode is only used with hex strings,
          // which can't be case-insensitive.

          match = ((*input & mask) == value);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 3;
          break;

        case RE_OPCODE_CLASS:
          prolog;
          match = _yr_re_is_char_in_class(
              (RE_CLASS*) (ip + 1), *input, flags & RE_FLAGS_NO_CASE);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += (sizeof(RE_CLASS) + 1);
          break;

        case RE_OPCODE_WORD_CHAR:
          prolog;
          match = _yr_re_is_word_char(input, character_size);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_NON_WORD_CHAR:
          prolog;
          match = !_yr_re_is_word_char(input, character_size);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_SPACE:
        case RE_OPCODE_NON_SPACE:

          prolog;

          switch (*input)
          {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case '\v':
            case '\f':
              match = true;
              break;
            default:
              match = false;
          }

          if (*ip == RE_OPCODE_NON_SPACE)
            match = !match;

          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_DIGIT:
          prolog;
          match = isdigit(*input);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_NON_DIGIT:
          prolog;
          match = !isdigit(*input);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_WORD_BOUNDARY:
        case RE_OPCODE_NON_WORD_BOUNDARY:

          if (bytes_matched == 0 && input_backwards_size < character_size)
          {
            match = true;
          }
          else if (bytes_matched >= max_bytes_matched)
          {
            match = true;
          }
          else
          {
            assert(input <  input_data + input_forwards_size);
            assert(input >= input_data - input_backwards_size);

            assert(input - input_incr <  input_data + input_forwards_size);
            assert(input - input_incr >= input_data - input_backwards_size);

            match = _yr_re_is_word_char(input, character_size) != \
                    _yr_re_is_word_char(input - input_incr, character_size);
          }

          if (*ip == RE_OPCODE_NON_WORD_BOUNDARY)
            match = !match;

          action = match ? ACTION_CONTINUE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_MATCH_AT_START:
          if (flags & RE_FLAGS_BACKWARDS)
            kill = input_backwards_size > (size_t) bytes_matched;
          else
            kill = input_backwards_size > 0 || (bytes_matched != 0);
          action = kill ? ACTION_KILL : ACTION_CONTINUE;
          fiber->ip += 1;
          break;

        case RE_OPCODE_MATCH_AT_END:
          kill = flags & RE_FLAGS_BACKWARDS ||
                 input_forwards_size > (size_t) bytes_matched;
          action = kill ? ACTION_KILL : ACTION_CONTINUE;
          fiber->ip += 1;
          break;

        case RE_OPCODE_MATCH:

          if (matches != NULL)
            *matches = bytes_matched;

          if (flags & RE_FLAGS_EXHAUSTIVE)
          {
            if (callback != NULL)
            {
              if (flags & RE_FLAGS_BACKWARDS)
              {
                FAIL_ON_ERROR_WITH_CLEANUP(
                    callback(
                        input + character_size,
                        bytes_matched,
                        flags,
                        callback_args),
                    _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));
              }
              else
              {
                FAIL_ON_ERROR_WITH_CLEANUP(
                    callback(
                        input_data,
                        bytes_matched,
                        flags,
                        callback_args),
                    _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));
              }
            }

            action = ACTION_KILL;
          }
          else
          {
            action = ACTION_KILL_TAIL;
          }

          break;

        default:
          assert(false);
      }

      switch (action)
      {
        case ACTION_KILL:
          fiber = _yr_re_fiber_kill(&fibers, &context->re_fiber_pool, fiber);
          break;

        case ACTION_KILL_TAIL:
          _yr_re_fiber_kill_tail(&fibers, &context->re_fiber_pool, fiber);
          fiber = NULL;
          break;

        case ACTION_CONTINUE:
          FAIL_ON_ERROR_WITH_CLEANUP(
              _yr_re_fiber_sync(&fibers, &context->re_fiber_pool, fiber),
              _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));
          break;

        default:
          next_fiber = fiber->next;
          FAIL_ON_ERROR_WITH_CLEANUP(
              _yr_re_fiber_sync(&fibers, &context->re_fiber_pool, fiber),
              _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));
          fiber = next_fiber;
      }
    }

    input += input_incr;
    bytes_matched += character_size;

    if (flags & RE_FLAGS_SCAN && bytes_matched < max_bytes_matched)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_re_fiber_create(&context->re_fiber_pool, &fiber),
          _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));

      fiber->ip = code;
      _yr_re_fiber_append(&fibers, fiber);

      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_re_fiber_sync(&fibers, &context->re_fiber_pool, fiber),
          _yr_re_fiber_kill_all(&fibers, &context->re_fiber_pool));
    }
  }

  return ERROR_SUCCESS;
}

//
// yr_re_fast_exec
//
// This function replaces yr_re_exec for regular expressions marked with flag
// RE_FLAGS_FAST_REGEXP. These are regular expression whose code contain only
// the following operations: RE_OPCODE_LITERAL, RE_OPCODE_MASKED_LITERAL,
// RE_OPCODE_ANY, RE_OPCODE_REPEAT_ANY_UNGREEDY and RE_OPCODE_MATCH. Some
// examples of regular expressions that can be executed with this function are:
//
//  /foobar/
//  /foo.*?bar/
//

int yr_re_fast_exec(
    YR_SCAN_CONTEXT* context,
    const uint8_t* code,
    const uint8_t* input_data,
    size_t input_forwards_size,
    size_t input_backwards_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args,
    int* matches)
{
  RE_REPEAT_ANY_ARGS* repeat_any_args;

  const uint8_t* code_stack[YR_MAX_FAST_RE_STACK];
  const uint8_t* input_stack[YR_MAX_FAST_RE_STACK];
  int matches_stack[YR_MAX_FAST_RE_STACK];

  const uint8_t* input = input_data;
  const uint8_t* next_input;
  const uint8_t* ip = code;
  const uint8_t* next_opcode;

  uint8_t mask;
  uint8_t value;

  int i;
  int stop;
  int input_incr;
  int sp = 0;
  int bytes_matched;
  int max_bytes_matched;

  max_bytes_matched = flags & RE_FLAGS_BACKWARDS ?
      (int) input_backwards_size :
      (int) input_forwards_size;

  input_incr = flags & RE_FLAGS_BACKWARDS ? -1 : 1;

  if (flags & RE_FLAGS_BACKWARDS)
    input--;

  code_stack[sp] = code;
  input_stack[sp] = input;
  matches_stack[sp] = 0;
  sp++;

  while (sp > 0)
  {
    sp--;
    ip = code_stack[sp];
    input = input_stack[sp];
    bytes_matched = matches_stack[sp];
    stop = false;

    while (!stop)
    {
      if (*ip == RE_OPCODE_MATCH)
      {
        if (flags & RE_FLAGS_EXHAUSTIVE)
        {
          FAIL_ON_ERROR(callback(
             flags & RE_FLAGS_BACKWARDS ? input + 1 : input_data,
             bytes_matched,
             flags,
             callback_args));

          break;
        }
        else
        {
          if (matches != NULL)
            *matches = bytes_matched;

          return ERROR_SUCCESS;
        }
      }

      if (bytes_matched >= max_bytes_matched)
        break;

      switch (*ip)
      {
        case RE_OPCODE_LITERAL:

          if (*input == *(ip + 1))
          {
            bytes_matched++;
            input += input_incr;
            ip += 2;
          }
          else
          {
            stop = true;
          }

          break;

        case RE_OPCODE_MASKED_LITERAL:

          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;

          if ((*input & mask) == value)
          {
            bytes_matched++;
            input += input_incr;
            ip += 3;
          }
          else
          {
            stop = true;
          }

          break;

        case RE_OPCODE_ANY:

          bytes_matched++;
          input += input_incr;
          ip += 1;

          break;

        case RE_OPCODE_REPEAT_ANY_UNGREEDY:

          repeat_any_args = (RE_REPEAT_ANY_ARGS*)(ip + 1);
          next_opcode = ip + 1 + sizeof(RE_REPEAT_ANY_ARGS);

          for (i = repeat_any_args->min + 1; i <= repeat_any_args->max; i++)
          {
            if (bytes_matched + i >= max_bytes_matched)
              break;

            next_input = input + i * input_incr;

            if ( *(next_opcode) != RE_OPCODE_LITERAL ||
                (*(next_opcode) == RE_OPCODE_LITERAL &&
                 *(next_opcode + 1) == *next_input))
            {
              if (sp >= YR_MAX_FAST_RE_STACK)
                return ERROR_TOO_MANY_RE_FIBERS;

              code_stack[sp] = next_opcode;
              input_stack[sp] = next_input;
              matches_stack[sp] = bytes_matched + i;
              sp++;
            }
          }

          input += input_incr * repeat_any_args->min;
          bytes_matched += repeat_any_args->min;
          bytes_matched = yr_min(bytes_matched, max_bytes_matched);
          ip = next_opcode;

          break;

        default:
          assert(false);
      }
    }
  }

  if (matches != NULL)
    *matches = -1;

  return ERROR_SUCCESS;
}


static void _yr_re_print_node(
    RE_NODE* re_node)
{
  int i;

  if (re_node == NULL)
    return;

  switch (re_node->type)
  {
  case RE_NODE_ALT:
    printf("Alt(");
    _yr_re_print_node(re_node->left);
    printf(", ");
    _yr_re_print_node(re_node->right);
    printf(")");
    break;

  case RE_NODE_CONCAT:
    printf("Cat(");
    _yr_re_print_node(re_node->left);
    printf(", ");
    _yr_re_print_node(re_node->right);
    printf(")");
    break;

  case RE_NODE_STAR:
    printf("Star(");
    _yr_re_print_node(re_node->left);
    printf(")");
    break;

  case RE_NODE_PLUS:
    printf("Plus(");
    _yr_re_print_node(re_node->left);
    printf(")");
    break;

  case RE_NODE_LITERAL:
    printf("Lit(%02X)", re_node->value);
    break;

  case RE_NODE_MASKED_LITERAL:
    printf("MaskedLit(%02X,%02X)", re_node->value, re_node->mask);
    break;

  case RE_NODE_WORD_CHAR:
    printf("WordChar");
    break;

  case RE_NODE_NON_WORD_CHAR:
    printf("NonWordChar");
    break;

  case RE_NODE_SPACE:
    printf("Space");
    break;

  case RE_NODE_NON_SPACE:
    printf("NonSpace");
    break;

  case RE_NODE_DIGIT:
    printf("Digit");
    break;

  case RE_NODE_NON_DIGIT:
    printf("NonDigit");
    break;

  case RE_NODE_ANY:
    printf("Any");
    break;

  case RE_NODE_RANGE:
    printf("Range(%d-%d, ", re_node->start, re_node->end);
    _yr_re_print_node(re_node->left);
    printf(")");
    break;

  case RE_NODE_CLASS:
    printf("Class(");
    for (i = 0; i < 256; i++)
      if (_yr_re_is_char_in_class(re_node->re_class, i, false))
        printf("%02X,", i);
    printf(")");
    break;

  default:
    printf("???");
    break;
  }
}

void yr_re_print(
    RE_AST* re_ast)
{
  _yr_re_print_node(re_ast->root_node);
}
