/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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


/*

This modules implements a regular expressions engine based on Thompson's
algorithm as described by Russ Cox in http://swtch.com/~rsc/regexp/regexp2.html.

What the article names a "thread" has been named a "fiber" in this code, in
order to avoid confusion with operating system threads.

*/

#include <assert.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <yara/limits.h>
#include <yara/globals.h>
#include <yara/utils.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/re_lexer.h>
#include <yara/hex_lexer.h>


#define RE_MAX_STACK      1024  // Maxium stack size for regexp evaluation
#define RE_MAX_CODE_SIZE  16384 // Maximum code size for a compiled regexp
#define RE_SCAN_LIMIT     4096  // Maximum input size scanned by yr_re_exec


#define EMIT_BACKWARDS                  0x01
#define EMIT_DONT_SET_FORWARDS_CODE     0x02
#define EMIT_DONT_SET_BACKWARDS_CODE    0x04
#define EMIT_NO_CASE                    0x08
#define EMIT_DOT_ALL                    0x10


typedef struct _RE_FIBER
{
  RE_CODE  ip;
  int32_t  sp;

  uint16_t stack[RE_MAX_STACK];

  struct _RE_FIBER* prev;
  struct _RE_FIBER* next;

} RE_FIBER;


typedef struct _RE_FIBER_LIST
{
  RE_FIBER* head;
  RE_FIBER* tail;

} RE_FIBER_LIST;


typedef struct _RE_THREAD_STORAGE
{
  RE_FIBER_LIST fiber_pool;

} RE_THREAD_STORAGE;


#ifdef _WIN32
DWORD thread_storage_key = 0;
#else
pthread_key_t thread_storage_key = 0;
#endif

//
// yr_re_initialize
//
// Should be called by main thread before any other
// function from this module.
//

int yr_re_initialize(void)
{
  #ifdef _WIN32
  thread_storage_key = TlsAlloc();
  #else
  pthread_key_create(&thread_storage_key, NULL);
  #endif

  return ERROR_SUCCESS;
}

//
// yr_re_finalize
//
// Should be called by main thread after every other thread
// stopped using functions from this module.
//

int yr_re_finalize(void)
{
  #ifdef _WIN32
  TlsFree(thread_storage_key);
  #else
  pthread_key_delete(thread_storage_key);
  #endif

  thread_storage_key = 0;
  return ERROR_SUCCESS;
}

//
// yr_re_finalize_thread
//
// Should be called by every thread using this module
// before exiting.
//

int yr_re_finalize_thread(void)
{
  RE_FIBER* fiber;
  RE_FIBER* next_fiber;
  RE_THREAD_STORAGE* storage;

  if (thread_storage_key != 0)
    #ifdef _WIN32
    storage = (RE_THREAD_STORAGE*) TlsGetValue(thread_storage_key);
    #else
    storage = (RE_THREAD_STORAGE*) pthread_getspecific(thread_storage_key);
    #endif
  else
    return ERROR_SUCCESS;

  if (storage != NULL)
  {
    fiber = storage->fiber_pool.head;

    while (fiber != NULL)
    {
      next_fiber = fiber->next;
      yr_free(fiber);
      fiber = next_fiber;
    }

    yr_free(storage);
  }

  #ifdef _WIN32
  TlsSetValue(thread_storage_key, NULL);
  #else
  pthread_setspecific(thread_storage_key, NULL);
  #endif

  return ERROR_SUCCESS;
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
    result->greedy = TRUE;
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
    yr_free(node->class_vector);

  yr_free(node);
}


int yr_re_create(
    RE** re)
{
  *re = (RE*) yr_malloc(sizeof(RE));

  if (*re == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  (*re)->flags = 0;
  (*re)->root_node = NULL;
  (*re)->code_arena = NULL;
  (*re)->code = NULL;

  return ERROR_SUCCESS;
}


void yr_re_destroy(
    RE* re)
{
  if (re->root_node != NULL)
    yr_re_node_destroy(re->root_node);

  if (re->code_arena != NULL)
    yr_arena_destroy(re->code_arena);

  yr_free(re);
}


//
// yr_re_parse
//
// Parses a regexp but don't emit its code. A further call to y
// yr_re_emit_code is required to get the code.
//

int yr_re_parse(
    const char* re_string,
    int flags,
    RE** re,
    RE_ERROR* error)
{
  return yr_parse_re_string(re_string, flags, re, error);
}


//
// yr_re_parse_hex
//
// Parses a hex string but don't emit its code. A further call to
// yr_re_emit_code is required to get the code.
//

int yr_re_parse_hex(
    const char* hex_string,
    int flags,
    RE** re,
    RE_ERROR* error)
{
  return yr_parse_hex_string(hex_string, flags, re, error);
}


//
// yr_re_compile
//
// Parses the regexp and emit its code to the provided code_arena,
// if code_arena is NULL the function creates a new arena of its own.
//

int yr_re_compile(
    const char* re_string,
    int flags,
    YR_ARENA* code_arena,
    RE** re,
    RE_ERROR* error)
{
  RE* compiled_re;
  YR_ARENA* arena;

  *re = NULL;

  FAIL_ON_ERROR(yr_re_parse(re_string, flags, &compiled_re, error));

  if (code_arena == NULL)
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_arena_create(
            RE_MAX_CODE_SIZE,
            ARENA_FLAGS_FIXED_SIZE,
            &arena),
        yr_re_destroy(compiled_re));

    compiled_re->code_arena = arena;
  }
  else
  {
    arena = code_arena;
  }

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_re_emit_code(compiled_re, arena),
      yr_re_destroy(compiled_re));

  *re = compiled_re;

  return ERROR_SUCCESS;
}


//
// yr_re_match
//
// Verifies if the target string matches the pattern
//
// Args:
//    uint8_t* re_code    -  A pointer to regexp code
//    char* target        -  Target string
//
// Returns:
//    Integer indicating the number of matching bytes, including 0 when
//    matching an empty regexp. Negative values indicate:
//      -1  No match
//      -2  An error ocurred


int yr_re_match(
    RE_CODE re_code,
    const char* target)
{
  return yr_re_exec(
      re_code,
      (uint8_t*) target,
      strlen(target),
      RE_FLAGS_SCAN,
      NULL,
      NULL);
}


//
// yr_re_extract_literal
//
// Verifies if the provided regular expression is just a literal string
// like "abc", "12345", without any wildcard, operator, etc. In that case
// returns the string as a SIZED_STRING, or returns NULL if otherwise.
//
// The caller is responsible for deallocating the returned SIZED_STRING by
// calling yr_free.
//

SIZED_STRING* yr_re_extract_literal(
    RE* re)
{
  SIZED_STRING* string;
  RE_NODE* node = re->root_node;

  int i, length = 0;
  char tmp;

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

  string->length = 0;

  node = re->root_node;

  while (node->type == RE_NODE_CONCAT)
  {
    string->c_string[string->length++] = node->right->value;
    node = node->left;
  }

  string->c_string[string->length++] = node->value;

  // The string ends up reversed. Reverse it back to its original value.

  for (i = 0; i < length / 2; i++)
  {
    tmp = string->c_string[i];
    string->c_string[i] = string->c_string[length - i - 1];
    string->c_string[length - i - 1] = tmp;
  }

  return string;
}


int _yr_re_node_contains_dot_star(
    RE_NODE* re_node)
{
  if (re_node->type == RE_NODE_STAR && re_node->left->type == RE_NODE_ANY)
    return TRUE;

  if (re_node->left != NULL && _yr_re_node_contains_dot_star(re_node->left))
    return TRUE;

  if (re_node->right != NULL && _yr_re_node_contains_dot_star(re_node->right))
    return TRUE;

  return FALSE;
}


int yr_re_contains_dot_star(
    RE* re)
{
  return _yr_re_node_contains_dot_star(re->root_node);
}


int yr_re_split_at_chaining_point(
    RE* re,
    RE** result_re,
    RE** remainder_re,
    int32_t* min_gap,
    int32_t* max_gap)
{
  RE_NODE* node = re->root_node;
  RE_NODE* child = re->root_node->left;
  RE_NODE* parent = NULL;

  int result;

  *result_re = re;
  *remainder_re = NULL;
  *min_gap = 0;
  *max_gap = 0;

  while (child != NULL && child->type == RE_NODE_CONCAT)
  {
    if (child->right != NULL &&
        child->right->type == RE_NODE_RANGE &&
        child->right->greedy == FALSE &&
        child->right->left->type == RE_NODE_ANY &&
        (child->right->start > STRING_CHAINING_THRESHOLD ||
         child->right->end > STRING_CHAINING_THRESHOLD))
    {
      result = yr_re_create(remainder_re);

      if (result != ERROR_SUCCESS)
        return result;

      (*remainder_re)->root_node = child->left;
      (*remainder_re)->flags = re->flags;

      child->left = NULL;

      if (parent != NULL)
        parent->left = node->right;
      else
        (*result_re)->root_node = node->right;

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
    YR_ARENA* arena,
    uint8_t opcode,
    uint8_t** instruction_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  *code_size = sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint8(
    YR_ARENA* arena,
    uint8_t opcode,
    uint8_t argument,
    uint8_t** instruction_addr,
    uint8_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint8_t),
      (void**) argument_addr));

  *code_size = 2 * sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint16(
    YR_ARENA* arena,
    uint8_t opcode,
    uint16_t argument,
    uint8_t** instruction_addr,
    uint16_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint16_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint32(
    YR_ARENA* arena,
    uint8_t opcode,
    uint32_t argument,
    uint8_t** instruction_addr,
    uint32_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint32_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint32_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_int16(
    YR_ARENA* arena,
    uint8_t opcode,
    int16_t argument,
    uint8_t** instruction_addr,
    int16_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      (void**) instruction_addr));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(int16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(int16_t);

  return ERROR_SUCCESS;
}


int _yr_re_emit(
    RE_NODE* re_node,
    YR_ARENA* arena,
    int flags,
    uint8_t** code_addr,
    int* code_size)
{
  int i;
  int branch_size;
  int split_size;
  int inst_size;
  int jmp_size;

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
        arena,
        flags & EMIT_NO_CASE ?
          RE_OPCODE_LITERAL_NO_CASE :
          RE_OPCODE_LITERAL,
        re_node->value,
        &instruction_addr,
        NULL,
        code_size));
    break;

  case RE_NODE_MASKED_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint16(
        arena,
        RE_OPCODE_MASKED_LITERAL,
        re_node->mask << 8 | re_node->value,
        &instruction_addr,
        NULL,
        code_size));
    break;

  case RE_NODE_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_WORD_CHAR,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_NON_WORD_CHAR,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_WORD_BOUNDARY:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_WORD_BOUNDARY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_WORD_BOUNDARY:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_NON_WORD_BOUNDARY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_SPACE,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_NON_SPACE,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_DIGIT,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_NON_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_NON_DIGIT,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_ANY:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        flags & EMIT_DOT_ALL ?
          RE_OPCODE_ANY :
          RE_OPCODE_ANY_EXCEPT_NEW_LINE,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_CLASS:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        (flags & EMIT_NO_CASE) ?
          RE_OPCODE_CLASS_NO_CASE :
          RE_OPCODE_CLASS,
        &instruction_addr,
        code_size));

    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        re_node->class_vector,
        32,
        NULL));

    *code_size += 32;
    break;

  case RE_NODE_ANCHOR_START:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_MATCH_AT_START,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_ANCHOR_END:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
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
        left,
        arena,
        flags,
        &instruction_addr,
        &branch_size));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_re_emit(
        right,
        arena,
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
        re_node->left,
        arena,
        flags,
        &instruction_addr,
        &branch_size));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        re_node->greedy ? RE_OPCODE_SPLIT_B : RE_OPCODE_SPLIT_A,
        -branch_size,
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

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        re_node->greedy ? RE_OPCODE_SPLIT_A : RE_OPCODE_SPLIT_B,
        0,
        &instruction_addr,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left,
        arena,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        RE_OPCODE_JUMP,
        -(branch_size + split_size),
        NULL,
        &jmp_offset_addr,
        &jmp_size));

    *code_size += jmp_size;

    // Update split offset.
    *split_offset_addr = split_size + branch_size + jmp_size;
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

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        RE_OPCODE_SPLIT_A,
        0,
        &instruction_addr,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left,
        arena,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        RE_OPCODE_JUMP,
        0,
        NULL,
        &jmp_offset_addr,
        &jmp_size));

    *code_size += jmp_size;

    // Update split offset.
    *split_offset_addr = split_size + branch_size + jmp_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->right,
        arena,
        flags,
        NULL,
        &branch_size));

    *code_size += branch_size;

    // Update offset for jmp instruction.
    *jmp_offset_addr = branch_size + jmp_size;
    break;


  case RE_NODE_RANGE:

    // Code for e1{n,m} looks like:
    //
    //            code for e1 (n times)
    //            push m-n
    //        L0: split L1, L2
    //        L1: code for e1
    //            jnztop L0
    //        L2: pop

    if (re_node->start > 0)
    {
      FAIL_ON_ERROR(_yr_re_emit(
          re_node->left,
          arena,
          flags,
          &instruction_addr,
          &branch_size));

      *code_size += branch_size;

      for (i = 0; i < re_node->start - 1; i++)
      {
        // Don't want re_node->forward_code updated in this call
        // forward_code must remain pointing to the code generated by
        // by the  _yr_re_emit above. However we want re_node->backward_code
        // being updated.

        FAIL_ON_ERROR(_yr_re_emit(
            re_node->left,
            arena,
            flags | EMIT_DONT_SET_FORWARDS_CODE,
            NULL,
            &branch_size));

        *code_size += branch_size;
      }
    }

    // m == n, no more code needed.
    if (re_node->end == re_node->start)
      break;

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint16(
        arena,
        RE_OPCODE_PUSH,
        re_node->end - re_node->start,
        re_node->start == 0 ? &instruction_addr : NULL,
        NULL,
        &inst_size));

    *code_size += inst_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        re_node->greedy ? RE_OPCODE_SPLIT_A : RE_OPCODE_SPLIT_B,
        0,
        NULL,
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left,
        arena,
        flags | EMIT_DONT_SET_FORWARDS_CODE | EMIT_DONT_SET_BACKWARDS_CODE,
        NULL,
        &branch_size));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena,
        RE_OPCODE_JNZ,
        -(branch_size + split_size),
        NULL,
        &jmp_offset_addr,
        &jmp_size));

    *code_size += jmp_size;
    *split_offset_addr = split_size + branch_size + jmp_size;

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
        RE_OPCODE_POP,
        NULL,
        &inst_size));

    *code_size += inst_size;
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


int yr_re_emit_code(
    RE* re,
    YR_ARENA* arena)
{
  int code_size;
  int total_size;

  int emit_flags = 0;

  if (re->flags & RE_FLAGS_NO_CASE)
    emit_flags |= EMIT_NO_CASE;

  if (re->flags & RE_FLAGS_DOT_ALL)
    emit_flags |= EMIT_DOT_ALL;

  // Ensure that we have enough contiguos memory space in the arena to
  // contain the regular expression code. The code can't span over multiple
  // non-contiguos pages.

  yr_arena_reserve_memory(arena, RE_MAX_CODE_SIZE);

  // Emit code for matching the regular expressions forwards.

  total_size = 0;

  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node,
      arena,
      emit_flags,
      &re->code,
      &code_size));

  total_size += code_size;

  FAIL_ON_ERROR(_yr_emit_inst(
      arena,
      RE_OPCODE_MATCH,
      NULL,
      &code_size));

  total_size += code_size;

  assert(total_size < RE_MAX_CODE_SIZE);

  yr_arena_reserve_memory(arena, RE_MAX_CODE_SIZE);

  // Emit code for matching the regular expressions backwards.

  total_size = 0;

  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node,
      arena,
      emit_flags | EMIT_BACKWARDS,
      NULL,
      &code_size));

  total_size += code_size;

  FAIL_ON_ERROR(_yr_emit_inst(
      arena,
      RE_OPCODE_MATCH,
      NULL,
      &code_size));

  total_size += code_size;

  assert(total_size < RE_MAX_CODE_SIZE);

  return ERROR_SUCCESS;
}


int _yr_re_alloc_storage(
    RE_THREAD_STORAGE** storage)
{
  #ifdef _WIN32
  *storage = (RE_THREAD_STORAGE*) TlsGetValue(thread_storage_key);
  #else
  *storage = (RE_THREAD_STORAGE*) pthread_getspecific(thread_storage_key);
  #endif

  if (*storage == NULL)
  {
    *storage = (RE_THREAD_STORAGE*) yr_malloc(sizeof(RE_THREAD_STORAGE));

    if (*storage == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    (*storage)->fiber_pool.head = NULL;
    (*storage)->fiber_pool.tail = NULL;

    #ifdef _WIN32
    TlsSetValue(thread_storage_key, *storage);
    #else
    pthread_setspecific(thread_storage_key, *storage);
    #endif
  }

  return ERROR_SUCCESS;
}


RE_FIBER* _yr_re_fiber_create(
    RE_FIBER_LIST* fiber_pool)
{
  RE_FIBER* fiber;

  if (fiber_pool->head != NULL)
  {
    fiber = fiber_pool->head;
    fiber_pool->head = fiber->next;
    if (fiber_pool->tail == fiber)
      fiber_pool->tail = NULL;
  }
  else
  {
    fiber = (RE_FIBER*) yr_malloc(sizeof(RE_FIBER));
  }

  if (fiber != NULL)
  {
    fiber->ip = NULL;
    fiber->sp = -1;
    fiber->next = NULL;
    fiber->prev = NULL;
  }

  return fiber;
}


//
// _yr_re_fiber_append
//
// Appends 'fiber' to 'fiber_list'
//

void _yr_re_fiber_append(
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
// Verifies if a fiber with the same properties (ip, sp, and stack values)
// than 'target_fiber' exists in 'fiber_list'. The list is iterated from
// the start until 'last_fiber' (inclusive). Fibers past 'last_fiber' are not
// taken into account.
//

int _yr_re_fiber_exists(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER* target_fiber,
    RE_FIBER* last_fiber)
{
  RE_FIBER* fiber = fiber_list->head;

  int equal_stacks;
  int i;


  if (last_fiber == NULL)
    return FALSE;

  while (fiber != last_fiber->next)
  {
    if (fiber->ip == target_fiber->ip &&
        fiber->sp == target_fiber->sp)
    {
      equal_stacks = TRUE;

      for (i = 0; i <= fiber->sp; i++)
      {
        if (fiber->stack[i] != target_fiber->stack[i])
        {
          equal_stacks = FALSE;
          break;
        }
      }

      if (equal_stacks)
        return TRUE;
    }

    fiber = fiber->next;
  }

  return FALSE;
}


//
// _yr_re_fiber_split
//
// Duplicates 'fiber' in 'fiber_list', if 'fiber_list' was:
//
//   f1 -> f2 -> f3 -> f4
//
// Splitting f2 will result in:
//
//   f1 -> f2 -> f2 -> f3 -> f4
//
//

RE_FIBER* _yr_re_fiber_split(
    RE_FIBER* fiber,
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_LIST* fiber_pool)
{
  RE_FIBER* new_fiber;
  int32_t i;

  new_fiber = _yr_re_fiber_create(fiber_pool);

  if (new_fiber == NULL)
    return NULL;

  new_fiber->sp = fiber->sp;
  new_fiber->ip = fiber->ip;

  for (i = 0; i <= fiber->sp; i++)
    new_fiber->stack[i] = fiber->stack[i];

  new_fiber->next = fiber->next;
  new_fiber->prev = fiber;

  if (fiber->next != NULL)
    fiber->next->prev = new_fiber;

  fiber->next = new_fiber;

  if (fiber_list->tail == fiber)
    fiber_list->tail = new_fiber;

  assert(fiber_list->tail->next == NULL);
  assert(fiber_list->head->prev == NULL);

  return new_fiber;
}


//
// _yr_re_fiber_kill
//
// Kills a given fiber by removing it from the fiber list and putting it
// in the fiber pool.
//

RE_FIBER* _yr_re_fiber_kill(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_LIST* fiber_pool,
    RE_FIBER* fiber)
{
  RE_FIBER* next_fiber = fiber->next;

  if (fiber->prev != NULL)
    fiber->prev->next = next_fiber;

  if (next_fiber != NULL)
    next_fiber->prev = fiber->prev;

  if (fiber_pool->tail != NULL)
    fiber_pool->tail->next = fiber;

  if (fiber_list->tail == fiber)
    fiber_list->tail = fiber->prev;

  if (fiber_list->head == fiber)
    fiber_list->head = next_fiber;

  fiber->next = NULL;
  fiber->prev = fiber_pool->tail;
  fiber_pool->tail = fiber;

  if (fiber_pool->head == NULL)
    fiber_pool->head = fiber;

  return next_fiber;
}


//
// _yr_re_fiber_kill_tail
//
// Kills all fibers from the given one up to the end of the fiber list.
//

void _yr_re_fiber_kill_tail(
  RE_FIBER_LIST* fiber_list,
  RE_FIBER_LIST* fiber_pool,
  RE_FIBER* fiber)
{
  RE_FIBER* prev_fiber = fiber->prev;

  if (prev_fiber != NULL)
    prev_fiber->next = NULL;

  fiber->prev = fiber_pool->tail;

  if (fiber_pool->tail != NULL)
    fiber_pool->tail->next = fiber;

  fiber_pool->tail = fiber_list->tail;
  fiber_list->tail = prev_fiber;

  if (fiber_list->head == fiber)
    fiber_list->head = NULL;

  if (fiber_pool->head == NULL)
    fiber_pool->head = fiber;
}


//
// _yr_re_fiber_kill_tail
//
// Kills all fibers in the fiber list.
//

void _yr_re_fiber_kill_all(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_LIST* fiber_pool)
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

int _yr_re_fiber_sync(
    RE_FIBER_LIST* fiber_list,
    RE_FIBER_LIST* fiber_pool,
    RE_FIBER* fiber_to_sync)
{
  RE_FIBER* fiber;
  RE_FIBER* last;
  RE_FIBER* prev;
  RE_FIBER* new_fiber;

  fiber = fiber_to_sync;
  prev = fiber_to_sync->prev;
  last = fiber_to_sync->next;

  while(fiber != last)
  {
    switch(*fiber->ip)
    {
      case RE_OPCODE_SPLIT_A:
        new_fiber = _yr_re_fiber_split(fiber, fiber_list, fiber_pool);
        if (new_fiber == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        new_fiber->ip += *(int16_t*)(fiber->ip + 1);
        fiber->ip += 3;
        break;

      case RE_OPCODE_SPLIT_B:
        new_fiber = _yr_re_fiber_split(fiber, fiber_list, fiber_pool);
        if (new_fiber == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        new_fiber->ip += 3;
        fiber->ip += *(int16_t*)(fiber->ip + 1);
        break;

      case RE_OPCODE_JUMP:
        fiber->ip += *(int16_t*)(fiber->ip + 1);
        break;

      case RE_OPCODE_JNZ:
        fiber->stack[fiber->sp]--;
        if (fiber->stack[fiber->sp] > 0)
          fiber->ip += *(int16_t*)(fiber->ip + 1);
        else
          fiber->ip += 3;
        break;

      case RE_OPCODE_PUSH:
        fiber->stack[++fiber->sp] = *(uint16_t*)(fiber->ip + 1);
        fiber->ip += 3;
        break;

      case RE_OPCODE_POP:
        fiber->sp--;
        fiber->ip++;
        break;

      default:
        if (_yr_re_fiber_exists(fiber_list, fiber, prev))
          fiber = _yr_re_fiber_kill(fiber_list, fiber_pool, fiber);
        else
          fiber = fiber->next;
    }
  }
  return ERROR_SUCCESS;
}


//
// yr_re_exec
//
// Executes a regular expression
//
// Args:
//   RE_CODE re_code                  - Regexp code be executed
//   uint8_t* input                   - Pointer to input data
//   size_t input_size                - Input data size
//   int flags                        - Flags:
//      RE_FLAGS_SCAN
//      RE_FLAGS_BACKWARDS
//      RE_FLAGS_EXHAUSTIVE
//      RE_FLAGS_WIDE
//      RE_FLAGS_NOT_AT_START
//   RE_MATCH_CALLBACK_FUNC callback  - Callback function
//   void* callback_args              - Callback argument
//
// Returns:
//    Integer indicating the number of matching bytes, including 0 when
//    matching an empty regexp. Negative values indicate:
//      -1  No match
//      -2  An error ocurred

int yr_re_exec(
    RE_CODE re_code,
    uint8_t* input_data,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args)
{
  uint8_t* input;
  uint8_t mask;
  uint8_t value;

  RE_CODE ip;
  RE_FIBER_LIST fibers;
  RE_THREAD_STORAGE* storage;
  RE_FIBER* fiber;
  RE_FIBER* next_fiber;

  int error;
  int count;
  int max_count;
  int match;
  int character_size;
  int input_incr;
  int kill;
  int action;
  int result = -1;

  #define ACTION_NONE       0
  #define ACTION_CONTINUE   1
  #define ACTION_KILL       2
  #define ACTION_KILL_TAIL  3

  #define prolog if (count >= max_count) \
      { \
        action = ACTION_KILL; \
        break; \
      }

  if (_yr_re_alloc_storage(&storage) != ERROR_SUCCESS)
    return -2;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;

  input = input_data;
  input_incr = character_size;

  if (flags & RE_FLAGS_BACKWARDS)
  {
    input -= character_size;
    input_incr = -input_incr;
  }

  max_count = min(input_size, RE_SCAN_LIMIT);

  // Round down max_count to a multiple of character_size, this way if
  // character_size is 2 and input_size is impair we are ignoring the
  // extra byte which can't match anyways.

  max_count = max_count - max_count % character_size;

  count = 0;

  fiber = _yr_re_fiber_create(&storage->fiber_pool);
  fiber->ip = re_code;

  fibers.head = fiber;
  fibers.tail = fiber;

  error = _yr_re_fiber_sync(&fibers, &storage->fiber_pool, fiber);

  if (error != ERROR_SUCCESS)
    return -2;

  while (fibers.head != NULL)
  {
    fiber = fibers.head;

    while(fiber != NULL)
    {
      ip = fiber->ip;
      action = ACTION_NONE;

      switch(*ip)
      {
        case RE_OPCODE_ANY:
          prolog;
          action = ACTION_NONE;
          fiber->ip += 1;
          break;

        case RE_OPCODE_ANY_EXCEPT_NEW_LINE:
          prolog;
          match = (*input != 0x0A);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_LITERAL:
          prolog;
          match = (*input == *(ip + 1));
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 2;
          break;

        case RE_OPCODE_LITERAL_NO_CASE:
          prolog;
          match = lowercase[*input] == lowercase[*(ip + 1)];
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
          match = CHAR_IN_CLASS(*input, ip + 1);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 33;
          break;

        case RE_OPCODE_CLASS_NO_CASE:
          prolog;
          match = CHAR_IN_CLASS(*input, ip + 1) ||
                  CHAR_IN_CLASS(altercase[*input], ip + 1);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 33;
          break;

        case RE_OPCODE_WORD_CHAR:
          prolog;
          match = IS_WORD_CHAR(*input);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_NON_WORD_CHAR:
          prolog;
          match = !IS_WORD_CHAR(*input);
          action = match ? ACTION_NONE : ACTION_KILL;
          fiber->ip += 1;
          break;

        case RE_OPCODE_SPACE:
        case RE_OPCODE_NON_SPACE:
          prolog;

          switch(*input)
          {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case '\v':
            case '\f':
              match = TRUE;
              break;

            default:
              match = FALSE;
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

          if (count == 0 &&
              !(flags & RE_FLAGS_NOT_AT_START) &&
              !(flags & RE_FLAGS_BACKWARDS))
            match = TRUE;
          else if (count >= max_count)
            match = TRUE;
          else if (IS_WORD_CHAR(*(input - input_incr)) != IS_WORD_CHAR(*input))
            match = TRUE;
          else
            match = FALSE;

          if (*ip == RE_OPCODE_NON_WORD_BOUNDARY)
            match = !match;

          action = match ? ACTION_CONTINUE : ACTION_KILL;
          break;

        case RE_OPCODE_MATCH_AT_START:
          if (flags & RE_FLAGS_BACKWARDS)
            kill = input_size > count;
          else
            kill = (flags & RE_FLAGS_NOT_AT_START) || (count != 0);
          action = kill ? ACTION_KILL : ACTION_CONTINUE;
          break;

        case RE_OPCODE_MATCH_AT_END:
          action = input_size > count ? ACTION_KILL : ACTION_CONTINUE;
          break;

        case RE_OPCODE_MATCH:
          result = count;

          if (flags & RE_FLAGS_EXHAUSTIVE)
          {
            if (callback != NULL)
            {
              if (flags & RE_FLAGS_BACKWARDS)
                callback(input + character_size, count,
                         flags, callback_args);
              else
                callback(input_data, count,
                         flags, callback_args);
            }

            action = ACTION_KILL;
          }
          else
          {
            action = ACTION_KILL_TAIL;
          }

          break;

        default:
          assert(FALSE);
      }

      switch(action)
      {
        case ACTION_KILL:
          fiber = _yr_re_fiber_kill(&fibers, &storage->fiber_pool, fiber);
          break;

        case ACTION_KILL_TAIL:
          _yr_re_fiber_kill_tail(&fibers, &storage->fiber_pool, fiber);
          fiber = NULL;
          break;

        case ACTION_CONTINUE:
          fiber->ip += 1;
          error = _yr_re_fiber_sync(&fibers, &storage->fiber_pool, fiber);
          if (error != ERROR_SUCCESS)
            return -2;
          break;

        default:
          next_fiber = fiber->next;
          error = _yr_re_fiber_sync(&fibers, &storage->fiber_pool, fiber);
          if (error != ERROR_SUCCESS)
            return -2;
          fiber = next_fiber;
      }
    }

    if (flags & RE_FLAGS_WIDE && *(input + 1) != 0)
      _yr_re_fiber_kill_all(&fibers, &storage->fiber_pool);

    input += input_incr;
    count += character_size;

    if (flags & RE_FLAGS_SCAN && count < max_count)
    {
      fiber = _yr_re_fiber_create(&storage->fiber_pool);
      fiber->ip = re_code;

      _yr_re_fiber_append(&fibers, fiber);

      error = _yr_re_fiber_sync(&fibers, &storage->fiber_pool, fiber);

      if (error != ERROR_SUCCESS)
        return -2;
    }
  }

  return result;
}


void _yr_re_print_node(
    RE_NODE* re_node)
{
  int i;

  if (re_node == NULL)
    return;

  switch(re_node->type)
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
      if (CHAR_IN_CLASS(i, re_node->class_vector))
        printf("%02X,", i);
    printf(")");
    break;

  default:
    printf("???");
    break;
  }
}

void yr_re_print(
    RE* re)
{
  _yr_re_print_node(re->root_node);
}
