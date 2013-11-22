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


/*

This modules implements a regular expressions engine based on Thompson's
algorithm as described by Russ Cox in http://swtch.com/~rsc/regexp/regexp2.html.

What the article names a "thread" has been named a "fiber" in this code, in
order to avoid confusion with operating system threads.

*/

#include <assert.h>
#include <ctype.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "yara.h"
#include "arena.h"
#include "mem.h"
#include "re.h"


#define MAX_RE_FIBERS   1024
#define MAX_RE_STACK    1024

#define RE_SCAN_LIMIT   65535

#define EMIT_FLAGS_BACKWARDS           1
#define EMIT_FLAGS_DONT_ANNOTATE_RE    2

#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
#endif

// Each fiber has an associated stack, which is used by
// PUSH, POP and JNZ

typedef struct _RE_STACK
{
  int top;
  uint16_t items[MAX_RE_STACK];

  struct _RE_STACK* next;
  struct _RE_STACK* prev;

} RE_STACK;


// Stacks are allocated as needed, and freed stacks are kept in
// a pool for later re-use.

typedef struct _RE_STACK_POOL
{
  RE_STACK* free;
  RE_STACK* used;

} RE_STACK_POOL;


// A fiber is described by its current instruction pointer and
// its stack.

typedef struct _RE_FIBER
{
  uint8_t*  ip;
  RE_STACK* stack;

} RE_FIBER;


typedef struct _RE_FIBER_LIST
{
  int count;
  RE_FIBER items[MAX_RE_FIBERS];

} RE_FIBER_LIST;


typedef struct _RE_THREAD_STORAGE
{
  RE_FIBER_LIST list1;
  RE_FIBER_LIST list2;
  RE_STACK_POOL stack_pool;

} RE_THREAD_STORAGE;


#ifdef WIN32
DWORD thread_storage_key;
#else
pthread_key_t thread_storage_key;
#endif


extern int yr_parse_re_string(
  const char* re_string,
  RE** re);


extern int yr_parse_hex_string(
  const char* hex_string,
  RE** re);


//
// yr_re_initialize
//
// Should be called by main thread before any other
// function from this module.
//

int yr_re_initialize()
{
  #ifdef WIN32
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

int yr_re_finalize()
{
  #ifdef WIN32
  TlsFree(thread_storage_key);
  #else
  pthread_key_delete(thread_storage_key);
  #endif

  return ERROR_SUCCESS;
}

//
// yr_re_finalize_thread
//
// Should be called by every thread using this module
// before exiting.
//

int yr_re_finalize_thread()
{
  RE_THREAD_STORAGE* thread_storage;

  #ifdef WIN32
  thread_storage = TlsGetValue(thread_storage_key);
  #else
  thread_storage = pthread_getspecific(thread_storage_key);
  #endif

  if (thread_storage != NULL)
    yr_free(thread_storage);

  return ERROR_SUCCESS;
}


RE_NODE* yr_re_node_create(
    int type,
    RE_NODE* left,
    RE_NODE* right)
{
  RE_NODE* result = yr_malloc(sizeof(RE_NODE));

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

  (*re)->literal_string_len = 0;
  (*re)->literal_string_max = 128;
  (*re)->literal_string = yr_malloc(128);

  if ((*re)->literal_string == NULL)
  {
    yr_free(*re);
    return ERROR_INSUFICIENT_MEMORY;
  }

  (*re)->flags = 0;
  (*re)->root_node = NULL;
  (*re)->error_message = NULL;
  (*re)->error_code = ERROR_SUCCESS;

  return ERROR_SUCCESS;
}


void yr_re_destroy(
  RE* re)
{
  if (re->root_node != NULL)
    yr_re_node_destroy(re->root_node);

  if (re->error_message != NULL)
    yr_free((char*) re->error_message);

  if (re->literal_string != NULL)
    yr_free(re->literal_string);

  yr_free(re);
}


int yr_re_compile(
    const char* re_string,
    RE** re)
{
  return yr_parse_re_string(re_string, re);
}


int yr_re_compile_hex(
    const char* hex_string,
    RE** re)
{
  return yr_parse_hex_string(hex_string, re);
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
  int jmp_offset;

  RE_NODE* left;
  RE_NODE* right;

  uint16_t idx;
  int16_t* split_offset_addr;
  int16_t* jmp_offset_addr;
  uint8_t* instruction_addr;

  *code_size = 0;

  switch(re_node->type)
  {
  case RE_NODE_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint8(
        arena,
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
        RE_OPCODE_ANY,
        &instruction_addr,
        code_size));
    break;

  case RE_NODE_CLASS:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena,
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

  case RE_NODE_CONCAT:

    if (flags & EMIT_FLAGS_BACKWARDS)
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
        FAIL_ON_ERROR(_yr_re_emit(
            re_node->left,
            arena,
            flags | EMIT_FLAGS_DONT_ANNOTATE_RE,
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
        flags | EMIT_FLAGS_DONT_ANNOTATE_RE,
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

  if (!(flags & EMIT_FLAGS_DONT_ANNOTATE_RE))
  {
    if (flags & EMIT_FLAGS_BACKWARDS)
      re_node->backward_code = instruction_addr;
    else
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

  // Emit code for matching the regular expressions forwards.
  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node,
      arena,
      0,
      NULL,
      &code_size));

  FAIL_ON_ERROR(_yr_emit_inst(
      arena,
      RE_OPCODE_MATCH,
      NULL,
      &code_size));

  // Emit code for matching the regular expressions backwards.
  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node,
      arena,
      EMIT_FLAGS_BACKWARDS,
      NULL,
      &code_size));

  FAIL_ON_ERROR(_yr_emit_inst(
      arena,
      RE_OPCODE_MATCH,
      NULL,
      &code_size));

  return ERROR_SUCCESS;
}


RE_STACK* _yr_re_alloc_stack(
    RE_STACK_POOL* pool)
{
  RE_STACK* stack;

  if (pool->free != NULL)
  {
    stack = pool->free;
    pool->free = stack->next;

    if (pool->free != NULL)
      pool->free->prev = NULL;
  }
  else
  {
    stack = yr_malloc(sizeof(RE_STACK));
  }

  stack->top = -1;
  stack->prev = NULL;

  if (pool->used != NULL)
    pool->used->prev = stack;

  stack->next = pool->used;
  pool->used = stack;

  return stack;
}


RE_STACK* _yr_re_clone_stack(
    RE_STACK* stack,
    RE_STACK_POOL* pool)
{
  RE_STACK* clon;

  if (stack == NULL)
    return NULL;

  clon = _yr_re_alloc_stack(pool);
  clon->top = stack->top;

  for (int i = 0; i < clon->top; i++)
    clon->items[i] = stack->items[i];

  return clon;
}


void _yr_re_free_stack(
    RE_STACK* stack,
    RE_STACK_POOL* pool)
{
  if (stack == NULL)
    return;

  if (stack->prev != NULL)
    stack->prev->next = stack->next;

  if (stack->next != NULL)
    stack->next->prev = stack->prev;

  stack->next = pool->free;

  if (pool->free != NULL)
    pool->free->prev = stack;

  pool->free = stack;
  stack->prev = NULL;

  if (pool->used == stack)
    pool->used = NULL;
}


int _yr_re_fiber_exists(
    RE_FIBER_LIST* fibers,
    uint8_t* ip)
{
  int i;

  for (i = 0; i < fibers->count; i++)
    if (fibers->items[i].ip == ip)
      return TRUE;

  return FALSE;
}


void _yr_re_add_fiber(
    RE_FIBER_LIST* fibers,
    RE_THREAD_STORAGE* storage,
    uint8_t* ip,
    RE_STACK* stack)
{
  RE_STACK* new_stack;

  uint16_t counter_index;
  int16_t jmp_offset;

  if (_yr_re_fiber_exists(fibers, ip))
  {
    _yr_re_free_stack(stack, &storage->stack_pool);
    return;
  }

  switch(*ip)
  {
    case RE_OPCODE_JUMP:
      jmp_offset = *(int16_t*)(ip + 1);
      _yr_re_add_fiber(fibers, storage, ip + jmp_offset, stack);
      break;

    case RE_OPCODE_JNZ:
      jmp_offset = *(int16_t*)(ip + 1);
      stack->items[stack->top]--;

      if (stack->items[stack->top] > 0)
        _yr_re_add_fiber(fibers, storage, ip + jmp_offset, stack);
      else
        _yr_re_add_fiber(fibers, storage, ip + 3, stack);
      break;

    case RE_OPCODE_PUSH:
      if (stack == NULL)
        stack = _yr_re_alloc_stack(&storage->stack_pool);
      stack->items[++stack->top] = *(uint16_t*)(ip + 1);
      _yr_re_add_fiber(fibers, storage, ip + 3, stack);
      break;

    case RE_OPCODE_POP:
      stack->top--;
      if (stack->top == -1)
      {
        _yr_re_free_stack(stack, &storage->stack_pool);
        stack = NULL;
      }
      _yr_re_add_fiber(fibers, storage, ip + 1, stack);
      break;

    case RE_OPCODE_SPLIT_A:
      jmp_offset = *(int16_t*)(ip + 1);
      new_stack = _yr_re_clone_stack(stack, &storage->stack_pool);

      _yr_re_add_fiber(fibers, storage, ip + 3, stack);
      _yr_re_add_fiber(fibers, storage, ip + jmp_offset, new_stack);
      break;

    case RE_OPCODE_SPLIT_B:
      jmp_offset = *(int16_t*)(ip + 1);
      new_stack = _yr_re_clone_stack(stack, &storage->stack_pool);

      _yr_re_add_fiber(fibers, storage, ip + jmp_offset, stack);
      _yr_re_add_fiber(fibers, storage, ip + 3, new_stack);
      break;

    default:
      assert(fibers->count < MAX_RE_FIBERS);
      fibers->items[fibers->count].ip = ip;
      fibers->items[fibers->count].stack = stack;
      fibers->count++;
  }
}


#define swap_fibers(x, y) \
  { \
    RE_FIBER_LIST* tmp; \
    tmp = x; \
    x = y; \
    y = tmp; \
  }

//
// yr_re_exec
//
// Executes a regular expression
//
// Args:
//   uint8_t* code                    - Pointer to regexp code be executed
//   uint8_t* input                   - Pointer to input data
//   size_t input_size                - Input data size
//   int flags                        - Flags:
//      RE_FLAGS_SCAN
//      RE_FLAGS_BACKWARDS
//      RE_FLAGS_EXHAUSTIVE
//      RE_FLAGS_WIDE
//   RE_MATCH_CALLBACK_FUNC callback  - Callback function
//   void* callback_args              - Callback argument
//

int yr_re_exec(
    uint8_t* code,
    uint8_t* input,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args)
{
  size_t i, t;
  uint8_t* ip;
  uint8_t* current_input;
  uint8_t mask;
  uint8_t value;

  RE_THREAD_STORAGE* storage;
  RE_FIBER_LIST* current_fibers;
  RE_FIBER_LIST* next_fibers;
  RE_STACK* stack;

  int idx;
  int match;
  char character;
  int character_size;
  int result = -1;

  #ifdef WIN32
  storage = TlsGetValue(thread_storage_key);
  #else
  storage = pthread_getspecific(thread_storage_key);
  #endif

  if (storage == NULL)
  {
    storage = yr_malloc(sizeof(RE_THREAD_STORAGE));

    if (storage == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    storage->stack_pool.free = NULL;
    storage->stack_pool.used = NULL;

    #ifdef WIN32
    TlsSetValue(thread_storage_key, storage);
    #else
    pthread_setspecific(thread_storage_key, storage);
    #endif
  }

  current_fibers = &storage->list1;
  next_fibers = &storage->list2;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;

  current_fibers->count = 0;
  next_fibers->count = 0;

  // Create the initial execution fiber starting at the provided the beginning
  // of the provided code. The stack is initially NULL and will be created
  // dynamically when the first PUSH instruction is found.

  _yr_re_add_fiber(current_fibers, storage, code, NULL);

  current_input = input;

  for (i = 0; i < min(input_size, RE_SCAN_LIMIT); i += character_size)
  {
    if ((flags & RE_FLAGS_SCAN) &&
        !(flags & RE_FLAGS_START_ANCHORED))
      _yr_re_add_fiber(current_fibers, storage, code, NULL);

    if (current_fibers->count == 0)
      break;

    for(t = 0; t < current_fibers->count; t++)
    {
      ip = current_fibers->items[t].ip;
      stack = current_fibers->items[t].stack;

      switch(*ip)
      {
        case RE_OPCODE_LITERAL:
          if (flags & RE_FLAGS_NO_CASE)
            match = lowercase[*current_input] == lowercase[*(ip + 1)];
          else
            match = *current_input == *(ip + 1);
          if (match)
            _yr_re_add_fiber(next_fibers, storage, ip + 2, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_MASKED_LITERAL:
          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;

          // We don't need to take into account the case-insensitive
          // case because this opcode is only used with hex strings,
          // which can't be case-insensitive.

          if ((*current_input & mask) == value)
            _yr_re_add_fiber(next_fibers, storage, ip + 3, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_CLASS:
          if (flags & RE_FLAGS_NO_CASE)
            match = CHAR_IN_CLASS(*current_input, ip + 1) ||
                    CHAR_IN_CLASS(altercase[*current_input], ip + 1);
          else
            match = CHAR_IN_CLASS(*current_input, ip + 1);

          if (match)
            _yr_re_add_fiber(next_fibers, storage, ip + 33, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_WORD_CHAR:
          if (isalnum(*current_input) || *current_input == '_')
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_NON_WORD_CHAR:
          if (!isalnum(*current_input) && *current_input != '_')
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_SPACE:
          if (*current_input == ' ' || *current_input == '\t')
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_NON_SPACE:
          if (*current_input != ' ' && *current_input != '\t')
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_DIGIT:
          if (isdigit(*current_input))
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_NON_DIGIT:
          if (!isdigit(*current_input))
            _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          else
            _yr_re_free_stack(stack, &storage->stack_pool);
          break;

        case RE_OPCODE_ANY:
          _yr_re_add_fiber(next_fibers, storage, ip + 1, stack);
          break;

        case RE_OPCODE_MATCH:
          _yr_re_free_stack(stack, &storage->stack_pool);

          if (flags & RE_FLAGS_END_ANCHORED && i < input_size)
            break;

          if (flags & RE_FLAGS_EXHAUSTIVE)
          {
            if (flags & RE_FLAGS_BACKWARDS)
              callback(
                  current_input + character_size,
                  i,
                  flags,
                  callback_args);
            else
              callback(
                  input,
                  i,
                  flags,
                  callback_args);

            result = i;
          }
          else
          {
            result = i;
            goto _break;
          }
          break;

        default:
          assert(FALSE);
      }
    }

  _break:

    // Free the stacks for any remaining fiber that didn't
    // survived for the next step.

    for(; t < current_fibers->count; t++)
      _yr_re_free_stack(
          current_fibers->items[t].stack,
          &storage->stack_pool);

    swap_fibers(current_fibers, next_fibers);
    next_fibers->count = 0;

    if (flags & RE_FLAGS_WIDE && *(current_input + 1) != 0)
      break;

    if (flags & RE_FLAGS_BACKWARDS)
      current_input -= character_size;
    else
      current_input += character_size;
  }

  if (!(flags & RE_FLAGS_END_ANCHORED) || i == input_size)
  {
    for(t = 0; t < current_fibers->count; t++)
    {
      if (*current_fibers->items[t].ip == RE_OPCODE_MATCH)
      {
        if (flags & RE_FLAGS_EXHAUSTIVE)
        {
          if (flags & RE_FLAGS_BACKWARDS)
            callback(
                current_input + character_size,
                i,
                flags,
                callback_args);
          else
            callback(
                input,
                i,
                flags,
                callback_args);
        }
        else
        {
          result = i;
          break;
        }
      }
    }
  }

  // Ensure that every stack was released
  assert(storage->stack_pool.used == NULL);

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
