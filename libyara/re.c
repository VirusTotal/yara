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

typedef struct _RE_FIBER_DATA
{
  int stack_top;
  uint16_t stack[MAX_RE_STACK];

  struct _RE_FIBER_DATA* next;
  struct _RE_FIBER_DATA* prev;

} RE_FIBER_DATA;


// Stacks are allocated as needed, and freed stacks are kept in
// a pool for later re-use.

typedef struct _RE_FIBER_DATA_POOL
{
  RE_FIBER_DATA* free;
  RE_FIBER_DATA* used;

} RE_FIBER_DATA_POOL;


// A fiber is described by its current instruction pointer and
// its fiber_data.

typedef struct _RE_FIBER
{
  uint8_t*  ip;
  RE_FIBER_DATA* fiber_data;

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
  RE_FIBER_DATA_POOL fiber_data_pool;

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
  RE_FIBER_DATA* fiber_data;
  RE_FIBER_DATA* next_fiber_data;
  RE_THREAD_STORAGE* storage;

  #ifdef WIN32
  storage = TlsGetValue(thread_storage_key);
  #else
  storage = pthread_getspecific(thread_storage_key);
  #endif

  if (storage != NULL)
  {
    fiber_data = storage->fiber_data_pool.free;

    while (fiber_data != NULL)
    {
      next_fiber_data = fiber_data->next;
      yr_free(fiber_data);
      fiber_data = next_fiber_data;
    }

    yr_free(storage);
  }

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


RE_FIBER_DATA* _yr_re_alloc_fiber_data(
    RE_FIBER_DATA_POOL* pool)
{
  RE_FIBER_DATA* fiber_data;

  if (pool->free != NULL)
  {
    fiber_data = pool->free;
    pool->free = fiber_data->next;

    if (pool->free != NULL)
      pool->free->prev = NULL;
  }
  else
  {
    fiber_data = yr_malloc(sizeof(RE_FIBER_DATA));
  }

  fiber_data->stack_top = -1;
  fiber_data->prev = NULL;

  if (pool->used != NULL)
    pool->used->prev = fiber_data;

  fiber_data->next = pool->used;
  pool->used = fiber_data;

  return fiber_data;
}


RE_FIBER_DATA* _yr_re_clone_fiber_data(
    RE_FIBER_DATA* fiber_data,
    RE_FIBER_DATA_POOL* pool)
{
  RE_FIBER_DATA* clon;
  int i;

  if (fiber_data == NULL)
    return NULL;

  clon = _yr_re_alloc_fiber_data(pool);
  clon->stack_top = fiber_data->stack_top;

  for (i = 0; i < clon->stack_top; i++)
    clon->stack[i] = fiber_data->stack[i];

  return clon;
}


void _yr_re_free_fiber_data(
    RE_FIBER_DATA* fiber_data,
    RE_FIBER_DATA_POOL* pool)
{
  if (fiber_data == NULL)
    return;

  if (pool->used == fiber_data)
    pool->used = fiber_data->next;

  if (fiber_data->prev != NULL)
    fiber_data->prev->next = fiber_data->next;

  if (fiber_data->next != NULL)
    fiber_data->next->prev = fiber_data->prev;

  fiber_data->next = pool->free;

  if (pool->free != NULL)
    pool->free->prev = fiber_data;

  pool->free = fiber_data;
  fiber_data->prev = NULL;
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
    uint8_t* input,
    RE_FIBER_DATA* fiber_data)
{
  RE_FIBER_DATA* new_fiber_data;

  uint16_t counter_index;
  int16_t jmp_offset;

  if (_yr_re_fiber_exists(fibers, ip))
  {
    _yr_re_free_fiber_data(fiber_data, &storage->fiber_data_pool);
    return;
  }

  switch(*ip)
  {
    case RE_OPCODE_JUMP:
      jmp_offset = *(int16_t*)(ip + 1);
      _yr_re_add_fiber(fibers, storage, ip + jmp_offset, input, fiber_data);
      break;

    case RE_OPCODE_JNZ:
      jmp_offset = *(int16_t*)(ip + 1);
      fiber_data->stack[fiber_data->stack_top]--;

      if (fiber_data->stack[fiber_data->stack_top] > 0)
        _yr_re_add_fiber(fibers, storage, ip + jmp_offset, input, fiber_data);
      else
        _yr_re_add_fiber(fibers, storage, ip + 3, input, fiber_data);
      break;

    case RE_OPCODE_PUSH:
      if (fiber_data == NULL)
        fiber_data = _yr_re_alloc_fiber_data(&storage->fiber_data_pool);

      fiber_data->stack[++fiber_data->stack_top] = *(uint16_t*)(ip + 1);
      _yr_re_add_fiber(fibers, storage, ip + 3, input, fiber_data);
      break;

    case RE_OPCODE_POP:
      fiber_data->stack_top--;
      if (fiber_data->stack_top == -1)
      {
        _yr_re_free_fiber_data(fiber_data, &storage->fiber_data_pool);
        fiber_data = NULL;
      }
      _yr_re_add_fiber(fibers, storage, ip + 1, input, fiber_data);
      break;

    case RE_OPCODE_SPLIT_A:
      jmp_offset = *(int16_t*)(ip + 1);

      new_fiber_data = _yr_re_clone_fiber_data(
          fiber_data, &storage->fiber_data_pool);

      _yr_re_add_fiber(
          fibers, storage, ip + 3, input, fiber_data);
      _yr_re_add_fiber(
          fibers, storage, ip + jmp_offset, input, new_fiber_data);
      break;

    case RE_OPCODE_SPLIT_B:
      jmp_offset = *(int16_t*)(ip + 1);

      new_fiber_data = _yr_re_clone_fiber_data(
          fiber_data, &storage->fiber_data_pool);

      _yr_re_add_fiber(fibers, storage, ip + jmp_offset, input, fiber_data);
      _yr_re_add_fiber(fibers, storage, ip + 3, input, new_fiber_data);
      break;

    default:
      assert(fibers->count < MAX_RE_FIBERS);
      fibers->items[fibers->count].ip = ip;
      fibers->items[fibers->count].fiber_data = fiber_data;
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
    uint8_t* input_data,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args)
{
  size_t i;
  uint8_t* ip;
  uint8_t* input;
  uint8_t mask;
  uint8_t value;

  RE_THREAD_STORAGE* storage;
  RE_FIBER_LIST* fibers;
  RE_FIBER_LIST* next_fibers;
  RE_FIBER_DATA* fiber_data;

  int fiber_idx;
  int j;
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

    storage->fiber_data_pool.free = NULL;
    storage->fiber_data_pool.used = NULL;

    #ifdef WIN32
    TlsSetValue(thread_storage_key, storage);
    #else
    pthread_setspecific(thread_storage_key, storage);
    #endif
  }

  input = input_data;
  fibers = &storage->list1;
  next_fibers = &storage->list2;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;

  fibers->count = 0;
  next_fibers->count = 0;

  // Create the initial execution fiber starting at the provided the beginning
  // of the provided code. The fiber data is initially NULL and will be created
  // dynamically when the first PUSH instruction is found.

  _yr_re_add_fiber(fibers, storage, code, input, NULL);

  for (i = 0; i < min(input_size, RE_SCAN_LIMIT); i += character_size)
  {
    if ((flags & RE_FLAGS_SCAN) &&
        !(flags & RE_FLAGS_START_ANCHORED))
      _yr_re_add_fiber(fibers, storage, code, input, NULL);

    if (fibers->count == 0)
      break;

    for(fiber_idx = 0; fiber_idx < fibers->count; fiber_idx++)
    {
      ip = fibers->items[fiber_idx].ip;
      fiber_data = fibers->items[fiber_idx].fiber_data;

      switch(*ip)
      {
        case RE_OPCODE_LITERAL:
          if (flags & RE_FLAGS_NO_CASE)
            match = lowercase[*input] == lowercase[*(ip + 1)];
          else
            match = (*input == *(ip + 1));
          ip += 2;
          break;

        case RE_OPCODE_MASKED_LITERAL:
          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;

          // We don't need to take into account the case-insensitive
          // case because this opcode is only used with hex strings,
          // which can't be case-insensitive.

          match = ((*input & mask) == value);
          ip += 3;
          break;

        case RE_OPCODE_CLASS:
          if (flags & RE_FLAGS_NO_CASE)
            match = CHAR_IN_CLASS(*input, ip + 1) ||
                    CHAR_IN_CLASS(altercase[*input], ip + 1);
          else
            match = CHAR_IN_CLASS(*input, ip + 1);
          ip += 33;
          break;

        case RE_OPCODE_WORD_CHAR:
          match = (isalnum(*input) || *input == '_');
          ip += 1;
          break;

        case RE_OPCODE_NON_WORD_CHAR:
          match = (!isalnum(*input) && *input != '_');
          ip += 1;
          break;

        case RE_OPCODE_SPACE:
          match = (*input == ' ' || *input == '\t');
          ip += 1;
          break;

        case RE_OPCODE_NON_SPACE:
          match = (*input != ' ' && *input != '\t');
          ip += 1;
          break;

        case RE_OPCODE_DIGIT:
          match = isdigit(*input);
          ip += 1;
          break;

        case RE_OPCODE_NON_DIGIT:
          match = !isdigit(*input);
          ip += 1;
          break;

        case RE_OPCODE_ANY:
          match = (*input != 0x0A || flags & RE_FLAGS_DOT_ALL);
          ip += 1;
          break;

        case RE_OPCODE_MATCH:

          match = FALSE;
          result = i;

          if (flags & RE_FLAGS_END_ANCHORED && i < input_size)
            break;

          if (flags & RE_FLAGS_EXHAUSTIVE)
          {
            if (flags & RE_FLAGS_BACKWARDS)
              callback(input + character_size, i, flags, callback_args);
            else
              callback(input_data, i, flags, callback_args);
          }
          else
          {
            // As we are forcing a jump out of the loop fiber_idx
            // won't be incremented. Let's do it before exiting.

            //fiber_idx++;
            goto _exit_loop;
          }

          break;

        default:
          assert(FALSE);
      }

      if (match)
        _yr_re_add_fiber(
            next_fibers,
            storage,
            ip,
            input + character_size,
            fiber_data);
      else
        _yr_re_free_fiber_data(
            fiber_data,
            &storage->fiber_data_pool);
    }

  _exit_loop:

    // Free the fiber data for any remaining fiber that didn't
    // survived for the next step.

    for(; fiber_idx < fibers->count; fiber_idx++)
      _yr_re_free_fiber_data(
          fibers->items[fiber_idx].fiber_data,
          &storage->fiber_data_pool);

    swap_fibers(fibers, next_fibers);
    next_fibers->count = 0;

    if (flags & RE_FLAGS_WIDE && *(input + 1) != 0)
      break;

    if (flags & RE_FLAGS_BACKWARDS)
      input -= character_size;
    else
      input += character_size;

  } //for (i = 0; i < min(input_size, RE_SCAN_LIMIT) ...

  if (!(flags & RE_FLAGS_END_ANCHORED) || i == input_size)
  {
    for(fiber_idx = 0; fiber_idx < fibers->count; fiber_idx++)
    {
      if (*fibers->items[fiber_idx].ip != RE_OPCODE_MATCH)
        continue;

      if (flags & RE_FLAGS_EXHAUSTIVE)
      {
        if (flags & RE_FLAGS_BACKWARDS)
          callback(
              input + character_size, i, flags, callback_args);
        else
          callback(
              input_data, i, flags, callback_args);
      }
      else
      {
        result = i;
        break;
      }
    }
  }

  for(fiber_idx = 0; fiber_idx < fibers->count; fiber_idx++)
    _yr_re_free_fiber_data(
        fibers->items[fiber_idx].fiber_data,
        &storage->fiber_data_pool);

  // Ensure that every fiber data was released
  assert(storage->fiber_data_pool.used == NULL);

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
