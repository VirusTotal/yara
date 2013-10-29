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

#include <assert.h>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "yara.h"
#include "arena.h"
#include "mem.h"
#include "re.h"


#define MAX_RE_THREADS  1024
#define MAX_RE_COUNTERS 1024
#define RE_SCAN_LIMIT   65535

#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
#endif

typedef struct _RE_THREAD_LIST
{
  int count;
  uint8_t* threads[MAX_RE_THREADS];
  
} RE_THREAD_LIST;


typedef struct _RE_THREAD_STORAGE
{
  RE_THREAD_LIST list1;
  RE_THREAD_LIST list2;

  uint16_t counters[MAX_RE_COUNTERS];

} RE_THREAD_STORAGE;


#ifdef WIN32
DWORD thread_storage_key;
#else
pthread_key_t thread_storage_key;
#endif


int yr_re_initialize()
{
  #ifdef WIN32
  thread_storage_key = TlsAlloc();
  #else
  pthread_key_create(&thread_storage_key, NULL);
  #endif

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


int _yr_emit_inst(
    ARENA* arena,
    uint8_t opcode,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      NULL));

  *code_size = sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint8(
    ARENA* arena,
    uint8_t opcode, 
    uint8_t argument,
    uint8_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      NULL));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint8_t),
      (void**) argument_addr));

  *code_size = 2 * sizeof(uint8_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint16(
    ARENA* arena,
    uint8_t opcode, 
    uint16_t argument,
    uint16_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      NULL));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint16_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint16_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_uint32(
    ARENA* arena,
    uint8_t opcode, 
    uint32_t argument,
    uint32_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      NULL));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &argument,
      sizeof(uint32_t),
      (void**) argument_addr));

  *code_size = sizeof(uint8_t) + sizeof(uint32_t);

  return ERROR_SUCCESS;
}


int _yr_emit_inst_arg_int16(
    ARENA* arena,
    uint8_t opcode, 
    int16_t argument,
    int16_t** argument_addr,
    int* code_size)
{
  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      &opcode,
      sizeof(uint8_t),
      NULL));

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
    ARENA* arena,
    int backwards,
    int* code_size,
    uint16_t* counter_index)
{
  int i;
  int branch_size;
  int split_size;
  int set_size;
  int jmp_size;
  int jmp_offset;

  RE_NODE* left;
  RE_NODE* right;

  uint16_t idx;
  int16_t* split_offset_addr;
  int16_t* jmp_offset_addr;

  *code_size = 0;

  if (backwards)
    re_node->backward_code = yr_arena_current_address(arena);
  else
    re_node->forward_code = yr_arena_current_address(arena);

  switch(re_node->type)
  {
  case RE_NODE_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint8(
        arena, 
        RE_OPCODE_LITERAL, 
        re_node->value, 
        NULL,
        code_size));
    break;

  case RE_NODE_MASKED_LITERAL:

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint16(
        arena, 
        RE_OPCODE_MASKED_LITERAL, 
        re_node->mask << 8 | re_node->value, 
        NULL,
        code_size));
    break;

  case RE_NODE_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_WORD_CHAR,
        code_size));
    break;

  case RE_NODE_NON_WORD_CHAR:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_NON_WORD_CHAR,
        code_size));
    break;

  case RE_NODE_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_SPACE,
        code_size));
    break;

  case RE_NODE_NON_SPACE:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_NON_SPACE,
        code_size));
    break;

  case RE_NODE_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_DIGIT,
        code_size));
    break;

  case RE_NODE_NON_DIGIT:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_NON_DIGIT,
        code_size));
    break;

  case RE_NODE_ANY:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_ANY,
        code_size));
    break;

  case RE_NODE_CLASS:

    FAIL_ON_ERROR(_yr_emit_inst(
        arena, 
        RE_OPCODE_CLASS,
        code_size));

    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        re_node->class_vector,
        32,
        NULL));

    *code_size += 32;
    break;

  case RE_NODE_CONCAT:
    
    if (backwards)
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
        left, arena, backwards, &branch_size, counter_index));
    *code_size += branch_size;
    
    FAIL_ON_ERROR(_yr_re_emit(
        right, arena, backwards, &branch_size, counter_index));
    *code_size += branch_size;

    break;

  case RE_NODE_PLUS:

    // Code for e+ looks like:
    //
    //          L1: code for e
    //              split L1, L2
    //          L2:

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left, arena, backwards, &branch_size, counter_index));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena, 
        re_node->greedy ? RE_OPCODE_SPLIT_B : RE_OPCODE_SPLIT_A, 
        -branch_size, 
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
        &split_offset_addr, 
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left, arena, backwards, &branch_size, counter_index));

    *code_size += branch_size;

    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena, 
        RE_OPCODE_JUMP, 
        -(branch_size + split_size), 
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
        &split_offset_addr, 
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left, arena, backwards, &branch_size, counter_index));

    *code_size += branch_size;
  
    // Emit jump with offset set to 0.

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena, 
        RE_OPCODE_JUMP, 
        0, 
        &jmp_offset_addr, 
        &jmp_size));

    *code_size += jmp_size;

    // Update split offset.
    *split_offset_addr = split_size + branch_size + jmp_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->right, arena, backwards, &branch_size, counter_index));

    *code_size += branch_size;

    // Update offset for jmp instruction.
    *jmp_offset_addr = branch_size + jmp_size;
    break;


  case RE_NODE_RANGE:

    // Code for e1{n,m} looks like:
    //
    //            code for e1 (n times)
    //            set counter, m-n
    //        L1: split L1, L2
    //            code for e1 
    //            jcnz L1
    //        L2:

    for (i = 0; i < re_node->start; i++)
    {
      FAIL_ON_ERROR(_yr_re_emit(
          re_node->left, arena, backwards, &branch_size, counter_index));

      *code_size += branch_size;
    }

    // m == n, no more code needed.
    if (re_node->end == re_node->start)
      break;

    idx = *counter_index;
    assert(idx < MAX_RE_COUNTERS);
    (*counter_index)++;

    FAIL_ON_ERROR(_yr_emit_inst_arg_uint32(
        arena, 
        RE_OPCODE_SET_COUNTER, 
        idx << 16 | re_node->end - re_node->start, 
        NULL, 
        &set_size));

    *code_size += set_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena, 
        re_node->greedy ? RE_OPCODE_SPLIT_A : RE_OPCODE_SPLIT_B, 
        0, 
        &split_offset_addr,
        &split_size));

    *code_size += split_size;

    FAIL_ON_ERROR(_yr_re_emit(
        re_node->left, arena, backwards, &branch_size, counter_index));

    *code_size += branch_size;

    FAIL_ON_ERROR(_yr_emit_inst_arg_int16(
        arena, 
        RE_OPCODE_JCNZ, 
        -(branch_size + split_size), 
        &jmp_offset_addr, 
        &jmp_size));

    *code_size += jmp_size;

    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        &idx,
        sizeof(uint16_t),
        NULL));

    *code_size += sizeof(uint16_t);

    *split_offset_addr = split_size + branch_size + 
                         jmp_size + sizeof(uint16_t);
    break;
  }

  return ERROR_SUCCESS;
}


int yr_re_emit_code(
    RE* re,
    ARENA* arena)
{
  uint16_t counter_index;
  int code_size;

  counter_index = 0;

  // Emit code for matching the regular expressions forwards.
  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node, arena, FALSE, &code_size, &counter_index));

  FAIL_ON_ERROR(_yr_emit_inst(
      arena, RE_OPCODE_MATCH, &code_size));

  counter_index = 0;

  // Emit code for matching the regular expressions backwards.
  FAIL_ON_ERROR(_yr_re_emit(
      re->root_node, arena, TRUE, &code_size, &counter_index));

  FAIL_ON_ERROR(_yr_emit_inst(
      arena, RE_OPCODE_MATCH, &code_size));

  return ERROR_SUCCESS;
}


void _yr_re_add_thread(
    RE_THREAD_LIST* thread_list,
    RE_THREAD_STORAGE* thread_storage,
    uint8_t* ip)
{
  uint16_t counter_index;
  int16_t jmp_offset;
  int i;

  for (i = 0; i < thread_list->count; i++)
    if (thread_list->threads[i] == ip)
      return;
  
  switch(*ip)
  {
    case RE_OPCODE_JUMP:
      jmp_offset = *(int16_t*)(ip + 1);
      _yr_re_add_thread(thread_list, thread_storage, ip + jmp_offset);
      break;

    case RE_OPCODE_JCNZ:
      jmp_offset = *(int16_t*)(ip + 1);
      counter_index = *(uint16_t*)(ip + 3);
      if (thread_storage->counters[counter_index] > 0)
      {
        thread_storage->counters[counter_index]--;
        _yr_re_add_thread(thread_list, thread_storage, ip + jmp_offset);
      }
      break;

    case RE_OPCODE_SET_COUNTER:
      counter_index = *(uint32_t*)(ip + 1) >> 16;
      thread_storage->counters[counter_index] = *(uint32_t*)(ip + 1) & 0xFFFF;
      _yr_re_add_thread(thread_list, thread_storage, ip + 5);
      break;

    case RE_OPCODE_SPLIT_A:
      jmp_offset = *(int16_t*)(ip + 1);
      _yr_re_add_thread(thread_list, thread_storage, ip + 3);
      _yr_re_add_thread(thread_list, thread_storage, ip + jmp_offset);
      break;

    case RE_OPCODE_SPLIT_B:
      jmp_offset = *(int16_t*)(ip + 1);
      _yr_re_add_thread(thread_list, thread_storage, ip + jmp_offset);
      _yr_re_add_thread(thread_list, thread_storage, ip + 3);
      break;

    default:
      assert(thread_list->count < MAX_RE_THREADS);
      thread_list->threads[thread_list->count] = ip;
      thread_list->count++;
  }
}


#define swap_threads(x, y) \
  { \
    RE_THREAD_LIST* tmp; \
    tmp = x; \
    x = y; \
    y = tmp; \
  }


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

  RE_THREAD_STORAGE* thread_storage;
  RE_THREAD_LIST* current_threads;
  RE_THREAD_LIST* next_threads;

  int character_size;
  int result = -1;

  #ifdef WIN32
  thread_storage = TlsGetValue(thread_storage_key);
  #else
  thread_storage = pthread_getspecific(thread_storage_key);
  #endif

  if (thread_storage == NULL)
  {
    thread_storage = yr_malloc(sizeof(RE_THREAD_STORAGE));

    if (thread_storage == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    #ifdef WIN32
    TlsSetValue(thread_storage_key, thread_storage);
    #else
    pthread_setspecific(thread_storage_key, thread_storage);
    #endif
  }

  current_threads = &thread_storage->list1; 
  next_threads = &thread_storage->list2;

  if (flags & RE_FLAGS_WIDE)
    character_size = 2;
  else
    character_size = 1;
    
  current_threads->count = 0;
  next_threads->count = 0;

  _yr_re_add_thread(current_threads, thread_storage, code);

  current_input = input;

  for (i = 0; i < min(input_size, RE_SCAN_LIMIT); i += character_size)
  {
    if (flags & RE_FLAGS_SCAN)
      _yr_re_add_thread(current_threads, thread_storage, code);

    if (current_threads->count == 0)
      break;

    for(t = 0; t < current_threads->count; t++)
    {
      ip = current_threads->threads[t];

      switch(*ip)
      {
        case RE_OPCODE_LITERAL:
          if (*current_input == *(ip + 1))
            _yr_re_add_thread(next_threads, thread_storage, ip + 2); 
          break;

        case RE_OPCODE_MASKED_LITERAL:
          value = *(int16_t*)(ip + 1) & 0xFF;
          mask = *(int16_t*)(ip + 1) >> 8;
          if ((*current_input & mask) == value)
            _yr_re_add_thread(next_threads, thread_storage, ip + 3); 
          break;

        case RE_OPCODE_CLASS:
          if (CHAR_IN_CLASS(*current_input, ip + 1))
            _yr_re_add_thread(next_threads, thread_storage, ip + 33); 
          break;

        case RE_OPCODE_WORD_CHAR:
          if (isalnum(*current_input) || *current_input == '_') 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_NON_WORD_CHAR:
          if (!isalnum(*current_input) && *current_input != '_') 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_SPACE:
          if (*current_input == ' ' || *current_input == '\t') 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_NON_SPACE:
          if (*current_input != ' ' && *current_input != '\t') 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_DIGIT:
          if (isdigit(*current_input)) 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_NON_DIGIT:
          if (!isdigit(*current_input)) 
            _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_ANY:
          _yr_re_add_thread(next_threads, thread_storage, ip + 1);
          break;

        case RE_OPCODE_MATCH:
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
      }
    }

  _break:

    swap_threads(current_threads, next_threads);
    next_threads->count = 0;

    if (flags & RE_FLAGS_WIDE && *(current_input + 1) != 0)
      break;

    if (flags & RE_FLAGS_BACKWARDS)
      current_input -= character_size;
    else
      current_input += character_size;
  }

  for(t = 0; t < current_threads->count; t++)
  {
    if (*current_threads->threads[t] == RE_OPCODE_MATCH)
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
