/*
Copyright (c) 2013-2014. The YARA Authors. All Rights Reserved.

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

#include <assert.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <yara.h>
#include <yara/arena.h>
#include <yara/endian.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/globals.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/object.h>
#include <yara/re.h>
#include <yara/sizedstr.h>
#include <yara/stopwatch.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#define MEM_SIZE YR_MAX_LOOP_NESTING*(YR_MAX_LOOP_VARS + YR_INTERNAL_LOOP_VARS)

#define push(x)                         \
  if (stack.sp < stack.capacity)        \
  {                                     \
    stack.items[stack.sp++] = (x);      \
  }                                     \
  else                                  \
  {                                     \
    result = ERROR_EXEC_STACK_OVERFLOW; \
    stop = true;                        \
    break;                              \
  }

#define pop(x)                   \
  {                              \
    assert(stack.sp > 0);        \
    x = stack.items[--stack.sp]; \
  }

#define is_undef(x) IS_UNDEFINED((x).i)

#define ensure_defined(x) \
  if (is_undef(x))        \
  {                       \
    r1.i = YR_UNDEFINED;  \
    push(r1);             \
    break;                \
  }

#define ensure_within_mem(x)             \
  if (x < 0 || x >= MEM_SIZE)            \
  {                                      \
    stop = true;                         \
    result = ERROR_INTERNAL_FATAL_ERROR; \
    break;                               \
  }

// Make sure that the string pointer is within the rules arena.
#define ensure_within_rules_arena(x)                              \
  {                                                               \
    YR_ARENA_REF ref;                                             \
    if (yr_arena_ptr_to_ref(context->rules->arena, x, &ref) == 0) \
    {                                                             \
      stop = true;                                                \
      result = ERROR_INTERNAL_FATAL_ERROR;                        \
      break;                                                      \
    }                                                             \
  }

#define check_object_canary(o)           \
  if (o->canary != context->canary)      \
  {                                      \
    stop = true;                         \
    result = ERROR_INTERNAL_FATAL_ERROR; \
    break;                               \
  }

#define little_endian_uint8_t(x)  (x)
#define little_endian_int8_t(x)   (x)
#define little_endian_uint16_t(x) yr_le16toh(x)
#define little_endian_int16_t(x)  yr_le16toh(x)
#define little_endian_uint32_t(x) yr_le32toh(x)
#define little_endian_int32_t(x)  yr_le32toh(x)

#define big_endian_uint8_t(x)  (x)
#define big_endian_int8_t(x)   (x)
#define big_endian_uint16_t(x) yr_be16toh(x)
#define big_endian_int16_t(x)  yr_be16toh(x)
#define big_endian_uint32_t(x) yr_be32toh(x)
#define big_endian_int32_t(x)  yr_be32toh(x)

#define function_read(type, endianess)                            \
  int64_t read_##type##_##endianess(                              \
      YR_MEMORY_BLOCK_ITERATOR* iterator, size_t offset)          \
  {                                                               \
    YR_MEMORY_BLOCK* block = iterator->first(iterator);           \
    while (block != NULL)                                         \
    {                                                             \
      if (offset >= block->base && block->size >= sizeof(type) && \
          offset <= block->base + block->size - sizeof(type))     \
      {                                                           \
        type result;                                              \
        const uint8_t* data = block->fetch_data(block);           \
        if (data == NULL)                                         \
          return YR_UNDEFINED;                                    \
        result = *(type*) (data + offset - block->base);          \
        result = endianess##_##type(result);                      \
        return result;                                            \
      }                                                           \
      block = iterator->next(iterator);                           \
    }                                                             \
    return YR_UNDEFINED;                                          \
  };

function_read(uint8_t, little_endian);
function_read(uint16_t, little_endian);
function_read(uint32_t, little_endian);
function_read(int8_t, little_endian);
function_read(int16_t, little_endian);
function_read(int32_t, little_endian);
function_read(uint8_t, big_endian);
function_read(uint16_t, big_endian);
function_read(uint32_t, big_endian);
function_read(int8_t, big_endian);
function_read(int16_t, big_endian);
function_read(int32_t, big_endian);

static const uint8_t* jmp_if(int condition, const uint8_t* ip)
{
  size_t off;

  if (condition)
  {
    // The condition is true, the instruction pointer is incremented in the
    // amount specified by the jump's offset. The offset is relative to the
    // jump opcode, but now the instruction pointer is pointing past the opcode
    // that's why we decrement the offset by 1.
    off = *(int32_t*) (ip) -1;
  }
  else
  {
    // The condition is false, the execution flow proceeds with the instruction
    // right after the jump.
    off = sizeof(int32_t);
  }

  return ip + off;
}

static int iter_array_next(YR_ITERATOR* self, YR_VALUE_STACK* stack)
{
  YR_OBJECT* obj;

  // Check that there's two available slots in the stack, one for the next
  // item returned by the iterator and another one for the boolean that
  // indicates if there are more items.
  if (stack->sp + 1 >= stack->capacity)
    return ERROR_EXEC_STACK_OVERFLOW;

  if (self->array_it.index < yr_object_array_length(self->array_it.array))
  {
    // Push the false value that indicates that the iterator is not exhausted.
    stack->items[stack->sp++].i = 0;

    obj = yr_object_array_get_item(
        self->array_it.array, 0, self->array_it.index);

    if (obj != NULL)
      stack->items[stack->sp++].o = obj;
    else
      stack->items[stack->sp++].i = YR_UNDEFINED;

    self->array_it.index++;
  }
  else
  {
    // Push true for indicating the iterator has been exhausted.
    stack->items[stack->sp++].i = 1;
    // Push YR_UNDEFINED as a placeholder for the next item.
    stack->items[stack->sp++].i = YR_UNDEFINED;
  }

  return ERROR_SUCCESS;
}

static int iter_dict_next(YR_ITERATOR* self, YR_VALUE_STACK* stack)
{
  YR_DICTIONARY_ITEMS* items = object_as_dictionary(self->dict_it.dict)->items;

  // Check that there's three available slots in the stack, two for the next
  // item returned by the iterator and its key, and another one for the boolean
  // that indicates if there are more items.
  if (stack->sp + 2 >= stack->capacity)
    return ERROR_EXEC_STACK_OVERFLOW;

  // If the dictionary has no items or the iterator reached the last item, abort
  // the iteration, if not push the next key and value.
  if (items == NULL || self->dict_it.index == items->used)
  {
    // Push true for indicating the iterator has been exhausted.
    stack->items[stack->sp++].i = 1;
    // Push YR_UNDEFINED as a placeholder for the next key and value.
    stack->items[stack->sp++].i = YR_UNDEFINED;
    stack->items[stack->sp++].i = YR_UNDEFINED;
  }
  else
  {
    // Push the false value that indicates that the iterator is not exhausted.
    stack->items[stack->sp++].i = 0;

    if (items->objects[self->dict_it.index].obj != NULL)
    {
      stack->items[stack->sp++].o = items->objects[self->dict_it.index].obj;
      stack->items[stack->sp++].p = items->objects[self->dict_it.index].key;
    }
    else
    {
      stack->items[stack->sp++].i = YR_UNDEFINED;
      stack->items[stack->sp++].i = YR_UNDEFINED;
    }

    self->dict_it.index++;
  }

  return ERROR_SUCCESS;
}

static int iter_int_range_next(YR_ITERATOR* self, YR_VALUE_STACK* stack)
{
  // Check that there's two available slots in the stack, one for the next
  // item returned by the iterator and another one for the boolean that
  // indicates if there are more items.
  if (stack->sp + 1 >= stack->capacity)
    return ERROR_EXEC_STACK_OVERFLOW;

  if (!IS_UNDEFINED(self->int_range_it.next) &&
      !IS_UNDEFINED(self->int_range_it.last) &&
      self->int_range_it.next <= self->int_range_it.last)
  {
    // Push the false value that indicates that the iterator is not exhausted.
    stack->items[stack->sp++].i = 0;
    stack->items[stack->sp++].i = self->int_range_it.next;
    self->int_range_it.next++;
  }
  else
  {
    // Push true for indicating the iterator has been exhausted.
    stack->items[stack->sp++].i = 1;
    // Push YR_UNDEFINED as a placeholder for the next item.
    stack->items[stack->sp++].i = YR_UNDEFINED;
  }

  return ERROR_SUCCESS;
}

static int iter_int_enum_next(YR_ITERATOR* self, YR_VALUE_STACK* stack)
{
  // Check that there's two available slots in the stack, one for the next
  // item returned by the iterator and another one for the boolean that
  // indicates if there are more items.
  if (stack->sp + 1 >= stack->capacity)
    return ERROR_EXEC_STACK_OVERFLOW;

  if (!IS_UNDEFINED(self->int_enum_it.next) &&
      !IS_UNDEFINED(self->int_enum_it.count) &&
      self->int_enum_it.next < self->int_enum_it.count)
  {
    // Push the false value that indicates that the iterator is not exhausted.
    stack->items[stack->sp++].i = 0;
    stack->items[stack->sp++].i =
        self->int_enum_it.items[self->int_enum_it.next];
    self->int_enum_it.next++;
  }
  else
  {
    // Push true for indicating the iterator has been exhausted.
    stack->items[stack->sp++].i = 1;
    // Push YR_UNDEFINED as a placeholder for the next item.
    stack->items[stack->sp++].i = YR_UNDEFINED;
  }

  return ERROR_SUCCESS;
}

int yr_execute_code(YR_SCAN_CONTEXT* context)
{
  YR_DEBUG_FPRINTF(2, stderr, "+ %s() {\n", __FUNCTION__);

  const uint8_t* ip = context->rules->code_start;

  YR_VALUE mem[MEM_SIZE];
  YR_VALUE args[YR_MAX_FUNCTION_ARGS];
  YR_VALUE r1;
  YR_VALUE r2;
  YR_VALUE r3;
  YR_VALUE r4;

  YR_VALUE_STACK stack;

  uint64_t elapsed_time;

#ifdef YR_PROFILING_ENABLED
  uint64_t start_time;
#endif

  uint32_t current_rule_idx = 0;
  YR_RULE* current_rule = NULL;
  YR_RULE* rule;
  YR_MATCH* match;
  YR_OBJECT_FUNCTION* function;
  YR_OBJECT** obj_ptr;
  YR_ARENA* obj_arena;
  YR_NOTEBOOK* it_notebook;

  char* identifier;
  char* args_fmt;

  int found;
  int count;
  int result = ERROR_SUCCESS;
  int cycle = 0;
  int obj_count = 0;

  bool stop = false;

  uint8_t opcode;

  yr_get_configuration(YR_CONFIG_STACK_SIZE, (void*) &stack.capacity);

  stack.sp = 0;
  stack.items = (YR_VALUE*) yr_malloc(stack.capacity * sizeof(YR_VALUE));

  if (stack.items == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_arena_create(1, 512 * sizeof(YR_OBJECT*), &obj_arena),
      yr_free(stack.items));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_notebook_create(512 * sizeof(YR_ITERATOR), &it_notebook),
      yr_arena_release(obj_arena);
      yr_free(stack.items));

#ifdef YR_PROFILING_ENABLED
  start_time = yr_stopwatch_elapsed_ns(&context->stopwatch);
#endif

#if YR_PARANOID_EXEC
  memset(mem, 0, MEM_SIZE * sizeof(mem[0]));
#endif

  while (!stop)
  {
    // Read the opcode from the address indicated by the instruction pointer.
    opcode = *ip;

    // Advance the instruction pointer, which now points past the opcode.
    ip++;

    switch (opcode)
    {
    case OP_NOP:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_NOP: // %s()\n", __FUNCTION__);
      break;

    case OP_HALT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_HALT: // %s()\n", __FUNCTION__);
      assert(stack.sp == 0);  // When HALT is reached the stack should be empty.
      stop = true;
      break;

    case OP_ITER_START_ARRAY:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ITER_START_ARRAY: // %s()\n", __FUNCTION__);
      r2.p = yr_notebook_alloc(it_notebook, sizeof(YR_ITERATOR));

      if (r2.p == NULL)
      {
        result = ERROR_INSUFFICIENT_MEMORY;
      }
      else
      {
        pop(r1);
        r2.it->array_it.array = r1.o;
        r2.it->array_it.index = 0;
        r2.it->next = iter_array_next;
        push(r2);
      }

      stop = (result != ERROR_SUCCESS);
      break;

    case OP_ITER_START_DICT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ITER_START_DICT: // %s()\n", __FUNCTION__);
      r2.p = yr_notebook_alloc(it_notebook, sizeof(YR_ITERATOR));

      if (r2.p == NULL)
      {
        result = ERROR_INSUFFICIENT_MEMORY;
      }
      else
      {
        pop(r1);
        r2.it->dict_it.dict = r1.o;
        r2.it->dict_it.index = 0;
        r2.it->next = iter_dict_next;
        push(r2);
      }

      stop = (result != ERROR_SUCCESS);
      break;

    case OP_ITER_START_INT_RANGE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ITER_START_INT_RANGE: // %s()\n", __FUNCTION__);
      // Creates an iterator for an integer range. The higher bound of the
      // range is at the top of the stack followed by the lower bound.
      r3.p = yr_notebook_alloc(it_notebook, sizeof(YR_ITERATOR));

      if (r3.p == NULL)
      {
        result = ERROR_INSUFFICIENT_MEMORY;
      }
      else
      {
        pop(r2);
        pop(r1);
        r3.it->int_range_it.next = r1.i;
        r3.it->int_range_it.last = r2.i;
        r3.it->next = iter_int_range_next;
        push(r3);
      }

      stop = (result != ERROR_SUCCESS);
      break;

    case OP_ITER_START_INT_ENUM:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ITER_START_INT_ENUM: // %s()\n", __FUNCTION__);
      // Creates an iterator for an integer enumeration. The number of items
      // in the enumeration is at the top of the stack, followed by the
      // items in reverse order.
      pop(r1);

      r3.p = yr_notebook_alloc(
          it_notebook, sizeof(YR_ITERATOR) + sizeof(uint64_t) * (size_t) r1.i);

      if (r3.p == NULL)
      {
        result = ERROR_INSUFFICIENT_MEMORY;
      }
      else
      {
        r3.it->int_enum_it.count = r1.i;
        r3.it->int_enum_it.next = 0;
        r3.it->next = iter_int_enum_next;

        for (int64_t i = r1.i; i > 0; i--)
        {
          pop(r2);
          r3.it->int_enum_it.items[i - 1] = r2.i;
        }

        push(r3);
      }

      stop = (result != ERROR_SUCCESS);
      break;

    case OP_ITER_NEXT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ITER_NEXT: // %s()\n", __FUNCTION__);
      // Loads the iterator in r1, but leaves the iterator in the stack.
      pop(r1);
      push(r1);
      // The iterator's next function is responsible for pushing the next
      // item in the stack, and a boolean indicating if there are more items
      // to retrieve. The boolean will be at the top of the stack after
      // calling "next".
      result = r1.it->next(r1.it, &stack);
      stop = (result != ERROR_SUCCESS);
      break;

    case OP_PUSH:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_PUSH: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
      push(r1);
      break;

    case OP_PUSH_8:
      r1.i = *ip;
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- case OP_PUSH_8: r1.i=%" PRId64 " // %s()\n",
          r1.i,
          __FUNCTION__);
      ip += sizeof(uint8_t);
      push(r1);
      break;

    case OP_PUSH_16:
      r1.i = *(uint16_t*) (ip);
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- case OP_PUSH_16: r1.i=%" PRId64 " // %s()\n",
          r1.i,
          __FUNCTION__);
      ip += sizeof(uint16_t);
      push(r1);
      break;

    case OP_PUSH_32:
      r1.i = *(uint32_t*) (ip);
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- case OP_PUSH_32: r1.i=%" PRId64 " // %s()\n",
          r1.i,
          __FUNCTION__);
      ip += sizeof(uint32_t);
      push(r1);
      break;

    case OP_PUSH_U:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_PUSH_U: // %s()\n", __FUNCTION__);
      r1.i = YR_UNDEFINED;
      push(r1);
      break;

    case OP_POP:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_POP: // %s()\n", __FUNCTION__);
      pop(r1);
      break;

    case OP_CLEAR_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_CLEAR_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      mem[r1.i].i = 0;
      break;

    case OP_ADD_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_ADD_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      pop(r2);
      if (!is_undef(r2))
        mem[r1.i].i += r2.i;
      break;

    case OP_INCR_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INCR_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      mem[r1.i].i++;
      break;

    case OP_PUSH_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_PUSH_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      r1 = mem[r1.i];
      push(r1);
      break;

    case OP_POP_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_POP_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      pop(r2);
      mem[r1.i] = r2;
      break;

    case OP_SET_M:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_SET_M: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      pop(r2);
      push(r2);
      if (!is_undef(r2))
        mem[r1.i] = r2;
      break;

    case OP_SWAPUNDEF:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_SWAPUNDEF: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);
#if YR_PARANOID_EXEC
      ensure_within_mem(r1.i);
#endif
      pop(r2);

      if (is_undef(r2))
      {
        r1 = mem[r1.i];
        push(r1);
      }
      else
      {
        push(r2);
      }
      break;

    case OP_JNUNDEF:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JNUNDEF: // %s()\n", __FUNCTION__);
      pop(r1);
      push(r1);
      ip = jmp_if(!is_undef(r1), ip);
      break;

    case OP_JUNDEF_P:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_JUNDEF_P: // %s()\n", __FUNCTION__);
      pop(r1);
      ip = jmp_if(is_undef(r1), ip);
      break;

    case OP_JL_P:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JL_P: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ip = jmp_if(r1.i < r2.i, ip);
      break;

    case OP_JLE_P:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JLE_P: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ip = jmp_if(r1.i <= r2.i, ip);
      break;

    case OP_JTRUE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JTRUE: // %s()\n", __FUNCTION__);
      pop(r1);
      push(r1);
      ip = jmp_if(!is_undef(r1) && r1.i, ip);
      break;

    case OP_JTRUE_P:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JTRUE_P: // %s()\n", __FUNCTION__);
      pop(r1);
      ip = jmp_if(!is_undef(r1) && r1.i, ip);
      break;

    case OP_JFALSE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JFALSE: // %s()\n", __FUNCTION__);
      pop(r1);
      push(r1);
      ip = jmp_if(is_undef(r1) || !r1.i, ip);
      break;

    case OP_JFALSE_P:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_JFALSE_P: // %s()\n", __FUNCTION__);
      pop(r1);
      ip = jmp_if(is_undef(r1) || !r1.i, ip);
      break;

    case OP_JZ:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JZ: // %s()\n", __FUNCTION__);
      pop(r1);
      push(r1);
      ip = jmp_if(r1.i == 0, ip);
      break;

    case OP_JZ_P:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_JZ_P: // %s()\n", __FUNCTION__);
      pop(r1);
      ip = jmp_if(r1.i == 0, ip);
      break;

    case OP_AND:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_AND: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      if (is_undef(r1) || is_undef(r2))
        r1.i = 0;
      else
        r1.i = r1.i && r2.i;

      push(r1);
      break;

    case OP_OR:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_OR: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      if (is_undef(r1))
      {
        push(r2);
      }
      else if (is_undef(r2))
      {
        push(r1);
      }
      else
      {
        r1.i = r1.i || r2.i;
        push(r1);
      }
      break;

    case OP_NOT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_NOT: // %s()\n", __FUNCTION__);
      pop(r1);

      if (is_undef(r1))
        r1.i = YR_UNDEFINED;
      else
        r1.i = !r1.i;

      push(r1);
      break;

    case OP_MOD:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_MOD: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      if (r2.i != 0)
        r1.i = r1.i % r2.i;
      else
        r1.i = YR_UNDEFINED;
      push(r1);
      break;

    case OP_SHR:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_SHR: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      if (r2.i < 0)
        r1.i = YR_UNDEFINED;
      else if (r2.i < 64)
        r1.i = r1.i >> r2.i;
      else
        r1.i = 0;
      push(r1);
      break;

    case OP_SHL:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_SHL: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      if (r2.i < 0)
        r1.i = YR_UNDEFINED;
      else if (r2.i < 64)
        r1.i = r1.i << r2.i;
      else
        r1.i = 0;
      push(r1);
      break;

    case OP_BITWISE_NOT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_BITWISE_NOT: // %s()\n", __FUNCTION__);
      pop(r1);
      ensure_defined(r1);
      r1.i = ~r1.i;
      push(r1);
      break;

    case OP_BITWISE_AND:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_BITWISE_AND: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i & r2.i;
      push(r1);
      break;

    case OP_BITWISE_OR:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_BITWISE_OR: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i | r2.i;
      push(r1);
      break;

    case OP_BITWISE_XOR:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_BITWISE_XOR: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i ^ r2.i;
      push(r1);
      break;

    case OP_PUSH_RULE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_PUSH_RULE: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);

      rule = &context->rules->rules_table[r1.i];

      if (RULE_IS_DISABLED(rule))
      {
        r2.i = YR_UNDEFINED;
      }
      else
      {
        if yr_bitmask_is_set (context->rule_matches_flags, r1.i)
          r2.i = 1;
        else
          r2.i = 0;
      }

      push(r2);
      break;

    case OP_INIT_RULE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_INIT_RULE: // %s()\n", __FUNCTION__);
      // After the opcode there's an int32_t corresponding to the jump's
      // offset and an uint32_t corresponding to the rule's index.
      current_rule_idx = *(uint32_t*) (ip + sizeof(int32_t));

      assert(current_rule_idx < context->rules->num_rules);

      current_rule = &context->rules->rules_table[current_rule_idx];

      // If the rule is disabled let's skip its code.
      ip = jmp_if(RULE_IS_DISABLED(current_rule), ip);

      // Skip the bytes corresponding to the rule's index, but only if not
      // taking the jump.
      if (!RULE_IS_DISABLED(current_rule))
        ip += sizeof(uint32_t);

      break;

    case OP_MATCH_RULE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_MATCH_RULE: // %s()\n", __FUNCTION__);
      pop(r1);

      memcpy(&r2.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);

      rule = &context->rules->rules_table[r2.i];

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(rule);
#endif

      if (!is_undef(r1) && r1.i)
        yr_bitmask_set(context->rule_matches_flags, r2.i);
      else if (RULE_IS_GLOBAL(rule))
        yr_bitmask_set(context->ns_unsatisfied_flags, rule->ns->idx);

#ifdef YR_PROFILING_ENABLED
      elapsed_time = yr_stopwatch_elapsed_ns(&context->stopwatch);
      context->profiling_info[r2.i].exec_time += (elapsed_time - start_time);
      start_time = elapsed_time;
#endif

      assert(stack.sp == 0);  // at this point the stack should be empty.
      break;

    case OP_OBJ_LOAD:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_OBJ_LOAD: // %s()\n", __FUNCTION__);
      identifier = *(char**) (ip);
      ip += sizeof(uint64_t);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(identifier);
#endif

      r1.o = (YR_OBJECT*) yr_hash_table_lookup(
          context->objects_table, identifier, NULL);

      assert(r1.o != NULL);
      push(r1);
      break;

    case OP_OBJ_FIELD:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_OBJ_FIELD: // %s()\n", __FUNCTION__);
      identifier = *(char**) (ip);
      ip += sizeof(uint64_t);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(identifier);
#endif

      pop(r1);
      ensure_defined(r1);

      r1.o = yr_object_lookup_field(r1.o, identifier);

      if (r1.o == NULL)
      {
        result = ERROR_INVALID_FIELD_NAME;
        stop = true;
        break;
      }

      push(r1);
      break;

    case OP_OBJ_VALUE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_OBJ_VALUE: // %s()\n", __FUNCTION__);
      pop(r1);
      ensure_defined(r1);

#if YR_PARANOID_EXEC
      check_object_canary(r1.o);
#endif

      switch (r1.o->type)
      {
      case OBJECT_TYPE_INTEGER:
        r1.i = r1.o->value.i;
        break;

      case OBJECT_TYPE_FLOAT:
        if (isnan(r1.o->value.d))
          r1.i = YR_UNDEFINED;
        else
          r1.d = r1.o->value.d;
        break;

      case OBJECT_TYPE_STRING:
        if (r1.o->value.ss == NULL)
          r1.i = YR_UNDEFINED;
        else
          r1.ss = r1.o->value.ss;
        break;

      default:
        assert(false);
      }

      push(r1);
      break;

    case OP_INDEX_ARRAY:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_INDEX_ARRAY: // %s()\n", __FUNCTION__);
      pop(r1);  // index
      pop(r2);  // array

      ensure_defined(r1);
      ensure_defined(r2);

      assert(r2.o->type == OBJECT_TYPE_ARRAY);

#if YR_PARANOID_EXEC
      check_object_canary(r2.o);
#endif

      r1.o = yr_object_array_get_item(r2.o, 0, (int) r1.i);

      if (r1.o == NULL)
        r1.i = YR_UNDEFINED;

      push(r1);
      break;

    case OP_LOOKUP_DICT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_LOOKUP_DICT: // %s()\n", __FUNCTION__);
      pop(r1);  // key
      pop(r2);  // dictionary

      ensure_defined(r1);
      ensure_defined(r2);

      assert(r2.o->type == OBJECT_TYPE_DICTIONARY);

#if YR_PARANOID_EXEC
      check_object_canary(r2.o);
#endif

      r1.o = yr_object_dict_get_item(r2.o, 0, r1.ss->c_string);

      if (r1.o == NULL)
        r1.i = YR_UNDEFINED;

      push(r1);
      break;

    case OP_CALL:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_CALL: // %s()\n", __FUNCTION__);
      args_fmt = *(char**) (ip);
      ip += sizeof(uint64_t);

      int i = (int) strlen(args_fmt);
      count = 0;

#if YR_PARANOID_EXEC
      if (i > YR_MAX_FUNCTION_ARGS)
      {
        stop = true;
        result = ERROR_INTERNAL_FATAL_ERROR;
        break;
      }
#endif

      // pop arguments from stack and copy them to args array

      while (i > 0)
      {
        pop(r1);

        if (is_undef(r1))  // count the number of undefined args
          count++;

        args[i - 1] = r1;
        i--;
      }

      pop(r2);
      ensure_defined(r2);

#if YR_PARANOID_EXEC
      check_object_canary(r2.o);
#endif

      if (count > 0)
      {
        // If there are undefined args, result for function call
        // is undefined as well.

        r1.i = YR_UNDEFINED;
        push(r1);
        break;
      }

      function = object_as_function(r2.o);
      result = ERROR_INTERNAL_FATAL_ERROR;

      for (int i = 0; i < YR_MAX_OVERLOADED_FUNCTIONS; i++)
      {
        if (function->prototypes[i].arguments_fmt == NULL)
          break;

        if (strcmp(function->prototypes[i].arguments_fmt, args_fmt) == 0)
        {
          result = function->prototypes[i].code(args, context, function);
          break;
        }
      }

      // If i == YR_MAX_OVERLOADED_FUNCTIONS at this point no matching
      // prototype was found, but this shouldn't happen.
      assert(i < YR_MAX_OVERLOADED_FUNCTIONS);

      // Make a copy of the returned object and push the copy into the stack,
      // function->return_obj can't be pushed because it can change in
      // subsequent calls to the same function.
      if (result == ERROR_SUCCESS)
        result = yr_object_copy(function->return_obj, &r1.o);

      // A pointer to the copied object is stored in a arena in order to
      // free the object before exiting yr_execute_code, obj_count tracks
      // the number of objects written.
      if (result == ERROR_SUCCESS)
      {
        result = yr_arena_write_data(obj_arena, 0, &r1.o, sizeof(r1.o), NULL);
        obj_count++;
      }

      stop = (result != ERROR_SUCCESS);
      push(r1);
      break;

    case OP_FOUND:
      pop(r1);
      r2.i = context->matches[r1.s->idx].tail != NULL ? 1 : 0;
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- case OP_FOUND: r2.i=%" PRId64 " // %s()\n",
          r2.i,
          __FUNCTION__);
      push(r2);
      break;

    case OP_FOUND_AT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_FOUND_AT: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      if (is_undef(r1))
      {
        r1.i = 0;
        push(r1);
        break;
      }

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r2.p);
#endif

      match = context->matches[r2.s->idx].head;
      r3.i = false;

      while (match != NULL)
      {
        if (r1.i == match->base + match->offset)
        {
          r3.i = true;
          break;
        }

        if (r1.i < match->base + match->offset)
          break;

        match = match->next;
      }

      push(r3);
      break;

    case OP_FOUND_IN:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_FOUND_IN: // %s()\n", __FUNCTION__);
      pop(r3);
      pop(r2);
      pop(r1);

      ensure_defined(r1);
      ensure_defined(r2);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r3.p);
#endif

      match = context->matches[r3.s->idx].head;
      r4.i = false;

      while (match != NULL && !r4.i)
      {
        if (match->base + match->offset >= r1.i &&
            match->base + match->offset <= r2.i)
        {
          r4.i = true;
        }

        if (match->base + match->offset > r2.i)
          break;

        match = match->next;
      }

      push(r4);
      break;

    case OP_COUNT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_COUNT: // %s()\n", __FUNCTION__);
      pop(r1);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r1.p);
#endif

      r2.i = context->matches[r1.s->idx].count;
      push(r2);
      break;

    case OP_OFFSET:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_OFFSET: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      ensure_defined(r1);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r2.p);
#endif

      match = context->matches[r2.s->idx].head;

      i = 1;
      r3.i = YR_UNDEFINED;

      while (match != NULL && r3.i == YR_UNDEFINED)
      {
        if (r1.i == i)
          r3.i = match->base + match->offset;

        i++;
        match = match->next;
      }

      push(r3);
      break;

    case OP_LENGTH:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_LENGTH: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      ensure_defined(r1);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r2.p);
#endif

      match = context->matches[r2.s->idx].head;

      i = 1;
      r3.i = YR_UNDEFINED;

      while (match != NULL && r3.i == YR_UNDEFINED)
      {
        if (r1.i == i)
          r3.i = match->match_length;

        i++;
        match = match->next;
      }

      push(r3);
      break;

    case OP_OF:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_OF: // %s()\n", __FUNCTION__);
      found = 0;
      count = 0;
      pop(r1);

      while (!is_undef(r1))
      {
        if (context->matches[r1.s->idx].tail != NULL)
        {
          found++;
        }
        count++;
        pop(r1);
      }

      pop(r2);

      if (is_undef(r2))
        r1.i = found >= count ? 1 : 0;
      else
        r1.i = found >= r2.i ? 1 : 0;

      push(r1);
      break;

    case OP_FILESIZE:
      r1.i = context->file_size;
      YR_DEBUG_FPRINTF(
          2,
          stderr,
          "- case OP_FILESIZE: r1.i=%" PRId64 "%s // %s()\n",
          r1.i,
          r1.i == YR_UNDEFINED ? " AKA YR_UNDEFINED" : "",
          __FUNCTION__);
      push(r1);
      break;

    case OP_ENTRYPOINT:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_ENTRYPOINT: // %s()\n", __FUNCTION__);
      r1.i = context->entry_point;
      push(r1);
      break;

    case OP_INT8:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT8: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int8_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_INT16:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT16: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int16_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_INT32:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT32: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int32_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT8:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_UINT8: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint8_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT16:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_UINT16: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint16_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT32:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_UINT32: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint32_t_little_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_INT8BE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT8BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int8_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_INT16BE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT16BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int16_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_INT32BE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT32BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_int32_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT8BE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_UINT8BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint8_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT16BE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_UINT16BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint16_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_UINT32BE:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_UINT32BE: // %s()\n", __FUNCTION__);
      pop(r1);
      r1.i = read_uint32_t_big_endian(context->iterator, (size_t) r1.i);
      push(r1);
      break;

    case OP_IMPORT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_IMPORT: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);

#if YR_PARANOID_EXEC
      ensure_within_rules_arena(r1.p);
#endif

      result = yr_modules_load((char*) r1.p, context);

      if (result != ERROR_SUCCESS)
        stop = true;

      break;

    case OP_MATCHES:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_MATCHES: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);

      if (is_undef(r1) || is_undef(r2) || r1.ss->length == 0)
      {
        r1.i = false;
        push(r1);
        break;
      }

      result = yr_re_exec(
          context,
          (uint8_t*) r2.re->code,
          (uint8_t*) r1.ss->c_string,
          r1.ss->length,
          0,
          r2.re->flags | RE_FLAGS_SCAN,
          NULL,
          NULL,
          &found);

      if (result != ERROR_SUCCESS)
        stop = true;

      r1.i = found >= 0;
      push(r1);
      break;

    case OP_INT_TO_DBL:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_INT_TO_DBL: // %s()\n", __FUNCTION__);
      memcpy(&r1.i, ip, sizeof(uint64_t));
      ip += sizeof(uint64_t);

#if YR_PARANOID_EXEC
      if (r1.i > stack.sp || stack.sp - r1.i >= stack.capacity)
      {
        stop = true;
        result = ERROR_INTERNAL_FATAL_ERROR;
        break;
      }
#endif

      r2 = stack.items[stack.sp - r1.i];

      if (is_undef(r2))
        stack.items[stack.sp - r1.i].i = YR_UNDEFINED;
      else
        stack.items[stack.sp - r1.i].d = (double) r2.i;
      break;

    case OP_STR_TO_BOOL:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_STR_TO_BOOL: // %s()\n", __FUNCTION__);
      pop(r1);
      ensure_defined(r1);
      r1.i = r1.ss->length > 0;
      push(r1);
      break;

    case OP_INT_EQ:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_EQ: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i == r2.i;
      push(r1);
      break;

    case OP_INT_NEQ:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_NEQ: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i != r2.i;
      push(r1);
      break;

    case OP_INT_LT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_LT: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i < r2.i;
      push(r1);
      break;

    case OP_INT_GT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_GT: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i > r2.i;
      push(r1);
      break;

    case OP_INT_LE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_LE: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i <= r2.i;
      push(r1);
      break;

    case OP_INT_GE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_GE: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.i >= r2.i;
      push(r1);
      break;

    case OP_INT_ADD:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_ADD: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i + r2.i;
      push(r1);
      break;

    case OP_INT_SUB:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_SUB: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i - r2.i;
      push(r1);
      break;

    case OP_INT_MUL:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_MUL: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.i = r1.i * r2.i;
      push(r1);
      break;

    case OP_INT_DIV:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_INT_DIV: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      if (r2.i != 0)
        r1.i = r1.i / r2.i;
      else
        r1.i = YR_UNDEFINED;
      push(r1);
      break;

    case OP_INT_MINUS:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_INT_MINUS: // %s()\n", __FUNCTION__);
      pop(r1);
      ensure_defined(r1);
      r1.i = -r1.i;
      push(r1);
      break;

    case OP_DBL_LT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_LT: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.d < r2.d;
      push(r1);
      break;

    case OP_DBL_GT:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_GT: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.d > r2.d;
      push(r1);
      break;

    case OP_DBL_LE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_LE: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.d <= r2.d;
      push(r1);
      break;

    case OP_DBL_GE:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_GE: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = r1.d >= r2.d;
      push(r1);
      break;

    case OP_DBL_EQ:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_EQ: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = fabs(r1.d - r2.d) < DBL_EPSILON;
      push(r1);
      break;

    case OP_DBL_NEQ:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_NEQ: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      if (is_undef(r1) || is_undef(r2))
        r1.i = false;
      else
        r1.i = fabs(r1.d - r2.d) >= DBL_EPSILON;
      push(r1);
      break;

    case OP_DBL_ADD:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_ADD: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.d = r1.d + r2.d;
      push(r1);
      break;

    case OP_DBL_SUB:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_SUB: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.d = r1.d - r2.d;
      push(r1);
      break;

    case OP_DBL_MUL:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_MUL: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.d = r1.d * r2.d;
      push(r1);
      break;

    case OP_DBL_DIV:
      YR_DEBUG_FPRINTF(2, stderr, "- case OP_DBL_DIV: // %s()\n", __FUNCTION__);
      pop(r2);
      pop(r1);
      ensure_defined(r2);
      ensure_defined(r1);
      r1.d = r1.d / r2.d;
      push(r1);
      break;

    case OP_DBL_MINUS:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case OP_DBL_MINUS: // %s()\n", __FUNCTION__);
      pop(r1);
      ensure_defined(r1);
      r1.d = -r1.d;
      push(r1);
      break;

    case OP_STR_EQ:
    case OP_STR_NEQ:
    case OP_STR_LT:
    case OP_STR_LE:
    case OP_STR_GT:
    case OP_STR_GE:

      pop(r2);
      pop(r1);

      if (is_undef(r1) || is_undef(r2))
      {
        r1.i = false;
      }
      else
      {
        switch (opcode)
        {
        case OP_STR_EQ:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_EQ: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) == 0);
          break;
        case OP_STR_NEQ:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_NEQ: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) != 0);
          break;
        case OP_STR_LT:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_LT: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) < 0);
          break;
        case OP_STR_LE:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_LE: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) <= 0);
          break;
        case OP_STR_GT:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_GT: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) > 0);
          break;
        case OP_STR_GE:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STR_GE: // %s()\n", __FUNCTION__);
          r1.i = (ss_compare(r1.ss, r2.ss) >= 0);
          break;
        }
      }

      push(r1);
      break;

    case OP_CONTAINS:
    case OP_ICONTAINS:
    case OP_STARTSWITH:
    case OP_ISTARTSWITH:
    case OP_ENDSWITH:
    case OP_IENDSWITH:

      pop(r2);
      pop(r1);

      if (is_undef(r1) || is_undef(r2))
      {
        r1.i = false;
      }
      else
      {
        switch (opcode)
        {
        case OP_CONTAINS:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_CONTAINS: // %s()\n", __FUNCTION__);
          r1.i = ss_contains(r1.ss, r2.ss);
          break;
        case OP_ICONTAINS:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_ICONTAINS: // %s()\n", __FUNCTION__);
          r1.i = ss_icontains(r1.ss, r2.ss);
          break;
        case OP_STARTSWITH:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_STARTSWITH: // %s()\n", __FUNCTION__);
          r1.i = ss_startswith(r1.ss, r2.ss);
          break;
        case OP_ISTARTSWITH:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_ISTARTSWITH: // %s()\n", __FUNCTION__);
          r1.i = ss_istartswith(r1.ss, r2.ss);
          break;
        case OP_ENDSWITH:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_ENDSWITH: // %s()\n", __FUNCTION__);
          r1.i = ss_endswith(r1.ss, r2.ss);
          break;
        case OP_IENDSWITH:
          YR_DEBUG_FPRINTF(
              2, stderr, "- case OP_IENDSWITH: // %s()\n", __FUNCTION__);
          r1.i = ss_iendswith(r1.ss, r2.ss);
          break;
        }
      }

      push(r1);
      break;

    default:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case <unknown instruction>: // %s()\n", __FUNCTION__);
      // Unknown instruction, this shouldn't happen.
      assert(false);
    }

    // Check for timeout every 100 instruction cycles. If timeout == 0 it means
    // no timeout at all.

    if (context->timeout > 0ULL && ++cycle == 100)
    {
      elapsed_time = yr_stopwatch_elapsed_ns(&context->stopwatch);

      if (elapsed_time > context->timeout)
      {
#ifdef YR_PROFILING_ENABLED
        context->profiling_info[current_rule_idx].exec_time +=
            (elapsed_time - start_time);
#endif
        result = ERROR_SCAN_TIMEOUT;
        stop = true;
      }

      cycle = 0;
    }
  }

  obj_ptr = yr_arena_get_ptr(obj_arena, 0, 0);

  for (int i = 0; i < obj_count; i++) yr_object_destroy(obj_ptr[i]);

  yr_arena_release(obj_arena);
  yr_notebook_destroy(it_notebook);
  yr_modules_unload_all(context);
  yr_free(stack.items);

  YR_DEBUG_FPRINTF(
      2,
      stderr,
      "} = %d AKA %s // %s()\n",
      result,
      yr_debug_error_as_string(result),
      __FUNCTION__);

  return result;
}
