/*
Copyright (c) 2013-2014. The YARA Authors. All Rights Reserved.

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

#define _GNU_SOURCE

#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include <yara/exec.h>
#include <yara/limits.h>
#include <yara/error.h>
#include <yara/object.h>
#include <yara/modules.h>
#include <yara/re.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#include <yara.h>


#define STACK_SIZE 16384
#define MEM_SIZE   MAX_LOOP_NESTING * LOOP_LOCAL_VARS

union STACK_ITEM {
  int64_t i;
  double  d;
};

#define push(x)  \
    do { \
      if (sp < STACK_SIZE) stack[sp++] = (x); \
      else return ERROR_EXEC_STACK_OVERFLOW; \
    } while(0)


#define pop(x)  x = stack[--sp]

#define is_undef(x) IS_UNDEFINED((x).i)

#define ensure_defined(x) \
    if (is_undef(x)) \
    { \
      r1.i = UNDEFINED; \
      push(r1); \
      break; \
    }


#define little_endian_uint8_t(x)     (x)
#define little_endian_uint16_t(x)    (x)
#define little_endian_uint32_t(x)    (x)
#define little_endian_int8_t(x)      (x)
#define little_endian_int16_t(x)     (x)
#define little_endian_int32_t(x)     (x)

#define big_endian_uint8_t(x)         (x)

#define big_endian_uint16_t(x) \
    (((((uint16_t)(x) & 0xFF)) << 8) | \
     ((((uint16_t)(x) & 0xFF00)) >> 8))

#define big_endian_uint32_t(x) \
    (((((uint32_t)(x) & 0xFF)) << 24) | \
     ((((uint32_t)(x) & 0xFF00)) << 8) | \
     ((((uint32_t)(x) & 0xFF0000)) >> 8) | \
     ((((uint32_t)(x) & 0xFF000000)) >> 24))

#define big_endian_int8_t(x)   big_endian_uint8_t(x)
#define big_endian_int16_t(x)  big_endian_uint16_t(x)
#define big_endian_int32_t(x)  big_endian_uint32_t(x)


#define function_read(type, endianess) \
    int64_t read_##type##_##endianess(YR_MEMORY_BLOCK* block, size_t offset) \
    { \
      while (block != NULL) \
      { \
        if (offset >= block->base && \
            block->size >= sizeof(type) && \
            offset <= block->base + block->size - sizeof(type)) \
        { \
          type result = *(type *)(block->data + offset - block->base); \
          result = endianess##_##type(result); \
          return result; \
        } \
        block = block->next; \
      } \
      return UNDEFINED; \
    };


function_read(uint8_t, little_endian)
function_read(uint16_t, little_endian)
function_read(uint32_t, little_endian)
function_read(int8_t, little_endian)
function_read(int16_t, little_endian)
function_read(int32_t, little_endian)
function_read(uint8_t, big_endian)
function_read(uint16_t, big_endian)
function_read(uint32_t, big_endian)
function_read(int8_t, big_endian)
function_read(int16_t, big_endian)
function_read(int32_t, big_endian)


int yr_execute_code(
    YR_RULES* rules,
    YR_SCAN_CONTEXT* context,
    int timeout,
    time_t start_time)
{
  int64_t mem[MEM_SIZE];
  int64_t args[MAX_FUNCTION_ARGS];
  int32_t sp = 0;
  uint8_t* ip = rules->code_start;

  union STACK_ITEM stack[STACK_SIZE];
  union STACK_ITEM r1;
  union STACK_ITEM r2;
  union STACK_ITEM r3;

  YR_RULE* rule;
  YR_STRING* string;
  YR_MATCH* match;
  YR_OBJECT* object;
  YR_OBJECT_FUNCTION* function;

  SIZED_STRING* sized_str_1;
  SIZED_STRING* sized_str_2;

  char* identifier;
  char* args_fmt;

  int i;
  int found;
  int count;
  int result;
  int cycle = 0;
  int tidx = yr_get_tidx();

  #ifdef PROFILING_ENABLED
  clock_t start = clock();
  #endif

  while(1)
  {
    switch(*ip)
    {
      case OP_HALT:
        // When the halt instruction is reached the stack
        // should be empty.
        assert(sp == 0);
        return ERROR_SUCCESS;

      case OP_PUSH:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        push(r1);
        break;

      case OP_POP:
        pop(r1);
        break;

      case OP_CLEAR_M:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1.i] = 0;
        break;

      case OP_ADD_M:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        if (!is_undef(r2))
          mem[r1.i] += r2.i;
        break;

      case OP_INCR_M:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1.i]++;
        break;

      case OP_PUSH_M:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        r1.i = mem[r1.i];
        push(r1);
        break;

      case OP_POP_M:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        mem[r1.i] = r2.i;
        break;

      case OP_SWAPUNDEF:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        if (is_undef(r2))
        {
          r1.i = mem[r1.i];
          push(r1);
        }
        else
        {
          push(r2);
        }
        break;

      case OP_JNUNDEF:
        pop(r1);
        push(r1);
        if (!is_undef(r1))
        {
          ip = *(uint8_t**)(ip + 1);
          // ip will be incremented at the end of the loop,
          // decrement it here to compensate.
          ip--;
        }
        else
        {
          ip += sizeof(uint64_t);
        }
        break;

      case OP_JLE:
        pop(r2);
        pop(r1);
        push(r1);
        push(r2);

        if (r1.i <= r2.i)
        {
          ip = *(uint8_t**)(ip + 1);
          // ip will be incremented at the end of the loop,
          // decrement it here to compensate.
          ip--;
        }
        else
        {
          ip += sizeof(uint64_t);
        }
        break;

      case OP_AND:
        pop(r2);
        pop(r1);

        if (is_undef(r1) || is_undef(r2))
          r1.i = 0;
        else
          r1.i = r1.i && r2.i;

        push(r1);
        break;

      case OP_OR:
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
        pop(r1);

        if (is_undef(r1))
          r1.i = UNDEFINED;
        else
          r1.i= !r1.i;

        push(r1);
        break;

      case OP_MOD:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i % r2.i;
        push(r1);
        break;

      case OP_SHR:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i >> r2.i;
        push(r1);
        break;

      case OP_SHL:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i << r2.i;
        push(r1);
        break;

      case OP_BITWISE_NOT:
        pop(r1);
        ensure_defined(r1);
        r1.i = ~r1.i;
        push(r1);
        break;

      case OP_BITWISE_AND:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i & r2.i;
        push(r1);
        break;

      case OP_BITWISE_OR:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i | r2.i;
        push(r1);
        break;

      case OP_BITWISE_XOR:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i ^ r2.i;
        push(r1);
        break;

      case OP_PUSH_RULE:
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);
        r1.i = rule->t_flags[tidx] & RULE_TFLAGS_MATCH ? 1 : 0;
        push(r1);
        break;

      case OP_MATCH_RULE:
        pop(r1);
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);

        if (!is_undef(r1) && r1.i)
          rule->t_flags[tidx] |= RULE_TFLAGS_MATCH;

        #ifdef PROFILING_ENABLED
        rule->clock_ticks += clock() - start;
        start = clock();
        #endif
        break;

      case OP_OBJ_LOAD:
        identifier = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        object = (YR_OBJECT*) yr_hash_table_lookup(
            context->objects_table,
            identifier,
            NULL);

        assert(object != NULL);
        r1.i = PTR_TO_UINT64(object);
        push(r1);
        break;

      case OP_OBJ_FIELD:
        identifier = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        pop(r1);
        ensure_defined(r1);

        object = UINT64_TO_PTR(YR_OBJECT*, r1.i);
        object = yr_object_lookup_field(object, identifier);

        assert(object != NULL);
        r1.i = PTR_TO_UINT64(object);
        push(r1);
        break;

      case OP_OBJ_VALUE:
        pop(r1);
        ensure_defined(r1);

        object = UINT64_TO_PTR(YR_OBJECT*, r1.i);

        switch(object->type)
        {
          case OBJECT_TYPE_INTEGER:
            r1.i = ((YR_OBJECT_INTEGER*) object)->value;
            break;

          case OBJECT_TYPE_DOUBLE:
            if (isnan(((YR_OBJECT_DOUBLE*) object)->value))
              r1.i = UNDEFINED;
            else
              r1.d = ((YR_OBJECT_DOUBLE*) object)->value;
            break;

          case OBJECT_TYPE_STRING:
            if (((YR_OBJECT_STRING*) object)->value == NULL)
              r1.i = UNDEFINED;
            else
              r1.i = PTR_TO_UINT64(((YR_OBJECT_STRING*) object)->value);
            break;

          default:
            assert(FALSE);
        }

        push(r1);
        break;

      case OP_INDEX_ARRAY:
        pop(r1);  // index
        pop(r2);  // array

        ensure_defined(r1);

        object = UINT64_TO_PTR(YR_OBJECT*, r2.i);
        assert(object->type == OBJECT_TYPE_ARRAY);
        object = yr_object_array_get_item(object, 0, r1.i);

        if (object != NULL)
          r1.i = PTR_TO_UINT64(object);
        else
          r1.i = UNDEFINED;

        push(r1);
        break;

      case OP_LOOKUP_DICT:
        pop(r1);  // key
        pop(r2);  // dictionary

        ensure_defined(r1);

        object = UINT64_TO_PTR(YR_OBJECT*, r2.i);
        assert(object->type == OBJECT_TYPE_DICTIONARY);

        object = yr_object_dict_get_item(
            object, 0, UINT64_TO_PTR(SIZED_STRING*, r1.i)->c_string);

        if (object != NULL)
          r1.i = PTR_TO_UINT64(object);
        else
          r1.i = UNDEFINED;

        push(r1);
        break;

      case OP_CALL:
        args_fmt = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        i = strlen(args_fmt);

        // pop arguments from stack and copy them to args array

        while (i > 0)
        {
          pop(r1);
          args[i - 1] = r1.i;
          i--;
        }

        pop(r2);
        ensure_defined(r2);

        function = UINT64_TO_PTR(YR_OBJECT_FUNCTION*, r2.i);
        result = ERROR_INTERNAL_FATAL_ERROR;

        for (i = 0; i < MAX_OVERLOADED_FUNCTIONS; i++)
        {
          if (function->prototypes[i].arguments_fmt == NULL)
            break;

          if (strcmp(function->prototypes[i].arguments_fmt, args_fmt) == 0)
          {
            result = function->prototypes[i].code(
                (void*) args,
                context,
                function);

            break;
          }
        }

        assert(i < MAX_OVERLOADED_FUNCTIONS);

        if (result == ERROR_SUCCESS)
        {
          r1.i = PTR_TO_UINT64(function->return_obj);
          push(r1);
        }
        else
        {
          return result;
        }

        break;

      case OP_FOUND:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1.i);
        r1.i = string->matches[tidx].tail != NULL ? 1 : 0;
        push(r1);
        break;

      case OP_FOUND_AT:
        pop(r2);
        pop(r1);

        if (is_undef(r1))
        {
          r1.i = 0;
          push(r1);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r2.i);
        match = string->matches[tidx].head;
        r3.i = FALSE;

        while (match != NULL)
        {
          if (r1.i == match->base + match->offset)
          {
            r3.i = TRUE;
            break;
          }

          if (r1.i < match->base + match->offset)
            break;

          match = match->next;
        }

        push(r3);
        break;

      case OP_FOUND_IN:
        pop(r3);
        pop(r2);
        pop(r1);

        ensure_defined(r1);
        ensure_defined(r2);

        string = UINT64_TO_PTR(YR_STRING*, r3.i);
        match = string->matches[tidx].head;
        r3.i = FALSE;

        while (match != NULL && !r3.i)
        {
          if (match->base + match->offset >= r1.i &&
              match->base + match->offset <= r2.i)
          {
            r3.i = TRUE;
          }

          if (match->base + match->offset > r2.i)
            break;

          match = match->next;
        }

        push(r3);
        break;

      case OP_COUNT:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1.i);
        r1.i = string->matches[tidx].count;
        push(r1);
        break;

      case OP_OFFSET:
        pop(r2);
        pop(r1);

        ensure_defined(r1);

        string = UINT64_TO_PTR(YR_STRING*, r2.i);
        match = string->matches[tidx].head;
        i = 1;
        r3.i = UNDEFINED;

        while (match != NULL && r3.i == UNDEFINED)
        {
          if (r1.i == i)
            r3.i = match->base + match->offset;

          i++;
          match = match->next;
        }

        push(r3);
        break;

      case OP_OF:
        found = 0;
        count = 0;
        pop(r1);

        while (!is_undef(r1))
        {
          string = UINT64_TO_PTR(YR_STRING*, r1.i);
          if (string->matches[tidx].tail != NULL)
            found++;
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
        push(r1);
        break;

      case OP_ENTRYPOINT:
        r1.i = context->entry_point;
        push(r1);
        break;

      case OP_INT8:
        pop(r1);
        r1.i = read_int8_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_INT16:
        pop(r1);
        r1.i = read_int16_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_INT32:
        pop(r1);
        r1.i = read_int32_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT8:
        pop(r1);
        r1.i = read_uint8_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT16:
        pop(r1);
        r1.i = read_uint16_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT32:
        pop(r1);
        r1.i = read_uint32_t_little_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_INT8BE:
        pop(r1);
        r1.i = read_int8_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_INT16BE:
        pop(r1);
        r1.i = read_int16_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_INT32BE:
        pop(r1);
        r1.i = read_int32_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT8BE:
        pop(r1);
        r1.i = read_uint8_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT16BE:
        pop(r1);
        r1.i = read_uint16_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_UINT32BE:
        pop(r1);
        r1.i = read_uint32_t_big_endian(context->mem_block, r1.i);
        push(r1);
        break;

      case OP_CONTAINS:
        pop(r2);
        pop(r1);

        ensure_defined(r1);
        ensure_defined(r2);

        sized_str_1 = UINT64_TO_PTR(SIZED_STRING*, r1.i);
        sized_str_2 = UINT64_TO_PTR(SIZED_STRING*, r2.i);

        r1.i = memmem(sized_str_1->c_string, sized_str_1->length,
                      sized_str_2->c_string, sized_str_2->length) != NULL;
        push(r1);
        break;

      case OP_IMPORT:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);

        FAIL_ON_ERROR(yr_modules_load(
            UINT64_TO_PTR(char*, r1.i),
            context));

        break;

      case OP_MATCHES:
        pop(r2);
        pop(r1);

        sized_str_1 = UINT64_TO_PTR(SIZED_STRING*, r1.i);

        if (sized_str_1->length == 0)
        {
          r1.i = FALSE;
          push(r1);
          break;
        }

        result = yr_re_exec(
          UINT64_TO_PTR(uint8_t*, r2.i),
          (uint8_t*) sized_str_1->c_string,
          sized_str_1->length,
          RE_FLAGS_SCAN,
          NULL,
          NULL);

        r1.i = result >= 0;
        push(r1);
        break;

      case OP_INT_TO_DBL:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        r2 = stack[sp - r1.i];
        if (is_undef(r2))
          stack[sp - r1.i].i = UNDEFINED;
        else
          stack[sp - r1.i].d = r2.i;
        break;

      case OP_STR_TO_BOOL:
        pop(r1);
        ensure_defined(r1);
        r1.i = UINT64_TO_PTR(SIZED_STRING*, r1.i)->length > 0;
        push(r1);
        break;

      case OP_INT_EQ:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i == r2.i;
        push(r1);
        break;

      case OP_INT_NEQ:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i != r2.i;
        push(r1);
        break;

      case OP_INT_LT:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i < r2.i;
        push(r1);
        break;

      case OP_INT_GT:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i > r2.i;
        push(r1);
        break;

      case OP_INT_LE:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i <= r2.i;
        push(r1);
        break;

      case OP_INT_GE:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i >= r2.i;
        push(r1);
        break;

      case OP_INT_ADD:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i + r2.i;
        push(r1);
        break;

      case OP_INT_SUB:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i - r2.i;
        push(r1);
        break;

      case OP_INT_MUL:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i * r2.i;
        push(r1);
        break;

      case OP_INT_DIV:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.i / r2.i;
        push(r1);
        break;

      case OP_DBL_LT:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d < r2.d;
        push(r1);
        break;

      case OP_DBL_GT:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d > r2.d;
        push(r1);
        break;

      case OP_DBL_LE:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d <= r2.d;
        push(r1);
        break;

      case OP_DBL_GE:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d >= r2.d;
        push(r1);
        break;

      case OP_DBL_EQ:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d == r2.d;
        push(r1);
        break;

      case OP_DBL_NEQ:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.i = r1.d != r2.d;
        push(r1);
        break;

      case OP_DBL_ADD:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.d = r1.d + r2.d;
        push(r1);
        break;

      case OP_DBL_SUB:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.d = r1.d - r2.d;
        push(r1);
        break;

      case OP_DBL_MUL:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.d = r1.d * r2.d;
        push(r1);
        break;

      case OP_DBL_DIV:
        pop(r2);
        pop(r1);
        ensure_defined(r2);
        ensure_defined(r1);
        r1.d = r1.d / r2.d;
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

        ensure_defined(r1);
        ensure_defined(r2);

        sized_str_1 = UINT64_TO_PTR(SIZED_STRING*, r1.i);
        sized_str_2 = UINT64_TO_PTR(SIZED_STRING*, r2.i);

        int r = sized_string_cmp(sized_str_1, sized_str_2);

        switch(*ip)
        {
          case OP_STR_EQ:
            r1.i = (r == 0);
            break;
          case OP_STR_NEQ:
            r1.i = (r != 0);
            break;
          case OP_STR_LT:
            r1.i = (r < 0);
            break;
          case OP_STR_LE:
            r1.i = (r <= 0);
            break;
          case OP_STR_GT:
            r1.i = (r > 0);
            break;
          case OP_STR_GE:
            r1.i = (r >= 0);
            break;
        }

        push(r1);
        break;

      default:
        // Unknown instruction, this shouldn't happen.
        assert(FALSE);
    }

    if (timeout > 0)  // timeout == 0 means no timeout
    {
      // Check for timeout every 10 instruction cycles.

      if (++cycle == 10)
      {
        if (difftime(time(NULL), start_time) > timeout)
          return ERROR_SCAN_TIMEOUT;

        cycle = 0;
      }
    }

    ip++;
  }

  // After executing the code the stack should be empty.
  assert(sp == 0);

  return ERROR_SUCCESS;
}
