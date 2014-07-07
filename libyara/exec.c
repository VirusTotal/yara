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

#include <string.h>
#include <assert.h>
#include <time.h>

#include <yara/exec.h>
#include <yara/limits.h>
#include <yara/error.h>
#include <yara/object.h>
#include <yara/modules.h>
#include <yara/re.h>


#include <yara.h>

#define STACK_SIZE 16384
#define MEM_SIZE   MAX_LOOP_NESTING * LOOP_LOCAL_VARS


#define push(x)  \
    do { \
      if (sp < STACK_SIZE) stack[sp++] = (x); \
      else return ERROR_EXEC_STACK_OVERFLOW; \
    } while(0)


#define pop(x)  x = stack[--sp]


#define operation(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (UNDEFINED) : (op1 operator op2)


#define comparison(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (0) : (op1 operator op2)


#define function_read(type) \
    int64_t read_##type(YR_MEMORY_BLOCK* block, size_t offset) \
    { \
      while (block != NULL) \
      { \
        if (offset >= block->base && \
            block->size >= sizeof(type) && \
            offset <= block->base + block->size - sizeof(type)) \
        { \
          return *((type *) (block->data + offset - block->base)); \
        } \
        block = block->next; \
      } \
      return UNDEFINED; \
    };

function_read(uint8_t)
function_read(uint16_t)
function_read(uint32_t)
function_read(int8_t)
function_read(int16_t)
function_read(int32_t)


int yr_execute_code(
    YR_RULES* rules,
    YR_SCAN_CONTEXT* context,
    int timeout,
    time_t start_time)
{
  int64_t r1;
  int64_t r2;
  int64_t r3;
  int64_t mem[MEM_SIZE];
  int64_t stack[STACK_SIZE];
  int64_t args[MAX_FUNCTION_ARGS];
  int32_t sp = 0;
  uint8_t* ip = rules->code_start;

  YR_RULE* rule;
  YR_STRING* string;
  YR_MATCH* match;
  YR_OBJECT* object;
  YR_OBJECT_FUNCTION* function;

  char* identifier;

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
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        push(r1);
        break;

      case OP_POP:
        pop(r1);
        break;

      case OP_CLEAR_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1] = 0;
        break;

      case OP_ADD_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        mem[r1] += r2;
        break;

      case OP_INCR_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1]++;
        break;

      case OP_PUSH_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        push(mem[r1]);
        break;

      case OP_POP_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(mem[r1]);
        break;

      case OP_SWAPUNDEF:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        if (r2 != UNDEFINED)
          push(r2);
        else
          push(mem[r1]);
        break;

      case OP_JNUNDEF:
        pop(r1);
        push(r1);

        if (r1 != UNDEFINED)
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

        if (r1 <= r2)
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
        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(0);
        else
          push(r1 & r2);
        break;

      case OP_OR:
        pop(r2);
        pop(r1);
        if (IS_UNDEFINED(r1))
          push(r2);
        else if (IS_UNDEFINED(r2))
          push(r1);
        else
          push(r1 | r2);
        break;

      case OP_NOT:
        pop(r1);
        if (IS_UNDEFINED(r1))
          push(UNDEFINED);
        else
          push(!r1);
        break;

      case OP_LT:
        pop(r2);
        pop(r1);
        push(comparison(<, r1, r2));
        break;

      case OP_GT:
        pop(r2);
        pop(r1);
        push(comparison(>, r1, r2));
        break;

      case OP_LE:
        pop(r2);
        pop(r1);
        push(comparison(<=, r1, r2));
        break;

      case OP_GE:
        pop(r2);
        pop(r1);
        push(comparison(>=, r1, r2));
        break;

      case OP_EQ:
        pop(r2);
        pop(r1);
        push(comparison(==, r1, r2));
        break;

      case OP_NEQ:
        pop(r2);
        pop(r1);
        push(comparison(!=, r1, r2));
        break;

      case OP_SZ_EQ:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(UNDEFINED);
        else
          push(strcmp(UINT64_TO_PTR(char*, r1),
                      UINT64_TO_PTR(char*, r2)) == 0);
        break;

      case OP_SZ_NEQ:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(UNDEFINED);
        else
          push(strcmp(UINT64_TO_PTR(char*, r1),
                      UINT64_TO_PTR(char*, r2)) != 0);
        break;

      case OP_SZ_TO_BOOL:
        pop(r1);

        if (IS_UNDEFINED(r1))
          push(UNDEFINED);
        else
          push(strlen(UINT64_TO_PTR(char*, r1)) > 0);

        break;

      case OP_ADD:
        pop(r2);
        pop(r1);
        push(operation(+, r1, r2));
        break;

      case OP_SUB:
        pop(r2);
        pop(r1);
        push(operation(-, r1, r2));
        break;

      case OP_MUL:
        pop(r2);
        pop(r1);
        push(operation(*, r1, r2));
        break;

      case OP_DIV:
        pop(r2);
        pop(r1);
        push(operation(/, r1, r2));
        break;

      case OP_MOD:
        pop(r2);
        pop(r1);
        push(operation(%, r1, r2));
        break;

      case OP_NEG:
        pop(r1);
        push(IS_UNDEFINED(r1) ? UNDEFINED : ~r1);
        break;

      case OP_SHR:
        pop(r2);
        pop(r1);
        push(operation(>>, r1, r2));
        break;

      case OP_SHL:
        pop(r2);
        pop(r1);
        push(operation(<<, r1, r2));
        break;

      case OP_XOR:
        pop(r2);
        pop(r1);
        push(operation(^, r1, r2));
        break;

      case OP_PUSH_RULE:
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);
        push(rule->t_flags[tidx] & RULE_TFLAGS_MATCH ? 1 : 0);
        break;

      case OP_MATCH_RULE:
        pop(r1);
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);

        if (!IS_UNDEFINED(r1) && r1)
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
        push(PTR_TO_UINT64(object));
        break;

      case OP_OBJ_FIELD:
        pop(r1);

        identifier = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r1);
        object = yr_object_lookup_field(object, identifier);
        assert(object != NULL);
        push(PTR_TO_UINT64(object));
        break;

      case OP_OBJ_VALUE:
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r1);

        switch(object->type)
        {
          case OBJECT_TYPE_INTEGER:
            push(((YR_OBJECT_INTEGER*) object)->value);
            break;

          case OBJECT_TYPE_STRING:
            if (((YR_OBJECT_STRING*) object)->value != NULL)
              push(PTR_TO_UINT64(((YR_OBJECT_STRING*) object)->value));
            else
              push(UNDEFINED);
            break;

          default:
            assert(FALSE);
        }

        break;

      case OP_INDEX_ARRAY:
        pop(r1);
        pop(r2);

        if (r1 == UNDEFINED)
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r2);
        assert(object->type == OBJECT_TYPE_ARRAY);
        object = yr_object_array_get_item(object, 0, r1);

        if (object != NULL)
          push(PTR_TO_UINT64(object));
        else
          push(UNDEFINED);

        break;

      case OP_CALL:

        // r1 = number of arguments

        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);

        // pop arguments from stack and copy them to args array

        while (r1 > 0)
        {
          pop(args[r1 - 1]);
          r1--;
        }

        pop(r2);

        function = UINT64_TO_PTR(YR_OBJECT_FUNCTION*, r2);
        result = function->code((void*) args, function);

        if (result == ERROR_SUCCESS)
          push(PTR_TO_UINT64(function->return_obj));
        else
          return result;

        break;

      case OP_STR_FOUND:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1);
        push(string->matches[tidx].tail != NULL ? 1 : 0);
        break;

      case OP_STR_FOUND_AT:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r2);
        match = string->matches[tidx].head;
        found = 0;

        while (match != NULL)
        {
          if (r1 == match->base + match->offset)
          {
            push(1);
            found = 1;
            break;
          }

          if (r1 < match->base + match->offset)
            break;

          match = match->next;
        }

        if (!found)
          push(0);

        break;

      case OP_STR_FOUND_IN:
        pop(r3);
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r3);
        match = string->matches[tidx].head;
        found = FALSE;

        while (match != NULL && !found)
        {
          if (match->base + match->offset >= r1 &&
              match->base + match->offset <= r2)
          {
            push(1);
            found = TRUE;
          }

          if (match->base + match->offset > r2)
            break;

          match = match->next;
        }

        if (!found)
          push(0);

        break;

      case OP_STR_COUNT:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1);
        push(string->matches[tidx].count);
        break;

      case OP_STR_OFFSET:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r2);
        match = string->matches[tidx].head;
        i = 1;
        found = FALSE;

        while (match != NULL && !found)
        {
          if (r1 == i)
          {
            push(match->base + match->offset);
            found = TRUE;
          }

          i++;
          match = match->next;
        }

        if (!found)
          push(UNDEFINED);

        break;

      case OP_OF:
        found = 0;
        count = 0;
        pop(r1);

        while (r1 != UNDEFINED)
        {
          string = UINT64_TO_PTR(YR_STRING*, r1);
          if (string->matches[tidx].tail != NULL)
            found++;
          count++;
          pop(r1);
        }

        pop(r2);

        if (r2 != UNDEFINED)
          push(found >= r2 ? 1 : 0);
        else
          push(found >= count ? 1 : 0);

        break;

      case OP_FILESIZE:
        push(context->file_size);
        break;

      case OP_ENTRYPOINT:
        push(context->entry_point);
        break;

      case OP_INT8:
        pop(r1);
        push(read_int8_t(context->mem_block, r1));
        break;

      case OP_INT16:
        pop(r1);
        push(read_int16_t(context->mem_block, r1));
        break;

      case OP_INT32:
        pop(r1);
        push(read_int32_t(context->mem_block, r1));
        break;

      case OP_UINT8:
        pop(r1);
        push(read_uint8_t(context->mem_block, r1));
        break;

      case OP_UINT16:
        pop(r1);
        push(read_uint16_t(context->mem_block, r1));
        break;

      case OP_UINT32:
        pop(r1);
        push(read_uint32_t(context->mem_block, r1));
        break;

      case OP_CONTAINS:
        pop(r2);
        pop(r1);
        push(strstr(UINT64_TO_PTR(char*, r1),
                    UINT64_TO_PTR(char*, r2)) != NULL);
        break;

      case OP_IMPORT:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);

        FAIL_ON_ERROR(yr_modules_load(
            UINT64_TO_PTR(char*, r1),
            context));

        break;

      case OP_MATCHES:
        pop(r2);
        pop(r1);

        count = strlen(UINT64_TO_PTR(char*, r1));

        if (count == 0)
        {
          push(FALSE);
          break;
        }

        result = yr_re_exec(
          UINT64_TO_PTR(uint8_t*, r2),
          UINT64_TO_PTR(uint8_t*, r1),
          count,
          RE_FLAGS_SCAN,
          NULL,
          NULL);

        push(result >= 0);
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
