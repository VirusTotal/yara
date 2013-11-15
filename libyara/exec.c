/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#include "exec.h"
#include "re.h"

#define STACK_SIZE 16384
#define MEM_SIZE   MAX_LOOP_NESTING * LOOP_LOCAL_VARS


#define push(x)  \
    if (sp < STACK_SIZE) stack[sp++] = (x); \
    else return ERROR_EXEC_STACK_OVERFLOW


#define pop(x)  x = stack[--sp]


#define operation(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (UNDEFINED) : (op1 operator op2)


#define comparison(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (0) : (op1 operator op2)


#define function_read(type) \
    int64_t read_##type(MEMORY_BLOCK* block, size_t offset) \
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
    YARA_RULES* rules,
    EVALUATION_CONTEXT* context)
{
  int64_t r1;
  int64_t r2;
  int64_t r3;
  int64_t mem[MEM_SIZE];
  int64_t stack[STACK_SIZE];
  int32_t sp = 0;
  uint8_t* ip = rules->code_start;

  RULE* rule;
  STRING* string;
  MATCH* match;
  EXTERNAL_VARIABLE* external;

  int i;
  int found;
  int count;
  int result;
  int tidx = yr_get_tidx();

  while(1)
  {
    switch(*ip)
    {
      case HALT:
        // When the halt instruction is reached the stack should be empty.
        assert(sp == 0);
        return ERROR_SUCCESS;

      case PUSH:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        push(r1);
        break;

      case POP:
        pop(r1);
        break;

      case CLEAR_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1] = 0;
        break;

      case ADD_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        mem[r1] += r2;
        break;

      case INCR_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        mem[r1]++;
        break;

      case PUSH_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        push(mem[r1]);
        break;

      case POP_M:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(mem[r1]);
        break;

      case SWAPUNDEF:
        r1 = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        pop(r2);
        if (r2 != UNDEFINED)
          push(r2);
        else
          push(mem[r1]);
        break;

      case JNUNDEF:
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

      case JLE:
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

      case AND:
        pop(r2);
        pop(r1);
        push(r1 & r2);
        break;

      case OR:
        pop(r2);
        pop(r1);
        push(r1 | r2);
        break;

      case NOT:
        pop(r1);
        push(!r1);
        break;

      case LT:
        pop(r2);
        pop(r1);
        push(comparison(<, r1, r2));
        break;

      case GT:
        pop(r2);
        pop(r1);
        push(comparison(>, r1, r2));
        break;

      case LE:
        pop(r2);
        pop(r1);
        push(comparison(<=, r1, r2));
        break;

      case GE:
        pop(r2);
        pop(r1);
        push(comparison(>=, r1, r2));
        break;

      case EQ:
        pop(r2);
        pop(r1);
        push(comparison(==, r1, r2));
        break;

      case NEQ:
        pop(r2);
        pop(r1);
        push(comparison(!=, r1, r2));
        break;

      case ADD:
        pop(r2);
        pop(r1);
        push(operation(+, r1, r2));
        break;

      case SUB:
        pop(r2);
        pop(r1);
        push(operation(-, r1, r2));
        break;

      case MUL:
        pop(r2);
        pop(r1);
        push(operation(*, r1, r2));
        break;

      case DIV:
        pop(r2);
        pop(r1);
        push(operation(/, r1, r2));
        break;

      case MOD:
        pop(r2);
        pop(r1);
        push(operation(%, r1, r2));
        break;

      case NEG:
        pop(r1);
        push(IS_UNDEFINED(r1) ? UNDEFINED : ~r1);
        break;

      case SHR:
        pop(r2);
        pop(r1);
        push(operation(>>, r1, r2));
        break;

      case SHL:
        pop(r2);
        pop(r1);
        push(operation(<<, r1, r2));
        break;

      case XOR:
        pop(r2);
        pop(r1);
        push(operation(^, r1, r2));
        break;

      case RULE_PUSH:
        rule = *(RULE**)(ip + 1);
        ip += sizeof(uint64_t);
        push(rule->t_flags[tidx] & RULE_TFLAGS_MATCH ? 1 : 0);
        break;

      case RULE_POP:
        pop(r1);
        rule = *(RULE**)(ip + 1);
        ip += sizeof(uint64_t);
        if (r1)
          rule->t_flags[tidx] |= RULE_TFLAGS_MATCH;
        break;

      case EXT_INT:
        external = *(EXTERNAL_VARIABLE**)(ip + 1);
        ip += sizeof(uint64_t);
        push(external->integer);
        break;

      case EXT_STR:
        external = *(EXTERNAL_VARIABLE**)(ip + 1);
        ip += sizeof(uint64_t);
        push(PTR_TO_UINT64(external->string));
        break;

      case EXT_BOOL:
        external = *(EXTERNAL_VARIABLE**)(ip + 1);
        ip += sizeof(uint64_t);
        if (external->type == EXTERNAL_VARIABLE_TYPE_FIXED_STRING ||
            external->type == EXTERNAL_VARIABLE_TYPE_MALLOC_STRING)
          push(strlen(external->string) > 0);
        else
          push(external->integer);
        break;

      case SFOUND:
        pop(r1);
        string = UINT64_TO_PTR(STRING*, r1);
        push(string->matches[tidx].tail != NULL ? 1 : 0);
        break;

      case SFOUND_AT:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(STRING*, r2);
        match = string->matches[tidx].head;
        found = 0;

        while (match != NULL)
        {
          if (r1 >= match->first_offset && r1 <= match->last_offset)
          {
            push(1);
            found = 1;
            break;
          }

          if (r1 < match->first_offset)
            break;

          match = match->next;
        }

        if (!found)
          push(0);

        break;

      case SFOUND_IN:
        pop(r3);
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(STRING*, r3);
        match = string->matches[tidx].head;
        found = FALSE;

        while (match != NULL && !found)
        {
          if ((match->first_offset >= r1 && match->first_offset <= r2) ||
              (match->last_offset >= r1 && match->last_offset <= r2) ||
              (match->first_offset <= r1 && match->last_offset >= r2))
          {
            push(1);
            found = TRUE;
          }

          if (match->first_offset > r2)
            break;

          match = match->next;
        }

        if (!found)
          push(0);

        break;

      case SCOUNT:
        pop(r1);
        string = UINT64_TO_PTR(STRING*, r1);
        match = string->matches[tidx].head;
        found = 0;
        while (match != NULL)
        {
          found += match->last_offset - match->first_offset + 1;
          match = match->next;
        }
        push(found);
        break;

      case SOFFSET:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        string = UINT64_TO_PTR(STRING*, r2);
        match = string->matches[tidx].head;
        i = 1;
        found = FALSE;

        while (match != NULL && !found)
        {
          if (r1 >= i &&
              r1 <= i + match->last_offset - match->first_offset)
          {
            push(match->first_offset + r1 - i);
            found = TRUE;
          }

          i += match->last_offset - match->first_offset + 1;
          match = match->next;
        }

        if (!found)
          push(UNDEFINED);

        break;

      case OF:
        found = 0;
        count = 0;
        pop(r1);

        while (r1 != UNDEFINED)
        {
          string = UINT64_TO_PTR(STRING*, r1);
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

      case SIZE:
        push(context->file_size);
        break;

      case ENTRYPOINT:
        push(context->entry_point);
        break;

      case INT8:
        pop(r1);
        push(read_int8_t(context->mem_block, r1));
        break;

      case INT16:
        pop(r1);
        push(read_int16_t(context->mem_block, r1));
        break;

      case INT32:
        pop(r1);
        push(read_int32_t(context->mem_block, r1));
        break;

      case UINT8:
        pop(r1);
        push(read_uint8_t(context->mem_block, r1));
        break;

      case UINT16:
        pop(r1);
        push(read_uint16_t(context->mem_block, r1));
        break;

      case UINT32:
        pop(r1);
        push(read_uint32_t(context->mem_block, r1));
        break;

      case CONTAINS:
        pop(r2);
        pop(r1);
        push(strstr(UINT64_TO_PTR(char*, r1),
                    UINT64_TO_PTR(char*, r2)) != NULL);
        break;

      case MATCHES:
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

    ip++;
  }

  // After executing the code the stack should be empty.
  assert(sp == 0);
}