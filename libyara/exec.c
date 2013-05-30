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

#define STACK_SIZE 2048


#define push(x)  \
    if (sp < STACK_SIZE) stack[sp++] = (x); \
    else return ERROR_STACK_OVERFLOW


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
  int64_t rA;
  int64_t rB;
  int64_t rC;
  int64_t r1;
  int64_t r2;
  int64_t r3;
  int64_t stack[STACK_SIZE];
  int32_t sp = 0;
  uint8_t* ip = rules->code_start;

  RULE* rule;
  STRING* string;
  MATCH* match;
  EXTERNAL_VARIABLE* external;
  REGEXP re;

  char* identifier;
  int i;
  int found;
  int count;
  int result;

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
        //printf("PUSH: %p\n", r1);
        break;

      case PUSH_A:
        push(rA);
        //printf("PUSH_A: %p\n", rA);
        break;

      case POP_A:
        pop(rA);
        //printf("POP_A: %p\n", rA);
        break;

      case PUSH_B:
        push(rB);
        //printf("PUSH_B: %p\n", rB);
        break;

      case POP_B:
        pop(rB);
        //printf("POP_B: %p\n", rB);
        break;

      case PUSH_C:
        push(rC);
        //printf("PUSH_C: %p\n", rC);
        break;

      case POP_C:
        pop(rC);
        //printf("POP_C: %p\n", rC);
        break;

      case CLEAR_B:
        //printf("CLEAR_B\n");
        rB = 0;
        break;

      case CLEAR_C:
        //printf("CLEAR_C\n");
        rC = 0;
        break;

      case INCR_A:
        pop(r1);
        rA += r1;
        //printf("INCR_A A:%d\n", rA);
        break;

      case INCR_B:
        pop(r1);
        rB += r1;
        //printf("INCR_B B:%d\n", rB);
        break;

      case INCR_C:
        pop(r1);
        rC += r1;
        //printf("INCR_C C:%d\n", rC);
        break;

      case JLE_A_B:
        //printf("JLE_A_B A:%d  B:%d\n", rA, rB);
        if (rA <= rB)
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

      case JNUNDEF_A:
        if (rA != UNDEFINED)
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

      case PNUNDEF_A_B:
        //printf("PNUNDEF_A_B  %p\n", rA != UNDEFINED ? rA : rB);
        if (rA != UNDEFINED)
          push(rA);
        else
          push(rB);
        break;

      case AND:
        pop(r2);
        pop(r1);
        push(r1 & r2);
        //printf("AND %p %p\n", r1, r2);
        break;

      case OR:
        pop(r2);
        pop(r1);
        push(r1 | r2);
        //printf("OR %p %p\n", r1, r2);
        break;

      case NOT:
        pop(r1);
        push(!r1);
        break;

      case LT:
        pop(r2);
        pop(r1);
        push(comparison(<, r1, r2));
        //printf("LT %p %p\n", r1, r2);
        break;

      case GT:
        pop(r2);
        pop(r1);
        push(comparison(>, r1, r2));
        //printf("GT %p %p\n", r1, r2);
        break;

      case LE:
        pop(r2);
        pop(r1);
        push(comparison(<=, r1, r2));
        //printf("LE %p %p\n", r1, r2);
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
        //printf("NEQ %p %p %p\n", r1, r2, comparison(!=, r1, r2));
        break;

      case ADD:
        pop(r2);
        pop(r1);
        push(operation(+, r1, r2));
        //printf("ADD %p %p %p\n", r1, r2, operation(+, r1, r2));
        break;

      case SUB:
        pop(r2);
        pop(r1);
        push(operation(-, r1, r2));
        //printf("SUB %p %p %p\n", r1, r2, operation(-, r1, r2));
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
        push(rule->flags & RULE_FLAGS_MATCH ? 1 : 0);
        //printf("RULE_PUSH %s %d\n", rule->identifier, rule->flags | RULE_FLAGS_MATCH ? 1 : 0);
        break;

      case RULE_POP:
        pop(r1);
        rule = *(RULE**)(ip + 1);
        ip += sizeof(uint64_t);
        if (r1)
          rule->flags |= RULE_FLAGS_MATCH;
        //printf("RULE_POP %s %d\n", rule->identifier, r1);
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
        push(string->flags & STRING_FLAGS_FOUND ? 1 : 0);
        //printf("SFOUND %s %d\n", string->identifier, string->flags & STRING_FLAGS_FOUND? 1 : 0);
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
        match = string->matches_list_head;
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
        match = string->matches_list_head;
        found = 0;

        while (match != NULL)
        {
          if ((match->first_offset >= r1 && match->first_offset <= r2) ||
              (match->last_offset >= r1 && match->last_offset <= r2) ||
              (match->first_offset <= r1 && match->last_offset >= r2))
          {
            push(1);
            found = 1;
            break;
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
        match = string->matches_list_head;
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
        match = string->matches_list_head;
        i = 1;
        found = 0;

        //printf("SOFFSET %s[%d] ", string->identifier, r1);

        while (match != NULL)
        {
          if (r1 >= i &&
              r1 <= i + match->last_offset - match->first_offset)
          {
            push(match->first_offset + r1 - i);
            //printf("%d", match->first_offset + r1 - i);
            found = 1;
          }

          i += match->last_offset - match->first_offset + 1;
          match = match->next;
        }

        if (!found)
          push(UNDEFINED);

        //printf("\n");

        break;

      case OF:
        found = 0;
        count = 0;
        pop(r1);
        while (r1 != UNDEFINED)
        {
          string = UINT64_TO_PTR(STRING*, r1);
          if (string->flags & STRING_FLAGS_FOUND)
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
        push(strstr(UINT64_TO_PTR(char*, r1), UINT64_TO_PTR(char*, r2)) != NULL);
        break;

      case MATCHES:
        pop(r2);
        pop(r1);

        result = regex_compile(&re,
            UINT64_TO_PTR(char*, r2),
            FALSE,
            NULL,
            0,
            &i);

        // Regexp should compile without errors,
        // it was verified during compile time.
        assert(result > 0);

        result = regex_exec(&re,
            FALSE,
            UINT64_TO_PTR(char*, r1),
            strlen(UINT64_TO_PTR(char*, r1)));

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