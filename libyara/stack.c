/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

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

#include <yara/error.h>
#include <yara/integers.h>
#include <yara/mem.h>
#include <yara/stack.h>

////////////////////////////////////////////////////////////////////////////////
// Creates a stack for items of the size specified by item_size. All items
// in the stack must have the same size. The stack will have an initial
// capacity as specified by initial_capacity and will grow as required when
// more objects are pushed.
//
int yr_stack_create(int initial_capacity, int item_size, YR_STACK** stack)
{
  *stack = (YR_STACK*) yr_malloc(sizeof(YR_STACK));

  if (*stack == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  (*stack)->items = yr_malloc(initial_capacity * item_size);

  if ((*stack)->items == NULL)
  {
    yr_free(*stack);
    *stack = NULL;
    return ERROR_INSUFFICIENT_MEMORY;
  }

  (*stack)->capacity = initial_capacity;
  (*stack)->item_size = item_size;
  (*stack)->top = 0;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys a stack and deallocates all its resources.
//
void yr_stack_destroy(YR_STACK* stack)
{
  yr_free(stack->items);
  yr_free(stack);
}

////////////////////////////////////////////////////////////////////////////////
// Pushes an item into the stack. If the stack has reached its capacity the
// function tries to double the capacity. This operation can fail with
// ERROR_INSUFFICIENT_MEMORY.
//
int yr_stack_push(YR_STACK* stack, void* item)
{
  if (stack->top == stack->capacity)
  {
    void* items = yr_realloc(
        stack->items, 2 * stack->capacity * stack->item_size);

    if (items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    stack->items = items;
    stack->capacity *= 2;
  }

  memcpy(
      (uint8_t*) stack->items + stack->top * stack->item_size,
      item,
      stack->item_size);

  stack->top++;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Pops an item from the stack. The caller must pass pointer to a buffer
// where the function will copy the item. The buffer must have enough space
// to hold the item. Returns 1 if an item could be poped and 0 if the stack
// was already empty.
//
int yr_stack_pop(YR_STACK* stack, void* item)
{
  if (stack->top == 0)  // Return 0 if stack is empty.
    return 0;

  stack->top--;

  memcpy(
      item,
      (uint8_t*) stack->items + stack->top * stack->item_size,
      stack->item_size);

  return 1;
}
