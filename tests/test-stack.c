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


#include <yara/stack.h>
#include <yara.h>
#include "util.h"


int main(int argc, char** argv)
{
  YR_STACK* stack;

  int item;

  yr_initialize();
  yr_stack_create(1, sizeof(item),  &stack);

  item = 1;

  if (yr_stack_push(stack, &item) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  item = 2;

  if (yr_stack_push(stack, &item) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  item = 3;

  if (yr_stack_push(stack, &item) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  item = 4;

  if (yr_stack_push(stack, &item) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  if (!yr_stack_pop(stack, &item) || item != 4)
    exit(EXIT_FAILURE);

  if (!yr_stack_pop(stack, &item) || item != 3)
    exit(EXIT_FAILURE);

  if (!yr_stack_pop(stack, &item) || item != 2)
    exit(EXIT_FAILURE);

  if (!yr_stack_pop(stack, &item) || item != 1)
    exit(EXIT_FAILURE);

  if (yr_stack_pop(stack, &item) || item != 1)
    exit(EXIT_FAILURE);

  yr_stack_destroy(stack);
  yr_finalize();
  return 0;
}
