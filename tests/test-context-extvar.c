/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>

#include <yara.h>
#include "util.h"

uint8_t buf[1024];
YR_RULES* rules;

static int callback(int message, void* message_data, void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    char id_initial = 'a' + (uintptr_t)user_data;
    YR_RULE *rule = (YR_RULE*)message_data;
    if (rule->identifier[0] != id_initial)
    {
      if ((uintptr_t)user_data >= 4)
        fprintf(stderr, "got %s, expected %c\n", rule->identifier, id_initial);
      return CALLBACK_ERROR;
    }
  }
  return CALLBACK_CONTINUE;
}


static int callback_nomatch(int message, void* message_data, void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    fprintf(stderr, "var=%"PRIiPTR", identifier=%s\n", (intptr_t)user_data, ((YR_RULE*)message_data)->identifier);
    return CALLBACK_ERROR;
  }
  return CALLBACK_CONTINUE;
}


// Scan / exercise ruleset using the default external variable set
static void* scan_global(void* data)
{
  assert(yr_rules_define_integer_variable(rules, "var", (intptr_t)data) == 0);

  for (;;)
  {
    if (yr_rules_scan_mem(rules, buf, sizeof(buf), 0, callback, (void*)0, 0) != 0)
    {
      fprintf(stderr, "scan_global: Scan failed\n");
      pthread_exit(NULL);
    }
    sched_yield();
  }
}


// Scan / exercise ruleset using a function-local external variable set
static void* scan_local_fixed(void* data)
{
  uint16_t ctx;
  intptr_t value = (intptr_t) data;
  assert(yr_rules_allocate_local_variable_context(rules, &ctx) == 0);
  printf("scan_local_fixed (var=%"PRIiPTR"): Got ctx = %"PRIu16"\n", value, ctx);
  if (yr_rules_define_local_integer_variable(rules, ctx, "var", value) != 0)
  {
    fprintf(stderr, "scan_local_fixed: Error setting local (var = %"PRIiPTR")\n", value);
    pthread_exit(NULL);
  }

  for (;;)
  {
    if (yr_rules_scan_mem(rules, buf, sizeof(buf), SCAN_EXTERNAL_VAR_CONTEXT(ctx), callback, (void*)value, 0) != 0)
    {
      fprintf(stderr, "scan_local_fixed: Scan failed (var=%"PRIu64")\n", value);
      pthread_exit(NULL);
    }
    sched_yield();
  }
}


// Scan / exercise ruleset using a function-local external variable,
// with "var" set to values that do not match any of the defined rules
// below.
static void* scan_local_random(void* data)
{
  uint16_t ctx;
  assert(yr_rules_allocate_local_variable_context(rules, &ctx) == 0);
  printf("scan_local_random: Got ctx = %"PRIu16"\n", ctx);

  for (;;)
  {
    intptr_t value = (rand() % 1000) + (intptr_t)data + 1;
    if (yr_rules_define_local_integer_variable(rules, ctx, "var", value) != 0)
    {
      fprintf(stderr, "scan_local_random: Error setting local variable\n");
      pthread_exit(NULL);
    }
    if(yr_rules_scan_mem(rules, buf, sizeof(buf), SCAN_EXTERNAL_VAR_CONTEXT(ctx), callback_nomatch, (void*)value, 0) != 0)
    {
      fprintf(stderr, "scan_local_random: Scan matched some rules (but should not: ctx=%d, var=%"PRIxPTR")\n", (int)ctx, value);
      pthread_exit(NULL);
    }
    sched_yield();
  }
}


int main(int argc, char **argv)
{
  memset(buf, 0, sizeof(buf));
  srand(time(NULL));
  yr_initialize();

  YR_COMPILER *compiler;
  assert(yr_compiler_create(&compiler) == 0);
  assert(yr_compiler_define_integer_variable(compiler, "var", 25) == 0);
  assert(yr_compiler_add_string(compiler,
      "rule a { condition: var == 0 }\n"
      "rule b { condition: var == 1 }\n"
      "rule c { condition: var == 2 }\n"
      "rule d { condition: var == 3 }\n"
      "rule z { condition: var == 25 }\n",
      NULL) == 0);
  assert(yr_compiler_get_rules(compiler, &rules) == 0);

  pthread_t threads[7];

  pthread_create(&threads[0], NULL, scan_global, NULL);
  pthread_create(&threads[1], NULL, scan_local_fixed, (void*) 1);
  pthread_create(&threads[2], NULL, scan_local_fixed, (void*) 2);
  pthread_create(&threads[3], NULL, scan_local_fixed, (void*) 3);
  pthread_create(&threads[4], NULL, scan_local_random, (void*) 26);
  pthread_create(&threads[5], NULL, scan_local_random, (void*) 26);
  pthread_create(&threads[6], NULL, scan_local_random, (void*) 26);

  sleep(3);

  int err = 0;
  for (int i=0; i < 7; i++)
  {
    if (pthread_cancel(threads[i]) != 0)
    {
      fprintf(stderr, "thread %d has exited prematurely\n", i);
      err++;
    }
  }

  if (err != 0)
    exit(EXIT_FAILURE);
  else
    exit(EXIT_SUCCESS);
}
