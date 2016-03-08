/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>
#include <unistd.h>

#include <yara.h>


YR_RULES* compile_rule(
    char* string)
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    goto _exit;
  }

  if (yr_compiler_add_string(compiler, string, NULL) != 0)
  {
    goto _exit;
  }

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    goto _exit;
  }

 _exit:
  yr_compiler_destroy(compiler);
  return rules;
}


static int count_matches(
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    (*(int*) user_data)++;
  }

  return CALLBACK_CONTINUE;
}


int matches_blob(
    char* rule,
    uint8_t* blob,
    size_t len)
{
  if (blob == NULL)
  {
    blob = (uint8_t*) "dummy";
    len = 5;
  }

  YR_RULES* rules = compile_rule(rule);

  if (rules == NULL)
  {
    fprintf(stderr, "failed to compile rule << %s >>\n", rule);
    exit(EXIT_FAILURE);
  }

  int matches = 0;
  int scan_result = yr_rules_scan_mem(
      rules, blob, len, 0, count_matches, &matches, 0);

  if (scan_result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error\n");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  return matches;
}


int matches_string(
    char* rule,
    char* string)
{
  size_t len = 0;

  if (string != NULL)
    len = strlen(string);

  return matches_blob(rule, (uint8_t*)string, len);
}

typedef struct
{
  char* expected;
  int found;

} find_string_t;


static int capture_matches(
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    find_string_t* f = (find_string_t*) user_data;

    YR_RULE* rule = (YR_RULE*) message_data;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string)
    {
      YR_MATCH* match;

      yr_string_matches_foreach(string, match)
      {
        if (strncmp(f->expected, (char*)(match->data), match->length) == 0)
          f->found++;
      }
    }
  }

  return CALLBACK_CONTINUE;
}


int capture_string(
    char* rule,
    char* string,
    char* expected_string)
{
  YR_RULES* rules = compile_rule(rule);

  if (rules == NULL)
  {
    fprintf(stderr, "failed to compile rule << %s >>\n", rule);
    exit(EXIT_FAILURE);
  }

  find_string_t f;

  f.found = 0;
  f.expected = expected_string;

  if (yr_rules_scan_mem(rules, (uint8_t*)string, strlen(string), 0,
                        capture_matches, &f, 0) != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_mem: error\n");
    exit(EXIT_FAILURE);
  }

  return f.found;
}
