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

#include <yara.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

void compile_callback(int error_level,
                      const char* file_name,
                      int line_number,
                      const char* message,
                      void* user_data) {
  printf("compile: %s:%d: %s\n", file_name, line_number, message);
}

int scan_callback(int message, void* message_data, void* user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    (*((int*)user_data))++;
  }
  return CALLBACK_CONTINUE;
}

int test_rule(char* rulefile, char* positive, char* negative) {
  YR_COMPILER *c;
  printf("Compiling %s ...\n", rulefile);
  FILE* f = fopen(rulefile, "r");
  if (f == NULL) {
    printf("fopen: %s: %s\n", rulefile, strerror(errno));
    return -1;
  }
  yr_compiler_create(&c);
  yr_compiler_set_callback(c, compile_callback, NULL);
  int error = -1;
  if (yr_compiler_add_file(c, f, NULL, rulefile) != 0) {
    printf("compile failed\n");
    goto out1;
  }
  YR_RULES *r;
  if (yr_compiler_get_rules(c, &r) != 0) {
    printf("yr_compiler_get_rules failed\n");
    goto out1;
  }
  int nmatches = 0;
  if (yr_rules_scan_mem(r, (unsigned char*)positive, strlen(positive), 0,
                        scan_callback, &nmatches, 0) == ERROR_SUCCESS) {
    if (nmatches == 0) {
      printf("Error: did not match <%s>\n", positive);
      goto out2;
    }
    printf("Ok: matched <%s>\n", positive);

  } else {
    printf("yr_rules_scan_mem: error\n");
    goto out2;
  }
  nmatches = 0;
  if (yr_rules_scan_mem(r, (unsigned char*)negative, strlen(negative), 0,
                        scan_callback, &nmatches, 0) == ERROR_SUCCESS) {
    if (nmatches > 0) {
      printf("Error: matched <%s>\n", negative);
      goto out2;
    }
    printf("Ok: did not match <%s>\n", negative);
  } else {
    printf("yr_rules_scan_mem: error\n");
    goto out2;
  }

  error = 0;
 out2:
  yr_rules_destroy(r);
 out1:
  fclose(f);
  yr_compiler_destroy(c);
  return error;
}

int main (int argc, char **argv) {
  yr_initialize();
  int error = 0;

  error += test_rule("tests/regular-string.yar", "1234", "3412");
  error += test_rule("tests/split-string1.yar", "1234", "3412");
  error += test_rule("tests/split-string2.yar", "ABCD", "CDAB");
  error += test_rule("tests/split-string3.yar", "abcd", "cdab");
  error += test_rule("tests/regular-hex.yar", "1234", "3412");
  error += test_rule("tests/split-hex1.yar", "1234", "3412");
  error += test_rule("tests/split-hex2.yar", "ABCD", "CDAB");
  error += test_rule("tests/split-hex3.yar", "abcd", "cdab");

  if (error != 0) {
    return 1;
  }
}
