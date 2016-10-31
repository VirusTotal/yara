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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

#include <yara.h>
#include "util.h"

int main(int argc, char **argv)
{
  char* filename = strdup("yara-testblob.XXXXXX");
  int fd = mkstemp(filename);
  char wbuf[4096];
  int i;

  if (fd <= 0)
  {
    perror("Create temp file");
    return 77;
  }

  unlink(filename);

  memset(wbuf, 'a', sizeof(wbuf));

  for (i = 0; i <= 3; i++)
    write(fd, wbuf, sizeof(wbuf));

  uint8_t* mapped_region = mmap(
      NULL, 4 * sizeof(wbuf), PROT_READ, MAP_SHARED, fd, 0);

  ftruncate(fd, 2 * sizeof(wbuf));

  /*
    mapped_region is now only partially backed by the open file
    referred to by fd. Accessing the memory beyond

        mapped_region + 2 * sizeof(wbuf)

    causes SIGBUS to be raised.
  */

  yr_initialize();

  YR_RULES* rules_a = compile_rule(
      "rule test { strings: $a = \"aaaa\" condition: all of them }");

  YR_RULES* rules_0 = compile_rule(
      "rule test { strings: $a = { 00 00 00 00 } condition: all of them }");

  puts("Scanning for \"aaaa\"...");

  int matches = 0;

  /*
    If YR_TRYCATCH is redefined like this

        #define YR_TRYCATCH(_try_clause_,_catch_clause_) {_try_clause_}

    yr_rules_scan_mem() will terminate the process.
  */

  int rc = yr_rules_scan_mem(
      rules_a, mapped_region, 4 * sizeof(wbuf), 0, count_matches, &matches, 0);

  printf("err = %d, matches = %d\n", rc, matches);

  if (rc == ERROR_SUCCESS || matches != 0)
    return 1;

  puts("Sending blocked SIGUSR1 to ourselves...");

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigprocmask(SIG_BLOCK, &set, NULL);
  kill(getpid(), SIGUSR1);

  puts("Scanning for {00 00 00 00}...");
  matches = 0;

  /*
    This tests that SIGUSR1 is not delivered when setting up SIGBUS
    signal handling -- or during SIGBUS signal handling
  */

  rc = yr_rules_scan_mem(
      rules_0, mapped_region, 4 * sizeof(wbuf), 0, count_matches, &matches, 0);

  printf("err = %d, matches = %d\n", rc, matches);

  if (rc == ERROR_SUCCESS || matches != 0)
    return 1;

  return 0;
}
