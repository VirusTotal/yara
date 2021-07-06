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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yara.h>

#include "util.h"

#define COUNT 128
char wbuf[1024];

extern char** environ;

int fd;
uint8_t* mapped_region;
YR_RULES *rules_a, *rules_0;

/*
Set up mapped_region so that it is only partially backed by the open
file referred to by fd. Accessing the memory beyond

    mapped_region + COUNT * sizeof(wbuf) / 2

should cause a signal (usually SIGBUS) to be raised.
*/
void setup_mmap()
{
  char* filename = strdup("yara-testblob.XXXXXX");
  fd = mkstemp(filename);

  if (fd <= 0)
  {
    perror("Create temp file");
    exit(77);
  }

  unlink(filename);

  memset(wbuf, 'a', sizeof(wbuf));

  for (int i = 0; i < COUNT; i++)
  {
    if (write(fd, wbuf, sizeof(wbuf)) != sizeof(wbuf))
      exit(EXIT_FAILURE);
  }

  mapped_region = mmap(
      NULL, COUNT * sizeof(wbuf), PROT_READ, MAP_SHARED, fd, 0);

  if (ftruncate(fd, COUNT * sizeof(wbuf) / 2) != 0)
    exit(EXIT_FAILURE);
}

void setup_rules()
{
  yr_initialize();

  compile_rule(
      "rule test { strings: $a = \"aaaa\" condition: all of them }", &rules_a);

  compile_rule(
      "rule test { strings: $a = { 00 00 00 00 } condition: all of them }",
      &rules_0);
}

void* crasher_func(void* x)
{
  sleep(1);
  int* i = 0;
  fputs("crashing process...\n", stderr);
  *i = 0;
  return NULL;
}

/* Set up a thread that will cause a null pointer dereference after one second
 */
void setup_crasher()
{
  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_create(&t, &attr, &crasher_func, NULL);
}

/* Simple yr_scan_* callback function that delays execution by 2 seconds */
int delay_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    (*(int*) user_data)++;
  }
  fputs("callback: delaying execution...\n", stderr);
  sleep(2);
  return CALLBACK_CONTINUE;
}

/* Scan a partially backed memory map, raising an exceptions, usually SIGBUS or
 * SIGSEGV. */
int test_crash(int handle_exceptions)
{
  setup_mmap();
  setup_rules();

  fputs("Scanning for \"aaaa\"...\n", stderr);

  struct COUNTERS counters;

  counters.rules_not_matching = 0;
  counters.rules_matching = 0;

  int flags = (handle_exceptions ? 0 : SCAN_FLAGS_NO_TRYCATCH);

  int rc = yr_rules_scan_mem(
      rules_a, mapped_region, COUNT * sizeof(wbuf), flags, count, &counters, 0);

  printf("err = %d, matches = %d\n", rc, counters.rules_matching);

  if (rc == ERROR_SUCCESS || counters.rules_matching != 0)
    return 1;

  return 0;
}

/*
Scan memory while another thread accesses invalid memory. The signal
for that invalid memory access should not be caught by the handler set
up using YR_TRYCATCH.
*/
int test_crash_other_thread()
{
  setup_mmap();
  setup_rules();
  setup_crasher();

  uint8_t mem[4096];
  memset(mem, 'a', sizeof(mem));

  fputs("Scanning for \"aaaa\"...\n", stderr);
  int matches = 0;

  int rc = yr_rules_scan_mem(
      rules_a, mem, sizeof(mem), 0, delay_callback, &matches, 0);

  printf("err = %d, matches = %d\n", rc, matches);

  if (rc == ERROR_SUCCESS || matches != 0)
    return 1;

  return 0;
}

/*
  This tests that SIGUSR1 is not delivered when setting up SIGBUS
  signal handling -- or during SIGBUS signal handling
*/
int test_blocked_signal()
{
  setup_mmap();
  setup_rules();

  fputs("Sending blocked SIGUSR1 to ourselves...\n", stderr);

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigprocmask(SIG_BLOCK, &set, NULL);
  kill(getpid(), SIGUSR1);

  fputs("Scanning for {00 00 00 00}...\n", stderr);

  struct COUNTERS counters;

  counters.rules_not_matching = 0;
  counters.rules_matching = 0;

  int rc = yr_rules_scan_mem(
      rules_0, mapped_region, COUNT * sizeof(wbuf), 0, count, &counters, 0);

  printf("err = %d, matches = %d\n", rc, counters.rules_matching);

  if (rc == ERROR_SUCCESS || counters.rules_matching != 0)
    return 1;

  return 0;
}

int reexec(char* program)
{
  char* argv[] = {program, NULL};
  int status;
  int pid = fork();
  switch (pid)
  {
  case 0:
    return execve(program, argv, environ);
  case -1:
    return -1;
  }
  waitpid(pid, &status, 0);
  return status;
}

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  char* op = getenv("TEST_OP");
  if (op == NULL)
  {
    int status;
    fputs("Test: crash\n", stderr);
    setenv("TEST_OP", "CRASH", 1);
    status = reexec(argv[0]);
    if (status != 0)
    {
      result = 1;
      goto _exit;
    }

    fputs("Test: crash-no-handle\n", stderr);
    setenv("TEST_OP", "CRASH-NO-HANDLE", 1);
    status = reexec(argv[0]);
    if (!WIFSIGNALED(status))
    {
      fputs("Expected subprocess to be terminated by signal\n", stderr);
      result = 1;
      goto _exit;
    }

    fputs("Test: blocked-signal\n", stderr);
    setenv("TEST_OP", "BLOCKED-SIGNAL", 1);
    status = reexec(argv[0]);
    if (status != 0)
    {
      result = 1;
      goto _exit;
    }

    fputs("Test: crash-other-thread\n", stderr);
    setenv("TEST_OP", "CRASH-OTHER-THREAD", 1);
    status = reexec(argv[0]);
    if (!WIFSIGNALED(status))
    {
      fputs("Expected subprocess to be terminated by signal\n", stderr);
      result = 1;
      goto _exit;
    }

    fputs("Done.\n", stderr);
  }
  else if (!strcmp(op, "CRASH"))
  {
    result = test_crash(1);
    goto _exit;
  }
  else if (!strcmp(op, "CRASH-NO-HANDLE"))
  {
    result = test_crash(0);
    goto _exit;
  }
  else if (!strcmp(op, "BLOCKED-SIGNAL"))
  {
    result = test_blocked_signal();
    goto _exit;
  }
  else if (!strcmp(op, "CRASH-OTHER-THREAD"))
  {
    result = test_crash_other_thread();
    goto _exit;
  }
  else
  {
    fprintf(stderr, "wrong op '%s'\n", op);
    result = 77;
    goto _exit;
  }

_exit:

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
