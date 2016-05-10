/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

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

#ifndef YR_EXCEPTION_H
#define YR_EXCEPTION_H

#include <assert.h>

#if _WIN32 || __CYGWIN__

#include <windows.h>
#include <setjmp.h>

jmp_buf *exc_jmp_buf[MAX_THREADS];

static LONG CALLBACK exception_handler(
    PEXCEPTION_POINTERS ExceptionInfo)
{
  int tidx = yr_get_tidx();

  switch(ExceptionInfo->ExceptionRecord->ExceptionCode)
  {
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_ACCESS_VIOLATION:
      if (tidx != -1 && exc_jmp_buf[tidx] != NULL)
        longjmp(*exc_jmp_buf[tidx], 1);

      assert(FALSE);  // We should not reach this point.
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

#define YR_TRYCATCH(_try_clause_, _catch_clause_)                       \
  do                                                                    \
  {                                                                     \
    jmp_buf jb;                                                         \
    HANDLE exh = AddVectoredExceptionHandler(1, exception_handler);     \
    int tidx = yr_get_tidx();                                           \
    assert(tidx != -1);                                                 \
    exc_jmp_buf[tidx] = &jb;                                            \
    if (setjmp(jb) == 0)                                                \
      { _try_clause_ }                                                  \
    else                                                                \
      { _catch_clause_ }                                                \
    exc_jmp_buf[tidx] = NULL;                                           \
    RemoveVectoredExceptionHandler(exh);                                \
  } while(0)

#else

#include <setjmp.h>
#include <signal.h>

sigjmp_buf *exc_jmp_buf[MAX_THREADS];

static void exception_handler(int sig) {
  if (sig == SIGBUS)
  {
    int tidx = yr_get_tidx();

    if (tidx != -1 && exc_jmp_buf[tidx] != NULL)
      siglongjmp(*exc_jmp_buf[tidx], 1);

    assert(FALSE);  // We should not reach this point.
  }
}

typedef struct sigaction sa;

#define YR_TRYCATCH(_try_clause_, _catch_clause_)               \
  do                                                            \
  {                                                             \
    struct sigaction oldact;                                    \
    struct sigaction act;                                       \
    sigset_t oldmask;                                           \
    act.sa_handler = exception_handler;                         \
    act.sa_flags = 0; /* SA_ONSTACK? */                         \
    sigemptyset(&oldmask);                                      \
    sigemptyset(&act.sa_mask);                                  \
    pthread_sigmask(SIG_SETMASK, &act.sa_mask, &oldmask);       \
    sigaction(SIGBUS, &act, &oldact);                           \
    int tidx = yr_get_tidx();                                   \
    assert(tidx != -1);                                         \
    sigjmp_buf jb;                                              \
    exc_jmp_buf[tidx] = &jb;                                    \
    if (sigsetjmp(jb, 1) == 0)                                  \
      { _try_clause_ }                                          \
    else                                                        \
      { _catch_clause_ }                                        \
    exc_jmp_buf[tidx] = NULL;                                   \
    sigaction(SIGBUS, &oldact, NULL);                           \
    pthread_sigmask(SIG_SETMASK, &oldmask, NULL);               \
  } while (0)

#endif

#endif
