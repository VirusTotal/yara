/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

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

#ifndef YR_EXCEPTION_H
#define YR_EXCEPTION_H

#include <assert.h>

#if _WIN32 || __CYGWIN__

#include <windows.h>
#include <setjmp.h>

jmp_buf *exc_jmp_buf[YR_MAX_THREADS];

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
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

#ifdef _MSC_VER

#include <excpt.h>

#define YR_TRYCATCH(_do_,_try_clause_,_catch_clause_)           \
  do                                                            \
  {                                                             \
    if (_do_)                                                   \
    {                                                           \
      __try                                                     \
      { _try_clause_ }                                          \
      __except(exception_handler(GetExceptionInformation()))    \
      { _catch_clause_ }                                        \
    }                                                           \
    else                                                        \
    { _try_clause_ }                                            \
  } while(0)

#else

#define YR_TRYCATCH(_do_,_try_clause_,_catch_clause_)                   \
  do                                                                    \
  {                                                                     \
    if (_do_)                                                           \
    {                                                                   \
      jmp_buf jb;                                                       \
      HANDLE exh = AddVectoredExceptionHandler(1, exception_handler);   \
      int tidx = yr_get_tidx();                                         \
      assert(tidx != -1);                                               \
      exc_jmp_buf[tidx] = &jb;                                          \
      if (setjmp(jb) == 0)                                              \
        { _try_clause_ }                                                \
      else                                                              \
        { _catch_clause_ }                                              \
      exc_jmp_buf[tidx] = NULL;                                         \
      RemoveVectoredExceptionHandler(exh);                              \
    }                                                                   \
    else                                                                \
    {                                                                   \
      _try_clause_                                                      \
    }                                                                   \
  } while(0)

#endif

#else

#include <setjmp.h>
#include <signal.h>

sigjmp_buf *exc_jmp_buf[YR_MAX_THREADS];

static void exception_handler(int sig) {
  if (sig == SIGBUS || sig == SIGSEGV)
  {
    int tidx = yr_get_tidx();

    if (tidx != -1 && exc_jmp_buf[tidx] != NULL)
      siglongjmp(*exc_jmp_buf[tidx], 1); 
  }
}

typedef struct sigaction sa;

#define YR_TRYCATCH(_do_,_try_clause_, _catch_clause_)          \
  do                                                            \
  {                                                             \
    if (_do_)                                                   \
    {                                                           \
      struct sigaction old_sigbus_act;                          \
      struct sigaction old_sigsegv_act;                         \
      struct sigaction act;                                     \
      act.sa_handler = exception_handler;                       \
      act.sa_flags = 0; /* SA_ONSTACK? */                       \
      sigfillset(&act.sa_mask);                                 \
      sigaction(SIGBUS, &act, &old_sigbus_act);                 \
      sigaction(SIGSEGV, &act, &old_sigsegv_act);               \
      int tidx = yr_get_tidx();                                 \
      assert(tidx != -1);                                       \
      sigjmp_buf jb;                                            \
      exc_jmp_buf[tidx] = &jb;                                  \
      if (sigsetjmp(jb, 1) == 0)                                \
        { _try_clause_ }                                        \
      else                                                      \
        { _catch_clause_ }                                      \
      exc_jmp_buf[tidx] = NULL;                                 \
      sigaction(SIGBUS, &old_sigbus_act, NULL);                 \
      sigaction(SIGSEGV, &old_sigsegv_act, NULL);               \
    }                                                           \
    else                                                        \
    {                                                           \
      _try_clause_                                              \
    }                                                           \
  } while (0)

#endif

#endif
