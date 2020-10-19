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
#include <yara/globals.h>

#if _WIN32 || __CYGWIN__

#include <windows.h>

// If compiling with Microsoft's compiler use structered exception handling.

#ifdef _MSC_VER

#include <excpt.h>

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
  switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
  {
  case EXCEPTION_IN_PAGE_ERROR:
  case EXCEPTION_ACCESS_VIOLATION:
    return EXCEPTION_EXECUTE_HANDLER;
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

#define YR_TRYCATCH(_do_, _try_clause_, _catch_clause_)       \
  do                                                          \
  {                                                           \
    if (_do_)                                                 \
    {                                                         \
      __try                                                   \
      {                                                       \
        _try_clause_                                          \
      }                                                       \
      __except (exception_handler(GetExceptionInformation())) \
      {                                                       \
        _catch_clause_                                        \
      }                                                       \
    }                                                         \
    else                                                      \
    {                                                         \
      _try_clause_                                            \
    }                                                         \
  } while (0)

#else

// If not compiling with Microsoft's compiler use vectored exception handling.

#include <setjmp.h>

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
  jmp_buf* jb_ptr;

  switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
  {
  case EXCEPTION_IN_PAGE_ERROR:
  case EXCEPTION_ACCESS_VIOLATION:
    jb_ptr =
        (jmp_buf*) yr_thread_storage_get_value(&yr_trycatch_trampoline_tls);

    if (jb_ptr != NULL)
      longjmp(*jb_ptr, 1);
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

#define YR_TRYCATCH(_do_, _try_clause_, _catch_clause_)               \
  do                                                                  \
  {                                                                   \
    if (_do_)                                                         \
    {                                                                 \
      jmp_buf jb;                                                     \
      /* Store pointer to sigjmp_buf in TLS */                        \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, &jb);  \
      HANDLE exh = AddVectoredExceptionHandler(1, exception_handler); \
      if (setjmp(jb) == 0)                                            \
      {                                                               \
        _try_clause_                                                  \
      }                                                               \
      else                                                            \
      {                                                               \
        _catch_clause_                                                \
      }                                                               \
      RemoveVectoredExceptionHandler(exh);                            \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, NULL); \
    }                                                                 \
    else                                                              \
    {                                                                 \
      _try_clause_                                                    \
    }                                                                 \
  } while (0)

#endif

#else

#include <setjmp.h>
#include <signal.h>
#include <yara/globals.h>

static void exception_handler(int sig)
{
  if (sig == SIGBUS || sig == SIGSEGV)
  {
    jmp_buf* jb_ptr =
        (jmp_buf*) yr_thread_storage_get_value(&yr_trycatch_trampoline_tls);

    if (jb_ptr != NULL)
      siglongjmp(*jb_ptr, 1);
  }
}

typedef struct sigaction sa;

#define YR_TRYCATCH(_do_, _try_clause_, _catch_clause_)               \
  do                                                                  \
  {                                                                   \
    if (_do_)                                                         \
    {                                                                 \
      struct sigaction old_sigbus_act;                                \
      struct sigaction old_sigsegv_act;                               \
      struct sigaction act;                                           \
      sigjmp_buf jb;                                                  \
      /* Store pointer to sigjmp_buf in TLS */                        \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, &jb);  \
      /* Set exception handler for SIGBUS and SIGSEGV*/               \
      act.sa_handler = exception_handler;                             \
      act.sa_flags = 0; /* SA_ONSTACK? */                             \
      sigfillset(&act.sa_mask);                                       \
      sigaction(SIGBUS, &act, &old_sigbus_act);                       \
      sigaction(SIGSEGV, &act, &old_sigsegv_act);                     \
      if (sigsetjmp(jb, 1) == 0)                                      \
      {                                                               \
        _try_clause_                                                  \
      }                                                               \
      else                                                            \
      {                                                               \
        _catch_clause_                                                \
      }                                                               \
      /* Stop capturing SIGBUS and SIGSEGV */                         \
      sigaction(SIGBUS, &old_sigbus_act, NULL);                       \
      sigaction(SIGSEGV, &old_sigsegv_act, NULL);                     \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, NULL); \
    }                                                                 \
    else                                                              \
    {                                                                 \
      _try_clause_                                                    \
    }                                                                 \
  } while (0)

#endif

#endif
