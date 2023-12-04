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

// If compiling with Microsoft's compiler use structured exception handling.

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

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <yara/globals.h>

static void exception_handler(int sig, siginfo_t * info, void *context)
{
  if (sig == SIGBUS || sig == SIGSEGV)
  {
    jmp_buf* jb_ptr =
        (jmp_buf*) yr_thread_storage_get_value(&yr_trycatch_trampoline_tls);

    if (jb_ptr != NULL)
    {
      siglongjmp(*jb_ptr, 1);
      // The long jump means the following code to invoke the old exception handler is never executed
    }

    // If we're here, the signal we received didn't originate from YARA.
    // In this case, we want to invoke the original signal handler, which may handle the signal.

    // Lock the exception handler mutex to prevent simultaneous write access while we read the old signal handler
    pthread_mutex_lock(&exception_handler_mutex);
    struct sigaction old_handler;
    if (sig == SIGBUS)
      old_handler = old_sigbus_exception_handler;
    else
      old_handler = old_sigsegv_exception_handler;
    pthread_mutex_unlock(&exception_handler_mutex);

    if (old_handler.sa_flags & SA_SIGINFO)
    {
      old_handler.sa_sigaction(sig, info, context);
    }
    else
    {
      if (old_handler.sa_handler == SIG_DFL)
      {
        // Old handler is the default action. To do this, set the signal handler back to default and raise the signal.
        // This is fairly volatile - since this is not an atomic operation, signals from other threads might also
        // cause the default action while we're doing this. However, the default action will typically cause a
        // process termination anyway.
        pthread_mutex_lock(&exception_handler_mutex);
        struct sigaction current_handler;
        sigaction(sig, &old_handler, &current_handler);
        raise(sig);
        sigaction(sig, &current_handler, NULL);
        pthread_mutex_unlock(&exception_handler_mutex);
      }
      else if (old_handler.sa_handler == SIG_IGN)
      {
        // SIG_IGN wants us to ignore the signal
        return;
      }
      old_handler.sa_handler(sig);
    }
  }
}

typedef struct sigaction sa;

#define YR_TRYCATCH(_do_, _try_clause_, _catch_clause_)               \
  do                                                                  \
  {                                                                   \
    if (_do_)                                                         \
    {                                                                 \
      pthread_mutex_lock(&exception_handler_mutex);                   \
      if (exception_handler_usecount == 0)                            \
      {                                                               \
        struct sigaction act;                                         \
        /* Set exception handler for SIGSEGV / SIGBUS */              \
        act.sa_sigaction = exception_handler;                         \
        act.sa_flags = SA_SIGINFO | SA_ONSTACK;                       \
        sigfillset(&act.sa_mask);                                     \
        sigaction(SIGBUS, &act, &old_sigbus_exception_handler);       \
        sigaction(SIGSEGV, &act, &old_sigsegv_exception_handler);     \
      }                                                               \
      exception_handler_usecount++;                                   \
      pthread_mutex_unlock(&exception_handler_mutex);                 \
      sigjmp_buf jb;                                                  \
      /* Store pointer to sigjmp_buf in TLS */                        \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, &jb);  \
      if (sigsetjmp(jb, 1) == 0)                                      \
      {                                                               \
        _try_clause_                                                  \
      }                                                               \
      else                                                            \
      {                                                               \
        _catch_clause_                                                \
      }                                                               \
      pthread_mutex_lock(&exception_handler_mutex);                   \
      exception_handler_usecount--;                                   \
      if (exception_handler_usecount == 0)                            \
      {                                                               \
        /* Stop capturing SIGBUS and SIGSEGV */                       \
        sigaction(SIGBUS, &old_sigbus_exception_handler, NULL);       \
        sigaction(SIGSEGV, &old_sigsegv_exception_handler, NULL);     \
      }                                                               \
      pthread_mutex_unlock(&exception_handler_mutex);                 \
      yr_thread_storage_set_value(&yr_trycatch_trampoline_tls, NULL); \
    }                                                                 \
    else                                                              \
    {                                                                 \
      _try_clause_                                                    \
    }                                                                 \
  } while (0)

#endif

#endif
