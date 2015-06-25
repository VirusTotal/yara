#ifndef _EXCEPTION_H_
#define _EXCEPTION_H_

#if _WIN32

#include <windows.h>
#include <setjmp.h>

#define YR_EXCEPT(_try_clause_, _catch_clause_) \
  _try_clause_

jmp_buf *exc_jmp_buf[MAX_THREADS];

static LONG CALLBACK exception_handler(
    PEXCEPTION_POINTERS ExceptionInfo)
{
  switch(ExceptionInfo->ExceptionRecord->ExceptionCode) {
  case EXCEPTION_IN_PAGE_ERROR:
  case EXCEPTION_ACCESS_VIOLATION:
    break;
  default:
    return EXCEPTION_CONTINUE_SEARCH;
  }
  int tidx = yr_get_tidx();
  if (tidx != -1 && exc_jmp_buf[tidx] != NULL) {
    longjmp(*exc_jmp_buf[tidx], 1);
  }
  /* We should not reach this point. */
  abort();
}

#define YR_TRYCATCH(_try_clause_,_catch_clause_)                        \
  do {                                                                  \
    HANDLE exh = AddVectoredExceptionHandler(1, exception_handler);     \
    int tidx = yr_get_tidx();                                           \
    if (tidx == -1) {                                                   \
      abort();                                                          \
    }                                                                   \
    jmp_buf jb;                                                         \
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
  if (sig == SIGBUS) {
    int tidx = yr_get_tidx();
    if (tidx != -1 && exc_jmp_buf[tidx] != NULL) {
      siglongjmp(*exc_jmp_buf[tidx], 1);
    }
    /* We should not reach this point. */
    abort();
  }
}

typedef struct sigaction sa;

#define YR_TRYCATCH(_try_clause_,_catch_clause_)                \
  do {                                                          \
    struct sigaction oldact;                                    \
    struct sigaction act;                                       \
    sigset_t oldmask;                                           \
    act.sa_handler = exception_handler;                         \
    act.sa_flags = 0; /* SA_ONSTACK? */                         \
    sigemptyset(&act.sa_mask);                                  \
    pthread_sigmask(SIG_SETMASK, &act.sa_mask, &oldmask);       \
    sigaction(SIGBUS, &act, &oldact);                           \
    int tidx = yr_get_tidx();                                   \
    if (tidx == -1) {                                           \
      abort();                                                  \
    }                                                           \
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

#endif /* _EXCEPTION_H_ */
