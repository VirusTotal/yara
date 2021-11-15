

#include <yara/stdinc.h>
#include <yara/mem.h>
#include <yara/threading.h>
#include <yara/stopwatch.h>
#include <yara/error.h>

HANDLE hHeap;

int yr_heap_alloc(void)
{
  hHeap = HeapCreate(0, 0x8000, 0);

  if (hHeap == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}

int yr_heap_free(void)
{
  if (HeapDestroy(hHeap))
    return ERROR_SUCCESS;
  else
    return ERROR_INTERNAL_FATAL_ERROR;
}

void* yr_calloc(size_t count, size_t size)
{
  return (void*) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, count * size);
}

void* yr_malloc(size_t size)
{
  return (void*) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
}

void* yr_realloc(void* ptr, size_t size)
{
  if (ptr == NULL)
    return (void*) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);

  return (void*) HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, ptr, size);
}

YR_API void yr_free(void* ptr)
{
  HeapFree(hHeap, 0, ptr);
}


int yr_thread_storage_create(YR_THREAD_STORAGE_KEY* storage)
{
  *storage = TlsAlloc();

  if (*storage == TLS_OUT_OF_INDEXES)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_destroy(YR_THREAD_STORAGE_KEY* storage)
{
  if (TlsFree(*storage) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


int yr_thread_storage_set_value(YR_THREAD_STORAGE_KEY* storage, void* value)
{
  if (TlsSetValue(*storage, value) == FALSE)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}


void* yr_thread_storage_get_value(YR_THREAD_STORAGE_KEY* storage)
{
  return TlsGetValue(*storage);
}

void yr_stopwatch_start(YR_STOPWATCH* sw)
{
  QueryPerformanceFrequency(&sw->frequency);
  QueryPerformanceCounter(&sw->start);
}


uint64_t yr_stopwatch_elapsed_ns(YR_STOPWATCH* sw)
{
  LARGE_INTEGER li;

  QueryPerformanceCounter(&li);

  return (li.QuadPart - sw->start.QuadPart) * 1000000000ULL /
         sw->frequency.QuadPart;
}
