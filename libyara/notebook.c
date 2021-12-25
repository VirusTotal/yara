/*
Copyright (c) 2020. The YARA Authors. All Rights Reserved.

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

#include <assert.h>
#include <stdint.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/notebook.h>

// Forward declaration of YR_NOTEBOOK_PAGE.
typedef struct YR_NOTEBOOK_PAGE YR_NOTEBOOK_PAGE;

// A notebook is a data structure that can be used for allocating memory
// space in the same way malloc() would do. However, the buffers returned
// by yr_notebook_alloc() are backed by a larger buffer reserved by the notebook
// beforehand called a "page". The notebook fulfills the allocations performed
// via yr_notebook_alloc() with space taken from the current page, or creates
// a new page when necessary. It's recommended that the page size is at least
// 4x the size of the buffers you plan to allocate with yr_notebook_alloc().
//
// Once the notebook is destroyed all the pages are freed, and consequently
// all the buffers allocated via yr_notebook_alloc().
struct YR_NOTEBOOK
{
  // Size of each page in the notebook.
  size_t page_size;
  // Pointer to the first page in the book, this is also the most recently
  // created page, the one that is being filled.
  YR_NOTEBOOK_PAGE* page_list_head;
};

struct YR_NOTEBOOK_PAGE
{
  // Amount of bytes in the page that are actually used.
  size_t used;
  // Pointer to next page.
  YR_NOTEBOOK_PAGE* next;
  // Page's data.
  uint8_t data[0];
};

////////////////////////////////////////////////////////////////////////////////
// Creates a new notebook. The notebook initially has a single page of the
// specified size, but more pages are created if needed.
//
// Args:
//   page_size: Size of each page in the notebook.
//   notebook: Address of a pointer to the newly created notebook.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_notebook_create(size_t page_size, YR_NOTEBOOK** notebook)
{
  YR_NOTEBOOK* new_notebook = yr_malloc(sizeof(YR_NOTEBOOK));

  if (new_notebook == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  new_notebook->page_list_head = yr_malloc(
      sizeof(YR_NOTEBOOK_PAGE) + page_size);

  if (new_notebook->page_list_head == NULL)
  {
    yr_free(new_notebook);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  new_notebook->page_size = page_size;
  new_notebook->page_list_head->used = 0;
  new_notebook->page_list_head->next = NULL;

  *notebook = new_notebook;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys a notebook and frees all the notebook's pages.
//
// Args:
//   notebook: Pointer to the notebook being destroyed.
//
// Returns:
//   ERROR_SUCCESS
//
int yr_notebook_destroy(YR_NOTEBOOK* notebook)
{
  YR_NOTEBOOK_PAGE* page = notebook->page_list_head;

  while (page != NULL)
  {
    YR_NOTEBOOK_PAGE* next = page->next;
    yr_free(page);
    page = next;
  }

  yr_free(notebook);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Allocates a memory buffer from a notebook. The memory is freed when the
// notebook is destroyed, allocated buffers can't be freed individually.
//
// Args:
//   notebook: Pointer to the notebook.
//   size: Size of the allocated memory.
//
// Returns:
//   Pointer to the allocated memory, or NULL if the allocation fails.
//
void* yr_notebook_alloc(YR_NOTEBOOK* notebook, size_t size)
{
  // The requested memory size can't be larger than a notebook's page.
  assert(size <= notebook->page_size);

  // If the requested size doesn't fit in current page's free space, allocate
  // a new page.
  if (notebook->page_size - notebook->page_list_head->used < size)
  {
    YR_NOTEBOOK_PAGE* new_page = yr_malloc(
        sizeof(YR_NOTEBOOK_PAGE) + notebook->page_size);

    if (new_page == NULL)
      return NULL;

    new_page->used = 0;
    new_page->next = notebook->page_list_head;
    notebook->page_list_head = new_page;
  }

  void* ptr = notebook->page_list_head->data + notebook->page_list_head->used;

// In ARM make sure the alignment of the returned buffer is 4 bytes.
#if defined(__arm__)
  uintptr_t misalignment = (uintptr_t) ptr & 3;

  if (misalignment)
  {
    size += 4 - misalignment;
    ptr += 4 - misalignment;
  }
#endif

  notebook->page_list_head->used += size;

  return ptr;
}
