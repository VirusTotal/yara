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
  // The mininum size of each page in the notebook.
  size_t min_page_size;
  // Pointer to the first page in the book, this is also the most recently
  // created page, the one that is being filled.
  YR_NOTEBOOK_PAGE* page_list_head;
};

struct YR_NOTEBOOK_PAGE
{
  // Size of this page.
  size_t size;
  // Amount of bytes in the page that are actually used.
  size_t used;
  // Pointer to next page.
  YR_NOTEBOOK_PAGE* next;
  // Page's data.
  //
  // This field must be 8-byte aligned to guarantee that all notebooks
  // allocations are 8-byte aligned.
  YR_ALIGN(8) uint8_t data[0];
};

////////////////////////////////////////////////////////////////////////////////
// Creates a new notebook. The notebook initially has a single page of size
// min_page_size, but more pages will be created as needed.
//
// Args:
//   min_page_size: The minimum size of each page in the notebook.
//   notebook: Address of a pointer to the newly created notebook.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_notebook_create(size_t min_page_size, YR_NOTEBOOK** notebook)
{
  YR_NOTEBOOK* new_notebook = yr_malloc(sizeof(YR_NOTEBOOK));

  if (new_notebook == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  new_notebook->page_list_head = yr_malloc(
      sizeof(YR_NOTEBOOK_PAGE) + min_page_size);

  if (new_notebook->page_list_head == NULL)
  {
    yr_free(new_notebook);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  new_notebook->min_page_size = min_page_size;
  new_notebook->page_list_head->size = min_page_size;
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
// notebook is destroyed, allocated buffers can't be freed individually. The
// returned buffer is guaranteed to be aligned to an 8-byte boundary.
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
  // Round up the size to a multiple of 8, which also implies that the returned
  // pointers are aligned to 8 bytes. The 8-byte alignment is required by some
  // platforms (e.g. ARM and Sparc) that have strict alignment requirements when
  // deferrencing pointers to types larger than a byte.
  size = (size + 7) & ~0x7;

  YR_NOTEBOOK_PAGE* current_page = notebook->page_list_head;

  // If the requested size doesn't fit in current page's free space, allocate
  // a new page.
  if (current_page->size - current_page->used < size)
  {
    size_t min_size = notebook->min_page_size;

    // The new page must be able to fit the requested buffer, so find the
    // multiple of notebook->min_page_size that is larger or equal than than
    // size.
    size_t page_size = (size / min_size) * min_size + min_size;

    YR_NOTEBOOK_PAGE* new_page = yr_malloc(
        sizeof(YR_NOTEBOOK_PAGE) + page_size);

    if (new_page == NULL)
      return NULL;

    new_page->size = page_size;
    new_page->used = 0;
    new_page->next = notebook->page_list_head;
    notebook->page_list_head = new_page;
  }

  void* ptr = notebook->page_list_head->data + notebook->page_list_head->used;

  notebook->page_list_head->used += size;

  return ptr;
}
