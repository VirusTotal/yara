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

#include <stdarg.h>
#include <stddef.h>
#include <yara/arena.h>
#include <yara/error.h>
#include <yara/mem.h>

typedef struct YR_ARENA_FILE_HEADER YR_ARENA_FILE_HEADER;
typedef struct YR_ARENA_FILE_BUFFER YR_ARENA_FILE_BUFFER;

#pragma pack(push)
#pragma pack(1)

struct YR_ARENA_FILE_HEADER
{
  uint8_t magic[4];
  uint8_t version;
  uint8_t num_buffers;
};

struct YR_ARENA_FILE_BUFFER
{
  uint64_t offset;
  uint32_t size;
};

#pragma pack(pop)

////////////////////////////////////////////////////////////////////////////////
// Tells the arena that certain offsets within a buffer contain relocatable
// pointers. The offsets are passed as a vararg list where the end of the
// list is indicated by the special value EOL (-1), offsets in the list are
// relative to base_offset, which in turns is relative to the beginning of the
// buffer.
//
// Args:
//   arena: Pointer the arena.
//   buffer_id: Buffer number.
//   base_offset: Base offset.
//   offsets: List of offsets relative to base offset.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
static int _yr_arena_make_ptr_relocatable(
    YR_ARENA* arena,
    uint32_t buffer_id,
    yr_arena_off_t base_offset,
    va_list offsets)
{
  size_t offset;

  int result = ERROR_SUCCESS;

  // The argument to va_arg is size_t because the offsets passed to this
  // function are obtained with offsetof().
  offset = va_arg(offsets, size_t);

  while (offset != EOL)
  {
    YR_RELOC* reloc = (YR_RELOC*) yr_malloc(sizeof(YR_RELOC));

    if (reloc == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    reloc->buffer_id = buffer_id;
    reloc->offset = base_offset + (yr_arena_off_t) offset;
    reloc->next = NULL;

    if (arena->reloc_list_head == NULL)
      arena->reloc_list_head = reloc;

    if (arena->reloc_list_tail != NULL)
      arena->reloc_list_tail->next = reloc;

    arena->reloc_list_tail = reloc;
    offset = va_arg(offsets, size_t);
  }

  return result;
}

// Flags for _yr_arena_allocate_memory.
#define YR_ARENA_ZERO_MEMORY 1

////////////////////////////////////////////////////////////////////////////////
// Allocates memory in a buffer within the arena.
//
// Args:
//   arena: Pointer to the arena.
//   flags: Flags. The only supported flag so far is YR_ARENA_ZERO_MEMORY.
//   buffer_id: Buffer number.
//   size : Size of the region to be allocated.
//   [out] ref: Pointer to a YR_ARENA_REF that will be updated with the
//              reference to the newly allocated region. The pointer can be
//              NULL.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_INSUFFICIENT_MEMORY
//
static int _yr_arena_allocate_memory(
    YR_ARENA* arena,
    int flags,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref)
{
  if (buffer_id > arena->num_buffers)
    return ERROR_INVALID_ARGUMENT;

  YR_ARENA_BUFFER* b = &arena->buffers[buffer_id];

  // If the new data doesn't fit in the remaining space the buffer must be
  // re-sized. This implies moving the buffer to a different memory location
  // and adjusting the pointers listed in the relocation list.

  if (b->size - b->used < size)
  {
    size_t new_size = (b->size == 0) ? arena->initial_buffer_size : b->size * 2;

    while (new_size < b->used + size) new_size *= 2;

    // Make sure that buffer size if not larger than 4GB.
    if (new_size > 1ULL << 32)
      return ERROR_INSUFFICIENT_MEMORY;

    uint8_t* new_data = yr_realloc(b->data, new_size);

    if (new_data == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

// When yr_realloc uses the Windows API (HeapAlloc, HeapReAlloc) it is not
// necessary to set the memory to zero because the API is called with the
// HEAP_ZERO_MEMORY flag.
#if !defined(_WIN32) && !defined(__CYGWIN__)
    if (flags & YR_ARENA_ZERO_MEMORY)
      memset(new_data + b->used, 0, new_size - b->used);
#endif

    YR_RELOC* reloc = arena->reloc_list_head;

    while (reloc != NULL)
    {
      // If the reloc entry is for the same buffer that is being relocated,
      // the base pointer that we use to access the buffer must be new_data
      // as arena->buffers[reloc->buffer_id].data (which is the same than
      // b->data) can't be accessed anymore after the call to yr_realloc.
      uint8_t* base = buffer_id == reloc->buffer_id
                          ? new_data
                          : arena->buffers[reloc->buffer_id].data;

      // reloc_address holds the address inside the buffer where the pointer
      // to be relocated resides.
      void** reloc_address = (void**) (base + reloc->offset);

      // reloc_target is the value of the relocatable pointer.
      void* reloc_target = *reloc_address;

      if ((uint8_t*) reloc_target >= b->data &&
          (uint8_t*) reloc_target < b->data + b->used)
      {
        // reloc_target points to some data inside the buffer being moved, so
        // the pointer needs to be adjusted.
        *reloc_address = (uint8_t*) reloc_target - b->data + new_data;
      }

      reloc = reloc->next;
    }

    b->size = new_size;
    b->data = new_data;
  }

  if (ref != NULL)
  {
    ref->buffer_id = buffer_id;
    ref->offset = (uint32_t) b->used;
  }

  b->used += size;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Creates an arena with the specified number of buffers.
//
// Args:
//   num_buffers: Number of buffers.
//   initial_buffer_size: Initial size of each buffer.
//   [out] arena: Address of a YR_ARENA* pointer that will receive the address
//                of the newly created arena.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_arena_create(
    uint32_t num_buffers,
    size_t initial_buffer_size,
    YR_ARENA** arena)
{
  YR_ARENA* new_arena = (YR_ARENA*) yr_calloc(1, sizeof(YR_ARENA));

  if (new_arena == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  new_arena->xrefs = 1;
  new_arena->num_buffers = num_buffers;
  new_arena->initial_buffer_size = initial_buffer_size;

  *arena = new_arena;

  return ERROR_SUCCESS;
}

void yr_arena_acquire(YR_ARENA* arena)
{
  arena->xrefs++;
}

////////////////////////////////////////////////////////////////////////////////
// Releases the arena.
//
// Decrements the cross-references counter for the arena, if the number of
// cross-references reaches zero the arena is destroyed and all its resources
// are freed.
//
// Args:
//   arena :Pointer to the arena.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_arena_release(YR_ARENA* arena)
{
  arena->xrefs--;

  if (arena->xrefs > 0)
    return ERROR_SUCCESS;

  for (uint32_t i = 0; i < arena->num_buffers; i++)
  {
    if (arena->buffers[i].data != NULL)
      yr_free(arena->buffers[i].data);
  }

  YR_RELOC* reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    YR_RELOC* next = reloc->next;
    yr_free(reloc);
    reloc = next;
  }

  yr_free(arena);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Allocates memory in a buffer within the arena.
//
// Args:
//   arena: Pointer to the arena.
//   buffer_id: Buffer number.
//   size : Size of the region to be allocated.
//   [out] offset: Pointer to a variable where the function puts the offset
//                 within the buffer of the allocated region. The pointer can
//                 be NULL.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_arena_allocate_memory(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref)
{
  return _yr_arena_allocate_memory(arena, 0, buffer_id, size, ref);
}

////////////////////////////////////////////////////////////////////////////////
// Allocates memory in a buffer within the arena and fill it with zeroes.
//
// Args:
//   arena: Pointer to the arena.
//   buffer_id: Buffer number.
//   size : Size of the region to be allocated.
//   [out] offset: Pointer to a variable where the function puts the offset
//                 within the buffer of the allocated region. The pointer can
//                 be NULL.
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_arena_allocate_zeroed_memory(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref)
{
  return _yr_arena_allocate_memory(
      arena, YR_ARENA_ZERO_MEMORY, buffer_id, size, ref);
}

////////////////////////////////////////////////////////////////////////////////
// Allocates a structure within the arena. This function is similar to
// yr_arena_allocate_memory but additionally receives a variable-length
// list of offsets within the structure where pointers reside. This allows
// the arena to keep track of pointers that must be adjusted when memory
// is relocated. This is an example on how to invoke this function:
//
//  yr_arena_allocate_struct(
//        arena,
//        0,
//        sizeof(MY_STRUCTURE),
//        &ref,
//        offsetof(MY_STRUCTURE, field_1),
//        offsetof(MY_STRUCTURE, field_2),
//        ..
//        offsetof(MY_STRUCTURE, field_N),
//        EOL);
//
// Args:
//   arena: Pointer to the arena.
//   buffer_id: Buffer number.
//   size: Size of the region to be allocated.
//   [out] ref: Pointer to a reference that will point to the newly allocated
//              structure when the function returns. The pointer can be NULL
//              if you don't need the reference.
//   ...   Variable number of offsets relative to the beginning of the struct.
//         These offsets are of type size_t.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INVALID_ARGUMENT
//   ERROR_INSUFFICIENT_MEMORY
//
int yr_arena_allocate_struct(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref,
    ...)
{
  YR_ARENA_REF r;

  int result = _yr_arena_allocate_memory(
      arena, YR_ARENA_ZERO_MEMORY, buffer_id, size, &r);

  if (result != ERROR_SUCCESS)
    return result;

  va_list field_offsets;
  va_start(field_offsets, ref);

  result = _yr_arena_make_ptr_relocatable(
      arena, buffer_id, r.offset, field_offsets);

  va_end(field_offsets);

  if (result == ERROR_SUCCESS && ref != NULL)
  {
    ref->buffer_id = r.buffer_id;
    ref->offset = r.offset;
  }

  return result;
}

void* yr_arena_get_ptr(
    YR_ARENA* arena,
    uint32_t buffer_id,
    yr_arena_off_t offset)
{
  assert(buffer_id < arena->num_buffers);
  assert(offset <= arena->buffers[buffer_id].used);

  return arena->buffers[buffer_id].data + offset;
}

yr_arena_off_t yr_arena_get_current_offset(YR_ARENA* arena, uint32_t buffer_id)
{
  assert(buffer_id < arena->num_buffers);

  return (yr_arena_off_t) arena->buffers[buffer_id].used;
}

int yr_arena_ptr_to_ref(YR_ARENA* arena, const void* address, YR_ARENA_REF* ref)
{
  *ref = YR_ARENA_NULL_REF;

  if (address == NULL)
    return 1;

  for (uint32_t i = 0; i < arena->num_buffers; ++i)
  {
    if ((uint8_t*) address >= arena->buffers[i].data &&
        (uint8_t*) address < arena->buffers[i].data + arena->buffers[i].used)
    {
      ref->buffer_id = i;
      ref->offset =
          (yr_arena_off_t) ((uint8_t*) address - arena->buffers[i].data);

      return 1;
    }
  }

  return 0;
}

void* yr_arena_ref_to_ptr(YR_ARENA* arena, YR_ARENA_REF* ref)
{
  if (YR_ARENA_IS_NULL_REF(*ref))
    return NULL;

#if defined(__arm__)
  YR_ARENA_REF tmp_ref;
  memcpy(&tmp_ref, ref, sizeof(YR_ARENA_REF));
  ref = &tmp_ref;
#endif

  return yr_arena_get_ptr(arena, ref->buffer_id, ref->offset);
}

////////////////////////////////////////////////////////////////////////////////
// Tells the arena that certain addresses contains a relocatable pointer.
//
// Args:
//   arena: Pointer to the arena.
//   buffer_id: Buffer number.
//   ... : Variable number of size_t arguments with offsets within the buffer.
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//
int yr_arena_make_ptr_relocatable(YR_ARENA* arena, uint32_t buffer_id, ...)
{
  int result;

  va_list offsets;
  va_start(offsets, buffer_id);

  result = _yr_arena_make_ptr_relocatable(arena, buffer_id, 0, offsets);

  va_end(offsets);

  return result;
}

int yr_arena_write_data(
    YR_ARENA* arena,
    uint32_t buffer_id,
    const void* data,
    size_t size,
    YR_ARENA_REF* ref)
{
  YR_ARENA_REF r;

  // Allocate space in the buffer.
  FAIL_ON_ERROR(yr_arena_allocate_memory(arena, buffer_id, size, &r));

  // Copy the data into the allocated space.
  memcpy(arena->buffers[buffer_id].data + r.offset, data, size);

  if (ref != NULL)
  {
    ref->buffer_id = r.buffer_id;
    ref->offset = r.offset;
  }

  return ERROR_SUCCESS;
}

int yr_arena_write_string(
    YR_ARENA* arena,
    uint32_t buffer_id,
    const char* string,
    YR_ARENA_REF* ref)
{
  return yr_arena_write_data(arena, buffer_id, string, strlen(string) + 1, ref);
}

int yr_arena_write_uint32(
    YR_ARENA* arena,
    uint32_t buffer_id,
    uint32_t integer,
    YR_ARENA_REF* ref)
{
  return yr_arena_write_data(arena, buffer_id, &integer, sizeof(integer), ref);
}

int yr_arena_load_stream(YR_STREAM* stream, YR_ARENA** arena)
{
  YR_ARENA_FILE_HEADER hdr;

  if (yr_stream_read(&hdr, sizeof(hdr), 1, stream) != 1)
    return ERROR_INVALID_FILE;

  if (hdr.magic[0] != 'Y' || hdr.magic[1] != 'A' || hdr.magic[2] != 'R' ||
      hdr.magic[3] != 'A')
  {
    return ERROR_INVALID_FILE;
  }

  if (hdr.version != YR_ARENA_FILE_VERSION)
    return ERROR_UNSUPPORTED_FILE_VERSION;

  if (hdr.num_buffers > YR_MAX_ARENA_BUFFERS)
    return ERROR_INVALID_FILE;

  YR_ARENA_FILE_BUFFER buffers[YR_MAX_ARENA_BUFFERS];

  size_t read = yr_stream_read(
      buffers, sizeof(buffers[0]), hdr.num_buffers, stream);

  if (read != hdr.num_buffers)
    return ERROR_CORRUPT_FILE;

  YR_ARENA* new_arena;

  FAIL_ON_ERROR(yr_arena_create(hdr.num_buffers, 10485, &new_arena))

  for (int i = 0; i < hdr.num_buffers; ++i)
  {
    if (buffers[i].size == 0)
      continue;

    YR_ARENA_REF ref;

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_arena_allocate_memory(new_arena, i, buffers[i].size, &ref),
        yr_arena_release(new_arena))

    void* ptr = yr_arena_get_ptr(new_arena, i, ref.offset);

    if (yr_stream_read(ptr, buffers[i].size, 1, stream) != 1)
    {
      yr_arena_release(new_arena);
      return ERROR_CORRUPT_FILE;
    }
  }

  YR_ARENA_REF ref;

  while (yr_stream_read(&ref, sizeof(ref), 1, stream) == 1)
  {
    YR_ARENA_BUFFER* b = &new_arena->buffers[ref.buffer_id];

    if (ref.buffer_id >= new_arena->num_buffers ||
        ref.offset > b->used - sizeof(void*) || b->data == NULL)
    {
      yr_arena_release(new_arena);
      return ERROR_CORRUPT_FILE;
    }

    void** reloc_ptr = (void**) (b->data + ref.offset);

    // Let's convert the reference into a pointer.
    *reloc_ptr = yr_arena_ref_to_ptr(new_arena, (YR_ARENA_REF*) reloc_ptr);

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_arena_make_ptr_relocatable(
            new_arena, ref.buffer_id, ref.offset, EOL),
        yr_arena_release(new_arena))
  }

  *arena = new_arena;

  return ERROR_SUCCESS;
}

int yr_arena_save_stream(YR_ARENA* arena, YR_STREAM* stream)
{
  YR_ARENA_FILE_HEADER hdr;

  hdr.magic[0] = 'Y';
  hdr.magic[1] = 'A';
  hdr.magic[2] = 'R';
  hdr.magic[3] = 'A';

  hdr.version = YR_ARENA_FILE_VERSION;
  hdr.num_buffers = arena->num_buffers;

  if (yr_stream_write(&hdr, sizeof(hdr), 1, stream) != 1)
    return ERROR_WRITING_FILE;

  // The first buffer in the file is after the header and the buffer table,
  // calculate its offset accordingly.
  uint64_t offset = sizeof(YR_ARENA_FILE_HEADER) +
                    sizeof(YR_ARENA_FILE_BUFFER) * arena->num_buffers;

  for (uint32_t i = 0; i < arena->num_buffers; ++i)
  {
    YR_ARENA_FILE_BUFFER buffer = {
        .offset = offset,
        .size = (uint32_t) arena->buffers[i].used,
    };

    if (yr_stream_write(&buffer, sizeof(buffer), 1, stream) != 1)
      return ERROR_WRITING_FILE;

    offset += buffer.size;
  }

  // Iterate the relocation list and replace all the relocatable pointers by
  // references to the buffer and offset where they are pointing to. All
  // relocatable pointers are expected to be null or point to data stored in
  // some of the arena's buffers. If a relocatable pointer points outside the
  // arena that's an error.
  YR_RELOC* reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    // reloc_ptr is a pointer to the relocatable pointer, while *reloc_ptr
    // is the relocatable pointer itself.
    void** reloc_ptr =
        (void**) (arena->buffers[reloc->buffer_id].data + reloc->offset);

    YR_ARENA_REF ref;

#if !defined(NDEBUG)
    int found = yr_arena_ptr_to_ref(arena, *reloc_ptr, &ref);
    // yr_arena_ptr_to_ref returns 0 if the relocatable pointer is pointing
    // outside the arena, this should not happen.
    assert(found);
#else
    yr_arena_ptr_to_ref(arena, *reloc_ptr, &ref);
#endif

    // Replace the relocatable pointer with a reference that holds information
    // about the buffer and offset where the relocatable pointer is pointing to.
    memcpy(reloc_ptr, &ref, sizeof(ref));

    reloc = reloc->next;
  }

  // Now that all relocatable pointers are converted to references, write the
  // buffers.
  for (uint32_t i = 0; i < arena->num_buffers; ++i)
  {
    YR_ARENA_BUFFER* b = &arena->buffers[i];

    if (b->used > 0)
      if (yr_stream_write(b->data, b->used, 1, stream) != 1)
        return ERROR_WRITING_FILE;
  }

  // Write the relocation list and restore the pointers back.
  reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    YR_ARENA_REF ref = {
        .buffer_id = reloc->buffer_id,
        .offset = reloc->offset,
    };

    if (yr_stream_write(&ref, sizeof(ref), 1, stream) != 1)
      return ERROR_WRITING_FILE;

    void** reloc_ptr =
        (void**) (arena->buffers[reloc->buffer_id].data + reloc->offset);

    // reloc_ptr is now pointing to a YR_ARENA_REF.
    YR_ARENA_REF* ref_ptr = (YR_ARENA_REF*) reloc_ptr;

    // Let's convert the reference into a pointer again.
    *reloc_ptr = yr_arena_ref_to_ptr(arena, ref_ptr);

    reloc = reloc->next;
  }

  return ERROR_SUCCESS;
}
