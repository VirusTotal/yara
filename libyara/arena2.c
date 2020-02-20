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

#include <yara/arena2.h>
#include <yara/mem.h>
#include <yara/error.h>

typedef struct YR_ARENA2_FILE_HEADER YR_ARENA2_FILE_HEADER;
typedef struct YR_ARENA2_FILE_BUFFER YR_ARENA2_FILE_BUFFER;

#pragma pack(push)
#pragma pack(1)

struct YR_ARENA2_FILE_HEADER
{
  uint8_t magic[4];
  uint8_t version;
  uint8_t num_buffers;
};

struct YR_ARENA2_FILE_BUFFER
{
  uint64_t offset;
  uint32_t size;
};

#pragma pack(pop)


//
// _yr_arena2_make_ptr_relocatable
//
// Tells the arena that certain offsets within a buffer contain relocatable
// pointers. The offsets are passed as a vararg list where the end of the
// list is indicated by the special value EOL (-1), offsets in the list are
// relative to base_offset, which in turns is relative to the beginning of the
// buffer.
//
// Args:
//    [in]  YR_ARENA* arena     - Pointer the arena.
//    [in]  int buffer_id       - Buffer number.
//    [in]  size_t base_offset  - Base offset.
//    [in]  va_list offsets     - List of offsets relative to base offset.
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

static int _yr_arena2_make_ptr_relocatable(
    YR_ARENA2* arena,
    int buffer_id,
    yr_arena_off_t base_offset,
    va_list offsets)
{
  yr_arena_off_t offset;

  int result = ERROR_SUCCESS;

  offset = va_arg(offsets, yr_arena_off_t);

  while (offset != EOL2)
  {
    YR_RELOC2* reloc = (YR_RELOC2*) yr_malloc(sizeof(YR_RELOC2));

    if (reloc == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    reloc->buffer_id = buffer_id;
    reloc->offset = base_offset + offset;
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

//
// yr_arena2_create
//
// Creates an arena with the specified number of buffers.
//
// Args:
//    [in]  int num_buffers             - Number of buffers
//    [in]  size_t initial_buffer_size  - Initial size of each buffer.
//    [out] YR_ARENA2** arena           - Address of a YR_ARENA2* pointer that
//                                        will receive the address of the newly
//                                        created arena.
//

int yr_arena2_create(
    int number_of_buffers,
    size_t initial_buffer_size,
    YR_ARENA2** arena)
{
  YR_ARENA2* new_arena = (YR_ARENA2*) yr_calloc(1, sizeof(YR_ARENA2));

  if (new_arena == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  new_arena->num_buffers = number_of_buffers;
  new_arena->initial_buffer_size = initial_buffer_size;

  *arena = new_arena;

  return ERROR_SUCCESS;
}

//
// yr_arena2_destroy
//
// Destroys an arena.
//
// Args:
//    [in] YR_ARENA2* arena    - Pointer to the arena.
//

int yr_arena2_destroy(
    YR_ARENA2* arena)
{
  for (int i = 0; i < arena->num_buffers; i++)
  {
    if (arena->buffers[i].data != NULL)
      yr_free(arena->buffers[i].data);
  }

  YR_RELOC2* reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    YR_RELOC2* next = reloc->next;
    yr_free(reloc);
    reloc = next;
  }

  yr_free(arena);

  return ERROR_SUCCESS;
}

//
// yr_arena2_allocate_memory
//
// Allocates memory in a buffer within the arena.
//
// Args:
//    [in]  YR_ARENA* arena   - Pointer to the arena.
//    [in]  int buffer_id     - Buffer number.
//    [in]  size_t size       - Size of the region to be allocated.
//    [out] size_t* offset    - Pointer to a variable where the function puts
//                              the offset within the buffer of the allocated
//                              region. The pointer can be NULL.
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code if otherwise.
//

int yr_arena2_allocate_memory(
    YR_ARENA2* arena,
    int buffer_id,
    size_t size,
    YR_ARENA2_REFERENCE* ref)
{
  if (buffer_id > arena->num_buffers)
    return ERROR_INVALID_ARGUMENT;

  YR_ARENA2_BUFFER* b = &arena->buffers[buffer_id];

  // If the new data doesn't fit in the remaining space the buffer must be
  // re-sized. This implies moving the buffer to a different memory location
  // and adjusting the pointers listed in the relocation list.

  if (b->size - b->used < size)
  {
    size_t new_size = (b->size == 0) ? arena->initial_buffer_size : b->size * 2;

    while (new_size < size)
      new_size *= 2;

    void *new_data = yr_realloc(b->data, new_size);

    if (new_data == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    YR_RELOC2* reloc = arena->reloc_list_head;

    while (reloc != NULL)
    {
      // reloc_address holds the address inside the buffer where the pointer
      // to be relocated resides.
      void** reloc_address = (void**)(
          arena->buffers[reloc->buffer_id].data + reloc->offset);

      // reloc_target is the value of the relocatable pointer.
      void* reloc_target = *reloc_address;

      // reloc_target points to some data inside the buffer being moved, so
      // the pointer needs to be adjusted.
      if (reloc_target >= b->data && reloc_target < b->data + b->used)
      {
        *reloc_address = reloc_target - b->data + new_data;
      }

      reloc = reloc->next;
    }

    b->size = new_size;
    b->data = new_data;
  }

  if (ref != NULL)
  {
    ref->buffer_id = buffer_id;
    ref->offset = b->used;
  }

  b->used += size;

  return ERROR_SUCCESS;
}

//
// yr_arena2_allocate_struct
//
// Allocates a structure within the arena. This function is similar to
// yr_arena2_allocate_memory but additionally receives a variable-length
// list of offsets within the structure where pointers reside. This allows
// the arena to keep track of pointers that must be adjusted when memory
// is relocated. This is an example on how to invoke this function:
//
//  yr_arena2_allocate_struct(
//        arena,
//        0,
//        sizeof(MY_STRUCTURE),
//        &offset,
//        offsetof(MY_STRUCTURE, field_1),
//        offsetof(MY_STRUCTURE, field_2),
//        ..
//        offsetof(MY_STRUCTURE, field_N),
//        EOL);
//
// Args:
//    [in]  YR_ARENA* arena   - Pointer to the arena.
//    [in]  int buffer_id     - Buffer number.
//    [in]  size_t size       - Size of the region to be allocated.
//    [out] size_t* offset    - Pointer to a variable where the function puts
//                              the offset within the buffer of the allocated
//                              region. The pointer can be NULL.
//    ...                     - Variable number of offsets relative to the
//                              beginning of the struct. Offsets are of type
//                              size_t.
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

int yr_arena2_allocate_struct(
    YR_ARENA2* arena,
    int buffer_id,
    size_t size,
    YR_ARENA2_REFERENCE* ref,
    ...)
{
  YR_ARENA2_REFERENCE r;
  int result;

  va_list field_offsets;
  va_start(field_offsets, ref);

  result = yr_arena2_allocate_memory(arena, buffer_id, size, &r);

  va_end(field_offsets);

  if (result == ERROR_SUCCESS)
  {
    result = _yr_arena2_make_ptr_relocatable(
        arena, buffer_id, r.offset, field_offsets);
  }

  if (ref != NULL)
  {
    ref->buffer_id = r.buffer_id;
    ref->offset = r.offset;
  }

  return result;
}


static inline void* _yr_arena2_get_address(
    YR_ARENA2* arena,
    int buffer_id,
    yr_arena_off_t offset)
{
  assert(buffer_id < arena->num_buffers);
  assert(offset < arena->buffers[buffer_id].used);

  return arena->buffers[buffer_id].data + offset;
}


int yr_arena2_ptr_to_ref(
    YR_ARENA2* arena,
    void* address,
    YR_ARENA2_REFERENCE* ref)
{
  *ref = YR_ARENA_NULL_REF;

  if (address == NULL)
    return 1;

  for (int i = 0; i < arena->num_buffers; ++i)
  {
    if (address >= arena->buffers[i].data &&
        address <  arena->buffers[i].data + arena->buffers[i].used)
    {
      ref->buffer_id = i;
      ref->offset = address - arena->buffers[i].data;
      return 1;
    }
  }

  return 0;
}

void* yr_arena2_ref_to_ptr(
    YR_ARENA2* arena,
    YR_ARENA2_REFERENCE* ref)
{
  if (ref->buffer_id == YR_ARENA_NULL_REF.buffer_id &&
      ref->offset == YR_ARENA_NULL_REF.offset)
  {
    return NULL;
  }

  return _yr_arena2_get_address(arena, ref->buffer_id, ref->offset);
}



//
// yr_arena_make_ptr_relocatable
//
// Tells the arena that certain addresses contains a relocatable pointer.
//
// Args:
//    YR_ARENA* arena    - Pointer to the arena.
//    void* base         - Address within the arena.
//    ...                - Variable number of size_t arguments with offsets
//                         relative to base.
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

int yr_arena2_make_ptr_relocatable(
    YR_ARENA2* arena,
    int buffer_id,
    ...)
{
  int result;

  va_list offsets;
  va_start(offsets, buffer_id);

  result = _yr_arena2_make_ptr_relocatable(
      arena, buffer_id, 0, offsets);

  va_end(offsets);

  return result;
}


int yr_arena2_write_data(
    YR_ARENA2* arena,
    int buffer_id,
    const void* data,
    size_t size,
    YR_ARENA2_REFERENCE* ref)
{
  YR_ARENA2_REFERENCE r;

  // Allocate space in the buffer.
  FAIL_ON_ERROR(yr_arena2_allocate_memory(arena, buffer_id, size, &r));

  // Copy the data into the allocated space.
  memcpy(arena->buffers[buffer_id].data + r.offset, data, size);

  if (ref != NULL)
  {
    ref->buffer_id = r.buffer_id;
    ref->offset = r.offset;
  }

  return ERROR_SUCCESS;
}


int yr_arena2_write_string(
    YR_ARENA2* arena,
    int buffer_id,
    const char* string,
    YR_ARENA2_REFERENCE* ref)
{
  return yr_arena2_write_data(
      arena, buffer_id, string,strlen(string) + 1, ref);
}


int yr_arena2_load_stream(
    YR_STREAM* stream,
    YR_ARENA2** arena)
{
  YR_ARENA2_FILE_HEADER hdr;

  if (yr_stream_read(&hdr, sizeof(hdr), 1, stream) != 1)
    return ERROR_INVALID_FILE;

  if (hdr.magic[0] != 'Y' ||
      hdr.magic[1] != 'A' ||
      hdr.magic[2] != 'R' ||
      hdr.magic[3] != 'A')
  {
    return ERROR_INVALID_FILE;
  }

  if (hdr.version != YR_ARENA_FILE_VERSION)
    return ERROR_UNSUPPORTED_FILE_VERSION;

  if (hdr.num_buffers > YR_MAX_ARENA_BUFFERS)
    return ERROR_INVALID_FILE;

  YR_ARENA2_FILE_BUFFER buffers[YR_MAX_ARENA_BUFFERS];

  int read = yr_stream_read(
      buffers, sizeof(buffers[0]), hdr.num_buffers, stream);

  if (read != hdr.num_buffers)
    return ERROR_CORRUPT_FILE;

  YR_ARENA2* new_arena;

  FAIL_ON_ERROR(yr_arena2_create(hdr.num_buffers, 1048576, &new_arena))

  for (int i = 0; i < hdr.num_buffers; ++i)
  {
    YR_ARENA2_REFERENCE ref;

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_arena2_allocate_memory(
            new_arena, i, buffers[i].size, &ref),
        yr_arena2_destroy(new_arena))

    void* ptr = _yr_arena2_get_address(new_arena, i, ref.offset);

    if (yr_stream_read(ptr, buffers[i].size, 1, stream) != 1)
    {
      yr_arena2_destroy(new_arena);
      return ERROR_CORRUPT_FILE;
    }
  }

  YR_ARENA2_REFERENCE ref;

  while (yr_stream_read(&ref, sizeof(ref), 1, stream) == 1)
  {
    YR_ARENA2_BUFFER* b = &new_arena->buffers[ref.buffer_id];

    if (ref.buffer_id >= new_arena->num_buffers ||
        ref.offset > b->used - sizeof(void*))
    {
      yr_arena2_destroy(new_arena);
      return ERROR_CORRUPT_FILE;
    }

    void** reloc_ptr = b->data + ref.offset;

    *reloc_ptr = yr_arena2_ref_to_ptr(new_arena, (YR_ARENA2_REFERENCE *) reloc_ptr);

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_arena2_make_ptr_relocatable(
           new_arena,
           ref.buffer_id,
           ref.offset,
           EOL2),
        yr_arena2_destroy(new_arena))
  }

  *arena = new_arena;

  return ERROR_SUCCESS;
}


int yr_arena2_save_stream(
    YR_ARENA2* arena,
    YR_STREAM* stream)
{
  YR_ARENA2_FILE_HEADER hdr;

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
  uint64_t offset = sizeof(YR_ARENA2_FILE_HEADER)
      + sizeof(YR_ARENA2_FILE_BUFFER) * arena->num_buffers;

  for (int i = 0; i < arena->num_buffers; ++i)
  {
    YR_ARENA2_FILE_BUFFER buffer = {
      .offset = offset,
      .size = arena->buffers[i].used,
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
  YR_RELOC2* reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    // reloc_ptr is a pointer to the relocatable pointer, while *reloc_ptr
    // is the relocatable pointer itself.
    void** reloc_ptr = arena->buffers[reloc->buffer_id].data + reloc->offset;

    YR_ARENA2_REFERENCE ref;

    // Fill reference with zeroes, as this structure is going to be written
    // we don't want random bytes in the padding.
    memset(&ref, 0, sizeof(ref));

    int found = yr_arena2_ptr_to_ref(arena, *reloc_ptr, &ref);

    // yr_arena2_ptr_to_ref returns 0 if the relocatable pointer is pointing
    // outside the arena, this should not happen.
    assert(found);

    // Replace the relocatable pointer with a reference that holds information
    // about the buffer and offset where the relocatable pointer is pointing to.
    memcpy(reloc_ptr, &ref, sizeof(ref));

    reloc = reloc->next;
  }

  // Now that all relocatable pointers are converted to references, write the
  // buffers.
  for (int i = 0; i < arena->num_buffers; ++i)
  {
    YR_ARENA2_BUFFER* b = &arena->buffers[i];

    if (yr_stream_write(b->data, b->used, 1, stream) != 1)
      return ERROR_WRITING_FILE;
  }

  // Write the relocation list and restore the pointers back.
  reloc = arena->reloc_list_head;

  while (reloc != NULL)
  {
    YR_ARENA2_REFERENCE ref = {
      .buffer_id = reloc->buffer_id,
      .offset = reloc->offset,
    };

    if (yr_stream_write(&ref, sizeof(ref), 1, stream) != 1)
      return ERROR_WRITING_FILE;

    void** reloc_ptr = arena->buffers[reloc->buffer_id].data + reloc->offset;

    // reloc_ptr is now pointing to a YR_ARENA2_REFERENCE.
    YR_ARENA2_REFERENCE* ref_ptr = (YR_ARENA2_REFERENCE*) reloc_ptr;

    // Let's convert the reference into a pointer again.
    *reloc_ptr = arena->buffers[ref_ptr->buffer_id].data + ref_ptr->offset;

    reloc = reloc->next;
  }

  return ERROR_SUCCESS;
}




