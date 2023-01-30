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

#ifndef YR_ARENA_H
#define YR_ARENA_H

#include <stddef.h>
#include <yara/integers.h>
#include <yara/limits.h>
#include <yara/stream.h>

#define EOL ((size_t) -1)

#define YR_ARENA_FILE_VERSION 20

#define YR_ARENA_NULL_REF \
  (YR_ARENA_REF) { UINT32_MAX, UINT32_MAX }

#define YR_ARENA_IS_NULL_REF(ref) \
  (memcmp(&(ref), &YR_ARENA_NULL_REF, sizeof(YR_ARENA_NULL_REF)) == 0)

typedef uint32_t yr_arena_off_t;

typedef struct YR_ARENA YR_ARENA;
typedef struct YR_ARENA_BUFFER YR_ARENA_BUFFER;
typedef struct YR_ARENA_REF YR_ARENA_REF;
typedef struct YR_RELOC YR_RELOC;

// The YR_ARENA_REF must be 64-bits long because this structure occupies
// the place of relocatable pointers when arenas are saved to file. The pack(4)
// directive ensures that fields are aligned to 4-byte boundaries and the total
// size of the structure is 8 bytes. When compiling YARA for 32-bits, pointers
// are 4 bytes but this structure is still 8 bytes. For that reason structures
// that are saved in arenas must declare pointers using the DECLARE_REFERENCE
// macro, which ensures that 8 bytes are reserved for the pointer no matter if
// they are 32-bits pointers.

#pragma pack(push)
#pragma pack(4)

struct YR_ARENA_REF
{
  uint32_t buffer_id;
  yr_arena_off_t offset;
};

#pragma pack(pop)

struct YR_ARENA_BUFFER
{
  // Pointer the buffer's data.
  uint8_t* data;

  // Total buffer size, including the used and unused areas. The maximum size
  // allowed for a buffer is 4GB because offsets in YR_ARENA_REF are 32-bit
  // integers.
  size_t size;

  // Number of bytes that are actually used (equal to or lower than size).
  size_t used;
};

struct YR_RELOC
{
  // Buffer ID associated to this relocation entry.
  uint32_t buffer_id;

  // Offset within the buffer where the relocatable pointer resides.
  yr_arena_off_t offset;

  // Pointer to the next entry in the list.
  struct YR_RELOC* next;
};

/*
YR_ARENA is the structure that represents an arena.

An arena is a set of buffers in which you can write arbitrary data. When the
arena is created you can specify how many buffers it will have, this number is
limited by YR_MAX_ARENA_BUFFERS. Buffers are numbered 0, 1, 2, and so on, and
they are referenced by its number.

Initially each buffer will have a size that is determined by an argument
passed to yr_create_arena, but the size will grow automatically as you write
data into it. When the buffer is re-sized it may be moved to a different
location in memory, which means that any pointer you hold to data contained
in the buffer is valid only until the next call to a function that may
cause a buffer re-sizing. For long-lived references to data in a buffer
you should use a YR_ARENA_REF, which is simply a struct storing the buffer
number and the offset of the data relative to the beginning of the buffer.
Such YR_ARENA_REF structures are returned by all functions that allocate space
or write data in a buffer.

The yr_arena_get_ptr function can be used for getting a pointer to data
stored in the buffer given its offset, but this pointer should be used with
only in a limited scope where you can be sure that your program is not calling
a function that may cause a buffer re-sizing, like yr_arena_allocate_xxx and
yr_arena_write_xxx.

Arenas can also keep track pointers stored in some of its buffers that point to
some location within the arena (it can be to the same buffer or a different one
within the same arena). This is done with yr_arena_make_ptr_relocatable, this
function receives a buffer number and an offset, and it tells the arena that
the pointer stored at that particular location of the buffer must be adjusted
every time the memory it points to is moved around.

The yr_arena_allocate_struct function is an even more powerful mechanism for
tracking relocatable pointers. This function allows to allocate space in a
buffer for a structure, while at the same time telling the arena which fields
in the structure are relocatable pointers.

*/

struct YR_ARENA
{
  // Number of users of this arena. This is set to one when the arena is
  // created, and can be incremented by calling yr_arena_acquire. On each call
  // to yr_arena_release it gets decremented by one, if xrefs reaches zero
  // the buffers and the YR_ARENA structures are freed.
  uint32_t xrefs;

  // Number of buffers in this arena.
  uint32_t num_buffers;

  // Status of individual buffers.
  YR_ARENA_BUFFER buffers[YR_MAX_ARENA_BUFFERS];

  // Initial size for each buffer.
  size_t initial_buffer_size;

  // Head of the list containing relocation entries.
  YR_RELOC* reloc_list_head;

  // Tail of the list containing relocation entries.
  YR_RELOC* reloc_list_tail;
};

// Creates an arena with the specified number of buffers and takes ownership of
// it. Initially each buffer is empty, the first time that some data is written
// into a buffer at least initial_buffer_size are reserved for the buffer.
int yr_arena_create(
    uint32_t num_buffers,
    size_t initial_buffer_size,
    YR_ARENA** arena);

// Takes ownership of the arena.
void yr_arena_acquire(YR_ARENA* arena);

// Release ownership of the arena. If the number of owners drops to zero the
// arena is destroyed and all its resources are freed.
int yr_arena_release(YR_ARENA* arena);

// Given a reference to some data within the arena, it returns a pointer to
// the data. This pointer is valid only until the next call to any of the
// functions that allocates space in the buffer where the data resides, like
// yr_arena_allocate_xxx and yr_arena_write_xxx. These functions can cause
// the buffer to be moved to different memory location and the pointer won't
// valid any longer.
void* yr_arena_ref_to_ptr(YR_ARENA* arena, YR_ARENA_REF* ref);

// Given a pointer into the arena, it returns a reference to it. The reference
// can be used with yr_arena_ref_to_ptr to obtain a pointer again. Unlike
// pointers, references are during the arena's lifetime, even if the buffers
// are moved to a different memory location.
int yr_arena_ptr_to_ref(
    YR_ARENA* arena,
    const void* address,
    YR_ARENA_REF* ref);

// Given a buffer number and an offset within the buffer, returns a pointer
// to that offset. The same limitations explained for yr_arena_ref_to_ptr
// applies for the pointers returned by this function.
void* yr_arena_get_ptr(
    YR_ARENA* arena,
    uint32_t buffer_id,
    yr_arena_off_t offset);

yr_arena_off_t yr_arena_get_current_offset(YR_ARENA* arena, uint32_t buffer_id);

int yr_arena_allocate_memory(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref);

int yr_arena_allocate_zeroed_memory(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref);

int yr_arena_allocate_struct(
    YR_ARENA* arena,
    uint32_t buffer_id,
    size_t size,
    YR_ARENA_REF* ref,
    ...);

int yr_arena_make_ptr_relocatable(YR_ARENA* arena, uint32_t buffer_id, ...);

int yr_arena_write_data(
    YR_ARENA* arena,
    uint32_t buffer_id,
    const void* data,
    size_t size,
    YR_ARENA_REF* ref);

int yr_arena_write_string(
    YR_ARENA* arena,
    uint32_t buffer_id,
    const char* string,
    YR_ARENA_REF* ref);

int yr_arena_write_uint32(
    YR_ARENA* arena,
    uint32_t buffer_id,
    uint32_t integer,
    YR_ARENA_REF* ref);

int yr_arena_load_stream(YR_STREAM* stream, YR_ARENA** arena);

int yr_arena_save_stream(YR_ARENA* arena, YR_STREAM* stream);

#endif  // YR_ARENA_H
