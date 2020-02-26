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

#ifndef YARA_ARENA2_H
#define YARA_ARENA2_H

#include <stddef.h>
#include <yara/limits.h>
#include <yara/integers.h>
#include <yara/stream.h>

#define EOL2 ((uint32_t) -1)

#define YR_ARENA_FILE_VERSION  17

#define YR_ARENA_NULL_REF  \
    (YR_ARENA2_REFERENCE){.buffer_id=UINT8_MAX, .offset=UINT32_MAX}

typedef uint32_t yr_arena_off_t;

typedef struct YR_ARENA2 YR_ARENA2;
typedef struct YR_ARENA2_BUFFER YR_ARENA2_BUFFER;
typedef struct YR_ARENA2_REFERENCE YR_ARENA2_REFERENCE;
typedef struct YR_RELOC2 YR_RELOC2;

// The YR_ARENA2_REFERENCE must be 64-bits long because this structure occupies
// the place of relocatable pointers when arenas are saved to file. The pack(4)
// directive ensures that fields are aligned to 4-byte boundaries and the total
// size of the structure is 8 bytes. When compiling YARA for 32-bits, pointers
// are 4 bytes but this structure is still 8 bytes. For that reason structures
// that are saved in arenas must declare pointers using the DECLARE_REFERENCE
// macro, which ensures that 8 bytes are reserved for the pointer no matter if
// they are 32-bits pointers.

#pragma pack(push)
#pragma pack(4)

struct YR_ARENA2_REFERENCE
{
  uint8_t buffer_id;
  uint32_t offset;
};

#pragma pack(pop)


struct YR_ARENA2_BUFFER
{
  // Pointer the buffer's data.
  void* data;

  // Total buffer size, including the used and unused areas.
  size_t size;

  // Number of bytes that are actually used (equal to or lower than size).
  size_t used;
};


struct YR_RELOC2
{
  // Buffer ID associated to this relocation entry.
  uint8_t buffer_id;

  // Offset within the buffer where the relocatable pointer resides.
  yr_arena_off_t offset;

  // Pointer to the next entry in the list.
  struct YR_RELOC2* next;
};


/*
YR_ARENA2 is the structure that represents an arena.

An arena is a set of buffers in which you can write arbitrary data. When the
arena is created you can specify how many buffers it will have, this number is
limited by YR_MAX_ARENA_BUFFERS. Buffers are numbered 0, 1, 2, and so on, and
they are referenced by its number.

Initially each buffer will have a size that is a determined by an argument
passed to yr_create_arena, but the size will grow automatically as you write
data into it. When the buffer is re-sized it may be moved to a different
location in memory, which means that any pointer you hold to data contained
in the buffer is valid only until the next call to a function that may
cause a buffer re-sizing. For long-lived references to data in a buffer
you should use the offset of the data relative to the beginning of the buffer.
Such offsets are returned by all functions that allocate space or write data
in a buffer.

The yr_arena2_get_address function can be used for getting a pointer to data
stored in the buffer given its offset, but this pointer should be used with
only in a limited scope where you can be sure that your program is not calling
a function that may cause a buffer re-sizing, like yr_arena2_allocate_xxx and
yr_arena2_write_xxx.

Arenas can also keep track pointers stored in some of its buffers that point to
some location within the arena (it can be to the same buffer or a different one
within the same arena). This is done with yr_arena2_make_ptr_relocatable, this
function receives a buffer number and an offset, and it tells the arena that
the pointer stored at that particular location of the buffer must be adjusted
every time the memory it points to is moved around.

The yr_arena2_allocate_struct function is an even more powerful mechanism for
tracking relocatable pointers. This function allows to allocate space in a
buffer for a structure, while at the same time telling the arena which fields
in the structure are relocatable pointers.

*/

struct YR_ARENA2
{
  // Number of buffers in this arena.
  int num_buffers;

  // Status of individual buffers.
  YR_ARENA2_BUFFER buffers[YR_MAX_ARENA_BUFFERS];

  // Initial size for each buffer.
  size_t initial_buffer_size;

  // Head of the list containing relocation entries.
  YR_RELOC2* reloc_list_head;

  // Tail of the list containing relocation entries.
  YR_RELOC2* reloc_list_tail;
} ;


int yr_arena2_create(
    int number_of_buffers,
    size_t initial_buffer_size,
    YR_ARENA2** arena);


int yr_arena2_destroy(
    YR_ARENA2* arena);


void* yr_arena2_ref_to_ptr(
    YR_ARENA2* arena,
    YR_ARENA2_REFERENCE* ref);


int yr_arena2_ptr_to_ref(
    YR_ARENA2* arena,
    const void* address,
    YR_ARENA2_REFERENCE* ref);


void* yr_arena2_get_ptr(
    YR_ARENA2* arena,
    int buffer_id,
    yr_arena_off_t offset);


yr_arena_off_t yr_arena2_get_current_offset(
    YR_ARENA2* arena,
    int buffer_id);


int yr_arena2_allocate_memory(
    YR_ARENA2* arena,
    int buffer_id,
    size_t size,
    YR_ARENA2_REFERENCE* ref);


int yr_arena2_allocate_struct(
    YR_ARENA2* arena,
    int buffer_id,
    size_t size,
    YR_ARENA2_REFERENCE* ref,
    ...);


int yr_arena2_make_ptr_relocatable(
    YR_ARENA2* arena,
    int buffer_id,
    ...);


int yr_arena2_write_data(
    YR_ARENA2* arena,
    int buffer_id,
    const void* data,
    size_t size,
    YR_ARENA2_REFERENCE* ref);


int yr_arena2_write_string(
    YR_ARENA2* arena,
    int buffer_id,
    const char* string,
    YR_ARENA2_REFERENCE* ref);


int yr_arena2_write_uint32(
    YR_ARENA2* arena,
    int buffer_id,
    uint32_t integer,
    YR_ARENA2_REFERENCE* ref);


int yr_arena2_load_stream(
    YR_STREAM* stream,
    YR_ARENA2** arena);


int yr_arena2_save_stream(
    YR_ARENA2* arena,
    YR_STREAM* stream);

#endif //YARA_ARENA2_H
