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

#include <yara.h>
#include <yara/arena.h>
#include <yara/stream.h>

#include "util.h"

static void basic_tests()
{
  YR_ARENA* arena;

  yr_initialize();

  assert_true_expr(yr_arena_create(0, 10, &arena) == ERROR_INVALID_ARGUMENT);
  assert_true_expr(
      yr_arena_create(YR_MAX_ARENA_BUFFERS + 1, 10, &arena) ==
      ERROR_INVALID_ARGUMENT);

  // Create arena with 2 buffers of 10 bytes of initial size
  assert_true_expr(yr_arena_create(2, 10, &arena) == ERROR_SUCCESS);

  YR_ARENA_REF ref;

  assert_true_expr(
      yr_arena_allocate_memory(arena, 2, 5, &ref) == ERROR_INVALID_ARGUMENT);

  // Allocate 5 bytes.
  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, 5, &ref) == ERROR_SUCCESS);

  // Offset should be 0 as this is the first write.
  assert_true_expr(ref.offset == 0);

  // Write 16 bytes, "123456789ABCDEF" + null terminator. This forces a
  // reallocation.
  assert_true_expr(
      yr_arena_write_string(arena, 0, "123456789ABCDEF", &ref) ==
      ERROR_SUCCESS);

  // Offset should be 5 as this was written after the first 5-bytes write.
  assert_true_expr(ref.offset == 5);

  // Write 4 bytes, "bar" + null terminator.
  assert_true_expr(
      yr_arena_write_string(arena, 0, "123456789ABCDEF", &ref) ==
      ERROR_SUCCESS);

  // Offset should be 21.
  assert_true_expr(ref.offset == 21);

  yr_arena_release(arena);
  yr_finalize();
}

typedef struct TEST_STRUCT TEST_STRUCT;

struct TEST_STRUCT
{
  DECLARE_REFERENCE(char*, str1);
  DECLARE_REFERENCE(char*, str2);
};

static void advanced_tests()
{
  YR_ARENA* arena;

  yr_initialize();

  // Create arena with 3 buffers of 10 bytes of initial size. Only the first
  // two are used, the third one is left empty on purpose.
  int result = yr_arena_create(3, 10, &arena);
  assert_true_expr(result == ERROR_SUCCESS);

  YR_ARENA_REF ref;

  // Allocate a struct in buffer 0 indicating that the field "str" is a
  // relocatable pointer.
  result = yr_arena_allocate_struct(
      arena,
      0,
      sizeof(TEST_STRUCT),
      &ref,
      offsetof(TEST_STRUCT, str1),
      offsetof(TEST_STRUCT, str2),
      EOL);

  assert_true_expr(result == ERROR_SUCCESS);

  // Get the struct address, this pointer is valid as longs as we don't call
  // any other function that allocates memory in buffer 0.
  TEST_STRUCT* s = (TEST_STRUCT*) yr_arena_ref_to_ptr(arena, &ref);

  // Write a string in buffer 1.
  yr_arena_write_string(arena, 1, "foo", &ref);

  // Get the string's address and store it in the struct's "str" field.
  s->str1 = (char*) yr_arena_ref_to_ptr(arena, &ref);

  // Write another string in buffer 1.
  yr_arena_write_string(arena, 1, "bar", &ref);

  // Get the string's address and store it in the struct's "str" field.
  s->str2 = (char*) yr_arena_ref_to_ptr(arena, &ref);

  // The arena should have two reloc entries for the "str1" and "str2" fields.
  assert_true_expr(arena->reloc_list_head != NULL);
  assert_true_expr(arena->reloc_list_tail != NULL);
  assert_true_expr(arena->reloc_list_head->buffer_id == 0);
  assert_true_expr(arena->reloc_list_tail->buffer_id == 0);
  assert_true_expr(
      arena->reloc_list_head->offset == offsetof(TEST_STRUCT, str1));
  assert_true_expr(
      arena->reloc_list_tail->offset == offsetof(TEST_STRUCT, str2));

  // Write another string in buffer 1 that causes a buffer reallocation.
  yr_arena_write_string(arena, 1, "aaaaaaaaaaa", NULL);

  assert_true_expr(strcmp(s->str1, "foo") == 0);
  assert_true_expr(strcmp(s->str2, "bar") == 0);

  YR_STREAM stream;
  FILE* fh = fopen("test-arena-stream", "w+");

  assert_true_expr(fh != NULL);

  stream.user_data = fh;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;
  stream.read = (YR_STREAM_READ_FUNC) fread;

  if (yr_arena_save_stream(arena, &stream) != ERROR_SUCCESS)
    exit(EXIT_FAILURE);

  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  assert_true_expr(strcmp(s->str1, "foo") == 0);
  assert_true_expr(strcmp(s->str2, "bar") == 0);

  yr_arena_release(arena);

  result = yr_arena_load_stream(&stream, &arena);
  assert_true_expr(result == ERROR_SUCCESS);

  ref.buffer_id = 0;
  ref.offset = 0;

  s = (TEST_STRUCT*) yr_arena_ref_to_ptr(arena, &ref);

  assert_true_expr(strcmp(s->str1, "foo") == 0);
  assert_true_expr(strcmp(s->str2, "bar") == 0);

  fclose(fh);
  yr_arena_release(arena);
  yr_finalize();
}

// A relocation entry in a saved arena references a buffer by id. When loading
// an untrusted stream that id must be validated against num_buffers before the
// buffer is touched, otherwise the loader reads out of bounds.
static void corrupt_stream_tests()
{
  yr_initialize();

  uint8_t data[64];
  size_t n = 0;

  // YR_ARENA_FILE_HEADER: magic, version, num_buffers.
  memcpy(data + n, "YARA", 4); n += 4;
  data[n++] = YR_ARENA_FILE_VERSION;
  data[n++] = 1;

  // One YR_ARENA_FILE_BUFFER: offset (8) and size (4).
  uint64_t offset = 0; memcpy(data + n, &offset, 8); n += 8;
  uint32_t size = 8; memcpy(data + n, &size, 4); n += 4;

  // Buffer 0 contents.
  memset(data + n, 0, 8); n += 8;

  // A relocation entry pointing at a buffer id well beyond num_buffers.
  uint32_t buffer_id = 0x41414141;
  uint32_t reloc_offset = 0;
  memcpy(data + n, &buffer_id, 4); n += 4;
  memcpy(data + n, &reloc_offset, 4); n += 4;

  FILE* fh = fopen("test-arena-corrupt-stream", "w+b");
  assert_true_expr(fh != NULL);
  fwrite(data, 1, n, fh);
  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  YR_STREAM stream;
  stream.user_data = fh;
  stream.read = (YR_STREAM_READ_FUNC) fread;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

  YR_ARENA* arena = NULL;
  assert_true_expr(
      yr_arena_load_stream(&stream, &arena) == ERROR_CORRUPT_FILE);

  fclose(fh);
  yr_finalize();
}

// Each relocation entry occupies an 8-byte YR_ARENA_REF in the buffer, so the
// loader reads sizeof(YR_ARENA_REF) bytes at the entry offset. The bound check
// must reserve that many bytes; reserving only sizeof(void*) (4 bytes on 32-bit
// builds) lets an offset in the last 8 bytes of a fully used buffer through and
// the 8-byte read then runs past the allocation.
static void corrupt_reloc_offset_tests()
{
  yr_initialize();

  // Matches the initial buffer size used by yr_arena_load_stream so the loaded
  // buffer's used size equals its allocated size, leaving no slack after it.
  const uint32_t buffer_size = 10485;

  uint8_t data[6 + 12 + 10485 + 8];
  size_t n = 0;

  // YR_ARENA_FILE_HEADER: magic, version, num_buffers.
  memcpy(data + n, "YARA", 4); n += 4;
  data[n++] = YR_ARENA_FILE_VERSION;
  data[n++] = 1;

  // One YR_ARENA_FILE_BUFFER: offset (8) and size (4).
  uint64_t offset = 0; memcpy(data + n, &offset, 8); n += 8;
  memcpy(data + n, &buffer_size, 4); n += 4;

  // Buffer 0 contents.
  memset(data + n, 0, buffer_size); n += buffer_size;

  // A relocation entry pointing 4 bytes before the end of the buffer. The
  // 8-byte YR_ARENA_REF read at this offset reaches 4 bytes past the buffer,
  // which the old sizeof(void*) bound failed to reject on 32-bit builds.
  uint32_t buffer_id = 0;
  uint32_t reloc_offset = buffer_size - 4;
  memcpy(data + n, &buffer_id, 4); n += 4;
  memcpy(data + n, &reloc_offset, 4); n += 4;

  FILE* fh = fopen("test-arena-corrupt-reloc", "w+b");
  assert_true_expr(fh != NULL);
  fwrite(data, 1, n, fh);
  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  YR_STREAM stream;
  stream.user_data = fh;
  stream.read = (YR_STREAM_READ_FUNC) fread;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

  YR_ARENA* arena = NULL;
  assert_true_expr(
      yr_arena_load_stream(&stream, &arena) == ERROR_CORRUPT_FILE);

  fclose(fh);
  yr_finalize();
}

// The 8 bytes a relocation entry points at hold a YR_ARENA_REF that the loader
// converts back into a pointer with yr_arena_ref_to_ptr. That target buffer_id
// and offset also come from the stream, but yr_arena_get_ptr only guards them
// with assert (a no-op under NDEBUG), so an out-of-range target indexes past
// the buffers array. The loader must reject it as corrupt instead.
static void corrupt_reloc_target_tests()
{
  yr_initialize();

  uint8_t data[64];
  size_t n = 0;

  // YR_ARENA_FILE_HEADER: magic, version, num_buffers.
  memcpy(data + n, "YARA", 4); n += 4;
  data[n++] = YR_ARENA_FILE_VERSION;
  data[n++] = 1;

  // One YR_ARENA_FILE_BUFFER: offset (8) and size (4).
  uint64_t offset = 0; memcpy(data + n, &offset, 8); n += 8;
  uint32_t size = 8; memcpy(data + n, &size, 4); n += 4;

  // Buffer 0 contents: a YR_ARENA_REF whose buffer_id is well beyond
  // num_buffers. This is the relocation target read back during loading.
  uint32_t target_buffer_id = 0x41414141;
  uint32_t target_offset = 0;
  memcpy(data + n, &target_buffer_id, 4); n += 4;
  memcpy(data + n, &target_offset, 4); n += 4;

  // A valid relocation entry pointing at the start of buffer 0, so the loader
  // reaches the bad target ref stored in the buffer.
  uint32_t buffer_id = 0;
  uint32_t reloc_offset = 0;
  memcpy(data + n, &buffer_id, 4); n += 4;
  memcpy(data + n, &reloc_offset, 4); n += 4;

  FILE* fh = fopen("test-arena-corrupt-reloc-target", "w+b");
  assert_true_expr(fh != NULL);
  fwrite(data, 1, n, fh);
  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  YR_STREAM stream;
  stream.user_data = fh;
  stream.read = (YR_STREAM_READ_FUNC) fread;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

  YR_ARENA* arena = NULL;
  assert_true_expr(
      yr_arena_load_stream(&stream, &arena) == ERROR_CORRUPT_FILE);

  fclose(fh);
  yr_finalize();
}

static void corrupt_num_buffers_tests()
{
  yr_initialize();

  // Test loading with num_buffers = 0
  uint8_t data[6] = {'Y', 'A', 'R', 'A', YR_ARENA_FILE_VERSION, 0};
  FILE* fh = fopen("test-arena-corrupt-num0", "w+b");
  assert_true_expr(fh != NULL);
  fwrite(data, 1, sizeof(data), fh);
  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  YR_STREAM stream;
  stream.user_data = fh;
  stream.read = (YR_STREAM_READ_FUNC) fread;
  stream.write = (YR_STREAM_WRITE_FUNC) fwrite;

  YR_ARENA* arena = NULL;
  assert_true_expr(
      yr_arena_load_stream(&stream, &arena) == ERROR_CORRUPT_FILE);

  fclose(fh);

  // Test loading with num_buffers > YR_MAX_ARENA_BUFFERS
  data[5] = YR_MAX_ARENA_BUFFERS + 1;
  fh = fopen("test-arena-corrupt-num-max", "w+b");
  assert_true_expr(fh != NULL);
  fwrite(data, 1, sizeof(data), fh);
  fflush(fh);
  fseek(fh, 0, SEEK_SET);

  stream.user_data = fh;
  assert_true_expr(
      yr_arena_load_stream(&stream, &arena) == ERROR_CORRUPT_FILE);

  fclose(fh);
  yr_finalize();
}

// yr_arena_get_ptr, yr_arena_get_current_offset and yr_arena_ref_to_ptr used to
// enforce their bounds with assert only, which makes the checks disappear when
// NDEBUG is defined. Every reference reaching them can originate from a
// compiled rules file read by yr_arena_load_stream, so an out-of-range
// reference has to resolve to NULL instead of to a pointer outside the arena.
static void out_of_range_reference_tests()
{
  YR_ARENA* arena;

  yr_initialize();

  assert_true_expr(yr_arena_create(2, 10, &arena) == ERROR_SUCCESS);

  YR_ARENA_REF ref;

  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, 5, &ref) == ERROR_SUCCESS);

  // In-range accesses keep working, including the offset one past the last
  // allocated byte, which is where the next allocation in the buffer starts.
  assert_true_expr(yr_arena_get_ptr(arena, 0, 0) != NULL);
  assert_true_expr(yr_arena_get_ptr(arena, 0, ref.offset) != NULL);
  assert_true_expr(yr_arena_get_ptr(arena, 0, 5) != NULL);
  assert_true_expr(yr_arena_get_current_offset(arena, 0) == 5);

  // A buffer that has not been allocated yet still yields NULL.
  assert_true_expr(yr_arena_get_ptr(arena, 1, 0) == NULL);

  // A buffer number the arena does not have must not index past the end of
  // the buffers array, whether it is just out of range or far out of range.
  assert_true_expr(yr_arena_get_ptr(arena, 2, 0) == NULL);
  assert_true_expr(yr_arena_get_ptr(arena, YR_MAX_ARENA_BUFFERS, 0) == NULL);
  assert_true_expr(yr_arena_get_ptr(arena, UINT32_MAX, 0) == NULL);
  assert_true_expr(yr_arena_get_current_offset(arena, 2) == 0);
  assert_true_expr(yr_arena_get_current_offset(arena, YR_MAX_ARENA_BUFFERS) == 0);

  // An offset past the end of the data written to the buffer must not produce
  // a pointer past the end of the buffer.
  assert_true_expr(yr_arena_get_ptr(arena, 0, 6) == NULL);
  assert_true_expr(yr_arena_get_ptr(arena, 0, UINT32_MAX) == NULL);

  // The same holds when the reference is resolved through
  // yr_arena_ref_to_ptr, which is how a reference stored inside a loaded arena
  // is turned back into a pointer.
  YR_ARENA_REF bad_ref;

  bad_ref.buffer_id = 0x41414141;
  bad_ref.offset = 0;
  assert_true_expr(yr_arena_ref_to_ptr(arena, &bad_ref) == NULL);

  bad_ref.buffer_id = 0;
  bad_ref.offset = 6;
  assert_true_expr(yr_arena_ref_to_ptr(arena, &bad_ref) == NULL);

  bad_ref.offset = 5;
  assert_true_expr(yr_arena_ref_to_ptr(arena, &bad_ref) != NULL);

  yr_arena_release(arena);
  yr_finalize();
}

// An allocation whose size overflows the sum with the bytes already used in the
// buffer must be rejected. It used to wrap around, leave the buffer smaller
// than the caller asked for and corrupt the running offset.
static void oversized_allocation_tests()
{
  const size_t size_max = (size_t) -1;

  YR_ARENA* arena;

  yr_initialize();

  assert_true_expr(yr_arena_create(1, 10, &arena) == ERROR_SUCCESS);

  YR_ARENA_REF ref;

  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, 5, &ref) == ERROR_SUCCESS);

  // size_max on its own wraps the growth loop, and size_max - 4 is the first
  // size that overflows 5 + size, so both have to be refused.
  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, size_max, &ref) ==
      ERROR_INSUFFICIENT_MEMORY);
  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, size_max - 4, &ref) ==
      ERROR_INSUFFICIENT_MEMORY);

  // The rejected allocations must not have disturbed the buffer.
  assert_true_expr(yr_arena_get_current_offset(arena, 0) == 5);

  // A reasonable allocation still succeeds afterwards.
  assert_true_expr(
      yr_arena_allocate_memory(arena, 0, 5, &ref) == ERROR_SUCCESS);
  assert_true_expr(ref.offset == 5);
  assert_true_expr(yr_arena_get_current_offset(arena, 0) == 10);

  yr_arena_release(arena);
  yr_finalize();
}

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  basic_tests();
  advanced_tests();
  corrupt_stream_tests();
  corrupt_reloc_offset_tests();
  corrupt_reloc_target_tests();
  corrupt_num_buffers_tests();
  out_of_range_reference_tests();
  oversized_allocation_tests();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
