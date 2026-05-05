/*
Copyright (c) 2026. The YARA Authors. All Rights Reserved.

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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

extern "C" {
#include <yara.h>
#include <yara/filemap.h>
}

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  yr_initialize();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  char temp_file[] = "/tmp/yara-filemap-fuzz-XXXXXX";
  int fd = mkstemp(temp_file);
  if (fd < 0) return 0;

  if (write(fd, data, size) != (ssize_t) size)
  {
    close(fd);
    unlink(temp_file);
    return 0;
  }

  YR_MAPPED_FILE mapped_file;
  if (yr_filemap_map_fd(fd, 0, size, &mapped_file) == ERROR_SUCCESS)
  {
    yr_filemap_unmap_fd(&mapped_file);
  }

  // Also try with some offsets and different sizes
  FuzzedDataProvider fdp(data, size);
  if (size > 0)
  {
      size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, size - 1);
      size_t map_size = fdp.ConsumeIntegralInRange<size_t>(0, size - offset);
      if (yr_filemap_map_fd(fd, offset, map_size, &mapped_file) == ERROR_SUCCESS)
      {
          yr_filemap_unmap_fd(&mapped_file);
      }
  }

  close(fd);
  unlink(temp_file);

  return 0;
}
