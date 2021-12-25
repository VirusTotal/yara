/*
Copyright (c) 2021. The YARA Authors. All Rights Reserved.

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char str[] = "!dlrow ,olleH";
int fd;

char* map_file(char* path)
{
  if ((fd = open(path, O_RDONLY)) < 0)
  {
    fprintf(stderr, "open: %s: %s\n", path, strerror(errno));
    exit(1);
  }
  char* rv = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (rv == NULL)
  {
    fprintf(stderr, "mmap: %s: failed: %s\n", path, strerror(errno));
    exit(1);
  }
  close(fd);
  return rv;
}

int main(int argc, char** argv)
{
  char* buf;

  if (argc < 2)
  {
    fprintf(stderr, "no argument\n");
    exit(1);
  }
  else if (strcmp(argv[1], "open") == 0)
  {
    if (argc < 3)
      exit(1);

    printf("%s: %s %s\n", argv[0], argv[1], argv[2]);
    buf = map_file(argv[2]);
  }
  else if (strcmp(argv[1], "patch") == 0)
  {
    if (argc < 3)
      exit(1);

    printf("%s: %s %s\n", argv[0], argv[1], argv[2]);
    buf = map_file(argv[2]);

    for (int i = 0; i < sizeof(str) - 1; i++)
    {
      buf[i] = str[sizeof(str) - i - 2];
    }
  }
  else
  {
    fprintf(stderr, "unknown argument <%s>\n", argv[1]);
    exit(1);
  }
  sleep(3600);
}
