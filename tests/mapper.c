#include <errno.h>
#include <error.h>
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
    for (int i = 0; i < sizeof(str) - 1; i++) buf[i] = str[sizeof(str) - i - 2];
  }
  else
  {
    fprintf(stderr, "unknown argument <%s>\n", argv[1]);
    exit(1);
  }
  sleep(3600);
}
