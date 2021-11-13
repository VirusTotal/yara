#pragma once

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif 

#ifdef _MSC_VER
#include <io.h>
#include <share.h>
#endif 

#include <float.h>
#include <math.h>

#include <setjmp.h>
