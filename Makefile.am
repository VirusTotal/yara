AM_CFLAGS=-std=gnu99 -Wall -I$(srcdir)/libyara/include

if DEBUG
AM_CFLAGS+=-g
endif

if OPTIMIZATION
AM_CFLAGS+=-O3
else
AM_CFLAGS+=-O0
endif

if ADDRESS_SANITIZER
AM_CFLAGS+=-fsanitize=address
endif

# Build the library in the hand subdirectory first.
SUBDIRS = libyara
DIST_SUBDIRS = libyara

ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS = yara yarac

yara_SOURCES = args.c args.h common.h threading.c threading.h yara.c
yara_LDADD = -Llibyara/.libs -lyara

yarac_SOURCES = args.c args.h common.h yarac.c
yarac_LDADD = -Llibyara/.libs -lyara

test_alignment_SOURCES = tests/test-alignment.c
test_atoms_SOURCES = tests/test-atoms.c tests/util.c libyara/atoms.c
test_atoms_LDADD = libyara/.libs/libyara.a
test_rules_SOURCES = tests/test-rules.c tests/util.c
test_rules_LDADD = libyara/.libs/libyara.a
test_pe_SOURCES = tests/test-pe.c tests/util.c
test_pe_LDADD = libyara/.libs/libyara.a
test_elf_SOURCES = tests/test-elf.c tests/util.c
test_elf_LDADD = libyara/.libs/libyara.a
test_version_SOURCES = tests/test-version.c
test_api_LDADD = libyara/.libs/libyara.a
test_api_SOURCES = tests/test-api.c tests/util.c
test_bitmask_SOURCES = tests/test-bitmask.c
test_bitmask_LDADD = libyara/.libs/libyara.a
test_math_SOURCES = tests/test-math.c tests/util.c
test_math_LDADD = libyara/.libs/libyara.a

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = TOP_SRCDIR=$(top_srcdir)

check_PROGRAMS = test-alignment \
  test-atoms \
  test-api \
  test-rules \
  test-pe \
  test-elf \
  test-version \
  test-bitmask \
  test-math

if POSIX
# The -fsanitize=address option makes test-exception fail. Include the test
# only if the option is not enabled.
if !ADDRESS_SANITIZER
check_PROGRAMS+=test-exception
test_exception_SOURCES = tests/test-exception.c tests/util.c
test_exception_LDADD = -Llibyara/.libs -lyara
endif
endif

if MACHO_MODULE
check_PROGRAMS+=test-macho
test_macho_SOURCES = tests/test-macho.c tests/util.c
test_macho_LDADD = -Llibyara/.libs -lyara
endif

if DEX_MODULE
check_PROGRAMS+=test-dex
test_dex_SOURCES = tests/test-dex.c tests/util.c
test_dex_LDADD = -Llibyara/.libs -lyara
endif

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md bootstrap.sh
