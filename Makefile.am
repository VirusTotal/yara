AM_CFLAGS=-Wall -I$(srcdir)/libyara/include

if GCOV

check:
	@tests/gcov-summary

MOSTLYCLEANFILES = {cli,tests}/*.gc{no,da,ov}
AM_CFLAGS+=-O0 -g -ftest-coverage -fprofile-arcs

else

if DEBUG
AM_CFLAGS+=-g
endif

if OPTIMIZATION
AM_CFLAGS+=-O3
else
AM_CFLAGS+=-O0
endif

endif

if ADDRESS_SANITIZER
AM_CFLAGS+=-fsanitize=address
endif

# Build the library in the hand subdirectory first.
SUBDIRS = libyara
DIST_SUBDIRS = libyara

ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS = yara yarac

yara_SOURCES = \
  cli/args.c \
  cli/args.h \
  cli/common.h \
  cli/threading.c \
  cli/threading.h \
  cli/yara.c

yara_LDADD = -Llibyara/.libs -lyara
yara_DEPENDENCIES = libyara/.libs/libyara.la

yarac_SOURCES = \
   cli/args.c \
   cli/args.h \
   cli/common.h \
   cli/yarac.c

yarac_LDADD = -Llibyara/.libs -lyara
yarac_DEPENDENCIES = libyara/.libs/libyara.la

tests_mapper_SOURCES = tests/mapper.c
tests_mapper_CFLAGS = -O0

test_alignment_SOURCES = tests/test-alignment.c tests/util.c
test_alignment_LDADD = libyara/.libs/libyara.a
test_arena_SOURCES = tests/test-arena.c tests/util.c
test_arena_LDADD = libyara/.libs/libyara.a
test_atoms_SOURCES = tests/test-atoms.c tests/util.c
test_atoms_LDADD = libyara/.libs/libyara.a
test_rules_SOURCES = tests/test-rules.c tests/util.c
test_rules_LDADD = libyara/.libs/libyara.a
if POSIX
EXTRA_test_rules_DEPENDENCIES = tests/mapper$(EXEEXT)
endif
test_pe_SOURCES = tests/test-pe.c tests/util.c
test_pe_LDADD = libyara/.libs/libyara.a
test_elf_SOURCES = tests/test-elf.c tests/util.c
test_elf_LDADD = libyara/.libs/libyara.a
test_version_SOURCES = tests/test-version.c tests/util.c
test_version_LDADD = libyara/.libs/libyara.a
test_api_SOURCES = tests/test-api.c tests/util.c
test_api_LDADD = libyara/.libs/libyara.a
test_bitmask_SOURCES = tests/test-bitmask.c tests/util.c
test_bitmask_LDADD = libyara/.libs/libyara.a
test_math_SOURCES = tests/test-math.c tests/util.c
test_math_LDADD = libyara/.libs/libyara.a
test_stack_SOURCES = tests/test-stack.c tests/util.c
test_stack_LDADD = libyara/.libs/libyara.a
test_re_split_SOURCES = tests/test-re-split.c tests/util.c
test_re_split_LDADD = libyara/.libs/libyara.a
test_async_SOURCES = tests/test-async.c tests/util.c
test_async_LDADD = libyara/.libs/libyara.a

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = TOP_SRCDIR=$(top_srcdir) TOP_BUILDDIR=$(top_builddir)

check_PROGRAMS = \
  test-arena \
  test-alignment \
  test-atoms \
  test-api \
  test-rules \
  test-pe \
  test-elf \
  test-version \
  test-bitmask \
  test-math \
  test-stack \
  test-re-split \
  test-async

EXTRA_PROGRAMS = tests/mapper
CLEANFILES = tests/mapper$(EXEEXT)

if POSIX
# The -fsanitize=address option makes test-exception fail. Include the test
# only if the option is not enabled.
if !ADDRESS_SANITIZER
check_PROGRAMS+=test-exception
test_exception_SOURCES = tests/test-exception.c tests/util.c
test_exception_LDADD = libyara/.libs/libyara.a
endif
endif

if MACHO_MODULE
check_PROGRAMS+=test-macho
test_macho_SOURCES = tests/test-macho.c tests/util.c
test_macho_LDADD = libyara/.libs/libyara.a
endif

if DEX_MODULE
check_PROGRAMS+=test-dex
test_dex_SOURCES = tests/test-dex.c tests/util.c
test_dex_LDADD = libyara/.libs/libyara.a
endif

if DOTNET_MODULE
check_PROGRAMS+=test-dotnet
test_dotnet_SOURCES = tests/test-dotnet.c tests/util.c
test_dotnet_LDADD = libyara/.libs/libyara.a
endif

if PB_TESTS_MODULE
check_PROGRAMS+=test-pb
test_pb_SOURCES = tests/test-pb.c tests/util.c
test_pb_LDADD = libyara/.libs/libyara.a
endif

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md bootstrap.sh
