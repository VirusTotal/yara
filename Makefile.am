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

yara_SOURCES = args.c args.h threading.c threading.h yara.c
yara_LDADD = libyara/.libs/libyara.a

yarac_SOURCES = args.c args.h yarac.c
yarac_LDADD = libyara/.libs/libyara.a

TESTS = $(check_PROGRAMS)
check_PROGRAMS = test-alignment test-rules test-pe test-elf test-version

# The -fsanitize=address option makes test-exception fail. Include the test
# only if the option is not enabled.

if !ADDRESS_SANITIZER
check_PROGRAMS+=test-exception
endif

test_alignment_SOURCES = tests/test-alignment.c
test_rules_SOURCES = tests/test-rules.c tests/util.c
test_rules_LDADD = libyara/.libs/libyara.a
test_pe_SOURCES = tests/test-pe.c tests/util.c
test_pe_LDADD = libyara/.libs/libyara.a
test_elf_SOURCES = tests/test-elf.c tests/util.c
test_elf_LDADD = libyara/.libs/libyara.a
test_exception_SOURCES = tests/test-exception.c tests/util.c
test_exception_LDADD = libyara/.libs/libyara.a
test_version_SOURCES = tests/test-version.c

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md
