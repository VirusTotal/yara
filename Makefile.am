AM_CFLAGS=-O3 -std=gnu99 -Wall -I$(srcdir)/libyara/include

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
check_PROGRAMS = test-alignment test-rules test-pe test-elf test-exception test-context-extvar
test_alignment_SOURCES = tests/test-alignment.c
test_rules_SOURCES = tests/test-rules.c tests/util.c
test_rules_LDADD = libyara/.libs/libyara.a
test_pe_SOURCES = tests/test-pe.c tests/util.c
test_pe_LDADD = libyara/.libs/libyara.a
test_elf_SOURCES = tests/test-elf.c tests/util.c
test_elf_LDADD = libyara/.libs/libyara.a
test_exception_SOURCES = tests/test-exception.c tests/util.c
test_exception_LDADD = libyara/.libs/libyara.a
test_context_extvar_SOURCES = tests/test-context-extvar.c tests/util.c
test_context_extvar_LDADD = libyara/.libs/libyara.a

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md

