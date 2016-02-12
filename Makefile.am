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
check_PROGRAMS = test-alignment test-syntax
test_alignment_SOURCES = tests/test-alignment.c
test_syntax_SOURCES = tests/test-syntax.c
test_syntax_LDADD = libyara/.libs/libyara.la

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md

