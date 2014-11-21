AM_CFLAGS=-O3 -std=gnu99 -Wall -I$(srcdir)/libyara/include

# Build the library in the hand subdirectory first.
SUBDIRS = libyara argparse
DIST_SUBDIRS = libyara argparse

ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS = yara yarac

yara_SOURCES = threading.c threading.h yara.c
yara_LDADD = libyara/.libs/libyara.a argparse/libargparse.a

yarac_SOURCES = yarac.c
yarac_LDADD = libyara/.libs/libyara.a argparse/libargparse.a

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md

