AM_CFLAGS=-g -O4 -I$(srcdir)/libyara

# Build the library in the hand subdirectory first.
SUBDIRS = libyara
DIST_SUBDIRS = libyara

ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS = yara yarac

yara_SOURCES = threading.c yara.c
yara_LDADD = libyara/.libs/libyara.a

yarac_SOURCES = yarac.c
yarac_LDADD = libyara/.libs/libyara.a

# man page
man1_MANS = yara.man

EXTRA_DIST = $(man1_MANS) REVISION

