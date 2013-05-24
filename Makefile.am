AM_CFLAGS=-g -O0

# Build the library in the hand subdirectory first.
SUBDIRS = libyara
DIST_SUBDIRS = libyara

AM_CPPFLAGS = -I$(srcdir)/libyara -g -O0
ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS = yara yarac

yara_SOURCES = yara.c
yara_LDADD = libyara/.libs/libyara.a

yarac_SOURCES = yarac.c
yarac_LDADD = libyara/.libs/libyara.a

# man page
man1_MANS = yara.man

EXTRA_DIST = $(man1_MANS) REVISION

if RE2
nodist_EXTRA_yara_SOURCES = force.cpp
endif

