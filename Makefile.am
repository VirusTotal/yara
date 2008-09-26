
# Build the library in the hand subdirectory first.
SUBDIRS = libyara

AM_CPPFLAGS = -I$(srcdir)/libyara


bin_PROGRAMS = yara
yara_SOURCES = yara.c
yara_LDADD = libyara/.libs/libyara.a

# man page
man_MANS = doc/yara.1
