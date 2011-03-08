AM_YFLAGS = -d

ACLOCAL_AMFLAGS=-I m4

include_HEADERS = yara.h

lib_LTLIBRARIES = libyara.la

libyara_la_SOURCES = \
  grammar.y \
  lex.l \
  ast.c \
  scan.c \
  filemap.c \
  eval.c \
  exe.c \
  xtoi.c \
  mem.c \
  proc.c \
  weight.c \
  libyara.c \
  lex.h \
  ast.h \
  eval.h \
  filemap.h \
  pe.h \
  elf.h \
  exe.h \
  xtoi.h \
  sizedstr.h \
  mem.h \
  proc.h \
  regex.h \
  weight.h

SUBDIRS = regex

libyara_la_LIBADD = regex/libregex.la
#libyara_la_LIBADD = $(LTLIBOBJS) re/.libs/libyara.la
