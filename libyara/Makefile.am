AM_YFLAGS = -d

CFLAGS=-g -O0

ACLOCAL_AMFLAGS=-I m4

include_HEADERS = yara.h

lib_LTLIBRARIES = libyara.la

libyara_la_SOURCES = \
  ahocorasick.c \
  ahocorasick.h \
  arena.c \
  arena.h \
  compiler.c \
  compiler.h \
  elf.h \
  exec.c \
  exec.h \
  exefiles.c \
  exefiles.h \
  filemap.c \
  filemap.h \
  grammar.y \
  hash.c \
  hash.h \
  lex.h \
  lex.l \
  libyara.c \
  mem.c \
  mem.h \
  parser.c \
  parser.h \
  pe.h \
  proc.c \
  proc.h \
  rules.c \
  rules.h \
  regex.h \
  sizedstr.h \
  utils.c \
  utils.h

SUBDIRS = regex

libyara_la_LIBADD = regex/libregex.la
#libyara_la_LIBADD = $(LTLIBOBJS) re/.libs/libyara.la
