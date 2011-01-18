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
  pefile.c \
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
  xtoi.h \
  pefile.h \
  sizedstr.h \
  mem.h \
  proc.h \
  weight.h

libyara_la_LIBDADD = /usr/local/lib/libpcre.la