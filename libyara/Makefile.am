YFLAGS=-d

include_HEADERS = yara.h

lib_LTLIBRARIES = libyara.la

libyara_la_SOURCES = \
  grammar.y \
  lex.l \
  ast.c \
  scan.c \
  filemap.c \
  error.c \
  compile.c \
  eval.c \
  pefile.c \
  xtoi.c \
  mem.c \
  ast.h \
  error.h \
  compile.h \
  eval.h \
  filemap.h \
  pe.h \
  xtoi.h \
  pefile.h \
  sizedstr.h \
  mem.h

libyara_la_LIBDADD = /usr/local/lib/libpcre.la