
MODULES =  modules/tests.c
MODULES += modules/pe.c
MODULES += modules/elf.c
MODULES += modules/math.c

if CUCKOO
MODULES += modules/cuckoo.c
endif

if MAGIC
MODULES += modules/magic.c
endif

if HASH
MODULES += modules/hash.c
endif

#
# Add your modules here:
#
# MODULES += modules/yourmodule.c
#

AM_YFLAGS=-d

AM_CFLAGS=-O3 -Wall -Wno-deprecated-declarations -std=gnu99 -I$(srcdir)/include

if GCC
AM_CFLAGS+=-fvisibility=hidden
endif

ACLOCAL_AMFLAGS=-I m4

include_HEADERS = include/yara.h

yaraincludedir = $(includedir)/yara
yarainclude_HEADERS = \
  include/yara/ahocorasick.h \
  include/yara/atoms.h \
  include/yara/limits.h \
  include/yara/re.h \
  include/yara/arena.h \
  include/yara/sizedstr.h \
  include/yara/types.h \
  include/yara/hash.h \
  include/yara/exec.h \
  include/yara/scan.h \
  include/yara/rules.h \
  include/yara/error.h \
  include/yara/utils.h \
  include/yara/filemap.h \
  include/yara/compiler.h \
  include/yara/modules.h \
  include/yara/object.h \
  include/yara/strutils.h \
  include/yara/stream.h \
  include/yara/libyara.h

lib_LTLIBRARIES = libyara.la

libyara_la_LDFLAGS = -version-number 3:4:0

libyara_la_SOURCES = \
  $(MODULES) \
  grammar.y \
  ahocorasick.c \
  arena.c \
  atoms.c \
  compiler.c \
  exec.c \
  exefiles.c \
  exefiles.h \
  filemap.c \
  filemap.h \
  hash.c \
  hash.h \
  hex_grammar.y \
  hex_lexer.h \
  hex_lexer.l \
  lexer.h \
  lexer.l \
  libyara.c \
  mem.c \
  mem.h \
  modules.c \
  modules.h \
  object.c \
  object.h \
  parser.c \
  parser.h \
  pe.h \
  proc.c \
  proc.h \
  re.c \
  re.h \
  re_grammar.y \
  re_lexer.h \
  re_lexer.l \
  rules.c \
  scan.c \
  sizedstr.c \
  sizedstr.h \
  strutils.c \
  strutils.h \
  stream.c \
  stream.h \
  utils.h

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = yara.pc

yara.pc: yara.pc.in
		sed -e 's![@]prefix[@]!$(prefix)!g' \
		    -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
		    -e 's![@]includedir[@]!$(includedir)!g' \
		    -e 's![@]libdir[@]!$(libdir)!g' \
		    -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
		    $(srcdir)/yara.pc.in > $@
