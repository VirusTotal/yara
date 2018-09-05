
MODULES =  modules/tests.c
MODULES += modules/pe.c
MODULES += modules/elf.c
MODULES += modules/math.c
MODULES += modules/time.c

# This isn't really a module, but needs to be compiled with them.
MODULES += modules/pe_utils.c

if CUCKOO_MODULE
MODULES += modules/cuckoo.c
endif

if MAGIC_MODULE
MODULES += modules/magic.c
endif

if HASH_MODULE
MODULES += modules/hash.c
endif

if DOTNET_MODULE
MODULES += modules/dotnet.c
endif

if MACHO_MODULE
MODULES += modules/macho.c
endif

if DEX_MODULE
MODULES += modules/dex.c
endif

#
# Add your modules here:
#
# MODULES += modules/yourmodule.c
#

AM_YFLAGS=-d

AM_CFLAGS=-Wall -Wno-deprecated-declarations -std=gnu99 -I$(srcdir)/include

if DEBUG
AM_CFLAGS+=-g
endif

if OPTIMIZATION
AM_CFLAGS+=-O3
else
AM_CFLAGS+=-O0
endif

if ADDRESS_SANITIZER
AM_CFLAGS+=-fsanitize=address
endif

if GCC
AM_CFLAGS+=-fvisibility=hidden
endif

ACLOCAL_AMFLAGS=-I m4

include_HEADERS = include/yara.h

yaraincludedir = $(includedir)/yara
yarainclude_HEADERS = \
  include/yara/ahocorasick.h \
  include/yara/arena.h \
  include/yara/atoms.h \
  include/yara/bitmask.h \
  include/yara/compiler.h \
  include/yara/error.h \
  include/yara/exec.h \
  include/yara/exefiles.h \
  include/yara/filemap.h \
  include/yara/hash.h \
  include/yara/integers.h \
  include/yara/libyara.h \
  include/yara/limits.h \
  include/yara/mem.h \
  include/yara/modules.h \
  include/yara/object.h \
  include/yara/parser.h \
  include/yara/proc.h \
  include/yara/re.h \
  include/yara/rules.h \
  include/yara/scan.h \
  include/yara/scanner.h \
  include/yara/sizedstr.h \
  include/yara/stopwatch.h \
  include/yara/stream.h \
  include/yara/strutils.h \
  include/yara/threading.h \
  include/yara/types.h \
  include/yara/utils.h

noinst_HEADERS = \
  crypto.h \
  exception.h \
  include/yara/dotnet.h \
  include/yara/elf.h \
  include/yara/endian.h \
  include/yara/globals.h \
  include/yara/hex_lexer.h \
  include/yara/lexer.h \
  include/yara/pe.h \
  include/yara/pe_utils.h \
  include/yara/re_lexer.h \
  modules/module_list


lib_LTLIBRARIES = libyara.la

libyara_la_LDFLAGS = -version-number 3:8:1

BUILT_SOURCES = \
  lexer.c \
  hex_lexer.c \
  re_lexer.c \
  grammar.c \
  hex_grammar.c \
  re_grammar.c

libyara_la_SOURCES = \
  $(MODULES) \
  grammar.y \
  ahocorasick.c \
  arena.c \
  atoms.c \
  bitmask.c \
  compiler.c \
  endian.c \
  exec.c \
  exefiles.c \
  filemap.c \
  hash.c \
  hex_grammar.y \
  hex_lexer.l \
  lexer.l \
  libyara.c \
  mem.c \
  modules.c \
  object.c \
  parser.c \
  proc.c \
  re.c \
  re_grammar.y \
  re_lexer.l \
  rules.c \
  scan.c \
  scanner.c \
  sizedstr.c \
  stopwatch.c \
  strutils.c \
  stream.c \
  threading.c


if USE_WINDOWS_PROC
libyara_la_SOURCES += proc/windows.c
endif

if USE_LINUX_PROC
libyara_la_SOURCES += proc/linux.c
endif

if USE_FREEBSD_PROC
libyara_la_SOURCES += proc/freebsd.c
endif

if USE_OPENBSD_PROC
libyara_la_SOURCES += proc/openbsd.c
endif

if USE_MACH_PROC
libyara_la_SOURCES += proc/mach.c
endif

if USE_NO_PROC
libyara_la_SOURCES += proc/none.c
endif

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = yara.pc
