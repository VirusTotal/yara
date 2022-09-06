# ABI_VERSION is passed to libtool as --version-number $(ABI_VERSION). This is
# not related to YARA's release version, this is used for tracking changes in
# the ABI, not in the project as a whole.
#
# The three number mean [current]:[revision]:[age], and they should updated as
# follow:
#
# 1. With every release increment "revision".
#
# 2. If any interfaces have been added, removed, or changed since the last
#    update, increment "current" and set "revision" to 0.
#
# 3. If the changes in the interface were backward compatible (i.e: only adding
#    new APIs) increment "age", or set it to 0 if otherwise.
#
# See https://autotools.io/libtool/version.html for more details.
#
ABI_VERSION = 9:0:1

# Rules for generating YARA modules from .proto files. For each .proto file
# three files are generated: .c, .pb-c.c, and .pb-c.h. The .c file is generated
# by protoc-gen-yara and the other two by protoc-gen-c. This is done only if
# protoc is found, if not, files already in the repository are used instead
# of generating fresh ones from the .proto file.
#
if PROTOC
SUFFIXES = .proto .pb-c.c .pb-c.h .c
.proto.pb-c.c:
		$(PROTOC) --c_out=$(builddir) $^ -Ipb/ -I=$(srcdir)

.proto.pb-c.h:
		$(PROTOC) --c_out=$(builddir) $^ -Ipb/ -I=$(srcdir)

.proto.c:
		$(PROTOC) --c_out=$(builddir) $^ -Ipb/ -I=$(srcdir)
endif

MODULES =  modules/tests/tests.c

MODULES += modules/elf/elf.c

MODULES += modules/math/math.c

MODULES += modules/time/time.c

MODULES += modules/pe/pe.c
MODULES += modules/pe/pe_utils.c

MODULES += modules/console/console.c

MODULES += modules/string/string.c

if CUCKOO_MODULE
MODULES += modules/cuckoo/cuckoo.c
endif

if MAGIC_MODULE
MODULES += modules/magic/magic.c
endif

if HASH_MODULE
MODULES += modules/hash/hash.c
endif

if DOTNET_MODULE
MODULES += modules/dotnet/dotnet.c
endif

if MACHO_MODULE
MODULES += modules/macho/macho.c
endif

if DEX_MODULE
MODULES += modules/dex/dex.c
endif

if PB_TESTS_MODULE
MODULES += modules/pb_tests/pb_tests.c
MODULES += modules/pb_tests/pb_tests.pb-c.c
endif

if AUTHENTICODE_MODULE
MODULES += modules/pe/authenticode-parser/authenticode.c
MODULES += modules/pe/authenticode-parser/certificate.c
MODULES += modules/pe/authenticode-parser/helper.c
MODULES += modules/pe/authenticode-parser/countersignature.c
MODULES += modules/pe/authenticode-parser/structs.c
endif

#
# Add your modules here:
#
# MODULES += modules/yourmodule.c
#

#
# When bison is used in POSIX yacc emulation mode (-y/--yacc option) it
# produces warnings if we use Bison-specific features that are not supported
# by yacc. With -Wno-yacc we turn off those warnings. Ideally we should call
# bison without the -y/--yacc option, but autoconf insists on using bison in
# yacc compatibility mode because of AC_PROG_YACC, and AC_PROG_BISON doesn't
# exist.
#
AM_YFLAGS=-d -Wno-yacc

AM_CFLAGS=-Wall -Wno-deprecated-declarations \
	-D_GNU_SOURCE \
	-I$(srcdir)/include

if GCOV
MOSTLYCLEANFILES = {.,proc,modules/*}/*.gc{no,da,ov}
AM_CFLAGS+=-O0 -g -ftest-coverage -fprofile-arcs
else

if DEBUG
AM_CFLAGS+=-g
endif

if OPTIMIZATION
AM_CFLAGS+=-O3
else
AM_CFLAGS+=-O0
endif

endif


if ADDRESS_SANITIZER
AM_CFLAGS+=-fsanitize=address
endif

if UB_SANITIZER
AM_CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=undefined
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
	include/yara/base64.h \
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
	include/yara/notebook.h \
	include/yara/object.h \
	include/yara/parser.h \
	include/yara/proc.h \
	include/yara/re.h \
	include/yara/rules.h \
	include/yara/scan.h \
	include/yara/scanner.h \
	include/yara/simple_str.h \
	include/yara/sizedstr.h \
	include/yara/stack.h \
	include/yara/stopwatch.h \
	include/yara/stream.h \
	include/yara/strutils.h \
	include/yara/threading.h \
	include/yara/types.h \
	include/yara/unaligned.h \
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

dist_noinst_DATA = pb/yara.proto


lib_LTLIBRARIES = libyara.la

libyara_la_LDFLAGS = -version-number $(ABI_VERSION)

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
	base64.c \
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
	notebook.c \
	object.c \
	parser.c \
	proc.c \
	re.c \
	re_grammar.y \
	re_lexer.l \
	rules.c \
	scan.c \
	scanner.c \
	simple_str.c \
	sizedstr.c \
	stack.c \
	stopwatch.c \
	strutils.c \
	stream.c \
	tlshc/tlsh.c \
	tlshc/tlsh_impl.c \
	tlshc/tlsh_util.c \
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
