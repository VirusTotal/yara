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
ABI_VERSION = 10:0:0

AM_CFLAGS=-Wall -D_GNU_SOURCE -I$(srcdir)/libyara/include

#
# When bison is used in POSIX yacc emulation mode (-y/--yacc option) it
# produces warnings if we use Bison-specific features that are not supported
# by yacc. With -Wno-yacc we turn off those warnings. Ideally we should call
# bison without the -y/--yacc option, but autoconf insists on using bison in
# yacc compatibility mode because of AC_PROG_YACC, and AC_PROG_BISON doesn't
# exist.
#
AM_YFLAGS=-d -Wno-yacc

if GCOV

check:
	@tests/gcov-summary

MOSTLYCLEANFILES = {cli,tests,libyara,libyara/proc,libyara/modules/*}/*.gc{no,da,ov}
AM_CFLAGS+=-O0 -g -ftest-coverage -fprofile-arcs

else

if DEBUG
AM_CFLAGS+=-g -fno-omit-frame-pointer
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

# Rules for generating YARA modules from .proto files. For each .proto file
# three files are generated: .c, .pb-c.c, and .pb-c.h. The .c file is generated
# by protoc-gen-yara and the other two by protoc-gen-c. This is done only if
# protoc is found, if not, files already in the repository are used instead
# of generating fresh ones from the .proto file.
#
if PROTOC
# SUFFIXES = .proto .pb-c.c .pb-c.h .c
.proto.pb-c.c:
		$(PROTOC) --c_out=$(builddir) $^ -Ilibyara/pb/ -I=$(srcdir)

.proto.pb-c.h:
		$(PROTOC) --c_out=$(builddir) $^ -Ilibyara/pb/ -I=$(srcdir)

.proto.c:
		$(PROTOC) --c_out=$(builddir) $^ -Ilibyara/pb/ -I=$(srcdir)
endif

MODULES =  libyara/modules/tests/tests.c

MODULES += libyara/modules/elf/elf.c

MODULES += libyara/modules/math/math.c

MODULES += libyara/modules/time/time.c

MODULES += libyara/modules/pe/pe.c
MODULES += libyara/modules/pe/pe_utils.c

MODULES += libyara/modules/console/console.c

MODULES += libyara/modules/string/string.c

if CUCKOO_MODULE
MODULES += libyara/modules/cuckoo/cuckoo.c
endif

if MAGIC_MODULE
MODULES += libyara/modules/magic/magic.c
endif

if HASH_MODULE
MODULES += libyara/modules/hash/hash.c
endif

if DOTNET_MODULE
MODULES += libyara/modules/dotnet/dotnet.c
endif

if MACHO_MODULE
MODULES += libyara/modules/macho/macho.c
endif

if DEX_MODULE
MODULES += libyara/modules/dex/dex.c
endif

if PB_TESTS_MODULE
MODULES += libyara/modules/pb_tests/pb_tests.c
MODULES += libyara/modules/pb_tests/pb_tests.pb-c.c
endif

if AUTHENTICODE_MODULE
MODULES += libyara/modules/pe/authenticode-parser/authenticode.c
MODULES += libyara/modules/pe/authenticode-parser/certificate.c
MODULES += libyara/modules/pe/authenticode-parser/helper.c
MODULES += libyara/modules/pe/authenticode-parser/countersignature.c
MODULES += libyara/modules/pe/authenticode-parser/structs.c
endif

#
# Add your modules here:
#
# MODULES += libyara/modules/yourmodule.c
#

include_HEADERS = libyara/include/yara.h

yaraincludedir = $(includedir)/yara
yarainclude_HEADERS = \
	libyara/include/yara/ahocorasick.h \
	libyara/include/yara/arena.h \
	libyara/include/yara/atoms.h \
	libyara/include/yara/base64.h \
	libyara/include/yara/bitmask.h \
	libyara/include/yara/compiler.h \
	libyara/include/yara/error.h \
	libyara/include/yara/exec.h \
	libyara/include/yara/exefiles.h \
	libyara/include/yara/filemap.h \
	libyara/include/yara/hash.h \
	libyara/include/yara/integers.h \
	libyara/include/yara/libyara.h \
	libyara/include/yara/limits.h \
	libyara/include/yara/mem.h \
	libyara/include/yara/modules.h \
	libyara/include/yara/notebook.h \
	libyara/include/yara/object.h \
	libyara/include/yara/parser.h \
	libyara/include/yara/proc.h \
	libyara/include/yara/re.h \
	libyara/include/yara/rules.h \
	libyara/include/yara/scan.h \
	libyara/include/yara/scanner.h \
	libyara/include/yara/simple_str.h \
	libyara/include/yara/sizedstr.h \
	libyara/include/yara/stack.h \
	libyara/include/yara/stopwatch.h \
	libyara/include/yara/stream.h \
	libyara/include/yara/strutils.h \
	libyara/include/yara/threading.h \
	libyara/include/yara/types.h \
	libyara/include/yara/unaligned.h \
	libyara/include/yara/utils.h

noinst_HEADERS = \
	libyara/crypto.h \
	libyara/exception.h \
	libyara/include/yara/dotnet.h \
	libyara/include/yara/elf.h \
	libyara/include/yara/endian.h \
	libyara/include/yara/globals.h \
	libyara/include/yara/hex_lexer.h \
	libyara/include/yara/lexer.h \
	libyara/include/yara/pe.h \
	libyara/include/yara/pe_utils.h \
	libyara/include/yara/re_lexer.h \
	libyara/modules/module_list

dist_noinst_DATA = libyara/pb/yara.proto

lib_LTLIBRARIES = libyara.la

libyara_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/libyara
libyara_la_LDFLAGS = -version-number $(ABI_VERSION)

BUILT_SOURCES = \
	libyara/lexer.c \
	libyara/hex_lexer.c \
	libyara/re_lexer.c \
	libyara/grammar.c libyara/grammar.h \
	libyara/hex_grammar.c libyara/hex_grammar.h \
	libyara/re_grammar.c libyara/re_grammar.h

libyara_la_SOURCES = \
	$(MODULES) \
	libyara/grammar.y \
	libyara/ahocorasick.c \
	libyara/arena.c \
	libyara/atoms.c \
	libyara/base64.c \
	libyara/bitmask.c \
	libyara/compiler.c \
	libyara/endian.c \
	libyara/exec.c \
	libyara/exefiles.c \
	libyara/filemap.c \
	libyara/hash.c \
	libyara/hex_grammar.y \
	libyara/hex_lexer.l \
	libyara/lexer.l \
	libyara/libyara.c \
	libyara/mem.c \
	libyara/modules.c \
	libyara/notebook.c \
	libyara/object.c \
	libyara/parser.c \
	libyara/proc.c \
	libyara/re.c \
	libyara/re_grammar.y \
	libyara/re_lexer.l \
	libyara/rules.c \
	libyara/scan.c \
	libyara/scanner.c \
	libyara/simple_str.c \
	libyara/sizedstr.c \
	libyara/stack.c \
	libyara/stopwatch.c \
	libyara/strutils.c \
	libyara/stream.c \
	libyara/tlshc/tlsh.c \
	libyara/tlshc/tlsh_impl.c \
	libyara/tlshc/tlsh_util.c \
	libyara/threading.c


if USE_WINDOWS_PROC
libyara_la_SOURCES += libyara/proc/windows.c
endif

if USE_LINUX_PROC
libyara_la_SOURCES += libyara/proc/linux.c
endif

if USE_FREEBSD_PROC
libyara_la_SOURCES += libyara/proc/freebsd.c
endif

if USE_OPENBSD_PROC
libyara_la_SOURCES += libyara/proc/openbsd.c
endif

if USE_MACH_PROC
libyara_la_SOURCES += libyara/proc/mach.c
endif

if USE_NO_PROC
libyara_la_SOURCES += libyara/proc/none.c
endif

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = yara.pc

bin_PROGRAMS = yara yarac

yara_SOURCES = \
  cli/args.c \
  cli/args.h \
  cli/common.c \
  cli/common.h \
  cli/threading.c \
  cli/threading.h \
  cli/yara.c

yara_LDADD = libyara.la

yarac_SOURCES = \
   cli/args.c \
   cli/args.h \
   cli/common.c \
   cli/common.h \
   cli/yarac.c

yarac_LDADD = libyara.la

tests_mapper_SOURCES = tests/mapper.c
tests_mapper_CFLAGS = -O0

test_alignment_SOURCES = tests/test-alignment.c tests/util.c
test_alignment_LDADD = libyara.la
test_alignment_LDFLAGS = -static
test_arena_SOURCES = tests/test-arena.c tests/util.c
test_arena_LDADD = libyara.la
test_arena_LDFLAGS = -static
test_atoms_SOURCES = tests/test-atoms.c tests/util.c
test_atoms_LDADD = libyara.la
test_atoms_LDFLAGS = -static
test_rules_SOURCES = tests/test-rules.c tests/util.c
test_rules_LDADD = libyara.la
test_rules_LDFLAGS = -static
if POSIX
EXTRA_test_rules_DEPENDENCIES = tests/mapper$(EXEEXT)
endif
test_pe_SOURCES = tests/test-pe.c tests/util.c
test_pe_LDADD = libyara.la
test_pe_LDFLAGS = -static
test_elf_SOURCES = tests/test-elf.c tests/util.c
test_elf_LDADD = libyara.la
test_elf_LDFLAGS = -static
test_version_SOURCES = tests/test-version.c tests/util.c
test_version_LDADD = libyara.la
test_version_LDFLAGS = -static
test_api_SOURCES = tests/test-api.c tests/util.c
test_api_LDADD = libyara.la
test_api_LDFLAGS = -static
test_bitmask_SOURCES = tests/test-bitmask.c tests/util.c
test_bitmask_LDADD = libyara.la
test_bitmask_LDFLAGS = -static
test_math_SOURCES = tests/test-math.c tests/util.c
test_math_LDADD = libyara.la
test_math_LDFLAGS = -static
test_string_SOURCES = tests/test-string.c tests/util.c
test_string_LDADD = libyara.la
test_string_LDFLAGS = -static
test_stack_SOURCES = tests/test-stack.c tests/util.c
test_stack_LDADD = libyara.la
test_stack_LDFLAGS = -static
test_re_split_SOURCES = tests/test-re-split.c tests/util.c
test_re_split_LDADD = libyara.la
test_re_split_LDFLAGS = -static
test_async_SOURCES = tests/test-async.c tests/util.c
test_async_LDADD = libyara.la
test_async_LDFLAGS = -static

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = TOP_SRCDIR=$(top_srcdir) TOP_BUILDDIR=$(top_builddir)

check_PROGRAMS = \
  test-arena \
  test-alignment \
  test-atoms \
  test-api \
  test-rules \
  test-pe \
  test-elf \
  test-version \
  test-bitmask \
  test-math \
  test-stack \
  test-re-split \
  test-async \
  test-string

EXTRA_PROGRAMS = tests/mapper
CLEANFILES = tests/mapper$(EXEEXT)

if POSIX
# The -fsanitize=address option makes test-exception fail. Include the test
# only if the option is not enabled.
if !ADDRESS_SANITIZER
check_PROGRAMS+=test-exception
test_exception_SOURCES = tests/test-exception.c tests/util.c
test_exception_LDADD = libyara.la
test_exception_LDFLAGS = -static
endif
endif

if MACHO_MODULE
check_PROGRAMS+=test-macho
test_macho_SOURCES = tests/test-macho.c tests/util.c
test_macho_LDADD = libyara.la
test_macho_LDFLAGS = -static
endif

if DEX_MODULE
check_PROGRAMS+=test-dex
test_dex_SOURCES = tests/test-dex.c tests/util.c
test_dex_LDADD = libyara.la
test_dex_LDFLAGS = -static
endif

if DOTNET_MODULE
check_PROGRAMS+=test-dotnet
test_dotnet_SOURCES = tests/test-dotnet.c tests/util.c
test_dotnet_LDADD = libyara.la
test_dotnet_LDFLAGS = -static
endif

if MAGIC_MODULE
check_PROGRAMS+=test-magic
test_magic_SOURCES = tests/test-magic.c tests/util.c
test_magic_LDADD = libyara.la
test_magic_LDFLAGS = -static
endif

if PB_TESTS_MODULE
check_PROGRAMS+=test-pb
test_pb_SOURCES = tests/test-pb.c tests/util.c
test_pb_LDADD = libyara.la
test_pb_LDFLAGS = -static
endif

# man pages
man1_MANS = yara.man yarac.man

EXTRA_DIST = $(man1_MANS) README.md bootstrap.sh
