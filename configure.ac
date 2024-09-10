AC_INIT([yara], [4.5.2], [vmalvarez@virustotal.com])

AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([cli/yara.c])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

# AC_PROG_CC sets CFLAGS to "-g -O2" if it wasn't previously set. Let's set
# an empty CFLAGS.
: ${CFLAGS=""}

no_std_allocator="-fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free"

# automake 1.12 seems to require AM_PROG_AR, but automake 1.11 doesn't
# recognize it.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AM_PROG_LEX
AC_PROG_YACC

# If the C compiler supports the keyword inline, do nothing. Otherwise define
# inline to __inline__ or __inline if it accepts one of those, otherwise define
# inline to be empty.
AC_C_INLINE
# Defines WORDS_BIGENDIAN if building in a big-endian host.
AC_C_BIGENDIAN

LT_INIT
AC_CANONICAL_HOST

case $host_alias in
     i?86-*-mingw*) CFLAGS="$CFLAGS -D__MINGW_USE_VC2005_COMPAT" ;;
esac

AC_ARG_ENABLE([proc-scan],
  [AS_HELP_STRING([--disable-proc-scan], [disable process scanning])],
  [if test x$enableval = xyes; then
    AC_MSG_ERROR([
*****************************************************************
  Process scanning is enabled by default, remove --enable-proc-scan.
*****************************************************************
])
  else
    proc_interface=none
    CFLAGS="$CFLAGS -DUSE_NO_PROC"
  fi],
  [case $host_os in
    darwin*) CFLAGS="$CFLAGS -I/opt/local/include"
             # Starting with Mac OS X 10.11 (El Capitan) the OpenSSL headers
             # are in /usr/local/opt/openssl/include
             CFLAGS="$CFLAGS -DUSE_MACH_PROC -I/usr/local/opt/openssl/include"
             LDFLAGS="$LDFLAGS -L/usr/local/opt/openssl/lib"
             posix=true
             proc_interface=mach
             jemalloc_prefix=je_ ;;
    mingw*|msys*|cygwin*) CFLAGS="$CFLAGS -DUSE_WINDOWS_PROC"
            proc_interface=windows
            jemalloc_prefix= ;;
    linux*|netbsd*|dragonfly*|kfreebsd*)
            CFLAGS="$CFLAGS -DUSE_LINUX_PROC"
            posix=true
            proc_interface=linux
            jemalloc_prefix= ;;
    freebsd*)
            CFLAGS="$CFLAGS -DUSE_FREEBSD_PROC"
            posix=true
            proc_interface=freebsd
            jemalloc_prefix= ;;
    openbsd*)
            CFLAGS="$CFLAGS -DUSE_OPENBSD_PROC"
            CFLAGS="$CFLAGS -I/usr/local/include -L/usr/local/lib"
            posix=true
            proc_interface=openbsd
            jemalloc_prefix= ;;
    *)
            CFLAGS="$CFLAGS -DUSE_NO_PROC"
            proc_interface=none
            jemalloc_prefix= ;;
  esac])



ACX_PTHREAD(
    [LIBS="$PTHREAD_LIBS $LIBS"
     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
     CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread API support is required.])])

AC_CHECK_LIB(m, isnan)
AC_CHECK_LIB(m, log2)
AS_IF([test "ac_cv_lib_m_isnan" = yes || test "$ac_cv_lib_m_log2" = yes],
    [PC_LIBS_PRIVATE="$PC_LIBS_PRIVATE -lm"])
AC_CHECK_FUNCS([strlcpy strlcat memmem timegm _mkgmtime clock_gettime])
AC_CHECK_HEADERS([stdbool.h])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [compiles with -g option])],
  [if test x$enableval = xyes; then
    debug=true
  fi])

AC_ARG_ENABLE([gcov],
  [AS_HELP_STRING([--enable-gcov], [compiles with -O0 -g -ftest-coverage -fprofile-arcs])],
  [if test x$enableval = xyes; then
    gcov=true
  fi])

AC_ARG_ENABLE([optimization],
  [AS_HELP_STRING([--disable-optimization], [disable compiler optimizations with -O0])],
  [if test x$enableval = xyes; then
    optimization=false
  fi],
  [optimization=true])

AC_ARG_ENABLE([address-sanitizer],
  [AS_HELP_STRING([--enable-address-sanitizer], [compiles with -fsanitize=address])],
  [if test x$enableval = xyes; then
    address_sanitizer=true
  fi])

AC_ARG_ENABLE([undefined-behaviour-sanitizer],
  [AS_HELP_STRING([--enable-undefined-behaviour-sanitizer], [compiles with -fsanitize=undefined])],
  [if test x$enableval = xyes; then
    undefined_behaviour_sanitizer=true
  fi])


AC_ARG_ENABLE([profiling],
  [AS_HELP_STRING([--enable-profiling], [enable rules profiling support])],
  [if test x$enableval = xyes; then
    profiling_enabled=true
    CFLAGS="$CFLAGS -DYR_PROFILING_ENABLED"
  fi])

AC_ARG_WITH([debug-verbose],
  [AS_HELP_STRING([--with-debug-verbose=[[NUM]]], [Turn on runtime debugging information])],
  [if test $withval -gt 0; then
    AC_DEFINE_UNQUOTED([YR_DEBUG_VERBOSITY], [$withval])
   else
    AC_MSG_ERROR([debug verbosity must be greater than 0])
  fi])

AC_ARG_ENABLE([cuckoo],
  [AS_HELP_STRING([--enable-cuckoo], [enable cuckoo module])],
  [if test x$enableval = xyes; then
    build_cuckoo_module=true
    AC_CHECK_HEADERS([jansson.h],,
      AC_MSG_ERROR([please install Jansson library]))
    AC_CHECK_LIB(jansson, json_loadb,,
      AC_MSG_ERROR([please install Jansson library]))
    CFLAGS="$CFLAGS -DCUCKOO_MODULE"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE jansson"
  fi])

AC_ARG_ENABLE([magic],
  [AS_HELP_STRING([--enable-magic], [enable magic module])],
  [if test x$enableval = xyes; then
    build_magic_module=true
    AC_CHECK_HEADERS([magic.h],,
      AC_MSG_ERROR([please install libmagic library]))
    AC_CHECK_LIB(magic, magic_open,,
      AC_MSG_ERROR([please install libmagic library]))
    CFLAGS="$CFLAGS -DMAGIC_MODULE"
    PC_LIBS_PRIVATE="$PC_LIBS_PRIVATE -lmagic"
  fi])

AC_ARG_ENABLE([macho],
  [AS_HELP_STRING([--enable-macho], [enable macho module])],
  [if test x$enableval = xyes; then
    build_macho_module=true
    CFLAGS="$CFLAGS -DMACHO_MODULE"
  fi])

AC_ARG_ENABLE([dex],
  [AS_HELP_STRING([--enable-dex], [enable dex module])],
  [if test x$enableval = xyes; then
    build_dex_module=true
    CFLAGS="$CFLAGS -DDEX_MODULE"
  fi])

AC_ARG_ENABLE([debug-dex],
  [AS_HELP_STRING([--enable-debug-dex], [enable dex module debugging])],
  [if test x$enableval = xyes; then
    debug_dex_module=true
    CFLAGS="$CFLAGS -DDEBUG_DEX_MODULE"
  fi])

AC_ARG_ENABLE([pb-tests],
  [AS_HELP_STRING([--enable-pb-tests], [enable protobuf test module])],
  [if test x$enableval = xyes; then
    build_pb_tests_module=true
    AC_CHECK_PROG(PROTOC, protoc, protoc)
    AS_IF([test "x${PROTOC}" == "x"],
        [AC_MSG_ERROR([protobuf compiler "protoc" not found])])
    # AC_CHECK_PROG(PROTOC_GEN_YARA, protoc-gen-yara, protoc-gen-yara)
    # AS_IF([test "x${PROTOC_GEN_YARA}" == "x"],
    #    [AC_MSG_ERROR([please install https://github.com/VirusTotal/protoc-gen-yara])])
    PKG_CHECK_MODULES([PROTOBUF_C], [libprotobuf-c >= 1.0.0])
    AC_CHECK_LIB([protobuf-c], protobuf_c_message_unpack,,
      AC_MSG_ERROR([please install libprotobuf-c library]))
    CFLAGS="$CFLAGS -DPB_TESTS_MODULE"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE libprotobuf-c"
  fi])

# "dotnet" module is enabled by default. It can be disabled with --disable-dotnet.
AC_ARG_ENABLE([dotnet],
  [AS_HELP_STRING([--disable-dotnet], [disable dotnet module])],
  [if test x$enableval = xyes; then
        AC_MSG_WARN([
*****************************************************************
  The dotnet module is enabled by default now. No need to specify
  --enable-dotnet. To disable this module please use
  --disable-dotnet.
*****************************************************************
])
    build_dotnet_module=true
    CFLAGS="$CFLAGS -DDOTNET_MODULE"
  else
    build_dotnet_module=false
  fi],
  [
    build_dotnet_module=true
    CFLAGS="$CFLAGS -DDOTNET_MODULE"
  ] )

AC_ARG_WITH([jemalloc],
  [AS_HELP_STRING([--with-jemalloc],
    [use jemalloc to debug heap-related issues])],
  [if test x$withval = xyes; then
    mallctl=mallctl
    malloc_stats_print=malloc_stats_print
    AC_CHECK_LIB(jemalloc, $jemalloc_prefix$mallctl,,
      AC_MSG_ERROR([please install jemalloc library]))
    CFLAGS="$CFLAGS -DJEMALLOC -Dmallctl=$jemalloc_prefix$mallctl -Dmalloc_stats_print=$jemalloc_prefix$malloc_stats_print $no_std_allocator"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE jemalloc"
  fi])

AC_ARG_WITH([tcmalloc],
  [AS_HELP_STRING([--with-tcmalloc],
    [use tcmalloc as the default heap allocator])],
  [if test x$withval = xyes; then
    if test "x$with_jemalloc" = "xyes"; then
      AC_MSG_ERROR([Cannot compile with both tcmalloc and jemalloc])
    fi
    AC_CHECK_LIB(tcmalloc, tc_cfree,,
      AC_MSG_ERROR([please install https://github.com/gperftools/gperftools]))
    CFLAGS="$CFLAGS -DTCMALLOC $no_std_allocator"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE tcmalloc"
  fi])

AC_ARG_WITH([cpu-profiler],
  [AS_HELP_STRING([--with-cpu-profiler],
    [compile with CPU profiling support])],
  [if test x$withval = xyes; then
    AC_CHECK_LIB(profiler, ProfilerStart,,
      AC_MSG_ERROR([please install https://github.com/gperftools/gperftools]))
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE libprofiler"
  fi])

AC_ARG_WITH([crypto],
  AS_HELP_STRING([--without-crypto],
    [ignore presence of OpenSSL and disable it]))

AS_IF([test "x$with_crypto" != "xno"],
  [
    AC_CHECK_HEADERS([openssl/evp.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/asn1.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/crypto.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/bio.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/pkcs7.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/x509.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/safestack.h],, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_DigestInit,, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_DigestUpdate,, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_DigestFinal,, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_md5,, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_sha1,, [have_crypto=no])
    AC_CHECK_LIB(crypto, EVP_sha256,, [have_crypto=no])
  ],
  [
    have_crypto=no
  ])


AS_IF([test "x$have_crypto" = "xno"],
  [
    AS_IF([test "x$with_crypto" = "xyes"],
      [
        AC_MSG_ERROR([please install OpenSSL library])
      ],
      [
        AC_MSG_WARN([

*****************************************************************
  Could not find OpenSSL library. Some features in "pe" module
  have been disabled. If you want to enable all features please
  install OpenSSL and run this script again.
*****************************************************************
])
	      AC_MSG_CHECKING([for Microsoft Crypto API])
        AC_CHECK_HEADERS([wincrypt.h],
          [
	          AC_MSG_RESULT([The "hash" module functions will be provided through the Microsoft Crypto API])
            # FIXME: Add PC_LIBS_PRIVATE entries?
            build_hash_module=true
          ],
          [],
          [#include <windows.h>])
	      AC_MSG_CHECKING([for MacOSX Common Crypto API])
        AC_CHECK_HEADERS([CommonCrypto/CommonCrypto.h],
          [
	          AC_MSG_RESULT([
*****************************************************************
  As an alternative to OpenSSL the "hash" module functions will
  be provided through the MacOSX Common Crypto API.
*****************************************************************
])
            # FIXME: Add PC_LIBS_PRIVATE entries?
            build_hash_module=true
          ])
        AS_IF([test x$build_hash_module = xtrue],
          [
            build_hash_module=true
            CFLAGS="$CFLAGS -DHASH_MODULE"
          ],
          [
            AC_MSG_WARN([

*****************************************************************
  Could not find alternative APIs for hash functions. The "hash"
  module has been disabled.
*****************************************************************
            ])
          ])
      ])
  ],
  [
    build_authenticode_module=true # Authenticode relies on openssl
    build_hash_module=true
    CFLAGS="$CFLAGS -DHASH_MODULE"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE libcrypto"
  ])



AM_CONDITIONAL([GCC], [test "x$GCC" = xyes])
AM_CONDITIONAL([PROTOC], [test "x${PROTOC}" != "x"])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])
AM_CONDITIONAL([GCOV], [test x$gcov = xtrue])
AM_CONDITIONAL([POSIX], [test x$posix = xtrue])
AM_CONDITIONAL([PROFILING_ENABLED], [test x$profiling_enabled = xtrue])
AM_CONDITIONAL([OPTIMIZATION], [test x$optimization = xtrue])
AM_CONDITIONAL([ADDRESS_SANITIZER], [test x$address_sanitizer = xtrue])
AM_CONDITIONAL([UB_SANITIZER], [test x$undefined_behaviour_sanitizer = xtrue])
AM_CONDITIONAL([CUCKOO_MODULE], [test x$build_cuckoo_module = xtrue])
AM_CONDITIONAL([MAGIC_MODULE], [test x$build_magic_module = xtrue])
AM_CONDITIONAL([HASH_MODULE], [test x$build_hash_module = xtrue])
AM_CONDITIONAL([AUTHENTICODE_MODULE], [test x$build_authenticode_module = xtrue])
AM_CONDITIONAL([DOTNET_MODULE], [test x$build_dotnet_module = xtrue])
AM_CONDITIONAL([MACHO_MODULE], [test x$build_macho_module = xtrue])
AM_CONDITIONAL([PB_TESTS_MODULE], [test x$build_pb_tests_module = xtrue])
AM_CONDITIONAL([DEX_MODULE], [test x$build_dex_module = xtrue])
AM_CONDITIONAL([DEBUG_DEX_MODULE], [test x$debug_dex_module = xtrue])

AM_CONDITIONAL([USE_WINDOWS_PROC], [test x$proc_interface = xwindows ])
AM_CONDITIONAL([USE_LINUX_PROC], [test x$proc_interface = xlinux ])
AM_CONDITIONAL([USE_FREEBSD_PROC], [test x$proc_interface = xfreebsd ])
AM_CONDITIONAL([USE_OPENBSD_PROC], [test x$proc_interface = xopenbsd ])
AM_CONDITIONAL([USE_MACH_PROC], [test x$proc_interface = xmach ])
AM_CONDITIONAL([USE_NO_PROC], [test x$proc_interface = xnone ])
AS_IF(
  [test x$proc_interface != xnone],[AC_DEFINE([HAVE_SCAN_PROC_IMPL],[1])],
  [test x$proc_interface = xnone],[AC_DEFINE([HAVE_SCAN_PROC_IMPL],[0])])

# Configure TLSH function
CFLAGS="$CFLAGS -DBUCKETS_128=1 -DCHECKSUM_1B=1"

AC_SUBST([PC_REQUIRES_PRIVATE])
AC_SUBST([PC_LIBS_PRIVATE])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([yara.pc])

AC_OUTPUT
