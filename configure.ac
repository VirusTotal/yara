AC_INIT([yara], [3.3.0], [vmalvarez@virustotal.com])

AC_CONFIG_SRCDIR([yara.c])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

# automake 1.12 seems to require AM_PROG_AR, but automake 1.11 doesn't
# recognize it
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LEX
AC_PROG_YACC

LT_INIT
AC_PROG_LIBTOOL

AC_CANONICAL_HOST

case $host_alias in
     i?86-*-mingw*) CFLAGS="$CFLAGS -D__MINGW_USE_VC2005_COMPAT" ;;
esac


AC_ARG_ENABLE([profiling],
  [AS_HELP_STRING([--enable-profiling], [enable profiling support])],
  [if test x$enableval = xyes; then
    CFLAGS="$CFLAGS -DPROFILING_ENABLED"
  fi])

AC_ARG_ENABLE([dmalloc],
  [AS_HELP_STRING([--enable-dmalloc],
    [enable dmalloc to debug heap-related issues])],
  [if test x$enableval = xyes; then
    AC_CHECK_LIB(dmalloc, dmalloc_malloc,,
      AC_MSG_ERROR([please install dmalloc library]))
    AC_DEFINE([DMALLOC], [1], [enable dmalloc])
  fi])

AC_ARG_ENABLE([cuckoo],
  [AS_HELP_STRING([--enable-cuckoo], [enable cuckoo module])],
  [if test x$enableval = xyes; then
    build_cuckoo_module=true
    AC_CHECK_LIB(jansson, json_loadb,,
      AC_MSG_ERROR([please install Jansson library]))
    AC_DEFINE([CUCKOO], [1], [enable cuckoo module])
  fi])

AC_ARG_ENABLE([magic],
  [AS_HELP_STRING([--enable-magic], [enable magic module])],
  [if test x$enableval = xyes; then
    build_magic_module=true
    AC_CHECK_LIB(magic, magic_open,,
      AC_MSG_ERROR([please install libmagic library]))
    AC_DEFINE([MAGIC], [1], [enable magic module])
  fi])

AC_ARG_WITH([crypto],
  AS_HELP_STRING([--without-crypto],
    [ignore presence of OpenSSL and disable it]))

  AS_IF([test "x$with_crypto" != "xno"],
    [
      AC_CHECK_LIB(crypto, MD5_Init,, [have_crypto=no])
      AC_CHECK_LIB(crypto, MD5_Update,, [have_crypto=no])
      AC_CHECK_LIB(crypto, MD5_Final,, [have_crypto=no])
      AC_CHECK_LIB(crypto, SHA256_Init,, [have_crypto=no])
      AC_CHECK_LIB(crypto, SHA256_Update,, [have_crypto=no])
      AC_CHECK_LIB(crypto, SHA256_Final,, [have_crypto=no])
    ],
    [
      have_crypto=no
    ])

  AS_IF([test "x$have_crypto" = "xno"],
    [
      AS_IF([test "x$with_crypto" = "xyes"],
        [
          AC_MSG_ERROR([OpenSSL requested but not found])
        ])
    ],
    [
      build_hash_module=true
      AC_DEFINE([HASH], [1], [enable hash module])
    ])

ACX_PTHREAD(
    [LIBS="$PTHREAD_LIBS $LIBS"
     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
     CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread API support is required.])])

AC_CHECK_LIB(m, isnan)
AC_CHECK_LIB(m, log2)
AC_CHECK_FUNCS([strlcpy strlcat memmem timegm])

AM_CONDITIONAL([CUCKOO], [test x$build_cuckoo_module = xtrue])
AM_CONDITIONAL([MAGIC], [test x$build_magic_module = xtrue])
AM_CONDITIONAL([HASH], [test x$build_hash_module = xtrue])
AM_CONDITIONAL([GCC], [test "x$GCC" = xyes])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([libyara/Makefile])
AC_CONFIG_HEADERS([config.h])

AC_OUTPUT
