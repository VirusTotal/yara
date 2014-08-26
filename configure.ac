AC_INIT([yara], [3.1], [vmalvarez@virustotal.com])

AC_CONFIG_SRCDIR([yara.c])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

${CFLAGS=""}

# automake 1.12 seems to require AM_PROG_AR, but automake 1.11 doesn't
# recognize it
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_CC
AM_PROG_LEX
AC_PROG_YACC

LT_INIT
AC_PROG_LIBTOOL

AC_ARG_ENABLE([dmalloc],
  [AS_HELP_STRING([--enable-dmalloc], [enable dmalloc to debug heap-related issues])],
  [if test x$enableval = xyes; then
    AC_CHECK_LIB(dmalloc, dmalloc_malloc,, AC_MSG_ERROR(please install dmalloc library))
    AC_DEFINE([DMALLOC], [1], [enable dmalloc])
  fi])

AC_ARG_ENABLE([cuckoo],
  [AS_HELP_STRING([--enable-cuckoo], [enable cuckoo module])],
  [if test x$enableval = xyes; then
    cuckoo=true
    AC_CHECK_LIB(jansson, json_loadb,, AC_MSG_ERROR(please install Jansson library))
    AC_DEFINE([CUCKOO], [1], [enable cuckoo module])
  fi])

AC_ARG_ENABLE([magic],
  [AS_HELP_STRING([--enable-magic], [enable magic module])],
  [if test x$enableval = xyes; then
    magic=true
    AC_CHECK_LIB(magic, magic_open,, AC_MSG_ERROR(please install libmagic library))
    AC_DEFINE([MAGIC], [1], [enable magic module])
  fi])

AC_CHECK_FUNCS_ONCE(strlcpy strlcat)

AM_CONDITIONAL([CUCKOO], [test x$cuckoo = xtrue])
AM_CONDITIONAL([MAGIC], [test x$magic = xtrue])

AC_CHECK_LIB(pthread, pthread_create)

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([libyara/Makefile])
AC_CONFIG_HEADERS([config.h])

AC_OUTPUT
