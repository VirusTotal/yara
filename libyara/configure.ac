AC_INIT([libyara], [2.0], [vmalvarez@virustotal.com])

${CFLAGS=""}

# automake 1.12 seems to require AM_PROG_AR, but automake 1.11 doesn't 
# recognize it

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
			Makefile
		])
AC_OUTPUT
