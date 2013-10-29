AC_INIT([yara], [2.0], [vmalvarez@virustotal.com])

${CFLAGS=""}

LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_SUBDIRS([libyara])

REVISION=`svnversion $srcdir | sed 's/[[A-Z]]//g'`
which svnversion > /dev/null; \
if test $? -ne 0  || test "x$REVISION" = "xexported"
  then REVISION=`cat $srcdir/REVISION`
  else echo "#define REVISION \"$REVISION\"">$srcdir/REVISION
fi
AC_SUBST(REVISION)
AC_OUTPUT
