AC_INIT([libyara], [1.7], [vmalvarez@virustotal.com])
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-extra-portability])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_YACC
AM_PROG_LEX
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_ARG_WITH([re2],
	[AS_HELP_STRING([--with-re2],[use RE2])],
        [
		AC_LANG_CPLUSPLUS
		AC_CHECK_LIB(re2, main,,AC_MSG_ERROR(please install RE2 library))
		[re2=true]
        ],
        [
        	AC_CHECK_LIB(pcre, main,,AC_MSG_ERROR(please install PCRE library))
        ])
AM_CONDITIONAL([RE2], [test x$re2 = xtrue])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
			Makefile 
			regex/Makefile
		])
AC_OUTPUT
