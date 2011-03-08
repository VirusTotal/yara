AC_INIT([yara], [1.4], [vmalvarez@hispasec.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_MACRO_DIR([m4])
AC_ARG_WITH([re2],
	[AS_HELP_STRING([--with-re2],[use RE2 instead of PCRE])],
        [
			AC_LANG_CPLUSPLUS
			AC_CHECK_LIB(re2, main,,AC_MSG_ERROR(please install RE2 library))
			[re2=true]
        ],
        [
        	AC_CHECK_LIB(pcre, main,,AC_MSG_ERROR(please install PCRE library))
        	[re2=false]
        ])
AM_CONDITIONAL([RE2], [test x$re2 = xtrue])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_SUBDIRS([libyara])
AC_OUTPUT
