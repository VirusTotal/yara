AC_INIT([libyara], [1.4], [vmalvarez@hispasec.com])
        AM_INIT_AUTOMAKE([-Wall -Werror foreign])
        AC_PROG_CC
		AC_PROG_YACC
		AM_PROG_LEX
		AC_PROG_LIBTOOL
		AC_CONFIG_MACRO_DIR([m4])
		AC_CHECK_LIB(pcre,pcre_compile,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_exec,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_get_substring,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_free,,AC_MSG_ERROR(please install pcre library))
        AC_CONFIG_HEADERS([config.h])
        AC_CONFIG_FILES([Makefile])
        AC_OUTPUT