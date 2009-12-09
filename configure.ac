AC_INIT([yara], [1.3], [vmalvarez@hispasec.com])
        AM_INIT_AUTOMAKE([-Wall -Werror])
        AC_PROG_CC
		AC_CONFIG_MACRO_DIR([m4])
		#AC_CHECK_LIB(yara,compile_rules,,AC_MSG_ERROR(yara not found))
		AC_CHECK_LIB(pcre,pcre_compile,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_exec,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_get_substring,,AC_MSG_ERROR(please install pcre library))
		AC_CHECK_LIB(pcre,pcre_free,,AC_MSG_ERROR(please install pcre library))
        AC_CONFIG_HEADERS([config.h])
        AC_CONFIG_FILES([Makefile])
		AC_CONFIG_SUBDIRS([libyara])
        AC_OUTPUT
