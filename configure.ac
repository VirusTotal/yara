AC_INIT([yara], [3.6.3], [vmalvarez@virustotal.com])

AC_CONFIG_SRCDIR([yara.c])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

# AC_PROG_CC sets CFLAGS to "-g -O2" if it wasn't previously set. Let's set
# an empty CFLAGS
: ${CFLAGS=""}

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

case $host_os in
    darwin*) CFLAGS="$CFLAGS -I/opt/local/include"
             # Starting with Mac OS X 10.11 (El Capitan) the OpenSSL headers
             # are in /usr/local/opt/openssl/include
             CFLAGS="$CFLAGS -I/usr/local/opt/openssl/include" ;;
esac

AC_C_BIGENDIAN

ACX_PTHREAD(
    [LIBS="$PTHREAD_LIBS $LIBS"
     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
     CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread API support is required.])])

AC_CHECK_LIB(m, isnan)
AC_CHECK_LIB(m, log2)
AC_CHECK_FUNCS([strlcpy strlcat memmem timegm])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [compiles with -g option])],
  [if test x$enableval = xyes; then
    debug=true
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
    CFLAGS="$CFLAGS -DDMALLOC"
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
  fi])

AC_ARG_ENABLE([dotnet],
  [AS_HELP_STRING([--enable-dotnet], [enable dotnet module])],
  [if test x$enableval = xyes; then
    build_dotnet_module=true
    CFLAGS="$CFLAGS -DDOTNET_MODULE"
  fi])

AC_ARG_WITH([crypto],
  AS_HELP_STRING([--without-crypto],
    [ignore presence of OpenSSL and disable it]))

AS_IF([test "x$with_crypto" != "xno"],
  [
    AC_CHECK_HEADERS([openssl/md5.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/sha.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/asn1.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/crypto.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/bio.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/pkcs7.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/x509.h],, [have_crypto=no])
    AC_CHECK_HEADERS([openssl/safestack.h],, [have_crypto=no])
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
        AC_MSG_ERROR([please install OpenSSL library])
      ],
      [
        AC_MSG_WARN([
*******************************************************************************
  Could not find OpenSSL library. The "hash" module and some features in "pe"
  module have been disabled. If you want to enable all features please install
  it and run this script again.
*******************************************************************************
        ])
      ])
  ],
  [
    build_hash_module=true
    CFLAGS="$CFLAGS -DHASH_MODULE"
  ])

AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])
AM_CONDITIONAL([OPTIMIZATION], [test x$optimization = xtrue])
AM_CONDITIONAL([ADDRESS_SANITIZER], [test x$address_sanitizer = xtrue])
AM_CONDITIONAL([CUCKOO_MODULE], [test x$build_cuckoo_module = xtrue])
AM_CONDITIONAL([MAGIC_MODULE], [test x$build_magic_module = xtrue])
AM_CONDITIONAL([HASH_MODULE], [test x$build_hash_module = xtrue])
AM_CONDITIONAL([DOTNET_MODULE], [test x$build_dotnet_module = xtrue])
AM_CONDITIONAL([GCC], [test "x$GCC" = xyes])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([libyara/Makefile])

AC_OUTPUT
