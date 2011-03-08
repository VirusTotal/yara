noinst_LTLIBRARIES = libregex.la

if RE2
libregex_la_SOURCES = regex-re2.cc
else
libregex_la_SOURCES = regex-pcre.c
endif

libregex_la_LIBADD = $(LTLIBOBJS)
