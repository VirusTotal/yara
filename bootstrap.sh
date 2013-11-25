#!/bin/sh

# Quick and dirty script to reset everything
# regarding libtool, autoconf, automake, etc.

rm -rf m4
rm -rf libyara/m4

mkdir m4
mkdir libyara/m4

cd libyara

# Check if libtoolize exists, if not,
# try with glibtoolize (Mac OS X name it that way)

hash libtoolize &> /dev/null
if [ $? -eq 1 ]; then
    glibtoolize --force
else
    libtoolize --force
fi

aclocal
autoheader
automake --add-missing
autoreconf

cd ..

hash libtoolize &> /dev/null
if [ $? -eq 1 ]; then
    glibtoolize --force
else
    libtoolize --force
fi

aclocal
autoheader
automake --add-missing
autoreconf