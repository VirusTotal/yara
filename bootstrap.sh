#!/bin/sh

# Quick and dirty script to reset everything
# regarding libtool, autoconf, automake, etc.


mkdir m4
mkdir libyara/m4

# Check if libtoolize exists, if not, try with glibtoolize (Mac OS X name it that way)
hash libtoolize &> /dev/null

if [ $? -eq 1 ]; then
    glibtoolize
else
    libtoolize
fi

automake --add-missing 
cd libyara  && aclocal && automake --add-missing && cd ..

autoreconf -vif
cd libyara && aclocal && autoreconf -vif && cd ..
