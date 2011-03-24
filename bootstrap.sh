#!/bin/sh

# Quick and dirty script to reset everything
# regarding libtool, autoconf, automake, etc.

make distclean
aclocal
libtoolize
autoreconf --force && cd libyara/ && autoreconf --force
