#!/bin/bash
set -ev
unset CC # A pre-set CC overrides --host settings.
./bootstrap.sh
./configure $CONFIGFLAGS
make
make check
