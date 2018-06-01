#!/bin/bash
set -ev
unset CC # A pre-set CC overrides --host settings.
./bootstrap.sh
./configure
make
make check
