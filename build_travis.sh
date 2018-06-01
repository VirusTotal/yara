#!/bin/bash
set -ev
./bootstrap.sh
./configure
make
make check
