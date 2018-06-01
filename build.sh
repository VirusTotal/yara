#!/bin/bash
set -ev
./configure
make
make check
