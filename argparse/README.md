NAME
====

argparse - A command line arguments parsing library.

[![Build Status](https://travis-ci.org/Cofyc/argparse.png)](https://travis-ci.org/Cofyc/argparse)

DESCRIPTION
===========

This module is inspired by parse-options.c (git) and python's argparse
module.

Arguments parsing is common task in cli program, but traditional `getopt`
libraries are not easy to use. This library provides high-level arguments
parsing solutions.

The program defines what arguments it requires, and `argparse` will figure
out how to parse those out of `argc` and `argv`, it also automatically
generates help and usage messages and issues errors when users give the
program invalid arguments.

Features
========

 - handles both optional and positional arguments
 - produces highly informative usage messages
 - issures errors when given invalid arguments

There are basically three types of options:

 - boolean options
 - options with mandatory argument
 - options with optional argument

There are basically two forms of options:

 - short option consist of one dash (`-`) and one alphanumeric character.
 - long option begin with two dashes (`--`) and some alphanumeric characters.

Short options may be bundled, e.g. `-a -b` can be specified as `-ab`.

Options are case-sensitive.

Options and non-option arguments can clearly be separated using the `--` option.

Examples
========

```c
#include "argparse.h"

static const char *const usage[] = {
   "test_argparse [options] [[--] args]",
   NULL,
};

int
main(int argc, const char **argv)
{
   int force = 0;
   int num = 0;
   const char *path = NULL;
   struct argparse_option options[] = {
       OPT_HELP(),
       OPT_BOOLEAN('f', "force", &force, "force to do", NULL),
       OPT_STRING('p', "path", &path, "path to read", NULL),
       OPT_INTEGER('n', "num", &num, "selected num", NULL),
       OPT_END(),
   };
   struct argparse argparse;
   argparse_init(&argparse, options, usage, 0);
   argc = argparse_parse(&argparse, argc, argv);
   if (force != 0)
       printf("force: %d\n", force);
   if (path != NULL)
       printf("path: %s\n", path);
   if (num != 0)
       printf("num: %d\n", num);
   if (argc != 0) {
       printf("argc: %d\n", argc);
       int i;
       for (i = 0; i < argc; i++) {
           printf("argv[%d]: %s\n", i, *(argv + i));
       }
   }
   return 0;
}
```
