/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef enum _args_error_type {
  ARGS_ERROR_OK,
  ARGS_ERROR_UKNOWN_OPT,
  ARGS_ERROR_TOO_MANY,
  ARGS_ERROR_REQUIRED_INTEGER_ARG,
  ARGS_ERROR_REQUIRED_STRING_ARG,
  ARGS_ERROR_UNEXPECTED_ARG,
} args_error_type_t;


typedef enum _args_option_type {
  // special
  ARGS_OPT_END,
  ARGS_OPT_GROUP,
  // options with no arguments
  ARGS_OPT_BOOLEAN,
  // options with arguments (optional or required)
  ARGS_OPT_INTEGER,
  ARGS_OPT_STRING,
} args_option_type_t;


typedef struct _args_option {
  args_option_type_t type;
  const char short_name;
  const char *long_name;
  void *value;
  int max_count;
  const char *help;
  const char *type_help;
  int count;
} args_option_t;


#define OPT_BOOLEAN(short_name, long_name, value, ...) \
    { ARGS_OPT_BOOLEAN, short_name, long_name, value, 1, __VA_ARGS__ }

#define OPT_INTEGER(short_name, long_name, value, ...) \
    { ARGS_OPT_INTEGER, short_name, long_name, value, 1, __VA_ARGS__ }

#define OPT_STRING_MULTI(short_name, long_name, value, max_count, ...) \
    { ARGS_OPT_STRING, short_name, long_name, value, max_count, __VA_ARGS__ }

#define OPT_STRING(short_name, long_name, value, ...) \
    OPT_STRING_MULTI(short_name, long_name, value, 1, __VA_ARGS__)

#define OPT_END() { ARGS_OPT_END, 0 }


int args_parse(
    args_option_t *options,
    int argc,
    const char **argv);


void args_print_usage(
    args_option_t *options,
    int aligment);


#ifdef __cplusplus
}
#endif

#endif
