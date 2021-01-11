/*
Copyright (c) 2014-2021. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "args.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#include "args.h"
#include "common.h"


#define args_is_short_arg(arg) \
  (arg[0] == '-' && arg[1] != '-' && arg[1] != '\0')



args_option_t* args_get_short_option(
    args_option_t *options,
    const char_t opt)
{
  while (options->type != ARGS_OPT_END)
  {
    if (opt == options->short_name)
      return options;

    options++;
  }

  return NULL;
}


args_option_t* args_get_long_option(
    args_option_t *options,
    const char_t* arg)
{
  arg += 2;  // skip starting --

  while (options->type != ARGS_OPT_END)
  {
    if (options->long_name != NULL)
    {
      size_t l = _tcslen(options->long_name);

      if ((arg[l] == '\0' || arg[l] == '=') &&
          _tcsstr(arg, options->long_name) == arg)
      {
        return options;
      }
    }

    options++;
  }

  return NULL;
}


args_error_type_t args_parse_option(
    args_option_t* opt,
    const char_t* opt_arg,
    int* opt_arg_was_used)
{
  char_t *endptr = NULL;

  if (opt_arg_was_used != NULL)
    *opt_arg_was_used = 0;

  if (opt->count == opt->max_count)
    return ARGS_ERROR_TOO_MANY;

  switch (opt->type)
  {
  case ARGS_OPT_BOOLEAN:
    *(bool*) opt->value = !(*(bool*) opt->value);
    break;

    case ARGS_OPT_INTEGER:
      if (opt_arg == NULL)
        return ARGS_ERROR_REQUIRED_INTEGER_ARG;

      *(long*) opt->value = _tcstol(opt_arg, &endptr, 0);

    if (*endptr != '\0')
      return ARGS_ERROR_REQUIRED_INTEGER_ARG;

    if (opt_arg_was_used != NULL)
      *opt_arg_was_used = 1;

    break;

    case ARGS_OPT_STRING:
      if (opt_arg == NULL)
        return ARGS_ERROR_REQUIRED_STRING_ARG;

#ifdef _UNICODE
	  if (opt->max_count > 1)
		  ((const char**) opt->value)[opt->count] = unicode_to_ansi(opt_arg);
	  else
		  *(const char**) opt->value = unicode_to_ansi(opt_arg);
#else
	  if (opt->max_count > 1)
		  ((const char**) opt->value)[opt->count] = opt_arg;
	  else
		  *(const char**) opt->value = opt_arg;
#endif

    if (opt_arg_was_used != NULL)
      *opt_arg_was_used = 1;

    break;

  default:
    assert(0);
  }

  opt->count++;

  return ARGS_ERROR_OK;
}


void args_print_error(
    args_error_type_t error,
    const char_t* option)
{
  switch (error)
  {
    case ARGS_ERROR_UNKNOWN_OPT:
      _ftprintf(stderr, _T("unknown option `%s`\n"), option);
      break;
    case ARGS_ERROR_TOO_MANY:
	  _ftprintf(stderr, _T("too many `%s` options\n"), option);
      break;
    case ARGS_ERROR_REQUIRED_INTEGER_ARG:
      _ftprintf(stderr, _T("option `%s` requires an integer argument\n"), option);
      break;
    case ARGS_ERROR_REQUIRED_STRING_ARG:
      _ftprintf(stderr, _T("option `%s` requires a string argument\n"), option);
      break;
    case ARGS_ERROR_UNEXPECTED_ARG:
      _ftprintf(stderr, _T("option `%s` doesn't expect an argument\n"), option);
      break;
    default:
      return;
  }
}


int args_parse(
    args_option_t *options,
    int argc,
    const char_t **argv)
{
  args_error_type_t error = ARGS_ERROR_OK;

  int i = 1;  // start with i = 1, argv[0] is the program name
  int o = 0;

  while (i < argc)
  {
    const char_t* arg = argv[i];

    if (args_is_long_arg(arg))
    {
      args_option_t* opt = args_get_long_option(options, arg);

      if (opt != NULL)
      {
        const char_t* equal = _tcschr(arg, '=');

        if (equal)
          error = args_parse_option(opt, equal + 1, NULL);
        else
          error = args_parse_option(opt, NULL, NULL);
      }
      else
      {
        error = ARGS_ERROR_UNKNOWN_OPT;
      }
    }
    else if (args_is_short_arg(arg))
    {
      for (int j = 1; arg[j] != '\0'; j++)
      {
        args_option_t* opt = args_get_short_option(options, arg[j]);

        if (opt != NULL)
        {
          if (arg[j + 1] == '\0')
          {
            int arg_used;

            // short option followed by a space, argv[i + 1] could be
            // an argument for the option (i.e: -a <arg>)
            error = args_parse_option(opt, argv[i + 1], &arg_used);

            // argv[i + 1] was actually an argument to the option, skip it.
            if (arg_used)
              i++;
          }
          else
          {
            // short option followed by another option (i.e: -ab), no
            // argument for this option
            error = args_parse_option(opt, NULL, NULL);
          }
        }
        else
        {
          error = ARGS_ERROR_UNKNOWN_OPT;
        }

        if (error != ARGS_ERROR_OK)
          break;
      }
    }
    else
    {
      argv[o++] = arg;
    }

    if (error != ARGS_ERROR_OK)
    {
      args_print_error(error, arg);
      exit(1);
    }

    i++;
  }

  // Initialize to NULL the value pointers for all options.
  for (; options->type != ARGS_OPT_END; options++)
	  options->value = NULL;

  return o;
}


void args_print_usage(args_option_t* options, int help_alignment)
{
  char_t buffer[128];

  for (; options->type != ARGS_OPT_END; options++)
  {
    int len = _stprintf(buffer, _T("  "));

    if (options->short_name != '\0')
      len += _stprintf(buffer + len, _T("-%c"), options->short_name);
    else
      len += _stprintf(buffer + len, _T("     "));

    if (options->short_name != '\0' && options->long_name != NULL)
      len += _stprintf(buffer + len, _T( ",  "));

    if (options->long_name != NULL)
      len += _stprintf(buffer + len, _T("--%s"), options->long_name);

    if (options->type == ARGS_OPT_STRING || options->type == ARGS_OPT_INTEGER)
    {
      len += _stprintf(
          buffer + len,
          _T("%s%s"),
          (options->long_name != NULL) ? _T("=") : _T(" "),
          options->type_help);
    }

    _tprintf(_T("%-*s%s\n"), help_alignment, buffer, options->help);
  }
}


void args_free(
	args_option_t *options)
{
	for (; options->type != ARGS_OPT_END; options++)
	{
		if (options->type == ARGS_OPT_STRING && options->value != NULL)
		{
		  free(options->value);
		}
	}
}