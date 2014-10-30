/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

/* Lexical analyzer for hex strings */

%{


#include <setjmp.h>

#include <yara/limits.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/strutils.h>
#include <yara/hex_lexer.h>

#include "hex_grammar.h"

#ifdef _WIN32
#define snprintf _snprintf
#endif

#define ERROR_IF(x, error) \
    if (x) \
    { \
      RE* re = yyget_extra(yyscanner); \
      re->error_code = error; \
      YYABORT; \
    } \

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option noinput
%option nounput
%option never-interactive
%option yylineno
%option prefix="hex_yy"

%option outfile="lex.yy.c"

%option verbose
%option warn

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]

%x range

%%


<INITIAL>{hexdigit}{2}  {

  yylval->integer = xtoi(yytext);
  return _BYTE_;
}

<INITIAL>{hexdigit}\?  {

  yytext[1] = '0'; // replace ? by 0
  yylval->integer = xtoi(yytext) | 0xF000 ;
  return _MASKED_BYTE_;
}

\?{hexdigit}  {

  yytext[0] = '0'; // replace ? by 0
  yylval->integer = xtoi(yytext) | 0x0F00 ;
  return _MASKED_BYTE_;
}

\?\? {

  yylval->integer = 0x0000;
  return _MASKED_BYTE_;
}

\[ {

  BEGIN(range);
  return yytext[0];
}

<range>- {
  return yytext[0];
}

<range>\. {
  return yytext[0];
}

<range>{digit}+ {

  yylval->integer = atoi(yytext);
  return _NUMBER_;
}

<range>\] {

  BEGIN(INITIAL);
  return yytext[0];
}


[ \t\r\n]   // skip whitespace


. {

  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    return yytext[0];
  }
  else
  {
    yyerror(yyscanner, lex_env, "non-ascii character");
    yyterminate();
  }
}

%%


#ifdef _WIN32
#include <windows.h>
extern DWORD recovery_state_key;
#else
#include <pthread.h>
extern pthread_key_t recovery_state_key;
#endif


void yyfatal(
    yyscan_t yyscanner,
    const char *error_message)
{
  jmp_buf* recovery_state;

  #ifdef _WIN32
  recovery_state = (jmp_buf*) TlsGetValue(recovery_state_key) ;
  #else
  recovery_state = (jmp_buf*) pthread_getspecific(recovery_state_key);
  #endif

  longjmp(*recovery_state, 1);
}

void yyerror(
    yyscan_t yyscanner,
    HEX_LEX_ENVIRONMENT* lex_env,
    const char *error_message)
{
  // if lex_env->last_error_code was set to some error code before
  // don't overwrite it, we are interested in the first error, not in
  // subsequent errors like "syntax error, unexpected $end" caused by
  // early parser termination.

  if (lex_env->last_error_code == ERROR_SUCCESS)
  {
    lex_env->last_error_code = ERROR_INVALID_HEX_STRING;

    strlcpy(
        lex_env->last_error_message,
        error_message,
        sizeof(lex_env->last_error_message));
  }
}


int yr_parse_hex_string(
  const char* hex_string,
  int flags,
  RE** re,
  RE_ERROR* error)
{
  yyscan_t yyscanner;
  jmp_buf recovery_state;
  HEX_LEX_ENVIRONMENT lex_env;

  lex_env.last_error_code = ERROR_SUCCESS;
  lex_env.inside_or = 0;
  lex_env.token_count = 0;

  #ifdef _WIN32
  TlsSetValue(recovery_state_key, (LPVOID) &recovery_state);
  #else
  pthread_setspecific(recovery_state_key, (void*) &recovery_state);
  #endif

  if (setjmp(recovery_state) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  FAIL_ON_ERROR(yr_re_create(re));

  // The RE_FLAGS_FAST_HEX_REGEXP flag indicates a regular expression derived
  // from a hex string that can be matched by faster algorithm. These regular
  // expressions come from hex strings not contaning alternatives, like in:
  // { ( 01 02 | 03 04) 05 06 }.
  //
  // This flag is unset later during parsing if alternatives are used.

  (*re)->flags |= RE_FLAGS_FAST_HEX_REGEXP;

  // Set RE_FLAGS_DOT_ALL because in hex strings the "dot" (?? in this case)
  // must match all characters including new-line.

  (*re)->flags |= RE_FLAGS_DOT_ALL;

  yylex_init(&yyscanner);
  yyset_extra(*re, yyscanner);
  yy_scan_string(hex_string, yyscanner);
  yyparse(yyscanner, &lex_env);
  yylex_destroy(yyscanner);

  if (lex_env.last_error_code != ERROR_SUCCESS)
  {
    strlcpy(error->message, lex_env.last_error_message, sizeof(error->message));
    return lex_env.last_error_code;
  }

  return ERROR_SUCCESS;
}
