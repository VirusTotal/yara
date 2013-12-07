/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

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

#include "yara.h"
#include "atoms.h"
#include "mem.h"
#include "re.h"
#include "hex_grammar.h"
#include "hex_lexer.h"
#include "utils.h"

#include "config.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifdef WIN32
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

<range>{digit}+ {

  yylval->integer = atoi(yytext);

  if (yylval->integer > INT16_MAX)
  {
    yyerror(yyscanner, lex_env, "range value too large");
    yyterminate();
  }

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


#ifdef WIN32
extern DWORD recovery_state_key;
#else
extern pthread_key_t recovery_state_key;
#endif


void yyfatal(
    yyscan_t yyscanner,
    const char *error_message)
{
  jmp_buf* recovery_state;

  #ifdef WIN32
  recovery_state = TlsGetValue(recovery_state_key) ;
  #else
  recovery_state = pthread_getspecific(recovery_state_key);
  #endif

  longjmp(*recovery_state, 1);
}

void yyerror(
    yyscan_t yyscanner,
    LEX_ENVIRONMENT* lex_env,
    const char *error_message)
{
  if (lex_env->last_error_message == NULL)
  {
    lex_env->last_error_message = yr_strdup(error_message);
  }
}

int yr_parse_hex_string(
  const char* hex_string,
  RE** re)
{
  yyscan_t yyscanner;
  jmp_buf recovery_state;
  LEX_ENVIRONMENT lex_env;

  lex_env.last_error_message = NULL;

  FAIL_ON_ERROR(yr_re_create(re));

  // The RE_FLAGS_LITERAL_STRING flag indicates that the regular expression
  // is just a literal string and it can be matched by doing a simple string
  // comparison, without executing any regular expression code.
  //
  // The RE_FLAGS_FAST_HEX_REGEXP flag indicates a regular expression derived
  // from a hex string that can be matched by faster algorithm. These regular
  // expressions come from hex strings not contaning alternatives
  // (like in 01 02 | 03 04).
  //
  // These flags are unset later during parsing if necessary.

  (*re)->flags |= RE_FLAGS_LITERAL_STRING;
  (*re)->flags |= RE_FLAGS_FAST_HEX_REGEXP;

  #ifdef WIN32
  TlsSetValue(recovery_state_key, (LPVOID) &recovery_state);
  #else
  pthread_setspecific(recovery_state_key, (void*) &recovery_state);
  #endif

  if (setjmp(recovery_state) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  yylex_init(&yyscanner);
  yyset_extra(*re, yyscanner);
  yy_scan_string(hex_string, yyscanner);
  yyparse(yyscanner, &lex_env);
  yylex_destroy(yyscanner);

  if (lex_env.last_error_message != NULL)
  {
    (*re)->error_message = lex_env.last_error_message;
    return ERROR_INVALID_HEX_STRING;
  }

  return (*re)->error_code;
}




