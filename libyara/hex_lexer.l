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
#include "re.h"
#include "hex_grammar.h"
#include "hex_lexer.h"


#ifdef WIN32
#define snprintf _snprintf
#endif

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
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
    yyerror(yyscanner, "non-ascii character");
    yyterminate();
  }
}

%%

void yyerror(
    yyscan_t yyscanner,
    const char *error_message)
{
  printf("%s", error_message);

}


int yr_parse_hex_string(
  const char* hex_string,
  RE** re)
{
  yyscan_t yyscanner;

  FAIL_ON_ERROR(yr_re_create(re));

  // The RE_FLAGS_LITERAL_STRING flag indicates that the
  // regular expression is just a literal string and it can
  // be matched by doing a simple string comparison, without
  // executing any regular expression code. We initially set
  // this flag which is unset later during parsing if necessary.

  (*re)->flags |= RE_FLAGS_LITERAL_STRING;

  yylex_init(&yyscanner);
  yyset_extra(*re, yyscanner);
  yy_scan_string(hex_string, yyscanner);
  yyparse(yyscanner);
  yylex_destroy(yyscanner);

  return ERROR_SUCCESS;
}




