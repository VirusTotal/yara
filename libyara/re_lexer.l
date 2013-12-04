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

/* Lexical analyzer for regular expressions */

%{

#include "yara.h"
#include "atoms.h"
#include "mem.h"
#include "re.h"
#include "re_grammar.h"
#include "re_lexer.h"
#include "utils.h"


#ifdef WIN32
#define snprintf _snprintf
#endif


uint8_t read_escaped_char(yyscan_t yyscanner);

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option yylineno
%option prefix="re_yy"

%option outfile="lex.yy.c"

%option verbose
%option warn

%x char_class

digit         [0-9]
hex_digit     [0-9a-fA-F]

%%

\{{digit}*,{digit}*\} {

  // Examples: {3,8} {0,5} {,5} {7,}

  int hi_bound;
  int lo_bound = atoi(yytext + 1);

  char* comma = strchr(yytext, ',');

  if (comma - yytext == strlen(yytext) - 2)
    // if comma is followed by the closing curly bracket
    // (example: {2,}) set high bound value to maximum.
    hi_bound = INT16_MAX;
  else
    hi_bound = atoi(comma + 1);

  if (hi_bound > INT16_MAX)
  {
    yyerror(yyscanner, lex_env, "repeat interval too large");
    yyterminate();
  }

  if (hi_bound < lo_bound)
  {
    yyerror(yyscanner, lex_env, "bad repeat interval");
    yyterminate();
  }

  yylval->range = (hi_bound << 16) | lo_bound;

  return _RANGE_;
}


\{{digit}+\} {

  // Example: {10}

  int value = atoi(yytext + 1);

  if (value > INT16_MAX)
  {
    yyerror(yyscanner, lex_env, "repeat interval too large");
    yyterminate();
  }

  yylval->range = (value << 16) | value;

  return _RANGE_;
}


\[\^ {

  // Start of a negated character class. Example: [^abcd]

  BEGIN(char_class);
  memset(LEX_ENV->class_vector, 0, 32);
  LEX_ENV->negated_class = TRUE;
}

\[\^\] {

  // Start of character negated class containing a ].
  // Example: [^]abc] this must be interpreted as a class
  // not matching ], a, b, nor c

  BEGIN(char_class);
  memset(LEX_ENV->class_vector, 0, 32);
  LEX_ENV->negated_class = TRUE;
  LEX_ENV->class_vector[']' / 8] |= 1 << ']' % 8;
}


\[\] {

  // Start of character class containing a ].
  // Example: []abc] this must be interpreted as a class
  // matching ], a, b, or c.

  BEGIN(char_class);
  memset(LEX_ENV->class_vector, 0, 32);
  LEX_ENV->negated_class = FALSE;
  LEX_ENV->class_vector[']' / 8] |= 1 << ']' % 8;
}


\[ {

  // Start of character class. Example: [abcd]

  BEGIN(char_class);
  memset(LEX_ENV->class_vector, 0, 32);
  LEX_ENV->negated_class = FALSE;
}


[^\\\[\(\)\|\$\.\^\+\*\?] {

  // Any non-special character is passed as a CHAR token to the scanner.

  yylval->integer = yytext[0];
  return _CHAR_;
}


\\w {
  return _WORD_CHAR_;
}


\\W {
  return _NON_WORD_CHAR_;
}


\\s {
  return _SPACE_;
}


\\S {
  return _NON_SPACE_;
}


\\d {
  return _DIGIT_;
}


\\D {
  return _NON_DIGIT_;
}


\\ {
  yylval->integer = read_escaped_char(yyscanner);
  return _CHAR_;
}


<char_class>\] {

  // End of character class.

  int i;

  yylval->class_vector = yr_malloc(32);
  memcpy(yylval->class_vector, LEX_ENV->class_vector, 32);

  if (LEX_ENV->negated_class)
  {
    for(i = 0; i < 32; i++)
      yylval->class_vector[i] = ~yylval->class_vector[i];
  }

  BEGIN(INITIAL);
  return _CLASS_;
}


<char_class>[^\\]\-[^]] {

  // A range inside a character class.
  //  [abc0-9]
  //      ^- matching here

  int c;

  uint8_t start = yytext[0];
  uint8_t end = yytext[2];

  if (end == '\\')
    end = read_escaped_char(yyscanner);

  if (end < start)
  {
    yyerror(yyscanner, lex_env, "bad character range");
    yyterminate();
  }

  for (c = start; c <= end; c++)
  {
    LEX_ENV->class_vector[c / 8] |= 1 << c % 8;
  }
}


<char_class>\\] {

  LEX_ENV->class_vector[']' / 8] |= 1 << ']' % 8;
}


<char_class>\\w {

  int i;
  char word_chars[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03,
                        0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x07,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  for (i = 0; i < 32; i++)
    LEX_ENV->class_vector[i] |= word_chars[i];
}


<char_class>\\W {

  int i;
  char word_chars[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03,
                        0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x07,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  for (i = 0; i < 32; i++)
    LEX_ENV->class_vector[i] |= ~word_chars[i];
}


<char_class>\\s {

  LEX_ENV->class_vector[' ' / 8] |= 1 << ' ' % 8;
  LEX_ENV->class_vector['\t' / 8] |= 1 << '\t' % 8;
}


<char_class>\\S {

  int i;

  for (i = 0; i < 32; i++)
    LEX_ENV->class_vector[i] = 0xFF;

  LEX_ENV->class_vector[' ' / 8] &= ~(1 << ' ' % 8);
  LEX_ENV->class_vector['\t' / 8] &= ~(1 << '\t' % 8);
}


<char_class>\\d {

  char c;

  for (c = '0'; c <= '9'; c++)
    LEX_ENV->class_vector[c / 8] |= 1 << c % 8;
}


<char_class>\\D {

  int i;
  char c;

  for (i = 0; i < 32; i++)
    LEX_ENV->class_vector[i] = 0xFF;

  for (c = '0'; c <= '9'; c++)
    LEX_ENV->class_vector[c / 8] &= ~(1 << c % 8);
}


<char_class>\\ {

  uint8_t c = read_escaped_char(yyscanner);
  unput(c);
}


<char_class>(.|\n) {

  // A character class (i.e: [0-9a-f]) is represented by a 256-bits vector,
  // here we set to 1 the vector's bit corresponding to the input character.

  LEX_ENV->class_vector[yytext[0] / 8] |= 1 << yytext[0] % 8;
}


<char_class><<EOF>> {

  // End of regexp reached while scanning a character class.

  yyerror(yyscanner, lex_env, "missing terminating ] for character class");
  yyterminate();
}


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


<<EOF>> {

  yyterminate();
}

%%

uint8_t read_escaped_char(yyscan_t yyscanner)
{
  int result;
  char hex[3];
  int c = input(yyscanner);

  switch(c)
  {
  case 'x':
    hex[0] = input(yyscanner);
    hex[1] = input(yyscanner);
    hex[2] = '\0';
    sscanf(hex, "%x", &result);
    break;

  case 'n':
    result = '\n';
    break;

  case 't':
    result = '\t';
    break;

  case 'r':
    result = '\r';
    break;

  case 'f':
    result = '\f';
    break;

  case 'a':
    result = '\a';
    break;

  default:
    result = c;
  }

  return result;
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


int yr_parse_re_string(
  const char* re_string,
  RE** re)
{
  yyscan_t yyscanner;
  LEX_ENVIRONMENT lex_env;

  lex_env.last_error_message = NULL;

  FAIL_ON_ERROR(yr_re_create(re));

  // The RE_FLAGS_LITERAL_STRING flag indicates that the
  // regular expression is just a literal string and it can
  // be matched by doing a simple string comparison, without
  // executing any regular expression code. We initially set
  // this flag which is unset later during parsing if necessary.

  (*re)->flags |= RE_FLAGS_LITERAL_STRING;

  yylex_init(&yyscanner);
  yyset_extra(*re, yyscanner);
  yy_scan_string(re_string, yyscanner);
  yyparse(yyscanner, &lex_env);
  yylex_destroy(yyscanner);

  if (lex_env.last_error_message != NULL)
  {
    (*re)->error_message = lex_env.last_error_message;
    return ERROR_INVALID_REGULAR_EXPRESSION;
  }

  return (*re)->error_code;
}






