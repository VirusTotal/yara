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

/* Lexical analyzer for regular expressions */

%{

#include <assert.h>
#include <setjmp.h>


#include <yara/utils.h>
#include <yara/error.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/re_lexer.h>
#include <yara/strutils.h>


#ifdef _WIN32
#define snprintf _snprintf
#endif


uint8_t escaped_char_value(char* text);
uint8_t read_escaped_char(yyscan_t yyscanner);

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option nounput
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

  if (hi_bound < lo_bound || hi_bound < 0 || lo_bound < 0)
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


\\{digit}+ {

  yyerror(yyscanner, lex_env, "backreferences are not allowed");
  yyterminate();
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



<char_class>(\\x{hex_digit}{2}|\\.|[^\\])\-[^]] {

  // A range inside a character class.
  //  [abc0-9]
  //      ^- matching here

  int c;

  uint8_t start = yytext[0];
  uint8_t end = yytext[2];

  if (start == '\\')
  {
    start = escaped_char_value(yytext);

    if (yytext[1] == 'x')
      end = yytext[5];
    else
      end = yytext[3];
  }

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
  LEX_ENV->class_vector[c / 8] |= 1 << c % 8;
}


<char_class>. {

  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    // A character class (i.e: [0-9a-f]) is represented by a 256-bits vector,
    // here we set to 1 the vector's bit corresponding to the input character.

    LEX_ENV->class_vector[yytext[0] / 8] |= 1 << yytext[0] % 8;
  }
  else
  {
    yyerror(yyscanner, lex_env, "non-ascii character");
    yyterminate();
  }
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

uint8_t escaped_char_value(char* text)
{
  char hex[3];
  int result;

  assert(text[0] == '\\');

  switch(text[1])
  {
  case 'x':
    hex[0] = text[2];
    hex[1] = text[3];
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
    result = text[1];
  }

  return result;
}


uint8_t read_escaped_char(yyscan_t yyscanner)
{
  char text[4];

  text[0] = '\\';
  text[1] = input(yyscanner);

  if (text[1] == 'x')
  {
    text[2] = input(yyscanner);
    text[3] = input(yyscanner);
  }

  return escaped_char_value(text);
}



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
  recovery_state = TlsGetValue(recovery_state_key) ;
  #else
  recovery_state = pthread_getspecific(recovery_state_key);
  #endif

  longjmp(*recovery_state, 1);
}


void yyerror(
    yyscan_t yyscanner,
    RE_LEX_ENVIRONMENT* lex_env,
    const char *error_message)
{
  // if lex_env->last_error_code was set to some error code before
  // don't overwrite it, we are interested in the first error, not in
  // subsequent errors like "syntax error, unexpected $end" caused by
  // early parser termination.

  if (lex_env->last_error_code == ERROR_SUCCESS)
  {
    lex_env->last_error_code = ERROR_INVALID_REGULAR_EXPRESSION;

    strlcpy(
        lex_env->last_error_message,
        error_message,
        sizeof(lex_env->last_error_message));
  }
}


int yr_parse_re_string(
  const char* re_string,
  int flags,
  RE** re,
  RE_ERROR* error)
{
  yyscan_t yyscanner;
  jmp_buf recovery_state;
  RE_LEX_ENVIRONMENT lex_env;

  lex_env.last_error_code = ERROR_SUCCESS;

  #ifdef _WIN32
  TlsSetValue(recovery_state_key, (LPVOID) &recovery_state);
  #else
  pthread_setspecific(recovery_state_key, (void*) &recovery_state);
  #endif

  if (setjmp(recovery_state) != 0)
    return ERROR_INTERNAL_FATAL_ERROR;

  FAIL_ON_ERROR(yr_re_create(re));

  (*re)->flags = flags;

  yylex_init(&yyscanner);
  yyset_extra(*re, yyscanner);
  yy_scan_string(re_string, yyscanner);
  yyparse(yyscanner, &lex_env);
  yylex_destroy(yyscanner);

  if (lex_env.last_error_code != ERROR_SUCCESS)
  {
    yr_re_destroy(*re);
    *re = NULL;

    strlcpy(
        error->message,
        lex_env.last_error_message,
        sizeof(error->message));

    return lex_env.last_error_code;
  }

  return ERROR_SUCCESS;
}
