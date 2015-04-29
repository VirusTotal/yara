/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

/* Lexical analyzer for YARA */

%{

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>


#include <yara/lexer.h>
#include <yara/sizedstr.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/strutils.h>

#include "grammar.h"


#define LEX_CHECK_SPACE_OK(data, current_size, max_length) \
    if (strlen(data) + current_size >= max_length - 1) \
    { \
      yyerror(yyscanner, compiler, "out of space in lex_buf"); \
      yyterminate(); \
    }

#define YYTEXT_TO_BUFFER \
    { \
      char *yptr = yytext; \
      LEX_CHECK_SPACE_OK(yptr, yyextra->lex_buf_len, LEX_BUF_SIZE); \
      while(*yptr) \
      { \
        *yyextra->lex_buf_ptr++ = *yptr++; \
        yyextra->lex_buf_len++; \
      } \
    }

#define ALLOC_SIZED_STRING(str, str_len) \
  SIZED_STRING* str = (SIZED_STRING*) yr_malloc( \
      str_len + sizeof(SIZED_STRING)); \
  if (str == NULL) \
  { \
    yyerror(yyscanner, compiler, "not enough memory"); \
    yyterminate(); \
  } \
  else \
  { \
    str->length = (str_len); \
    str->flags = 0; \
  } \

#ifdef _WIN32
#define snprintf _snprintf
#endif

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option noinput
%option nounput
%option never-interactive
%option yylineno
%option prefix="yara_yy"
%option outfile="lex.yy.c"

%option verbose
%option warn

%x str
%x regexp
%x include
%x comment

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]

%%

"<"                     { return _LT_;          }
">"                     { return _GT_;          }
"<="                    { return _LE_;          }
">="                    { return _GE_;          }
"=="                    { return _EQ_;          }
"!="                    { return _NEQ_;         }
"<<"                    { return _SHIFT_LEFT_;  }
">>"                    { return _SHIFT_RIGHT_; }
"private"               { return _PRIVATE_;     }
"global"                { return _GLOBAL_;      }
"rule"                  { return _RULE_;        }
"meta"                  { return _META_;        }
"strings"               { return _STRINGS_;     }
"ascii"                 { return _ASCII_;       }
"wide"                  { return _WIDE_;        }
"fullword"              { return _FULLWORD_;    }
"nocase"                { return _NOCASE_;      }
"condition"             { return _CONDITION_;   }
"true"                  { return _TRUE_;        }
"false"                 { return _FALSE_;       }
"not"                   { return _NOT_;         }
"and"                   { return _AND_;         }
"or"                    { return _OR_;          }
"at"                    { return _AT_;          }
"in"                    { return _IN_;          }
"of"                    { return _OF_;          }
"them"                  { return _THEM_;        }
"for"                   { return _FOR_;         }
"all"                   { return _ALL_;         }
"any"                   { return _ANY_;         }
"entrypoint"            { return _ENTRYPOINT_;  }
"filesize"              { return _FILESIZE_;    }
"matches"               { return _MATCHES_;     }
"contains"              { return _CONTAINS_;    }
"import"                { return _IMPORT_;      }


"/*"                    { BEGIN(comment);       }
<comment>"*/"           { BEGIN(INITIAL);       }
<comment>(.|\n)         { /* skip comments */   }


"//"[^\n]*              { /* skip single-line comments */ }


include[ \t]+\"         {
                          yyextra->lex_buf_ptr = yyextra->lex_buf;
                          yyextra->lex_buf_len = 0;
                          BEGIN(include);
                        }


<include>[^\"]+         { YYTEXT_TO_BUFFER; }


<include>\"             {

  char            buffer[1024];
  char            *current_file_name;
  char            *s = NULL;
  char            *b = NULL;
  char            *f;
  FILE*           fh;

  if (compiler->allow_includes)
  {
    *yyextra->lex_buf_ptr = '\0'; // null-terminate included file path

    // move path of current source file into buffer
    current_file_name = yr_compiler_get_current_file_name(compiler);

    if (current_file_name != NULL)
    {
      strlcpy(buffer, current_file_name, sizeof(buffer));
    }
    else
    {
      buffer[0] = '\0';
    }

    // make included file path relative to current source file
    s = strrchr(buffer, '/');

    #ifdef _WIN32
    b = strrchr(buffer, '\\'); // in Windows both path delimiters are accepted
    #endif

    if (s != NULL || b != NULL)
    {
      f = (b > s)? (b + 1): (s + 1);

      strlcpy(f, yyextra->lex_buf, sizeof(buffer) - (f - buffer));

      f = buffer;

      // SECURITY: Potential for directory traversal here.
      fh = fopen(buffer, "r");

      // if include file was not found relative to current source file,
      // try to open it with path as specified by user (maybe user wrote
      // a full path)

      if (fh == NULL)
      {
        f = yyextra->lex_buf;

        // SECURITY: Potential for directory traversal here.
        fh = fopen(yyextra->lex_buf, "r");
      }
    }
    else
    {
      f = yyextra->lex_buf;

      // SECURITY: Potential for directory traversal here.
      fh = fopen(yyextra->lex_buf, "r");
    }

    if (fh != NULL)
    {
      int error_code = _yr_compiler_push_file_name(compiler, f);

      if (error_code != ERROR_SUCCESS)
      {
        if (error_code == ERROR_INCLUDES_CIRCULAR_REFERENCE)
        {
          yyerror(yyscanner, compiler, "includes circular reference");
        }
        else if (error_code == ERROR_INCLUDE_DEPTH_EXCEEDED)
        {
          yyerror(yyscanner, compiler, "includes depth exceeded");
        }

        yyterminate();
      }

      _yr_compiler_push_file(compiler, fh);
      yypush_buffer_state(
          yy_create_buffer(fh, YY_BUF_SIZE, yyscanner), yyscanner);
    }
    else
    {
      snprintf(buffer, sizeof(buffer),
               "can't open include file: %s", yyextra->lex_buf);
      yyerror(yyscanner, compiler, buffer);
    }
  }
  else // not allowing includes
  {
    yyerror(yyscanner, compiler, "includes are disabled");
    yyterminate();
  }

  BEGIN(INITIAL);
}


<<EOF>> {

  YR_COMPILER* compiler = yyget_extra(yyscanner);
  FILE* file = _yr_compiler_pop_file(compiler);

  if (file != NULL)
  {
    fclose(file);
  }

  _yr_compiler_pop_file_name(compiler);
  yypop_buffer_state(yyscanner);

  if (!YY_CURRENT_BUFFER)
  {
    yyterminate();
  }
}


$({letter}|{digit}|_)*"*"  {

  yylval->c_string = yr_strdup(yytext);

  if (yylval->c_string == NULL)
  {
    yyerror(yyscanner, compiler, "not enough memory");
    yyterminate();
  }

  return _STRING_IDENTIFIER_WITH_WILDCARD_;
}


$({letter}|{digit}|_)*  {

  yylval->c_string = yr_strdup(yytext);

  if (yylval->c_string == NULL)
  {
    yyerror(yyscanner, compiler, "not enough memory");
    yyterminate();
  }

  return _STRING_IDENTIFIER_;
}


#({letter}|{digit}|_)*  {

  yylval->c_string = yr_strdup(yytext);

  if (yylval->c_string == NULL)
  {
    yyerror(yyscanner, compiler, "not enough memory");
    yyterminate();
  }

  yylval->c_string[0] = '$'; /* replace # by $*/
  return _STRING_COUNT_;
}


@({letter}|{digit}|_)*  {

  yylval->c_string = yr_strdup(yytext);

  if (yylval->c_string == NULL)
  {
    yyerror(yyscanner, compiler, "not enough memory");
    yyterminate();
  }

  yylval->c_string[0] = '$'; /* replace @ by $*/
  return _STRING_OFFSET_;
}


u?int(8|16|32)(be)? {

  char* text = yytext;

  if (*text == 'u')
  {
    yylval->integer = 3;
    text++;
  }
  else
  {
    yylval->integer = 0;
  }

  if (strstr(text, "int8") == text)
  {
    yylval->integer += 0;
    text += 4;
  }
  else if (strstr(text, "int16") == text)
  {
    yylval->integer += 1;
    text += 5;
  }
  else if (strstr(text, "int32") == text)
  {
    yylval->integer += 2;
    text += 5;
  }

  if (strcmp(text, "be") == 0)
  {
    yylval->integer += 6;
  }

  return _INTEGER_FUNCTION_;
}


({letter}|_)({letter}|{digit}|_)*  {

  if (strlen(yytext) > 128)
  {
    yyerror(yyscanner, compiler, "indentifier too long");
  }

  yylval->c_string = yr_strdup(yytext);

  if (yylval->c_string == NULL)
  {
    yyerror(yyscanner, compiler, "not enough memory");
    yyterminate();
  }

  return _IDENTIFIER_;
}


{digit}+(MB|KB){0,1}  {

  #ifdef _MSC_VER
  yylval->integer = _atoi64(yytext);
  #else
  yylval->integer = atoll(yytext);
  #endif

  if (strstr(yytext, "KB") != NULL)
  {
     yylval->integer *= 1024;
  }
  else if (strstr(yytext, "MB") != NULL)
  {
     yylval->integer *= 1048576;
  }
  return _NUMBER_;
}

{digit}+"."{digit}+  {
  yylval->double_ = atof(yytext);
  return _DOUBLE_;
}

0x{hexdigit}+  {

  yylval->integer = xtoi(yytext + 2);
  return _NUMBER_;
}


<str>\"   {     /* saw closing quote - all done */

  *yyextra->lex_buf_ptr = '\0';

  BEGIN(INITIAL);
  ALLOC_SIZED_STRING(s, yyextra->lex_buf_len);

  memcpy(s->c_string, yyextra->lex_buf, yyextra->lex_buf_len + 1);
  yylval->sized_string = s;

  return _TEXT_STRING_;
}


<str>\\t   {

  LEX_CHECK_SPACE_OK("\t", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = '\t';
  yyextra->lex_buf_len++;
}


<str>\\n   {

  LEX_CHECK_SPACE_OK("\n", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = '\n';
  yyextra->lex_buf_len++;
}


<str>\\\"   {

  LEX_CHECK_SPACE_OK("\"", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = '\"';
  yyextra->lex_buf_len++;
}


<str>\\\\   {

  LEX_CHECK_SPACE_OK("\\", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = '\\';
  yyextra->lex_buf_len++;
}


<str>\\x{hexdigit}{2} {

   int result;

   sscanf( yytext + 2, "%x", &result );
   LEX_CHECK_SPACE_OK("X", yyextra->lex_buf_len, LEX_BUF_SIZE);
   *yyextra->lex_buf_ptr++ = result;
   yyextra->lex_buf_len++;
}


<str>[^\\\n\"]+   { YYTEXT_TO_BUFFER; }


<str>\n  {

  yyerror(yyscanner, compiler, "unterminated string");
  yyterminate();
}

<str>\\(.|\n) {

  yyerror(yyscanner, compiler, "illegal escape sequence");
}


<regexp>\/i?s?  {

  if (yyextra->lex_buf_len == 0)
  {
    yyerror(yyscanner, compiler, "empty regular expression");
  }

  *yyextra->lex_buf_ptr = '\0';

  BEGIN(INITIAL);
  ALLOC_SIZED_STRING(s, yyextra->lex_buf_len);

  if (yytext[1] == 'i')
    s->flags |= SIZED_STRING_FLAGS_NO_CASE;

  if (yytext[1] == 's' || yytext[2] == 's')
    s->flags |= SIZED_STRING_FLAGS_DOT_ALL;

  strlcpy(s->c_string, yyextra->lex_buf, s->length + 1);

  yylval->sized_string = s;

  return _REGEXP_;
}


<regexp>\\\/  {

  LEX_CHECK_SPACE_OK("/", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = '/';
  yyextra->lex_buf_len++ ;
}


<regexp>\\. {

  LEX_CHECK_SPACE_OK("\\.", yyextra->lex_buf_len, LEX_BUF_SIZE);
  *yyextra->lex_buf_ptr++ = yytext[0];
  *yyextra->lex_buf_ptr++ = yytext[1];
  yyextra->lex_buf_len += 2;
}


<regexp>[^/\n\\]+ { YYTEXT_TO_BUFFER; }


<regexp>\n  {

  yyerror(yyscanner, compiler, "unterminated regular expression");
  yyterminate();
}


\"  {

  yyextra->lex_buf_ptr = yyextra->lex_buf;
  yyextra->lex_buf_len = 0;
  BEGIN(str);
}


"/"  {

  yyextra->lex_buf_ptr = yyextra->lex_buf;
  yyextra->lex_buf_len = 0;
  BEGIN(regexp);
}


\{({hexdigit}|[ \-|\?\[\]\(\)\n\t])+\}  {

  ALLOC_SIZED_STRING(s, strlen(yytext));

  strlcpy(s->c_string, yytext, s->length + 1);
  yylval->sized_string = s;

  return _HEX_STRING_;
}


[ \t\r\n]   /* skip whitespace */

.   {

  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    return yytext[0];
  }
  else
  {
    yyerror(yyscanner, compiler, "non-ascii character");
    yyterminate();
  }
}

%%


void yywarning(
    yyscan_t yyscanner,
    const char *warning_message)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  char* file_name;

  if (compiler->callback == NULL)
    return;

  if (compiler->file_name_stack_ptr > 0)
    file_name = compiler->file_name_stack[compiler->file_name_stack_ptr - 1];
  else
    file_name = NULL;

  compiler->callback(
      YARA_ERROR_LEVEL_WARNING,
      file_name,
      yyget_lineno(yyscanner),
      warning_message,
      compiler->user_data);
}


void yyfatal(
    yyscan_t yyscanner,
    const char *error_message)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  yyerror(yyscanner, compiler, error_message);
  longjmp(compiler->error_recovery, 1);
}


void yyerror(
    yyscan_t yyscanner,
    YR_COMPILER* compiler,
    const char *error_message)
{
  char message[512] = {'\0'};
  char* file_name = NULL;

  /*
    if error_message != NULL the error comes from yyparse internal code
    else the error comes from my code and the error code is set in
    compiler->last_result
  */

  compiler->errors++;

  if (compiler->error_line != 0)
    compiler->last_error_line = compiler->error_line;
  else
    compiler->last_error_line = yyget_lineno(yyscanner);

  compiler->error_line = 0;

  if (compiler->file_name_stack_ptr > 0)
  {
    file_name = compiler->file_name_stack[compiler->file_name_stack_ptr - 1];
  }
  else
  {
    file_name = NULL;
  }

  if (error_message != NULL)
  {
    yr_compiler_set_error_extra_info(compiler, error_message);
    compiler->last_error = ERROR_SYNTAX_ERROR;

    if (compiler->callback != NULL)
    {
      compiler->callback(
          YARA_ERROR_LEVEL_ERROR,
          file_name,
          compiler->last_error_line,
          error_message,
          compiler->user_data);
    }
  }
  else
  {
    compiler->last_error = compiler->last_result;

    if (compiler->callback != NULL)
    {
      yr_compiler_get_error_message(compiler, message, sizeof(message));

      compiler->callback(
        YARA_ERROR_LEVEL_ERROR,
        file_name,
        compiler->last_error_line,
        message,
        compiler->user_data);
    }
  }

  compiler->last_result = ERROR_SUCCESS;
}


int yr_lex_parse_rules_string(
  const char* rules_string,
  YR_COMPILER* compiler)
{
  yyscan_t yyscanner;

  compiler->errors = 0;

  if (setjmp(compiler->error_recovery) != 0)
    return compiler->errors;

  yylex_init(&yyscanner);

  yyset_debug(1, yyscanner);

  yyset_extra(compiler, yyscanner);

  yy_scan_string(rules_string, yyscanner);

  yyset_lineno(1, yyscanner);
  yyparse(yyscanner, compiler);
  yylex_destroy(yyscanner);

  return compiler->errors;
}


int yr_lex_parse_rules_file(
  FILE* rules_file,
  YR_COMPILER* compiler)
{
  yyscan_t yyscanner;

  compiler->errors = 0;

  if (setjmp(compiler->error_recovery) != 0)
    return compiler->errors;

  yylex_init(&yyscanner);

  #if YYDEBUG
  printf("debug enabled");
  #endif

  yyset_debug(1, yyscanner);

  yyset_in(rules_file, yyscanner);
  yyset_extra(compiler, yyscanner);
  yyparse(yyscanner, compiler);
  yylex_destroy(yyscanner);

  return compiler->errors;
}
