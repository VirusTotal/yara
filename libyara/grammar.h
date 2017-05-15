/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YARA_YY_GRAMMAR_H_INCLUDED
# define YY_YARA_YY_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    _DOT_DOT_ = 258,
    _RULE_ = 259,
    _PRIVATE_ = 260,
    _GLOBAL_ = 261,
    _META_ = 262,
    _STRINGS_ = 263,
    _CONDITION_ = 264,
    _IDENTIFIER_ = 265,
    _STRING_IDENTIFIER_ = 266,
    _STRING_COUNT_ = 267,
    _STRING_OFFSET_ = 268,
    _STRING_LENGTH_ = 269,
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 270,
    _NUMBER_ = 271,
    _DOUBLE_ = 272,
    _INTEGER_FUNCTION_ = 273,
    _TEXT_STRING_ = 274,
    _HEX_STRING_ = 275,
    _REGEXP_ = 276,
    _ASCII_ = 277,
    _WIDE_ = 278,
    _NOCASE_ = 279,
    _FULLWORD_ = 280,
    _AT_ = 281,
    _FILESIZE_ = 282,
    _ENTRYPOINT_ = 283,
    _ALL_ = 284,
    _ANY_ = 285,
    _IN_ = 286,
    _OF_ = 287,
    _FOR_ = 288,
    _THEM_ = 289,
    _MATCHES_ = 290,
    _CONTAINS_ = 291,
    _IMPORT_ = 292,
    _TRUE_ = 293,
    _FALSE_ = 294,
    _OR_ = 295,
    _AND_ = 296,
    _EQ_ = 297,
    _NEQ_ = 298,
    _LT_ = 299,
    _LE_ = 300,
    _GT_ = 301,
    _GE_ = 302,
    _SHIFT_LEFT_ = 303,
    _SHIFT_RIGHT_ = 304,
    _NOT_ = 305,
    UNARY_MINUS = 306
  };
#endif
/* Tokens.  */
#define _DOT_DOT_ 258
#define _RULE_ 259
#define _PRIVATE_ 260
#define _GLOBAL_ 261
#define _META_ 262
#define _STRINGS_ 263
#define _CONDITION_ 264
#define _IDENTIFIER_ 265
#define _STRING_IDENTIFIER_ 266
#define _STRING_COUNT_ 267
#define _STRING_OFFSET_ 268
#define _STRING_LENGTH_ 269
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 270
#define _NUMBER_ 271
#define _DOUBLE_ 272
#define _INTEGER_FUNCTION_ 273
#define _TEXT_STRING_ 274
#define _HEX_STRING_ 275
#define _REGEXP_ 276
#define _ASCII_ 277
#define _WIDE_ 278
#define _NOCASE_ 279
#define _FULLWORD_ 280
#define _AT_ 281
#define _FILESIZE_ 282
#define _ENTRYPOINT_ 283
#define _ALL_ 284
#define _ANY_ 285
#define _IN_ 286
#define _OF_ 287
#define _FOR_ 288
#define _THEM_ 289
#define _MATCHES_ 290
#define _CONTAINS_ 291
#define _IMPORT_ 292
#define _TRUE_ 293
#define _FALSE_ 294
#define _OR_ 295
#define _AND_ 296
#define _EQ_ 297
#define _NEQ_ 298
#define _LT_ 299
#define _LE_ 300
#define _GT_ 301
#define _GE_ 302
#define _SHIFT_LEFT_ 303
#define _SHIFT_RIGHT_ 304
#define _NOT_ 305
#define UNARY_MINUS 306

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 204 "grammar.y" /* yacc.c:1915  */

  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;
  YR_RULE*        rule;

#line 167 "grammar.h" /* yacc.c:1915  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */
