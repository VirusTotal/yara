/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

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
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    _RULE_ = 258,
    _PRIVATE_ = 259,
    _GLOBAL_ = 260,
    _META_ = 261,
    _STRINGS_ = 262,
    _CONDITION_ = 263,
    _IDENTIFIER_ = 264,
    _STRING_IDENTIFIER_ = 265,
    _STRING_COUNT_ = 266,
    _STRING_OFFSET_ = 267,
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 268,
    _NUMBER_ = 269,
    _DOUBLE_ = 270,
    _INTEGER_FUNCTION_ = 271,
    _TEXT_STRING_ = 272,
    _HEX_STRING_ = 273,
    _REGEXP_ = 274,
    _ASCII_ = 275,
    _WIDE_ = 276,
    _NOCASE_ = 277,
    _FULLWORD_ = 278,
    _AT_ = 279,
    _FILESIZE_ = 280,
    _ENTRYPOINT_ = 281,
    _ALL_ = 282,
    _ANY_ = 283,
    _IN_ = 284,
    _OF_ = 285,
    _FOR_ = 286,
    _THEM_ = 287,
    _MATCHES_ = 288,
    _CONTAINS_ = 289,
    _IMPORT_ = 290,
    _TRUE_ = 291,
    _FALSE_ = 292,
    _OR_ = 293,
    _AND_ = 294,
    _LT_ = 295,
    _LE_ = 296,
    _GT_ = 297,
    _GE_ = 298,
    _EQ_ = 299,
    _NEQ_ = 300,
    _IS_ = 301,
    _SHIFT_LEFT_ = 302,
    _SHIFT_RIGHT_ = 303,
    _NOT_ = 304
  };
#endif
/* Tokens.  */
#define _RULE_ 258
#define _PRIVATE_ 259
#define _GLOBAL_ 260
#define _META_ 261
#define _STRINGS_ 262
#define _CONDITION_ 263
#define _IDENTIFIER_ 264
#define _STRING_IDENTIFIER_ 265
#define _STRING_COUNT_ 266
#define _STRING_OFFSET_ 267
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 268
#define _NUMBER_ 269
#define _DOUBLE_ 270
#define _INTEGER_FUNCTION_ 271
#define _TEXT_STRING_ 272
#define _HEX_STRING_ 273
#define _REGEXP_ 274
#define _ASCII_ 275
#define _WIDE_ 276
#define _NOCASE_ 277
#define _FULLWORD_ 278
#define _AT_ 279
#define _FILESIZE_ 280
#define _ENTRYPOINT_ 281
#define _ALL_ 282
#define _ANY_ 283
#define _IN_ 284
#define _OF_ 285
#define _FOR_ 286
#define _THEM_ 287
#define _MATCHES_ 288
#define _CONTAINS_ 289
#define _IMPORT_ 290
#define _TRUE_ 291
#define _FALSE_ 292
#define _OR_ 293
#define _AND_ 294
#define _LT_ 295
#define _LE_ 296
#define _GT_ 297
#define _GE_ 298
#define _EQ_ 299
#define _NEQ_ 300
#define _IS_ 301
#define _SHIFT_LEFT_ 302
#define _SHIFT_RIGHT_ 303
#define _NOT_ 304

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 215 "grammar.y" /* yacc.c:1915  */

  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;

#line 162 "grammar.h" /* yacc.c:1915  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */
