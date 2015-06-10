/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

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

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
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
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 269,
     _NUMBER_ = 270,
     _DOUBLE_ = 271,
     _INTEGER_FUNCTION_ = 272,
     _TEXT_STRING_ = 273,
     _HEX_STRING_ = 274,
     _REGEXP_ = 275,
     _ASCII_ = 276,
     _WIDE_ = 277,
     _NOCASE_ = 278,
     _FULLWORD_ = 279,
     _AT_ = 280,
     _FILESIZE_ = 281,
     _ENTRYPOINT_ = 282,
     _ALL_ = 283,
     _ANY_ = 284,
     _IN_ = 285,
     _OF_ = 286,
     _FOR_ = 287,
     _THEM_ = 288,
     _MATCHES_ = 289,
     _CONTAINS_ = 290,
     _IMPORT_ = 291,
     _TRUE_ = 292,
     _FALSE_ = 293,
     _OR_ = 294,
     _AND_ = 295,
     _NEQ_ = 296,
     _EQ_ = 297,
     _GE_ = 298,
     _GT_ = 299,
     _LE_ = 300,
     _LT_ = 301,
     _SHIFT_RIGHT_ = 302,
     _SHIFT_LEFT_ = 303,
     UNARY_MINUS = 304,
     _NOT_ = 305
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
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 269
#define _NUMBER_ 270
#define _DOUBLE_ 271
#define _INTEGER_FUNCTION_ 272
#define _TEXT_STRING_ 273
#define _HEX_STRING_ 274
#define _REGEXP_ 275
#define _ASCII_ 276
#define _WIDE_ 277
#define _NOCASE_ 278
#define _FULLWORD_ 279
#define _AT_ 280
#define _FILESIZE_ 281
#define _ENTRYPOINT_ 282
#define _ALL_ 283
#define _ANY_ 284
#define _IN_ 285
#define _OF_ 286
#define _FOR_ 287
#define _THEM_ 288
#define _MATCHES_ 289
#define _CONTAINS_ 290
#define _IMPORT_ 291
#define _TRUE_ 292
#define _FALSE_ 293
#define _OR_ 294
#define _AND_ 295
#define _NEQ_ 296
#define _EQ_ 297
#define _GE_ 298
#define _GT_ 299
#define _LE_ 300
#define _LT_ 301
#define _SHIFT_RIGHT_ 302
#define _SHIFT_LEFT_ 303
#define UNARY_MINUS 304
#define _NOT_ 305




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 181 "grammar.y"
{
  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;
  YR_RULE*        rule;
}
/* Line 1529 of yacc.c.  */
#line 160 "grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



