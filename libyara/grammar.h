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
     RULE = 258,
     PRIVATE = 259,
     GLOBAL = 260,
     META = 261,
     STRINGS = 262,
     CONDITION = 263,
     IDENTIFIER = 264,
     STRING_IDENTIFIER = 265,
     STRING_COUNT = 266,
     STRING_OFFSET = 267,
     STRING_IDENTIFIER_WITH_WILDCARD = 268,
     NUMBER = 269,
     TEXT_STRING = 270,
     HEX_STRING = 271,
     REGEXP = 272,
     ASCII = 273,
     WIDE = 274,
     NOCASE = 275,
     FULLWORD = 276,
     AT = 277,
     FILESIZE = 278,
     ENTRYPOINT = 279,
     ALL = 280,
     ANY = 281,
     IN = 282,
     OF = 283,
     FOR = 284,
     THEM = 285,
     INT8 = 286,
     INT16 = 287,
     INT32 = 288,
     UINT8 = 289,
     UINT16 = 290,
     UINT32 = 291,
     MATCHES = 292,
     CONTAINS = 293,
     IMPORT = 294,
     _TRUE_ = 295,
     _FALSE_ = 296,
     OR = 297,
     AND = 298,
     IS = 299,
     NEQ = 300,
     EQ = 301,
     GE = 302,
     GT = 303,
     LE = 304,
     LT = 305,
     SHIFT_RIGHT = 306,
     SHIFT_LEFT = 307,
     NOT = 308
   };
#endif
/* Tokens.  */
#define RULE 258
#define PRIVATE 259
#define GLOBAL 260
#define META 261
#define STRINGS 262
#define CONDITION 263
#define IDENTIFIER 264
#define STRING_IDENTIFIER 265
#define STRING_COUNT 266
#define STRING_OFFSET 267
#define STRING_IDENTIFIER_WITH_WILDCARD 268
#define NUMBER 269
#define TEXT_STRING 270
#define HEX_STRING 271
#define REGEXP 272
#define ASCII 273
#define WIDE 274
#define NOCASE 275
#define FULLWORD 276
#define AT 277
#define FILESIZE 278
#define ENTRYPOINT 279
#define ALL 280
#define ANY 281
#define IN 282
#define OF 283
#define FOR 284
#define THEM 285
#define INT8 286
#define INT16 287
#define INT32 288
#define UINT8 289
#define UINT16 290
#define UINT32 291
#define MATCHES 292
#define CONTAINS 293
#define IMPORT 294
#define _TRUE_ 295
#define _FALSE_ 296
#define OR 297
#define AND 298
#define IS 299
#define NEQ 300
#define EQ 301
#define GE 302
#define GT 303
#define LE 304
#define LT 305
#define SHIFT_RIGHT 306
#define SHIFT_LEFT 307
#define NOT 308




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 185 "grammar.y"
{
  SIZED_STRING*   sized_string;
  char*           c_string;
  int8_t          expression_type;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
  YR_OBJECT*      object;
}
/* Line 1529 of yacc.c.  */
#line 165 "grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



