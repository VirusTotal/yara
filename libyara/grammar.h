/* A Bison parser, made by GNU Bison 3.6.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YARA_YY_GRAMMAR_H_INCLUDED
# define YY_YARA_YY_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    _END_OF_FILE_ = 0,             /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    _END_OF_INCLUDED_FILE_ = 258,  /* "end of included file"  */
    _DOT_DOT_ = 259,               /* ".."  */
    _RULE_ = 260,                  /* "<rule>"  */
    _PRIVATE_ = 261,               /* "<private>"  */
    _GLOBAL_ = 262,                /* "<global>"  */
    _META_ = 263,                  /* "<meta>"  */
    _STRINGS_ = 264,               /* "<strings>"  */
    _VARIABLES_ = 265,             /* "<variables>"  */
    _CONDITION_ = 266,             /* "<condition>"  */
    _IDENTIFIER_ = 267,            /* "identifier"  */
    _STRING_IDENTIFIER_ = 268,     /* "string identifier"  */
    _STRING_COUNT_ = 269,          /* "string count"  */
    _STRING_OFFSET_ = 270,         /* "string offset"  */
    _STRING_LENGTH_ = 271,         /* "string length"  */
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 272, /* "string identifier with wildcard"  */
    _NUMBER_ = 273,                /* "integer number"  */
    _DOUBLE_ = 274,                /* "floating point number"  */
    _INTEGER_FUNCTION_ = 275,      /* "integer function"  */
    _TEXT_STRING_ = 276,           /* "text string"  */
    _HEX_STRING_ = 277,            /* "hex string"  */
    _REGEXP_ = 278,                /* "regular expression"  */
    _ASCII_ = 279,                 /* "<ascii>"  */
    _WIDE_ = 280,                  /* "<wide>"  */
    _XOR_ = 281,                   /* "<xor>"  */
    _BASE64_ = 282,                /* "<base64>"  */
    _BASE64_WIDE_ = 283,           /* "<base64wide>"  */
    _NOCASE_ = 284,                /* "<nocase>"  */
    _FULLWORD_ = 285,              /* "<fullword>"  */
    _AT_ = 286,                    /* "<at>"  */
    _FILESIZE_ = 287,              /* "<filesize>"  */
    _ENTRYPOINT_ = 288,            /* "<entrypoint>"  */
    _ALL_ = 289,                   /* "<all>"  */
    _ANY_ = 290,                   /* "<any>"  */
    _IN_ = 291,                    /* "<in>"  */
    _OF_ = 292,                    /* "<of>"  */
    _FOR_ = 293,                   /* "<for>"  */
    _THEM_ = 294,                  /* "<them>"  */
    _MATCHES_ = 295,               /* "<matches>"  */
    _CONTAINS_ = 296,              /* "<contains>"  */
    _IMPORT_ = 297,                /* "<import>"  */
    _TRUE_ = 298,                  /* "<true>"  */
    _FALSE_ = 299,                 /* "<false"  */
    _OR_ = 300,                    /* "<or>"  */
    _AND_ = 301,                   /* "<and>"  */
    _NOT_ = 302,                   /* "<not>"  */
    _EQ_ = 303,                    /* "=="  */
    _NEQ_ = 304,                   /* "!="  */
    _LT_ = 305,                    /* "<"  */
    _LE_ = 306,                    /* "<="  */
    _GT_ = 307,                    /* ">"  */
    _GE_ = 308,                    /* ">="  */
    _SHIFT_LEFT_ = 309,            /* "<<"  */
    _SHIFT_RIGHT_ = 310,           /* ">>"  */
    UNARY_MINUS = 311              /* UNARY_MINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define _END_OF_FILE_ 0
#define YYerror 256
#define YYUNDEF 257
#define _END_OF_INCLUDED_FILE_ 258
#define _DOT_DOT_ 259
#define _RULE_ 260
#define _PRIVATE_ 261
#define _GLOBAL_ 262
#define _META_ 263
#define _STRINGS_ 264
#define _VARIABLES_ 265
#define _CONDITION_ 266
#define _IDENTIFIER_ 267
#define _STRING_IDENTIFIER_ 268
#define _STRING_COUNT_ 269
#define _STRING_OFFSET_ 270
#define _STRING_LENGTH_ 271
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 272
#define _NUMBER_ 273
#define _DOUBLE_ 274
#define _INTEGER_FUNCTION_ 275
#define _TEXT_STRING_ 276
#define _HEX_STRING_ 277
#define _REGEXP_ 278
#define _ASCII_ 279
#define _WIDE_ 280
#define _XOR_ 281
#define _BASE64_ 282
#define _BASE64_WIDE_ 283
#define _NOCASE_ 284
#define _FULLWORD_ 285
#define _AT_ 286
#define _FILESIZE_ 287
#define _ENTRYPOINT_ 288
#define _ALL_ 289
#define _ANY_ 290
#define _IN_ 291
#define _OF_ 292
#define _FOR_ 293
#define _THEM_ 294
#define _MATCHES_ 295
#define _CONTAINS_ 296
#define _IMPORT_ 297
#define _TRUE_ 298
#define _FALSE_ 299
#define _OR_ 300
#define _AND_ 301
#define _NOT_ 302
#define _EQ_ 303
#define _NEQ_ 304
#define _LT_ 305
#define _LE_ 306
#define _GT_ 307
#define _GE_ 308
#define _SHIFT_LEFT_ 309
#define _SHIFT_RIGHT_ 310
#define UNARY_MINUS 311

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 305 "grammar.y"

  YR_EXPRESSION   expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_MODIFIER     modifier;

  YR_ARENA_REF tag;
  YR_ARENA_REF rule;
  YR_ARENA_REF meta;
  YR_ARENA_REF string;

#line 192 "grammar.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */
