/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
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
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

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

#ifndef YY_YARA_YY_LIBYARA_GRAMMAR_H_INCLUDED
# define YY_YARA_YY_LIBYARA_GRAMMAR_H_INCLUDED
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
    _CONDITION_ = 265,             /* "<condition>"  */
    _IDENTIFIER_ = 266,            /* "identifier"  */
    _STRING_IDENTIFIER_ = 267,     /* "string identifier"  */
    _STRING_COUNT_ = 268,          /* "string count"  */
    _STRING_OFFSET_ = 269,         /* "string offset"  */
    _STRING_LENGTH_ = 270,         /* "string length"  */
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 271, /* "string identifier with wildcard"  */
    _NUMBER_ = 272,                /* "integer number"  */
    _DOUBLE_ = 273,                /* "floating point number"  */
    _TEXT_STRING_ = 274,           /* "text string"  */
    _HEX_STRING_ = 275,            /* "hex string"  */
    _REGEXP_ = 276,                /* "regular expression"  */
    _INT8_FUNCTION_ = 277,         /* "<int8>"  */
    _UINT8_FUNCTION_ = 278,        /* "<uint8>"  */
    _INT16_FUNCTION_ = 279,        /* "<int16>"  */
    _UINT16_FUNCTION_ = 280,       /* "<uint16>"  */
    _INT32_FUNCTION_ = 281,        /* "<int32>"  */
    _UINT32_FUNCTION_ = 282,       /* "<uint32>"  */
    _INT8BE_FUNCTION_ = 283,       /* "<int8be>"  */
    _UINT8BE_FUNCTION_ = 284,      /* "<uint8be>"  */
    _INT16BE_FUNCTION_ = 285,      /* "<int16be>"  */
    _UINT16BE_FUNCTION_ = 286,     /* "<uint16be>"  */
    _INT32BE_FUNCTION_ = 287,      /* "<int32be>"  */
    _UINT32BE_FUNCTION_ = 288,     /* "<uint32be>"  */
    _ASCII_ = 289,                 /* "<ascii>"  */
    _WIDE_ = 290,                  /* "<wide>"  */
    _XOR_ = 291,                   /* "<xor>"  */
    _BASE64_ = 292,                /* "<base64>"  */
    _BASE64_WIDE_ = 293,           /* "<base64wide>"  */
    _NOCASE_ = 294,                /* "<nocase>"  */
    _FULLWORD_ = 295,              /* "<fullword>"  */
    _AT_ = 296,                    /* "<at>"  */
    _FILESIZE_ = 297,              /* "<filesize>"  */
    _ENTRYPOINT_ = 298,            /* "<entrypoint>"  */
    _ALL_ = 299,                   /* "<all>"  */
    _ANY_ = 300,                   /* "<any>"  */
    _NONE_ = 301,                  /* "<none>"  */
    _IN_ = 302,                    /* "<in>"  */
    _OF_ = 303,                    /* "<of>"  */
    _FOR_ = 304,                   /* "<for>"  */
    _THEM_ = 305,                  /* "<them>"  */
    _MATCHES_ = 306,               /* "<matches>"  */
    _CONTAINS_ = 307,              /* "<contains>"  */
    _STARTSWITH_ = 308,            /* "<startswith>"  */
    _ENDSWITH_ = 309,              /* "<endswith>"  */
    _ICONTAINS_ = 310,             /* "<icontains>"  */
    _ISTARTSWITH_ = 311,           /* "<istartswith>"  */
    _IENDSWITH_ = 312,             /* "<iendswith>"  */
    _IEQUALS_ = 313,               /* "<iequals>"  */
    _IMPORT_ = 314,                /* "<import>"  */
    _TRUE_ = 315,                  /* "<true>"  */
    _FALSE_ = 316,                 /* "<false>"  */
    _OR_ = 317,                    /* "<or>"  */
    _AND_ = 318,                   /* "<and>"  */
    _NOT_ = 319,                   /* "<not>"  */
    _DEFINED_ = 320,               /* "<defined>"  */
    _EQ_ = 321,                    /* "=="  */
    _NEQ_ = 322,                   /* "!="  */
    _LT_ = 323,                    /* "<"  */
    _LE_ = 324,                    /* "<="  */
    _GT_ = 325,                    /* ">"  */
    _GE_ = 326,                    /* ">="  */
    _SHIFT_LEFT_ = 327,            /* "<<"  */
    _SHIFT_RIGHT_ = 328,           /* ">>"  */
    UNARY_MINUS = 329              /* UNARY_MINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
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
#define _CONDITION_ 265
#define _IDENTIFIER_ 266
#define _STRING_IDENTIFIER_ 267
#define _STRING_COUNT_ 268
#define _STRING_OFFSET_ 269
#define _STRING_LENGTH_ 270
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 271
#define _NUMBER_ 272
#define _DOUBLE_ 273
#define _TEXT_STRING_ 274
#define _HEX_STRING_ 275
#define _REGEXP_ 276
#define _INT8_FUNCTION_ 277
#define _UINT8_FUNCTION_ 278
#define _INT16_FUNCTION_ 279
#define _UINT16_FUNCTION_ 280
#define _INT32_FUNCTION_ 281
#define _UINT32_FUNCTION_ 282
#define _INT8BE_FUNCTION_ 283
#define _UINT8BE_FUNCTION_ 284
#define _INT16BE_FUNCTION_ 285
#define _UINT16BE_FUNCTION_ 286
#define _INT32BE_FUNCTION_ 287
#define _UINT32BE_FUNCTION_ 288
#define _ASCII_ 289
#define _WIDE_ 290
#define _XOR_ 291
#define _BASE64_ 292
#define _BASE64_WIDE_ 293
#define _NOCASE_ 294
#define _FULLWORD_ 295
#define _AT_ 296
#define _FILESIZE_ 297
#define _ENTRYPOINT_ 298
#define _ALL_ 299
#define _ANY_ 300
#define _NONE_ 301
#define _IN_ 302
#define _OF_ 303
#define _FOR_ 304
#define _THEM_ 305
#define _MATCHES_ 306
#define _CONTAINS_ 307
#define _STARTSWITH_ 308
#define _ENDSWITH_ 309
#define _ICONTAINS_ 310
#define _ISTARTSWITH_ 311
#define _IENDSWITH_ 312
#define _IEQUALS_ 313
#define _IMPORT_ 314
#define _TRUE_ 315
#define _FALSE_ 316
#define _OR_ 317
#define _AND_ 318
#define _NOT_ 319
#define _DEFINED_ 320
#define _EQ_ 321
#define _NEQ_ 322
#define _LT_ 323
#define _LE_ 324
#define _GT_ 325
#define _GE_ 326
#define _SHIFT_LEFT_ 327
#define _SHIFT_RIGHT_ 328
#define UNARY_MINUS 329

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 354 "libyara/grammar.y"

  YR_EXPRESSION   expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_MODIFIER     modifier;
  YR_ENUMERATION  enumeration;

  YR_ARENA_REF tag;
  YR_ARENA_REF rule;
  YR_ARENA_REF meta;
  YR_ARENA_REF string;

#line 230 "libyara/grammar.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);


#endif /* !YY_YARA_YY_LIBYARA_GRAMMAR_H_INCLUDED  */
