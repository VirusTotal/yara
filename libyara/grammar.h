/* A Bison parser, made by GNU Bison 2.0.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     _RULE_ = 258,
     _PRIVATE_ = 259,
     _GLOBAL_ = 260,
     _STRINGS_ = 261,
     _CONDITION_ = 262,
     _END_ = 263,
     _IDENTIFIER_ = 264,
     _STRING_IDENTIFIER_ = 265,
     _STRING_COUNT_ = 266,
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 267,
     _ANONYMOUS_STRING_ = 268,
     _NUMBER_ = 269,
     _UNKNOWN_ = 270,
     _TEXTSTRING_ = 271,
     _HEXSTRING_ = 272,
     _REGEXP_ = 273,
     _ASCII_ = 274,
     _WIDE_ = 275,
     _NOCASE_ = 276,
     _FULLWORD_ = 277,
     _AT_ = 278,
     _SIZE_ = 279,
     _ENTRYPOINT_ = 280,
     _ALL_ = 281,
     _ANY_ = 282,
     _RVA_ = 283,
     _OFFSET_ = 284,
     _FILE_ = 285,
     _IN_ = 286,
     _OF_ = 287,
     _FOR_ = 288,
     _THEM_ = 289,
     _SECTION_ = 290,
     _INT8_ = 291,
     _INT16_ = 292,
     _INT32_ = 293,
     _UINT8_ = 294,
     _UINT16_ = 295,
     _UINT32_ = 296,
     _MZ_ = 297,
     _PE_ = 298,
     _DLL_ = 299,
     _TRUE_ = 300,
     _FALSE_ = 301,
     _OR_ = 302,
     _AND_ = 303,
     _NOT_ = 304,
     _IS_ = 305,
     _NEQ_ = 306,
     _EQ_ = 307,
     _GE_ = 308,
     _GT_ = 309,
     _LE_ = 310,
     _LT_ = 311
   };
#endif
#define _RULE_ 258
#define _PRIVATE_ 259
#define _GLOBAL_ 260
#define _STRINGS_ 261
#define _CONDITION_ 262
#define _END_ 263
#define _IDENTIFIER_ 264
#define _STRING_IDENTIFIER_ 265
#define _STRING_COUNT_ 266
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 267
#define _ANONYMOUS_STRING_ 268
#define _NUMBER_ 269
#define _UNKNOWN_ 270
#define _TEXTSTRING_ 271
#define _HEXSTRING_ 272
#define _REGEXP_ 273
#define _ASCII_ 274
#define _WIDE_ 275
#define _NOCASE_ 276
#define _FULLWORD_ 277
#define _AT_ 278
#define _SIZE_ 279
#define _ENTRYPOINT_ 280
#define _ALL_ 281
#define _ANY_ 282
#define _RVA_ 283
#define _OFFSET_ 284
#define _FILE_ 285
#define _IN_ 286
#define _OF_ 287
#define _FOR_ 288
#define _THEM_ 289
#define _SECTION_ 290
#define _INT8_ 291
#define _INT16_ 292
#define _INT32_ 293
#define _UINT8_ 294
#define _UINT16_ 295
#define _UINT32_ 296
#define _MZ_ 297
#define _PE_ 298
#define _DLL_ 299
#define _TRUE_ 300
#define _FALSE_ 301
#define _OR_ 302
#define _AND_ 303
#define _NOT_ 304
#define _IS_ 305
#define _NEQ_ 306
#define _EQ_ 307
#define _GE_ 308
#define _GT_ 309
#define _LE_ 310
#define _LT_ 311




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 92 "grammar.y"
typedef union YYSTYPE {
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;

} YYSTYPE;
/* Line 1318 of yacc.c.  */
#line 160 "grammar.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



