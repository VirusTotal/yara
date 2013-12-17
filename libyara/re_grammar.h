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
     _CHAR_ = 258,
     _ANY_ = 259,
     _RANGE_ = 260,
     _CLASS_ = 261,
     _WORD_CHAR_ = 262,
     _NON_WORD_CHAR_ = 263,
     _SPACE_ = 264,
     _NON_SPACE_ = 265,
     _DIGIT_ = 266,
     _NON_DIGIT_ = 267
   };
#endif
/* Tokens.  */
#define _CHAR_ 258
#define _ANY_ 259
#define _RANGE_ 260
#define _CLASS_ 261
#define _WORD_CHAR_ 262
#define _NON_WORD_CHAR_ 263
#define _SPACE_ 264
#define _NON_SPACE_ 265
#define _DIGIT_ 266
#define _NON_DIGIT_ 267




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 67 "re_grammar.y"
{
  int integer;
  uint32_t range;
  RE_NODE* re_node;
  uint8_t* class_vector;
}
/* Line 1529 of yacc.c.  */
#line 80 "re_grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



