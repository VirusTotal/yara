/* A Bison parser, made by GNU Bison 3.0.5.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018 Free Software Foundation, Inc.

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

#ifndef YY_RE_YY_RE_GRAMMAR_H_INCLUDED
# define YY_RE_YY_RE_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int re_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    _CHAR_ = 258,
    _ANY_ = 259,
    _RANGE_ = 260,
    _CLASS_ = 261,
    _WORD_CHAR_ = 262,
    _NON_WORD_CHAR_ = 263,
    _SPACE_ = 264,
    _NON_SPACE_ = 265,
    _DIGIT_ = 266,
    _NON_DIGIT_ = 267,
    _WORD_BOUNDARY_ = 268,
    _NON_WORD_BOUNDARY_ = 269
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
#define _WORD_BOUNDARY_ 268
#define _NON_WORD_BOUNDARY_ 269

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 81 "re_grammar.y" /* yacc.c:1916  */

  int integer;
  uint32_t range;
  RE_NODE* re_node;
  RE_CLASS* re_class;

#line 89 "re_grammar.h" /* yacc.c:1916  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int re_yyparse (void *yyscanner, RE_LEX_ENVIRONMENT *lex_env);

#endif /* !YY_RE_YY_RE_GRAMMAR_H_INCLUDED  */
