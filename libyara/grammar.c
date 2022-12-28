/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         yara_yyparse
#define yylex           yara_yylex
#define yyerror         yara_yyerror
#define yydebug         yara_yydebug
#define yynerrs         yara_yynerrs

/* First part of user prologue.  */
#line 32 "libyara/grammar.y"


#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>

#include <yara/arena.h>
#include <yara/integers.h>
#include <yara/utils.h>
#include <yara/strutils.h>
#include <yara/compiler.h>
#include <yara/object.h>
#include <yara/sizedstr.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/lexer.h>
#include <yara/parser.h>

#if defined(_MSC_VER)
#define llabs _abs64
#endif

#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define FOR_EXPRESSION_ALL  1
#define FOR_EXPRESSION_ANY  2
#define FOR_EXPRESSION_NONE 3

#define FOR_ITERATION_ITERATOR   1
#define FOR_ITERATION_STRING_SET 2

// fail_with_error() is used in parser actions for aborting the parsing with
// an error. If the error is recoverable (like syntax errors), the parser will
// report the error and continue parsing the next rule. If the error is a
// fatal, non-recoverable error, the parser will be completely aborted.
#define fail_with_error(e) \
    { \
      compiler->last_error = e; \
      yyerror(yyscanner, compiler, NULL); \
      switch (e) \
      { \
      case ERROR_INSUFFICIENT_MEMORY: \
        YYABORT; \
      default: \
        YYERROR; \
      } \
    }

// fail_if_error() is used in parser actions for aborting the parsing if an
// error has occurred. See fail_with_error for details.
#define fail_if_error(e) \
    if (e != ERROR_SUCCESS) \
    { \
      fail_with_error(e); \
    }


// check_type(expression, EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT) is
// used to ensure that the type of "expression" is either integer or float,
// the cleanup statements are executed if the condition is not met.
#define check_type_with_cleanup(expression, expected_type, op, cleanup) \
    if (((expression.type) & (expected_type)) == 0) \
    { \
      switch(expression.type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_FLOAT: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"float\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_STRING: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"string\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_BOOLEAN: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"boolean\" for " op " operator"); \
          break; \
      } \
      cleanup; \
      compiler->last_error = ERROR_WRONG_TYPE; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }

// check_type(expression, EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT) is
// used to ensure that the type of "expression" is either integer or float.
#define check_type(expression, expected_type, op) \
    check_type_with_cleanup(expression, expected_type, op, )


#define loop_vars_cleanup(loop_index) \
    {  \
      YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[loop_index]; \
      for (int i = 0; i < loop_ctx->vars_count; i++) \
      { \
        yr_free((void*) loop_ctx->vars[i].identifier.ptr); \
        loop_ctx->vars[i].identifier.ptr = NULL; \
        loop_ctx->vars[i].identifier.ref = YR_ARENA_NULL_REF; \
      } \
      loop_ctx->vars_count = 0; \
    } \


// Given a YR_EXPRESSION returns its identifier. It returns identifier.ptr if
// not NULL and relies on identifier.ref if otherwise.
#define expression_identifier(expr) \
    ((expr).identifier.ptr != NULL ? \
     (expr).identifier.ptr : \
     (const char*) yr_arena_ref_to_ptr(compiler->arena, &(expr).identifier.ref))


#define DEFAULT_BASE64_ALPHABET \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


#line 204 "libyara/grammar.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
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
    _INTEGER_FUNCTION_ = 274,      /* "integer function"  */
    _TEXT_STRING_ = 275,           /* "text string"  */
    _HEX_STRING_ = 276,            /* "hex string"  */
    _REGEXP_ = 277,                /* "regular expression"  */
    _ASCII_ = 278,                 /* "<ascii>"  */
    _WIDE_ = 279,                  /* "<wide>"  */
    _XOR_ = 280,                   /* "<xor>"  */
    _BASE64_ = 281,                /* "<base64>"  */
    _BASE64_WIDE_ = 282,           /* "<base64wide>"  */
    _NOCASE_ = 283,                /* "<nocase>"  */
    _FULLWORD_ = 284,              /* "<fullword>"  */
    _AT_ = 285,                    /* "<at>"  */
    _FILESIZE_ = 286,              /* "<filesize>"  */
    _ENTRYPOINT_ = 287,            /* "<entrypoint>"  */
    _ALL_ = 288,                   /* "<all>"  */
    _ANY_ = 289,                   /* "<any>"  */
    _NONE_ = 290,                  /* "<none>"  */
    _IN_ = 291,                    /* "<in>"  */
    _OF_ = 292,                    /* "<of>"  */
    _FOR_ = 293,                   /* "<for>"  */
    _THEM_ = 294,                  /* "<them>"  */
    _MATCHES_ = 295,               /* "<matches>"  */
    _CONTAINS_ = 296,              /* "<contains>"  */
    _STARTSWITH_ = 297,            /* "<startswith>"  */
    _ENDSWITH_ = 298,              /* "<endswith>"  */
    _ICONTAINS_ = 299,             /* "<icontains>"  */
    _ISTARTSWITH_ = 300,           /* "<istartswith>"  */
    _IENDSWITH_ = 301,             /* "<iendswith>"  */
    _IEQUALS_ = 302,               /* "<iequals>"  */
    _IMPORT_ = 303,                /* "<import>"  */
    _TRUE_ = 304,                  /* "<true>"  */
    _FALSE_ = 305,                 /* "<false>"  */
    _OR_ = 306,                    /* "<or>"  */
    _AND_ = 307,                   /* "<and>"  */
    _NOT_ = 308,                   /* "<not>"  */
    _DEFINED_ = 309,               /* "<defined>"  */
    _EQ_ = 310,                    /* "=="  */
    _NEQ_ = 311,                   /* "!="  */
    _LT_ = 312,                    /* "<"  */
    _LE_ = 313,                    /* "<="  */
    _GT_ = 314,                    /* ">"  */
    _GE_ = 315,                    /* ">="  */
    _SHIFT_LEFT_ = 316,            /* "<<"  */
    _SHIFT_RIGHT_ = 317,           /* ">>"  */
    UNARY_MINUS = 318              /* UNARY_MINUS  */
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
#define _INTEGER_FUNCTION_ 274
#define _TEXT_STRING_ 275
#define _HEX_STRING_ 276
#define _REGEXP_ 277
#define _ASCII_ 278
#define _WIDE_ 279
#define _XOR_ 280
#define _BASE64_ 281
#define _BASE64_WIDE_ 282
#define _NOCASE_ 283
#define _FULLWORD_ 284
#define _AT_ 285
#define _FILESIZE_ 286
#define _ENTRYPOINT_ 287
#define _ALL_ 288
#define _ANY_ 289
#define _NONE_ 290
#define _IN_ 291
#define _OF_ 292
#define _FOR_ 293
#define _THEM_ 294
#define _MATCHES_ 295
#define _CONTAINS_ 296
#define _STARTSWITH_ 297
#define _ENDSWITH_ 298
#define _ICONTAINS_ 299
#define _ISTARTSWITH_ 300
#define _IENDSWITH_ 301
#define _IEQUALS_ 302
#define _IMPORT_ 303
#define _TRUE_ 304
#define _FALSE_ 305
#define _OR_ 306
#define _AND_ 307
#define _NOT_ 308
#define _DEFINED_ 309
#define _EQ_ 310
#define _NEQ_ 311
#define _LT_ 312
#define _LE_ 313
#define _GT_ 314
#define _GE_ 315
#define _SHIFT_LEFT_ 316
#define _SHIFT_RIGHT_ 317
#define UNARY_MINUS 318

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 342 "libyara/grammar.y"

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

#line 398 "libyara/grammar.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);


#endif /* !YY_YARA_YY_LIBYARA_GRAMMAR_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL__END_OF_INCLUDED_FILE_ = 3,     /* "end of included file"  */
  YYSYMBOL__DOT_DOT_ = 4,                  /* ".."  */
  YYSYMBOL__RULE_ = 5,                     /* "<rule>"  */
  YYSYMBOL__PRIVATE_ = 6,                  /* "<private>"  */
  YYSYMBOL__GLOBAL_ = 7,                   /* "<global>"  */
  YYSYMBOL__META_ = 8,                     /* "<meta>"  */
  YYSYMBOL__STRINGS_ = 9,                  /* "<strings>"  */
  YYSYMBOL__CONDITION_ = 10,               /* "<condition>"  */
  YYSYMBOL__IDENTIFIER_ = 11,              /* "identifier"  */
  YYSYMBOL__STRING_IDENTIFIER_ = 12,       /* "string identifier"  */
  YYSYMBOL__STRING_COUNT_ = 13,            /* "string count"  */
  YYSYMBOL__STRING_OFFSET_ = 14,           /* "string offset"  */
  YYSYMBOL__STRING_LENGTH_ = 15,           /* "string length"  */
  YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_ = 16, /* "string identifier with wildcard"  */
  YYSYMBOL__NUMBER_ = 17,                  /* "integer number"  */
  YYSYMBOL__DOUBLE_ = 18,                  /* "floating point number"  */
  YYSYMBOL__INTEGER_FUNCTION_ = 19,        /* "integer function"  */
  YYSYMBOL__TEXT_STRING_ = 20,             /* "text string"  */
  YYSYMBOL__HEX_STRING_ = 21,              /* "hex string"  */
  YYSYMBOL__REGEXP_ = 22,                  /* "regular expression"  */
  YYSYMBOL__ASCII_ = 23,                   /* "<ascii>"  */
  YYSYMBOL__WIDE_ = 24,                    /* "<wide>"  */
  YYSYMBOL__XOR_ = 25,                     /* "<xor>"  */
  YYSYMBOL__BASE64_ = 26,                  /* "<base64>"  */
  YYSYMBOL__BASE64_WIDE_ = 27,             /* "<base64wide>"  */
  YYSYMBOL__NOCASE_ = 28,                  /* "<nocase>"  */
  YYSYMBOL__FULLWORD_ = 29,                /* "<fullword>"  */
  YYSYMBOL__AT_ = 30,                      /* "<at>"  */
  YYSYMBOL__FILESIZE_ = 31,                /* "<filesize>"  */
  YYSYMBOL__ENTRYPOINT_ = 32,              /* "<entrypoint>"  */
  YYSYMBOL__ALL_ = 33,                     /* "<all>"  */
  YYSYMBOL__ANY_ = 34,                     /* "<any>"  */
  YYSYMBOL__NONE_ = 35,                    /* "<none>"  */
  YYSYMBOL__IN_ = 36,                      /* "<in>"  */
  YYSYMBOL__OF_ = 37,                      /* "<of>"  */
  YYSYMBOL__FOR_ = 38,                     /* "<for>"  */
  YYSYMBOL__THEM_ = 39,                    /* "<them>"  */
  YYSYMBOL__MATCHES_ = 40,                 /* "<matches>"  */
  YYSYMBOL__CONTAINS_ = 41,                /* "<contains>"  */
  YYSYMBOL__STARTSWITH_ = 42,              /* "<startswith>"  */
  YYSYMBOL__ENDSWITH_ = 43,                /* "<endswith>"  */
  YYSYMBOL__ICONTAINS_ = 44,               /* "<icontains>"  */
  YYSYMBOL__ISTARTSWITH_ = 45,             /* "<istartswith>"  */
  YYSYMBOL__IENDSWITH_ = 46,               /* "<iendswith>"  */
  YYSYMBOL__IEQUALS_ = 47,                 /* "<iequals>"  */
  YYSYMBOL__IMPORT_ = 48,                  /* "<import>"  */
  YYSYMBOL__TRUE_ = 49,                    /* "<true>"  */
  YYSYMBOL__FALSE_ = 50,                   /* "<false>"  */
  YYSYMBOL__OR_ = 51,                      /* "<or>"  */
  YYSYMBOL__AND_ = 52,                     /* "<and>"  */
  YYSYMBOL__NOT_ = 53,                     /* "<not>"  */
  YYSYMBOL__DEFINED_ = 54,                 /* "<defined>"  */
  YYSYMBOL__EQ_ = 55,                      /* "=="  */
  YYSYMBOL__NEQ_ = 56,                     /* "!="  */
  YYSYMBOL__LT_ = 57,                      /* "<"  */
  YYSYMBOL__LE_ = 58,                      /* "<="  */
  YYSYMBOL__GT_ = 59,                      /* ">"  */
  YYSYMBOL__GE_ = 60,                      /* ">="  */
  YYSYMBOL__SHIFT_LEFT_ = 61,              /* "<<"  */
  YYSYMBOL__SHIFT_RIGHT_ = 62,             /* ">>"  */
  YYSYMBOL_63_ = 63,                       /* '|'  */
  YYSYMBOL_64_ = 64,                       /* '^'  */
  YYSYMBOL_65_ = 65,                       /* '&'  */
  YYSYMBOL_66_ = 66,                       /* '+'  */
  YYSYMBOL_67_ = 67,                       /* '-'  */
  YYSYMBOL_68_ = 68,                       /* '*'  */
  YYSYMBOL_69_ = 69,                       /* '\\'  */
  YYSYMBOL_70_ = 70,                       /* '%'  */
  YYSYMBOL_71_ = 71,                       /* '~'  */
  YYSYMBOL_UNARY_MINUS = 72,               /* UNARY_MINUS  */
  YYSYMBOL_73_include_ = 73,               /* "include"  */
  YYSYMBOL_74_ = 74,                       /* '{'  */
  YYSYMBOL_75_ = 75,                       /* '}'  */
  YYSYMBOL_76_ = 76,                       /* ':'  */
  YYSYMBOL_77_ = 77,                       /* '='  */
  YYSYMBOL_78_ = 78,                       /* '('  */
  YYSYMBOL_79_ = 79,                       /* ')'  */
  YYSYMBOL_80_ = 80,                       /* '.'  */
  YYSYMBOL_81_ = 81,                       /* '['  */
  YYSYMBOL_82_ = 82,                       /* ']'  */
  YYSYMBOL_83_ = 83,                       /* ','  */
  YYSYMBOL_YYACCEPT = 84,                  /* $accept  */
  YYSYMBOL_rules = 85,                     /* rules  */
  YYSYMBOL_import = 86,                    /* import  */
  YYSYMBOL_rule = 87,                      /* rule  */
  YYSYMBOL_88_1 = 88,                      /* @1  */
  YYSYMBOL_89_2 = 89,                      /* $@2  */
  YYSYMBOL_meta = 90,                      /* meta  */
  YYSYMBOL_strings = 91,                   /* strings  */
  YYSYMBOL_condition = 92,                 /* condition  */
  YYSYMBOL_rule_modifiers = 93,            /* rule_modifiers  */
  YYSYMBOL_rule_modifier = 94,             /* rule_modifier  */
  YYSYMBOL_tags = 95,                      /* tags  */
  YYSYMBOL_tag_list = 96,                  /* tag_list  */
  YYSYMBOL_meta_declarations = 97,         /* meta_declarations  */
  YYSYMBOL_meta_declaration = 98,          /* meta_declaration  */
  YYSYMBOL_string_declarations = 99,       /* string_declarations  */
  YYSYMBOL_string_declaration = 100,       /* string_declaration  */
  YYSYMBOL_101_3 = 101,                    /* $@3  */
  YYSYMBOL_102_4 = 102,                    /* $@4  */
  YYSYMBOL_103_5 = 103,                    /* $@5  */
  YYSYMBOL_string_modifiers = 104,         /* string_modifiers  */
  YYSYMBOL_string_modifier = 105,          /* string_modifier  */
  YYSYMBOL_regexp_modifiers = 106,         /* regexp_modifiers  */
  YYSYMBOL_regexp_modifier = 107,          /* regexp_modifier  */
  YYSYMBOL_hex_modifiers = 108,            /* hex_modifiers  */
  YYSYMBOL_hex_modifier = 109,             /* hex_modifier  */
  YYSYMBOL_identifier = 110,               /* identifier  */
  YYSYMBOL_arguments = 111,                /* arguments  */
  YYSYMBOL_arguments_list = 112,           /* arguments_list  */
  YYSYMBOL_regexp = 113,                   /* regexp  */
  YYSYMBOL_boolean_expression = 114,       /* boolean_expression  */
  YYSYMBOL_expression = 115,               /* expression  */
  YYSYMBOL_116_6 = 116,                    /* $@6  */
  YYSYMBOL_117_7 = 117,                    /* $@7  */
  YYSYMBOL_118_8 = 118,                    /* $@8  */
  YYSYMBOL_119_9 = 119,                    /* $@9  */
  YYSYMBOL_for_iteration = 120,            /* for_iteration  */
  YYSYMBOL_for_variables = 121,            /* for_variables  */
  YYSYMBOL_iterator = 122,                 /* iterator  */
  YYSYMBOL_set = 123,                      /* set  */
  YYSYMBOL_range = 124,                    /* range  */
  YYSYMBOL_enumeration = 125,              /* enumeration  */
  YYSYMBOL_string_iterator = 126,          /* string_iterator  */
  YYSYMBOL_string_set = 127,               /* string_set  */
  YYSYMBOL_128_10 = 128,                   /* $@10  */
  YYSYMBOL_string_enumeration = 129,       /* string_enumeration  */
  YYSYMBOL_string_enumeration_item = 130,  /* string_enumeration_item  */
  YYSYMBOL_rule_set = 131,                 /* rule_set  */
  YYSYMBOL_132_11 = 132,                   /* $@11  */
  YYSYMBOL_rule_enumeration = 133,         /* rule_enumeration  */
  YYSYMBOL_rule_enumeration_item = 134,    /* rule_enumeration_item  */
  YYSYMBOL_for_expression = 135,           /* for_expression  */
  YYSYMBOL_for_quantifier = 136,           /* for_quantifier  */
  YYSYMBOL_primary_expression = 137        /* primary_expression  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   476

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  84
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  54
/* YYNRULES -- Number of rules.  */
#define YYNRULES  168
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  275

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   319


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    70,    65,     2,
      78,    79,    68,    66,    83,    67,    80,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    76,     2,
       2,    77,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    81,    69,    82,    64,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    74,    63,    75,    71,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    72,    73
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   361,   361,   362,   363,   364,   365,   366,   367,   375,
     388,   393,   387,   420,   423,   439,   442,   457,   462,   463,
     468,   469,   475,   478,   494,   503,   545,   546,   551,   568,
     582,   596,   610,   628,   629,   635,   634,   651,   650,   671,
     670,   695,   701,   761,   762,   763,   764,   765,   766,   772,
     793,   824,   829,   846,   851,   871,   872,   886,   887,   888,
     889,   890,   894,   895,   909,   913,  1008,  1056,  1117,  1162,
    1163,  1167,  1202,  1255,  1297,  1320,  1326,  1332,  1344,  1354,
    1364,  1374,  1384,  1394,  1404,  1414,  1428,  1443,  1454,  1529,
    1567,  1471,  1695,  1706,  1717,  1736,  1755,  1767,  1804,  1810,
    1816,  1815,  1861,  1860,  1904,  1911,  1918,  1925,  1932,  1939,
    1946,  1950,  1958,  1959,  1984,  2004,  2032,  2106,  2134,  2153,
    2164,  2207,  2223,  2243,  2253,  2252,  2261,  2275,  2276,  2281,
    2291,  2306,  2305,  2318,  2319,  2324,  2357,  2382,  2438,  2445,
    2451,  2457,  2467,  2471,  2479,  2491,  2505,  2512,  2519,  2544,
    2556,  2568,  2580,  2595,  2607,  2622,  2665,  2686,  2721,  2756,
    2790,  2815,  2832,  2842,  2852,  2862,  2872,  2892,  2912
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"",
  "\"end of included file\"", "\"..\"", "\"<rule>\"", "\"<private>\"",
  "\"<global>\"", "\"<meta>\"", "\"<strings>\"", "\"<condition>\"",
  "\"identifier\"", "\"string identifier\"", "\"string count\"",
  "\"string offset\"", "\"string length\"",
  "\"string identifier with wildcard\"", "\"integer number\"",
  "\"floating point number\"", "\"integer function\"", "\"text string\"",
  "\"hex string\"", "\"regular expression\"", "\"<ascii>\"", "\"<wide>\"",
  "\"<xor>\"", "\"<base64>\"", "\"<base64wide>\"", "\"<nocase>\"",
  "\"<fullword>\"", "\"<at>\"", "\"<filesize>\"", "\"<entrypoint>\"",
  "\"<all>\"", "\"<any>\"", "\"<none>\"", "\"<in>\"", "\"<of>\"",
  "\"<for>\"", "\"<them>\"", "\"<matches>\"", "\"<contains>\"",
  "\"<startswith>\"", "\"<endswith>\"", "\"<icontains>\"",
  "\"<istartswith>\"", "\"<iendswith>\"", "\"<iequals>\"", "\"<import>\"",
  "\"<true>\"", "\"<false>\"", "\"<or>\"", "\"<and>\"", "\"<not>\"",
  "\"<defined>\"", "\"==\"", "\"!=\"", "\"<\"", "\"<=\"", "\">\"",
  "\">=\"", "\"<<\"", "\">>\"", "'|'", "'^'", "'&'", "'+'", "'-'", "'*'",
  "'\\\\'", "'%'", "'~'", "UNARY_MINUS", "\"include\"", "'{'", "'}'",
  "':'", "'='", "'('", "')'", "'.'", "'['", "']'", "','", "$accept",
  "rules", "import", "rule", "@1", "$@2", "meta", "strings", "condition",
  "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "$@3", "$@4", "$@5", "string_modifiers",
  "string_modifier", "regexp_modifiers", "regexp_modifier",
  "hex_modifiers", "hex_modifier", "identifier", "arguments",
  "arguments_list", "regexp", "boolean_expression", "expression", "$@6",
  "$@7", "$@8", "$@9", "for_iteration", "for_variables", "iterator", "set",
  "range", "enumeration", "string_iterator", "string_set", "$@10",
  "string_enumeration", "string_enumeration_item", "rule_set", "$@11",
  "rule_enumeration", "rule_enumeration_item", "for_expression",
  "for_quantifier", "primary_expression", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-172)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-138)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -172,   121,  -172,   -39,  -172,     2,  -172,  -172,   151,  -172,
    -172,  -172,  -172,    24,  -172,  -172,  -172,  -172,   -38,    59,
      16,  -172,    65,    95,  -172,    29,   109,   112,    55,  -172,
      71,   112,  -172,   130,   163,    22,  -172,   101,   130,  -172,
     116,   118,  -172,  -172,  -172,  -172,   178,    -5,  -172,    66,
    -172,  -172,   177,   174,   179,  -172,   -16,   162,   120,   123,
    -172,  -172,   124,  -172,  -172,  -172,  -172,  -172,  -172,  -172,
     132,  -172,  -172,    66,    66,   198,   198,    66,   103,  -172,
     110,  -172,   168,  -172,   277,  -172,  -172,  -172,   198,   129,
     129,   198,   198,   198,   198,     7,   376,  -172,  -172,  -172,
    -172,   110,   140,   237,    66,   197,   198,  -172,  -172,   -35,
     199,   198,   198,   198,   198,   198,   198,   198,   198,   198,
     198,   198,   198,   198,   198,   198,   198,   198,   198,   198,
     198,   198,   198,   157,    85,   111,   216,   376,   198,  -172,
    -172,   186,   287,   319,   338,  -172,    -4,   198,  -172,  -172,
     144,   142,   139,  -172,   297,    66,    66,  -172,   215,   -15,
    -172,  -172,   376,   376,   376,   376,   376,   376,   376,   376,
     376,   376,   376,   376,   376,    26,    26,   386,   396,   406,
     117,   117,  -172,  -172,   -35,  -172,  -172,  -172,  -172,   149,
     153,   154,  -172,  -172,  -172,  -172,  -172,  -172,  -172,  -172,
    -172,  -172,  -172,   176,  -172,  -172,  -172,  -172,   -33,   158,
       4,  -172,    66,  -172,   181,  -172,    20,   225,   198,   129,
    -172,  -172,   240,   238,   239,   198,  -172,  -172,  -172,  -172,
      -9,   249,   139,  -172,  -172,    46,  -172,   193,    53,  -172,
     376,  -172,   -48,   183,   184,   357,   188,   198,   103,  -172,
    -172,  -172,  -172,  -172,    20,  -172,  -172,   225,   247,  -172,
    -172,  -172,  -172,    66,    76,   176,  -172,  -172,   191,    23,
    -172,   198,  -172,  -172,   376
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    18,     8,     0,     4,     3,     0,     7,
       6,     5,     9,     0,    20,    21,    19,    10,    22,     0,
       0,    24,    23,    13,    25,     0,    15,     0,     0,    11,
       0,    14,    26,     0,     0,     0,    27,     0,    16,    33,
       0,     0,    29,    28,    31,    32,     0,    35,    34,     0,
      12,    30,     0,     0,     0,    65,    85,   150,   152,   154,
     146,   147,     0,   148,    73,   143,   144,   139,   140,   141,
       0,    75,    76,     0,     0,     0,     0,     0,   155,   168,
      17,    74,     0,   138,   110,    41,    55,    62,     0,     0,
       0,     0,     0,     0,     0,     0,   137,    98,    99,   156,
     165,     0,    74,   110,    69,     0,     0,   102,   100,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    36,    38,    40,    86,     0,    87,
     149,     0,     0,     0,     0,    88,     0,     0,   111,   142,
       0,    70,    71,    66,     0,     0,     0,   126,   124,    92,
      93,    77,    78,    80,    82,    79,    81,    83,    84,   108,
     109,   104,   106,   105,   107,   166,   167,   164,   162,   163,
     157,   158,   159,   160,     0,   161,    47,    44,    43,    48,
      51,    53,    45,    46,    42,    61,    58,    57,    59,    60,
      56,    64,    63,     0,   151,   153,   145,   114,     0,     0,
       0,    68,     0,    67,   103,   101,     0,     0,     0,     0,
      94,    95,     0,     0,     0,     0,   124,   113,   123,    90,
       0,     0,    72,   129,   130,     0,   127,   135,     0,   133,
      97,    96,     0,     0,     0,     0,     0,     0,   116,   112,
     117,   119,   115,   125,     0,   136,   132,     0,     0,    49,
      52,    54,   120,     0,     0,   121,   128,   134,     0,     0,
     118,     0,    50,    91,   122
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -172,  -172,   264,   268,  -172,  -172,  -172,  -172,  -172,  -172,
    -172,  -172,  -172,  -172,   241,  -172,   235,  -172,  -172,  -172,
    -172,  -172,  -172,  -172,  -172,  -172,    45,  -172,  -172,   175,
     -49,   -74,  -172,  -172,  -172,  -172,  -172,  -172,  -172,  -172,
     -89,  -172,  -172,  -171,  -172,  -172,    32,   104,  -172,  -172,
      30,   219,  -172,   -65
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     1,     6,     7,    18,    34,    26,    29,    41,     8,
      16,    20,    22,    31,    32,    38,    39,    52,    53,    54,
     134,   194,   135,   200,   136,   202,    78,   150,   151,    79,
     101,    81,   146,   246,   156,   155,   209,   210,   249,   250,
     139,   264,   227,   159,   216,   235,   236,   160,   217,   238,
     239,    82,    83,    84
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      80,   140,    55,   102,   157,    96,   157,   207,   145,     5,
      99,   100,   103,   220,    88,   218,   -39,   -37,   -89,   258,
      89,   219,    12,   137,    97,    98,   141,   142,   143,   144,
     152,   259,   233,   208,     9,    17,   234,   228,    19,    42,
     230,   154,    43,   158,   -89,   226,   162,   163,   164,   165,
     166,   167,   168,   169,   170,   171,   172,   173,   174,   175,
     176,   177,   178,   179,   180,   181,   182,   183,   185,   247,
      21,    44,    45,   203,   107,   108,    24,    55,    56,    57,
      58,    59,   185,    60,    61,    62,    63,   231,    64,    46,
      23,   186,   129,   130,   131,   132,   147,    65,    66,    67,
      68,    69,   273,    25,    70,    27,   214,   215,   187,   188,
     189,   190,   191,   192,   193,    71,    72,   195,    28,    73,
      74,     2,     3,    30,     4,   253,   -18,   -18,   -18,   254,
     241,    33,   256,    75,   196,   197,   257,    76,   232,   198,
     199,   251,    37,    55,    77,    57,    58,    59,    35,    60,
      61,    62,    63,   240,    64,   270,    13,    14,    15,   271,
     245,   107,   108,    65,    66,    67,    68,    69,    55,     5,
      57,    58,    59,    40,    60,    61,    62,    63,    47,    64,
     225,   104,   265,   105,   106,   131,   132,   147,    65,    66,
     -74,   -74,    49,    50,   184,    51,    86,    85,    90,    75,
      87,    91,    93,    76,    92,   109,   274,   138,   153,    55,
      94,    57,    58,    59,   269,    60,    61,    62,    63,   148,
      64,    64,   201,   211,    75,   212,  -131,   222,    76,    65,
      66,   223,   224,   108,   229,    94,   237,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   147,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   147,   242,   243,   244,
     252,   255,   260,   261,   268,    75,   263,    10,   204,    76,
     272,    11,    36,    48,  -137,   248,    94,   110,   111,   112,
     113,   114,   115,   116,   117,   161,   266,   267,   221,    95,
       0,     0,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,     0,     0,
       0,     0,     0,     0,  -137,     0,   149,   110,   111,   112,
     113,   114,   115,   116,   117,     0,     0,     0,     0,     0,
       0,     0,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   147,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   147,     0,   205,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   213,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   147,
       0,     0,     0,     0,     0,     0,     0,     0,   206,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   147,     0,
       0,     0,     0,     0,     0,     0,     0,   149,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   147,     0,     0,
       0,     0,     0,     0,     0,     0,   262,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   147,   124,   125,     0,
     127,   128,   129,   130,   131,   132,   147,   124,   125,     0,
       0,   128,   129,   130,   131,   132,   147,   124,   125,     0,
       0,     0,   129,   130,   131,   132,   147
};

static const yytype_int16 yycheck[] =
{
      49,    90,    11,    77,    39,    70,    39,    11,     1,    48,
      75,    76,    77,   184,    30,    30,    21,    22,    11,    67,
      36,    36,    20,    88,    73,    74,    91,    92,    93,    94,
     104,    79,    12,    37,    73,    11,    16,   208,    76,    17,
      36,   106,    20,    78,    37,    78,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,    78,
      11,    49,    50,   138,    51,    52,    11,    11,    12,    13,
      14,    15,   147,    17,    18,    19,    20,    83,    22,    67,
      74,     6,    66,    67,    68,    69,    70,    31,    32,    33,
      34,    35,    79,     8,    38,    76,   155,   156,    23,    24,
      25,    26,    27,    28,    29,    49,    50,     6,     9,    53,
      54,     0,     1,    11,     3,    79,     5,     6,     7,    83,
     219,    76,    79,    67,    23,    24,    83,    71,   212,    28,
      29,   230,    12,    11,    78,    13,    14,    15,    77,    17,
      18,    19,    20,   218,    22,    79,     5,     6,     7,    83,
     225,    51,    52,    31,    32,    33,    34,    35,    11,    48,
      13,    14,    15,    10,    17,    18,    19,    20,    77,    22,
       4,    78,   247,    80,    81,    68,    69,    70,    31,    32,
      51,    52,    76,    75,    37,    17,    22,    20,    36,    67,
      21,    81,    78,    71,    81,    37,   271,    78,    11,    11,
      78,    13,    14,    15,   263,    17,    18,    19,    20,    79,
      22,    22,     6,    79,    67,    83,    11,    78,    71,    31,
      32,    78,    78,    52,    76,    78,    11,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    17,    20,    20,
      11,    68,    79,    79,    17,    67,    78,     3,    82,    71,
      79,     3,    31,    38,    37,   230,    78,    40,    41,    42,
      43,    44,    45,    46,    47,   110,   254,   257,   184,    70,
      -1,    -1,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    -1,    -1,
      -1,    -1,    -1,    -1,    37,    -1,    79,    40,    41,    42,
      43,    44,    45,    46,    47,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    -1,    82,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    82,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    79,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    79,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    79,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    61,    62,    -1,
      64,    65,    66,    67,    68,    69,    70,    61,    62,    -1,
      -1,    65,    66,    67,    68,    69,    70,    61,    62,    -1,
      -1,    -1,    66,    67,    68,    69,    70
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    85,     0,     1,     3,    48,    86,    87,    93,    73,
      86,    87,    20,     5,     6,     7,    94,    11,    88,    76,
      95,    11,    96,    74,    11,     8,    90,    76,     9,    91,
      11,    97,    98,    76,    89,    77,    98,    12,    99,   100,
      10,    92,    17,    20,    49,    50,    67,    77,   100,    76,
      75,    17,   101,   102,   103,    11,    12,    13,    14,    15,
      17,    18,    19,    20,    22,    31,    32,    33,    34,    35,
      38,    49,    50,    53,    54,    67,    71,    78,   110,   113,
     114,   115,   135,   136,   137,    20,    22,    21,    30,    36,
      36,    81,    81,    78,    78,   135,   137,   114,   114,   137,
     137,   114,   115,   137,    78,    80,    81,    51,    52,    37,
      40,    41,    42,    43,    44,    45,    46,    47,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,   104,   106,   108,   137,    78,   124,
     124,   137,   137,   137,   137,     1,   116,    70,    79,    79,
     111,   112,   115,    11,   137,   119,   118,    39,    78,   127,
     131,   113,   137,   137,   137,   137,   137,   137,   137,   137,
     137,   137,   137,   137,   137,   137,   137,   137,   137,   137,
     137,   137,   137,   137,    37,   137,     6,    23,    24,    25,
      26,    27,    28,    29,   105,     6,    23,    24,    28,    29,
     107,     6,   109,   137,    82,    82,    79,    11,    37,   120,
     121,    79,    83,    82,   114,   114,   128,   132,    30,    36,
     127,   131,    78,    78,    78,     4,    78,   126,   127,    76,
      36,    83,   115,    12,    16,   129,   130,    11,   133,   134,
     137,   124,    17,    20,    20,   137,   117,    78,   110,   122,
     123,   124,    11,    79,    83,    68,    79,    83,    67,    79,
      79,    79,    79,    78,   125,   137,   130,   134,    17,   114,
      79,    83,    79,    79,   137
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_uint8 yyr1[] =
{
       0,    84,    85,    85,    85,    85,    85,    85,    85,    86,
      88,    89,    87,    90,    90,    91,    91,    92,    93,    93,
      94,    94,    95,    95,    96,    96,    97,    97,    98,    98,
      98,    98,    98,    99,    99,   101,   100,   102,   100,   103,
     100,   104,   104,   105,   105,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   106,   106,   107,   107,   107,
     107,   107,   108,   108,   109,   110,   110,   110,   110,   111,
     111,   112,   112,   113,   114,   115,   115,   115,   115,   115,
     115,   115,   115,   115,   115,   115,   115,   115,   115,   116,
     117,   115,   115,   115,   115,   115,   115,   115,   115,   115,
     118,   115,   119,   115,   115,   115,   115,   115,   115,   115,
     115,   115,   120,   120,   121,   121,   122,   122,   123,   123,
     124,   125,   125,   126,   128,   127,   127,   129,   129,   130,
     130,   132,   131,   133,   133,   134,   134,   135,   135,   136,
     136,   136,   137,   137,   137,   137,   137,   137,   137,   137,
     137,   137,   137,   137,   137,   137,   137,   137,   137,   137,
     137,   137,   137,   137,   137,   137,   137,   137,   137
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     2,
       0,     0,    11,     0,     3,     0,     3,     3,     0,     2,
       1,     1,     0,     2,     1,     2,     1,     2,     3,     3,
       4,     3,     3,     1,     2,     0,     5,     0,     5,     0,
       5,     0,     2,     1,     1,     1,     1,     1,     1,     4,
       6,     1,     4,     1,     4,     0,     2,     1,     1,     1,
       1,     1,     0,     2,     1,     1,     3,     4,     4,     0,
       1,     1,     3,     1,     1,     1,     1,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     3,     3,     3,     0,
       0,     9,     3,     3,     4,     4,     5,     5,     2,     2,
       0,     4,     0,     4,     3,     3,     3,     3,     3,     3,
       1,     3,     3,     2,     1,     3,     1,     1,     3,     1,
       5,     1,     3,     1,     0,     4,     1,     1,     3,     1,
       1,     0,     4,     1,     3,     1,     2,     1,     1,     1,
       1,     1,     3,     1,     1,     4,     1,     1,     1,     3,
       1,     4,     1,     4,     1,     1,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     2,     3,     3,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (yyscanner, compiler, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, yyscanner, compiler); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yyscanner);
  YY_USE (compiler);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep, yyscanner, compiler);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule, void *yyscanner, YR_COMPILER* compiler)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)], yyscanner, compiler);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, yyscanner, compiler); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YY_USE (yyvaluep);
  YY_USE (yyscanner);
  YY_USE (compiler);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL__IDENTIFIER_: /* "identifier"  */
#line 312 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1778 "libyara/grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_: /* "string identifier"  */
#line 316 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1784 "libyara/grammar.c"
        break;

    case YYSYMBOL__STRING_COUNT_: /* "string count"  */
#line 313 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1790 "libyara/grammar.c"
        break;

    case YYSYMBOL__STRING_OFFSET_: /* "string offset"  */
#line 314 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1796 "libyara/grammar.c"
        break;

    case YYSYMBOL__STRING_LENGTH_: /* "string length"  */
#line 315 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1802 "libyara/grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_: /* "string identifier with wildcard"  */
#line 317 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1808 "libyara/grammar.c"
        break;

    case YYSYMBOL__TEXT_STRING_: /* "text string"  */
#line 318 "libyara/grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1814 "libyara/grammar.c"
        break;

    case YYSYMBOL__HEX_STRING_: /* "hex string"  */
#line 319 "libyara/grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1820 "libyara/grammar.c"
        break;

    case YYSYMBOL__REGEXP_: /* "regular expression"  */
#line 320 "libyara/grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1826 "libyara/grammar.c"
        break;

    case YYSYMBOL_string_modifiers: /* string_modifiers  */
#line 333 "libyara/grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1838 "libyara/grammar.c"
        break;

    case YYSYMBOL_string_modifier: /* string_modifier  */
#line 325 "libyara/grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1850 "libyara/grammar.c"
        break;

    case YYSYMBOL_arguments: /* arguments  */
#line 322 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1856 "libyara/grammar.c"
        break;

    case YYSYMBOL_arguments_list: /* arguments_list  */
#line 323 "libyara/grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1862 "libyara/grammar.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (void *yyscanner, YR_COMPILER* compiler)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, yyscanner, compiler);
    }

  if (yychar <= _END_OF_FILE_)
    {
      yychar = _END_OF_FILE_;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 8: /* rules: rules "end of included file"  */
#line 368 "libyara/grammar.y"
      {
        _yr_compiler_pop_file_name(compiler);
      }
#line 2143 "libyara/grammar.c"
    break;

  case 9: /* import: "<import>" "text string"  */
#line 376 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        fail_if_error(result);
      }
#line 2155 "libyara/grammar.c"
    break;

  case 10: /* @1: %empty  */
#line 388 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[-2].integer), (yyvsp[0].c_string), &(yyval.rule)));
      }
#line 2164 "libyara/grammar.c"
    break;

  case 11: /* $@2: %empty  */
#line 393 "libyara/grammar.y"
      {
        YR_RULE* rule = (YR_RULE*) yr_arena_ref_to_ptr(
            compiler->arena, &(yyvsp[-4].rule));

        rule->tags = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &(yyvsp[-3].tag));

        rule->metas = (YR_META*) yr_arena_ref_to_ptr(
            compiler->arena, &(yyvsp[-1].meta));

        rule->strings = (YR_STRING*) yr_arena_ref_to_ptr(
            compiler->arena, &(yyvsp[0].string));
      }
#line 2182 "libyara/grammar.c"
    break;

  case 12: /* rule: rule_modifiers "<rule>" "identifier" @1 tags '{' meta strings $@2 condition '}'  */
#line 407 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, &(yyvsp[-7].rule)); // rule created in phase 1

        yr_free((yyvsp[-8].c_string));

        fail_if_error(result);
      }
#line 2195 "libyara/grammar.c"
    break;

  case 13: /* meta: %empty  */
#line 420 "libyara/grammar.y"
      {
        (yyval.meta) = YR_ARENA_NULL_REF;
      }
#line 2203 "libyara/grammar.c"
    break;

  case 14: /* meta: "<meta>" ':' meta_declarations  */
#line 424 "libyara/grammar.y"
      {
        YR_META* meta = yr_arena_get_ptr(
            compiler->arena,
            YR_METAS_TABLE,
            (compiler->current_meta_idx - 1) * sizeof(YR_META));

        meta->flags |= META_FLAGS_LAST_IN_RULE;

        (yyval.meta) = (yyvsp[0].meta);
      }
#line 2218 "libyara/grammar.c"
    break;

  case 15: /* strings: %empty  */
#line 439 "libyara/grammar.y"
      {
        (yyval.string) = YR_ARENA_NULL_REF;
      }
#line 2226 "libyara/grammar.c"
    break;

  case 16: /* strings: "<strings>" ':' string_declarations  */
#line 443 "libyara/grammar.y"
      {
        YR_STRING* string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            (compiler->current_string_idx - 1) * sizeof(YR_STRING));

        string->flags |= STRING_FLAGS_LAST_IN_RULE;

        (yyval.string) = (yyvsp[0].string);
      }
#line 2241 "libyara/grammar.c"
    break;

  case 18: /* rule_modifiers: %empty  */
#line 462 "libyara/grammar.y"
                                       { (yyval.integer) = 0;  }
#line 2247 "libyara/grammar.c"
    break;

  case 19: /* rule_modifiers: rule_modifiers rule_modifier  */
#line 463 "libyara/grammar.y"
                                       { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 2253 "libyara/grammar.c"
    break;

  case 20: /* rule_modifier: "<private>"  */
#line 468 "libyara/grammar.y"
                     { (yyval.integer) = RULE_FLAGS_PRIVATE; }
#line 2259 "libyara/grammar.c"
    break;

  case 21: /* rule_modifier: "<global>"  */
#line 469 "libyara/grammar.y"
                     { (yyval.integer) = RULE_FLAGS_GLOBAL; }
#line 2265 "libyara/grammar.c"
    break;

  case 22: /* tags: %empty  */
#line 475 "libyara/grammar.y"
      {
        (yyval.tag) = YR_ARENA_NULL_REF;
      }
#line 2273 "libyara/grammar.c"
    break;

  case 23: /* tags: ':' tag_list  */
#line 479 "libyara/grammar.y"
      {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        fail_if_error(yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, "", NULL));

        (yyval.tag) = (yyvsp[0].tag);
      }
#line 2289 "libyara/grammar.c"
    break;

  case 24: /* tag_list: "identifier"  */
#line 495 "libyara/grammar.y"
      {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, (yyvsp[0].c_string), &(yyval.tag));

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 2302 "libyara/grammar.c"
    break;

  case 25: /* tag_list: tag_list "identifier"  */
#line 504 "libyara/grammar.y"
      {
        YR_ARENA_REF ref;

        // Write the new tag identifier.
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, (yyvsp[0].c_string), &ref);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        // Get the address for the tag identifier just written.
        char* new_tag = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &ref);

        // Take the address of first tag's identifier in the list.
        char* tag = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &(yyval.tag));

        // Search for duplicated tags. Tags are written one after
        // the other, with zeroes in between (i.e: tag1/0tag2/0tag3)
        // that's why can use tag < new_tag as the condition for the
        // loop.
        while (tag < new_tag)
        {
          if (strcmp(tag, new_tag) == 0)
          {
            yr_compiler_set_error_extra_info(compiler, tag);
            fail_with_error(ERROR_DUPLICATED_TAG_IDENTIFIER);
          }

          tag += strlen(tag) + 1;
        }

        (yyval.tag) = (yyvsp[-1].tag);
      }
#line 2343 "libyara/grammar.c"
    break;

  case 26: /* meta_declarations: meta_declaration  */
#line 545 "libyara/grammar.y"
                                          {  (yyval.meta) = (yyvsp[0].meta); }
#line 2349 "libyara/grammar.c"
    break;

  case 27: /* meta_declarations: meta_declarations meta_declaration  */
#line 546 "libyara/grammar.y"
                                          {  (yyval.meta) = (yyvsp[-1].meta); }
#line 2355 "libyara/grammar.c"
    break;

  case 28: /* meta_declaration: "identifier" '=' "text string"  */
#line 552 "libyara/grammar.y"
      {
        SIZED_STRING* sized_string = (yyvsp[0].sized_string);

        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_STRING,
            (yyvsp[-2].c_string),
            sized_string->c_string,
            0,
            &(yyval.meta));

        yr_free((yyvsp[-2].c_string));
        yr_free((yyvsp[0].sized_string));

        fail_if_error(result);
      }
#line 2376 "libyara/grammar.c"
    break;

  case 29: /* meta_declaration: "identifier" '=' "integer number"  */
#line 569 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[-2].c_string),
            NULL,
            (yyvsp[0].integer),
            &(yyval.meta));

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);
      }
#line 2394 "libyara/grammar.c"
    break;

  case 30: /* meta_declaration: "identifier" '=' '-' "integer number"  */
#line 583 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[-3].c_string),
            NULL,
            -(yyvsp[0].integer),
            &(yyval.meta));

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);
      }
#line 2412 "libyara/grammar.c"
    break;

  case 31: /* meta_declaration: "identifier" '=' "<true>"  */
#line 597 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            true,
            &(yyval.meta));

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);
      }
#line 2430 "libyara/grammar.c"
    break;

  case 32: /* meta_declaration: "identifier" '=' "<false>"  */
#line 611 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            false,
            &(yyval.meta));

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);
      }
#line 2448 "libyara/grammar.c"
    break;

  case 33: /* string_declarations: string_declaration  */
#line 628 "libyara/grammar.y"
                                              { (yyval.string) = (yyvsp[0].string); }
#line 2454 "libyara/grammar.c"
    break;

  case 34: /* string_declarations: string_declarations string_declaration  */
#line 629 "libyara/grammar.y"
                                              { (yyval.string) = (yyvsp[-1].string); }
#line 2460 "libyara/grammar.c"
    break;

  case 35: /* $@3: %empty  */
#line 635 "libyara/grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2468 "libyara/grammar.c"
    break;

  case 36: /* string_declaration: "string identifier" '=' $@3 "text string" string_modifiers  */
#line 639 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));
        yr_free((yyvsp[0].modifier).alphabet);

        fail_if_error(result);
        compiler->current_line = 0;
      }
#line 2484 "libyara/grammar.c"
    break;

  case 37: /* $@4: %empty  */
#line 651 "libyara/grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2492 "libyara/grammar.c"
    break;

  case 38: /* string_declaration: "string identifier" '=' $@4 "regular expression" regexp_modifiers  */
#line 655 "libyara/grammar.y"
      {
        int result;

        (yyvsp[0].modifier).flags |= STRING_FLAGS_REGEXP;

        result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));

        fail_if_error(result);

        compiler->current_line = 0;
      }
#line 2512 "libyara/grammar.c"
    break;

  case 39: /* $@5: %empty  */
#line 671 "libyara/grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2520 "libyara/grammar.c"
    break;

  case 40: /* string_declaration: "string identifier" '=' $@5 "hex string" hex_modifiers  */
#line 675 "libyara/grammar.y"
      {
        int result;

        (yyvsp[0].modifier).flags |= STRING_FLAGS_HEXADECIMAL;

        result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));

        fail_if_error(result);

        compiler->current_line = 0;
      }
#line 2540 "libyara/grammar.c"
    break;

  case 41: /* string_modifiers: %empty  */
#line 695 "libyara/grammar.y"
      {
        (yyval.modifier).flags = 0;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 0;
        (yyval.modifier).alphabet = NULL;
      }
#line 2551 "libyara/grammar.c"
    break;

  case 42: /* string_modifiers: string_modifiers string_modifier  */
#line 702 "libyara/grammar.y"
      {
        (yyval.modifier) = (yyvsp[-1].modifier);

        // Only set the xor minimum and maximum if we are dealing with the
        // xor modifier. If we don't check for this then we can end up with
        // "xor wide" resulting in whatever is on the stack for "wide"
        // overwriting the values for xor.
        if ((yyvsp[0].modifier).flags & STRING_FLAGS_XOR)
        {
          (yyval.modifier).xor_min = (yyvsp[0].modifier).xor_min;
          (yyval.modifier).xor_max = (yyvsp[0].modifier).xor_max;
        }

        // Only set the base64 alphabet if we are dealing with the base64
        // modifier. If we don't check for this then we can end up with
        // "base64 ascii" resulting in whatever is on the stack for "ascii"
        // overwriting the values for base64.
        if (((yyvsp[0].modifier).flags & STRING_FLAGS_BASE64) ||
            ((yyvsp[0].modifier).flags & STRING_FLAGS_BASE64_WIDE))
        {
          if ((yyval.modifier).alphabet != NULL)
          {
            if (ss_compare((yyval.modifier).alphabet, (yyvsp[0].modifier).alphabet) != 0)
            {
              yr_compiler_set_error_extra_info(
                  compiler, "can not specify multiple alphabets");

              yr_free((yyvsp[0].modifier).alphabet);
              yr_free((yyval.modifier).alphabet);

              fail_with_error(ERROR_INVALID_MODIFIER);
            }
            else
            {
              yr_free((yyvsp[0].modifier).alphabet);
            }
          }
          else
          {
            (yyval.modifier).alphabet = (yyvsp[0].modifier).alphabet;
          }
        }

        if ((yyval.modifier).flags & (yyvsp[0].modifier).flags)
        {
          if ((yyval.modifier).alphabet != NULL)
            yr_free((yyval.modifier).alphabet);

          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          (yyval.modifier).flags = (yyval.modifier).flags | (yyvsp[0].modifier).flags;
        }
      }
#line 2611 "libyara/grammar.c"
    break;

  case 43: /* string_modifier: "<wide>"  */
#line 761 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2617 "libyara/grammar.c"
    break;

  case 44: /* string_modifier: "<ascii>"  */
#line 762 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2623 "libyara/grammar.c"
    break;

  case 45: /* string_modifier: "<nocase>"  */
#line 763 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2629 "libyara/grammar.c"
    break;

  case 46: /* string_modifier: "<fullword>"  */
#line 764 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2635 "libyara/grammar.c"
    break;

  case 47: /* string_modifier: "<private>"  */
#line 765 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2641 "libyara/grammar.c"
    break;

  case 48: /* string_modifier: "<xor>"  */
#line 767 "libyara/grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 255;
      }
#line 2651 "libyara/grammar.c"
    break;

  case 49: /* string_modifier: "<xor>" '(' "integer number" ')'  */
#line 773 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-1].integer) < 0 || (yyvsp[-1].integer) > 255)
        {
          yr_compiler_set_error_extra_info(compiler, "invalid xor range");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = (uint8_t) (yyvsp[-1].integer);
        (yyval.modifier).xor_max = (uint8_t) (yyvsp[-1].integer);
      }
#line 2671 "libyara/grammar.c"
    break;

  case 50: /* string_modifier: "<xor>" '(' "integer number" '-' "integer number" ')'  */
#line 794 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-3].integer) < 0)
        {
          yr_compiler_set_error_extra_info(
              compiler, "lower bound for xor range exceeded (min: 0)");
          result = ERROR_INVALID_MODIFIER;
        }

        if ((yyvsp[-1].integer) > 255)
        {
          yr_compiler_set_error_extra_info(
              compiler, "upper bound for xor range exceeded (max: 255)");
          result = ERROR_INVALID_MODIFIER;
        }

        if ((yyvsp[-3].integer) > (yyvsp[-1].integer))
        {
          yr_compiler_set_error_extra_info(
              compiler, "xor lower bound exceeds upper bound");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = (uint8_t) (yyvsp[-3].integer);
        (yyval.modifier).xor_max = (uint8_t) (yyvsp[-1].integer);
      }
#line 2706 "libyara/grammar.c"
    break;

  case 51: /* string_modifier: "<base64>"  */
#line 825 "libyara/grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2715 "libyara/grammar.c"
    break;

  case 52: /* string_modifier: "<base64>" '(' "text string" ')'  */
#line 830 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-1].sized_string)->length != 64)
        {
          yr_free((yyvsp[-1].sized_string));
          yr_compiler_set_error_extra_info(
              compiler, "length of base64 alphabet must be 64");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        (yyval.modifier).flags = STRING_FLAGS_BASE64;
        (yyval.modifier).alphabet = (yyvsp[-1].sized_string);
      }
#line 2736 "libyara/grammar.c"
    break;

  case 53: /* string_modifier: "<base64wide>"  */
#line 847 "libyara/grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64_WIDE;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2745 "libyara/grammar.c"
    break;

  case 54: /* string_modifier: "<base64wide>" '(' "text string" ')'  */
#line 852 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-1].sized_string)->length != 64)
        {
          yr_free((yyvsp[-1].sized_string));
          yr_compiler_set_error_extra_info(
              compiler, "length of base64 alphabet must be 64");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        (yyval.modifier).flags = STRING_FLAGS_BASE64_WIDE;
        (yyval.modifier).alphabet = (yyvsp[-1].sized_string);
      }
#line 2766 "libyara/grammar.c"
    break;

  case 55: /* regexp_modifiers: %empty  */
#line 871 "libyara/grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2772 "libyara/grammar.c"
    break;

  case 56: /* regexp_modifiers: regexp_modifiers regexp_modifier  */
#line 873 "libyara/grammar.y"
      {
        if ((yyvsp[-1].modifier).flags & (yyvsp[0].modifier).flags)
        {
          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          (yyval.modifier).flags = (yyvsp[-1].modifier).flags | (yyvsp[0].modifier).flags;
        }
      }
#line 2787 "libyara/grammar.c"
    break;

  case 57: /* regexp_modifier: "<wide>"  */
#line 886 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2793 "libyara/grammar.c"
    break;

  case 58: /* regexp_modifier: "<ascii>"  */
#line 887 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2799 "libyara/grammar.c"
    break;

  case 59: /* regexp_modifier: "<nocase>"  */
#line 888 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2805 "libyara/grammar.c"
    break;

  case 60: /* regexp_modifier: "<fullword>"  */
#line 889 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2811 "libyara/grammar.c"
    break;

  case 61: /* regexp_modifier: "<private>"  */
#line 890 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2817 "libyara/grammar.c"
    break;

  case 62: /* hex_modifiers: %empty  */
#line 894 "libyara/grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2823 "libyara/grammar.c"
    break;

  case 63: /* hex_modifiers: hex_modifiers hex_modifier  */
#line 896 "libyara/grammar.y"
      {
        if ((yyvsp[-1].modifier).flags & (yyvsp[0].modifier).flags)
        {
          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          (yyval.modifier).flags = (yyvsp[-1].modifier).flags | (yyvsp[0].modifier).flags;
        }
      }
#line 2838 "libyara/grammar.c"
    break;

  case 64: /* hex_modifier: "<private>"  */
#line 909 "libyara/grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2844 "libyara/grammar.c"
    break;

  case 65: /* identifier: "identifier"  */
#line 914 "libyara/grammar.y"
      {
        YR_EXPRESSION expr;

        int result = ERROR_SUCCESS;
        int var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string), &expr);

        if (var_index >= 0)
        {
          // The identifier corresponds to a loop variable.
          result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_M,
              var_index,
              NULL,
              NULL);

          // The expression associated to this identifier is the same one
          // associated to the loop variable.
          (yyval.expression) = expr;
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          YR_OBJECT* object = (YR_OBJECT*) yr_hash_table_lookup(
              compiler->objects_table, (yyvsp[0].c_string), NULL);

          YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
              compiler->arena,
              YR_NAMESPACES_TABLE,
              compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table, (yyvsp[0].c_string), ns->name);
          }

          if (object != NULL)
          {
            YR_ARENA_REF ref;

            result = _yr_compiler_store_string(
                compiler, (yyvsp[0].c_string), &ref);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  yr_arena_ref_to_ptr(compiler->arena, &ref),
                  NULL,
                  NULL);

            (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
            (yyval.expression).value.object = object;
            (yyval.expression).identifier.ptr = NULL;
            (yyval.expression).identifier.ref = ref;
          }
          else
          {
            uint32_t rule_idx = yr_hash_table_lookup_uint32(
                compiler->rules_table, (yyvsp[0].c_string), ns->name);

            if (rule_idx != UINT32_MAX)
            {
              result = yr_parser_emit_with_arg(
                  yyscanner,
                  OP_PUSH_RULE,
                  rule_idx,
                  NULL,
                  NULL);

              YR_RULE* rule = _yr_compiler_get_rule_by_idx(compiler, rule_idx);

              yr_arena_ptr_to_ref(compiler->arena, rule->identifier, &(yyval.expression).identifier.ref);

              (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
              (yyval.expression).value.integer = YR_UNDEFINED;
              (yyval.expression).identifier.ptr = NULL;
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
              result = ERROR_UNDEFINED_IDENTIFIER;
            }
          }
        }

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 2943 "libyara/grammar.c"
    break;

  case 66: /* identifier: identifier '.' "identifier"  */
#line 1009 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;
        YR_OBJECT* field = NULL;

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-2].expression).value.object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field((yyvsp[-2].expression).value.object, (yyvsp[0].c_string));

          if (field != NULL)
          {
            YR_ARENA_REF ref;

            result = _yr_compiler_store_string(
                compiler, (yyvsp[0].c_string), &ref);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  yr_arena_ref_to_ptr(compiler->arena, &ref),
                  NULL,
                  NULL);

            (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
            (yyval.expression).value.object = field;
            (yyval.expression).identifier.ref = ref;
            (yyval.expression).identifier.ptr = NULL;
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
            result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
             compiler, expression_identifier((yyvsp[-2].expression)));

          result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 2995 "libyara/grammar.c"
    break;

  case 67: /* identifier: identifier '[' primary_expression ']'  */
#line 1057 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;
        YR_OBJECT_ARRAY* array;
        YR_OBJECT_DICTIONARY* dict;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_ARRAY)
        {
          if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
          {
            yr_compiler_set_error_extra_info(
                compiler, "array indexes must be of integer type");
            result = ERROR_WRONG_TYPE;
          }

          fail_if_error(result);

          result = yr_parser_emit(
              yyscanner, OP_INDEX_ARRAY, NULL);

          array = object_as_array((yyvsp[-3].expression).value.object);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = array->prototype_item;
          (yyval.expression).identifier.ptr = array->identifier;
          (yyval.expression).identifier.ref = YR_ARENA_NULL_REF;
        }
        else if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
                 (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_DICTIONARY)
        {
          if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_STRING)
          {
            yr_compiler_set_error_extra_info(
                compiler, "dictionary keys must be of string type");
            result = ERROR_WRONG_TYPE;
          }

          fail_if_error(result);

          result = yr_parser_emit(
              yyscanner, OP_LOOKUP_DICT, NULL);

          dict = object_as_dictionary((yyvsp[-3].expression).value.object);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = dict->prototype_item;
          (yyval.expression).identifier.ptr = dict->identifier;
          (yyval.expression).identifier.ref = YR_ARENA_NULL_REF;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, expression_identifier((yyvsp[-3].expression)));

          result = ERROR_NOT_INDEXABLE;
        }

        fail_if_error(result);
      }
#line 3059 "libyara/grammar.c"
    break;

  case 68: /* identifier: identifier '(' arguments ')'  */
#line 1118 "libyara/grammar.y"
      {
        YR_ARENA_REF ref = YR_ARENA_NULL_REF;
        int result = ERROR_SUCCESS;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          YR_OBJECT_FUNCTION* function = object_as_function((yyvsp[-3].expression).value.object);

          result = yr_parser_check_types(compiler, function, (yyvsp[-1].c_string));

          if (result == ERROR_SUCCESS)
            result = _yr_compiler_store_string(
                compiler, (yyvsp[-1].c_string), &ref);

          if (result == ERROR_SUCCESS)
            result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                yr_arena_ref_to_ptr(compiler->arena, &ref),
                NULL,
                NULL);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = function->return_obj;
          (yyval.expression).identifier.ref = ref;
          (yyval.expression).identifier.ptr = NULL;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, expression_identifier((yyvsp[-3].expression)));

          result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[-1].c_string));

        fail_if_error(result);
      }
#line 3104 "libyara/grammar.c"
    break;

  case 69: /* arguments: %empty  */
#line 1162 "libyara/grammar.y"
                      { (yyval.c_string) = yr_strdup(""); }
#line 3110 "libyara/grammar.c"
    break;

  case 70: /* arguments: arguments_list  */
#line 1163 "libyara/grammar.y"
                      { (yyval.c_string) = (yyvsp[0].c_string); }
#line 3116 "libyara/grammar.c"
    break;

  case 71: /* arguments_list: expression  */
#line 1168 "libyara/grammar.y"
      {
        (yyval.c_string) = (char*) yr_malloc(YR_MAX_FUNCTION_ARGS + 1);

        if ((yyval.c_string) == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        switch((yyvsp[0].expression).type)
        {
          case EXPRESSION_TYPE_INTEGER:
            strlcpy((yyval.c_string), "i", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_FLOAT:
            strlcpy((yyval.c_string), "f", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_BOOLEAN:
            strlcpy((yyval.c_string), "b", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_STRING:
            strlcpy((yyval.c_string), "s", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_REGEXP:
            strlcpy((yyval.c_string), "r", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_UNKNOWN:
            yr_free((yyval.c_string));
            yr_compiler_set_error_extra_info(
                compiler, "unknown type for argument 1 in function call");
            fail_with_error(ERROR_WRONG_TYPE);
            break;
          default:
            // An unknown expression type is OK iff an error ocurred.
            assert(compiler->last_error != ERROR_SUCCESS);
        }
      }
#line 3155 "libyara/grammar.c"
    break;

  case 72: /* arguments_list: arguments_list ',' expression  */
#line 1203 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if (strlen((yyvsp[-2].c_string)) == YR_MAX_FUNCTION_ARGS)
        {
          result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch((yyvsp[0].expression).type)
          {
            case EXPRESSION_TYPE_INTEGER:
              strlcat((yyvsp[-2].c_string), "i", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_FLOAT:
              strlcat((yyvsp[-2].c_string), "f", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_BOOLEAN:
              strlcat((yyvsp[-2].c_string), "b", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_STRING:
              strlcat((yyvsp[-2].c_string), "s", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_REGEXP:
              strlcat((yyvsp[-2].c_string), "r", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_UNKNOWN:
              result = ERROR_WRONG_TYPE;
              yr_compiler_set_error_extra_info_fmt(
                  compiler, "unknown type for argument %zu in function call",
                  // As we add one character per argument, the length of $1 is
                  // the number of arguments parsed so far, and the argument
                  // represented by <expression> is length of $1 plus one.
                  strlen((yyvsp[-2].c_string)) + 1);
              break;
            default:
              // An unknown expression type is OK iff an error ocurred.
              assert(compiler->last_error != ERROR_SUCCESS);
          }
        }

        if (result != ERROR_SUCCESS)
          yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.c_string) = (yyvsp[-2].c_string);
      }
#line 3208 "libyara/grammar.c"
    break;

  case 73: /* regexp: "regular expression"  */
#line 1256 "libyara/grammar.y"
      {
        YR_ARENA_REF re_ref;
        RE_ERROR error;

        int result = ERROR_SUCCESS;
        int re_flags = 0;

        if ((yyvsp[0].sized_string)->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if ((yyvsp[0].sized_string)->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        result = yr_re_compile(
            (yyvsp[0].sized_string)->c_string,
            re_flags,
            compiler->arena,
            &re_ref,
            &error);

        yr_free((yyvsp[0].sized_string));

        if (result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        if (result == ERROR_SUCCESS)
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              yr_arena_ref_to_ptr(compiler->arena, &re_ref),
              NULL,
              NULL);

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_REGEXP;
      }
#line 3250 "libyara/grammar.c"
    break;

  case 74: /* boolean_expression: expression  */
#line 1298 "libyara/grammar.y"
      {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_STRING)
        {
          if (!YR_ARENA_IS_NULL_REF((yyvsp[0].expression).value.sized_string_ref))
          {
            SIZED_STRING* sized_string = yr_arena_ref_to_ptr(
                compiler->arena, &(yyvsp[0].expression).value.sized_string_ref);

            yywarning(yyscanner,
                "using literal string \"%s\" in a boolean operation.",
                sized_string->c_string);
          }

          fail_if_error(yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL));
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3274 "libyara/grammar.c"
    break;

  case 75: /* expression: "<true>"  */
#line 1321 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 1));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3284 "libyara/grammar.c"
    break;

  case 76: /* expression: "<false>"  */
#line 1327 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 0));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3294 "libyara/grammar.c"
    break;

  case 77: /* expression: primary_expression "<matches>" regexp  */
#line 1333 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        fail_if_error(yr_parser_emit(
            yyscanner,
            OP_MATCHES,
            NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3310 "libyara/grammar.c"
    break;

  case 78: /* expression: primary_expression "<contains>" primary_expression  */
#line 1345 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3324 "libyara/grammar.c"
    break;

  case 79: /* expression: primary_expression "<icontains>" primary_expression  */
#line 1355 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "icontains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "icontains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ICONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3338 "libyara/grammar.c"
    break;

  case 80: /* expression: primary_expression "<startswith>" primary_expression  */
#line 1365 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "startswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "startswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_STARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3352 "libyara/grammar.c"
    break;

  case 81: /* expression: primary_expression "<istartswith>" primary_expression  */
#line 1375 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "istartswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "istartswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ISTARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3366 "libyara/grammar.c"
    break;

  case 82: /* expression: primary_expression "<endswith>" primary_expression  */
#line 1385 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "endswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "endswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3380 "libyara/grammar.c"
    break;

  case 83: /* expression: primary_expression "<iendswith>" primary_expression  */
#line 1395 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iendswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iendswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3394 "libyara/grammar.c"
    break;

  case 84: /* expression: primary_expression "<iequals>" primary_expression  */
#line 1405 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iequals");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iequals");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IEQUALS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3408 "libyara/grammar.c"
    break;

  case 85: /* expression: "string identifier"  */
#line 1415 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_FOUND,
            YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3426 "libyara/grammar.c"
    break;

  case 86: /* expression: "string identifier" "<at>" primary_expression  */
#line 1429 "libyara/grammar.y"
      {
        int result;

        check_type_with_cleanup((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at", yr_free((yyvsp[-2].c_string)));

        result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_AT, (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3445 "libyara/grammar.c"
    break;

  case 87: /* expression: "string identifier" "<in>" range  */
#line 1444 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3460 "libyara/grammar.c"
    break;

  case 88: /* expression: "<for>" for_expression error  */
#line 1455 "libyara/grammar.y"
      {
        // Free all the loop variable identifiers, including the variables for
        // the current loop (represented by loop_index), and set loop_index to
        // -1. This is OK even if we have nested loops. If an error occurs while
        // parsing the inner loop, it will be propagated to the outer loop
        // anyways, so it's safe to do this cleanup while processing the error
        // for the inner loop.

        for (int i = 0; i <= compiler->loop_index; i++)
        {
          loop_vars_cleanup(i);
        }

        compiler->loop_index = -1;
        YYERROR;
      }
#line 3481 "libyara/grammar.c"
    break;

  case 89: /* $@6: %empty  */
#line 1529 "libyara/grammar.y"
      {
        // var_frame is used for accessing local variables used in this loop.
        // All local variables are accessed using var_frame as a reference,
        // like var_frame + 0, var_frame + 1, etc. Here we initialize var_frame
        // with the correct value, which depends on the number of variables
        // defined by any outer loops.

        int var_frame;
        int result = ERROR_SUCCESS;

        if (compiler->loop_index + 1 == YR_MAX_LOOP_NESTING)
          result = ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        fail_if_error(result);

        compiler->loop_index++;

        // This loop uses internal variables besides the ones explicitly
        // defined by the user.
        compiler->loop[compiler->loop_index].vars_internal_count = \
            YR_INTERNAL_LOOP_VARS;

        // Initialize the number of variables, this number will be incremented
        // as variable declaration are processed by for_variables.
        compiler->loop[compiler->loop_index].vars_count = 0;

        var_frame = _yr_compiler_get_var_frame(compiler);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, var_frame + 2, NULL, NULL));
      }
#line 3523 "libyara/grammar.c"
    break;

  case 90: /* $@7: %empty  */
#line 1567 "libyara/grammar.y"
      {
        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];
        YR_FIXUP* fixup;

        YR_ARENA_REF loop_start_ref;
        YR_ARENA_REF jmp_offset_ref;

        int var_frame = _yr_compiler_get_var_frame(compiler);

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_NEXT, &loop_start_ref));

        // For each variable generate an instruction that pops the value from
        // the stack and store it into one memory slot starting at var_frame +
        // YR_INTERNAL_LOOP_VARS because the first YR_INTERNAL_LOOP_VARS slots
        // in the frame are for the internal variables.

        for (int i = 0; i < loop_ctx->vars_count; i++)
        {
          fail_if_error(yr_parser_emit_with_arg(
              yyscanner,
              OP_POP_M,
              var_frame + YR_INTERNAL_LOOP_VARS + i,
              NULL,
              NULL));
        }

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE_P,
            0,              // still don't know the jump offset, use 0 for now.
            NULL,
            &jmp_offset_ref));

        // We still don't know the jump's target, so we push a fixup entry
        // in the stack, so that the jump's offset can be set once we know it.

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;

        loop_ctx->start_ref = loop_start_ref;
      }
#line 3576 "libyara/grammar.c"
    break;

  case 91: /* expression: "<for>" for_expression $@6 for_iteration ':' $@7 '(' boolean_expression ')'  */
#line 1616 "libyara/grammar.y"
      {
        int32_t jmp_offset;
        YR_FIXUP* fixup;
        YR_ARENA_REF pop_ref;

        int var_frame = _yr_compiler_get_var_frame(compiler);

        if ((yyvsp[-5].integer) == FOR_ITERATION_STRING_SET)
        {
          compiler->loop_for_of_var_index = -1;
        }

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        fail_if_error(yr_parser_emit(yyscanner, OP_ITER_CONDITION, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, var_frame + 0, NULL, NULL));

        jmp_offset = \
            compiler->loop[compiler->loop_index].start_ref.offset -
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION);

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE_P,
            jmp_offset,
            NULL,
            NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_POP, &pop_ref));

        // Pop from the stack the fixup entry containing the reference to
        // the jump offset that needs to be fixed.

        fixup = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup->next;

        // The fixup entry has a reference to the jump offset that need
        // to be fixed, convert the address into a pointer.
        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        // The reference in the fixup entry points to the jump's offset
        // but the jump instruction is one byte before, that's why we add
        // one to the offset.
        jmp_offset = pop_ref.offset - fixup->ref.offset + 1;

        // Fix the jump's offset.
        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        yr_free(fixup);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_END, NULL));

        loop_vars_cleanup(compiler->loop_index);

        compiler->loop_index--;

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3660 "libyara/grammar.c"
    break;

  case 92: /* expression: for_expression "<of>" string_set  */
#line 1696 "libyara/grammar.y"
      {
        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER && (yyvsp[-2].expression).value.integer > (yyvsp[0].integer))
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", (yyvsp[-2].expression).value.integer, (yyvsp[0].integer));
        }
        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_STRING_SET, NULL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3675 "libyara/grammar.c"
    break;

  case 93: /* expression: for_expression "<of>" rule_set  */
#line 1707 "libyara/grammar.y"
      {
        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER && (yyvsp[-2].expression).value.integer > (yyvsp[0].integer))
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", (yyvsp[-2].expression).value.integer, (yyvsp[0].integer));
        }
        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_RULE_SET, NULL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3690 "libyara/grammar.c"
    break;

  case 94: /* expression: primary_expression '%' "<of>" string_set  */
#line 1718 "libyara/grammar.y"
      {
        check_type((yyvsp[-3].expression), EXPRESSION_TYPE_INTEGER, "%");

        // The value of primary_expression can be undefined because
        // it could be a variable for which don't know the value during
        // compiling time. However, if the value is defined it should be
        // in the range [1,100].
        if (!IS_UNDEFINED((yyvsp[-3].expression).value.integer) &&
            ((yyvsp[-3].expression).value.integer < 1 || (yyvsp[-3].expression).value.integer > 100))
        {
          yr_compiler_set_error_extra_info(
              compiler, "percentage must be between 1 and 100 (inclusive)");

          fail_with_error(ERROR_INVALID_PERCENTAGE);
        }

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_STRING_SET, NULL, NULL);
      }
#line 3713 "libyara/grammar.c"
    break;

  case 95: /* expression: primary_expression '%' "<of>" rule_set  */
#line 1737 "libyara/grammar.y"
      {
        check_type((yyvsp[-3].expression), EXPRESSION_TYPE_INTEGER, "%");

        // The value of primary_expression can be undefined because
        // it could be a variable for which don't know the value during
        // compiling time. However, if the value is defined it should be
        // in the range [1,100].
        if (!IS_UNDEFINED((yyvsp[-3].expression).value.integer) &&
            ((yyvsp[-3].expression).value.integer < 1 || (yyvsp[-3].expression).value.integer > 100))
        {
          yr_compiler_set_error_extra_info(
              compiler, "percentage must be between 1 and 100 (inclusive)");

          fail_with_error(ERROR_INVALID_PERCENTAGE);
        }

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_RULE_SET, NULL, NULL);
      }
#line 3736 "libyara/grammar.c"
    break;

  case 96: /* expression: for_expression "<of>" string_set "<in>" range  */
#line 1756 "libyara/grammar.y"
      {
        if ((yyvsp[-4].expression).type == EXPRESSION_TYPE_INTEGER && (yyvsp[-4].expression).value.integer > (yyvsp[-2].integer))
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", (yyvsp[-4].expression).value.integer, (yyvsp[-2].integer));
        }

        yr_parser_emit(yyscanner, OP_OF_FOUND_IN, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3752 "libyara/grammar.c"
    break;

  case 97: /* expression: for_expression "<of>" string_set "<at>" primary_expression  */
#line 1768 "libyara/grammar.y"
      {
        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(compiler,
              "at expression must be an integer");

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ((yyvsp[-4].expression).type == EXPRESSION_TYPE_INTEGER && (yyvsp[-4].expression).value.integer > (yyvsp[-2].integer))
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", (yyvsp[-4].expression).value.integer, (yyvsp[-2].integer));
        }

        // Both of these are warnings:
        //
        // "N of them at 0" where N > 1
        //
        //"all of them at 0" where there is more than 1 in "them".
        //
        // This means you can do "all of them at 0" if you only have one string
        // defined in the set.
        if (((yyvsp[-4].expression).type == EXPRESSION_TYPE_INTEGER &&
              !IS_UNDEFINED((yyvsp[-4].expression).value.integer) && (yyvsp[-4].expression).value.integer > 1) ||
              ((yyvsp[-4].expression).type == EXPRESSION_TYPE_QUANTIFIER &&
              (yyvsp[-4].expression).value.integer == FOR_EXPRESSION_ALL && (yyvsp[-2].integer) > 1))
        {
          yywarning(yyscanner,
            "multiple strings at an offset is usually false.");
        }

        yr_parser_emit(yyscanner, OP_OF_FOUND_AT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3793 "libyara/grammar.c"
    break;

  case 98: /* expression: "<not>" boolean_expression  */
#line 1805 "libyara/grammar.y"
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3803 "libyara/grammar.c"
    break;

  case 99: /* expression: "<defined>" boolean_expression  */
#line 1811 "libyara/grammar.y"
      {
        yr_parser_emit(yyscanner, OP_DEFINED, NULL);
        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3812 "libyara/grammar.c"
    break;

  case 100: /* $@8: %empty  */
#line 1816 "libyara/grammar.y"
      {
        YR_FIXUP* fixup;
        YR_ARENA_REF jmp_offset_ref;

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump offset, use 0 for now.
            NULL,
            &jmp_offset_ref));

        // Create a fixup entry for the jump and push it in the stack.
        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 3838 "libyara/grammar.c"
    break;

  case 101: /* expression: boolean_expression "<and>" $@8 boolean_expression  */
#line 1838 "libyara/grammar.y"
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_AND, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3865 "libyara/grammar.c"
    break;

  case 102: /* $@9: %empty  */
#line 1861 "libyara/grammar.y"
      {
        YR_FIXUP* fixup;
        YR_ARENA_REF jmp_offset_ref;

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination, use 0 for now.
            NULL,
            &jmp_offset_ref));

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 3890 "libyara/grammar.c"
    break;

  case 103: /* expression: boolean_expression "<or>" $@9 boolean_expression  */
#line 1882 "libyara/grammar.y"
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_OR, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3917 "libyara/grammar.c"
    break;

  case 104: /* expression: primary_expression "<" primary_expression  */
#line 1905 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3928 "libyara/grammar.c"
    break;

  case 105: /* expression: primary_expression ">" primary_expression  */
#line 1912 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3939 "libyara/grammar.c"
    break;

  case 106: /* expression: primary_expression "<=" primary_expression  */
#line 1919 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3950 "libyara/grammar.c"
    break;

  case 107: /* expression: primary_expression ">=" primary_expression  */
#line 1926 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3961 "libyara/grammar.c"
    break;

  case 108: /* expression: primary_expression "==" primary_expression  */
#line 1933 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3972 "libyara/grammar.c"
    break;

  case 109: /* expression: primary_expression "!=" primary_expression  */
#line 1940 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3983 "libyara/grammar.c"
    break;

  case 110: /* expression: primary_expression  */
#line 1947 "libyara/grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3991 "libyara/grammar.c"
    break;

  case 111: /* expression: '(' expression ')'  */
#line 1951 "libyara/grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3999 "libyara/grammar.c"
    break;

  case 112: /* for_iteration: for_variables "<in>" iterator  */
#line 1958 "libyara/grammar.y"
                                  { (yyval.integer) = FOR_ITERATION_ITERATOR; }
#line 4005 "libyara/grammar.c"
    break;

  case 113: /* for_iteration: "<of>" string_iterator  */
#line 1960 "libyara/grammar.y"
      {
        int var_frame;
        int result = ERROR_SUCCESS;

        if (compiler->loop_for_of_var_index != -1)
          result = ERROR_NESTED_FOR_OF_LOOP;

        fail_if_error(result);

        // Simulate that we have 1 variable with string loops
        compiler->loop[compiler->loop_index].vars_count = 1;

        // Set where we can find our string in case $ is in
        // the body of the loop
        var_frame = _yr_compiler_get_var_frame(compiler);
        compiler->loop_for_of_var_index = var_frame +
            compiler->loop[compiler->loop_index].vars_internal_count;

        (yyval.integer) = FOR_ITERATION_STRING_SET;
      }
#line 4030 "libyara/grammar.c"
    break;

  case 114: /* for_variables: "identifier"  */
#line 1985 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string), NULL) >= 0)
        {
          yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
          yr_free((yyvsp[0].c_string));

          result = ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if_error(result);

        loop_ctx->vars[loop_ctx->vars_count++].identifier.ptr = (yyvsp[0].c_string);

        assert(loop_ctx->vars_count <= YR_MAX_LOOP_VARS);
      }
#line 4054 "libyara/grammar.c"
    break;

  case 115: /* for_variables: for_variables ',' "identifier"  */
#line 2005 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (loop_ctx->vars_count == YR_MAX_LOOP_VARS)
        {
          yr_compiler_set_error_extra_info(compiler, "too many loop variables");
          yr_free((yyvsp[0].c_string));

          result = ERROR_SYNTAX_ERROR;
        }
        else if (yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string), NULL) >= 0)
        {
          yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
          yr_free((yyvsp[0].c_string));

          result = ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if_error(result);

        loop_ctx->vars[loop_ctx->vars_count++].identifier.ptr = (yyvsp[0].c_string);
      }
#line 4083 "libyara/grammar.c"
    break;

  case 116: /* iterator: identifier  */
#line 2033 "libyara/grammar.y"
      {
        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        // Initially we assume that the identifier is from a non-iterable type,
        // this will change later if it's iterable.
        int result = ERROR_WRONG_TYPE;

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_OBJECT)
        {
          switch((yyvsp[0].expression).value.object->type)
          {
            case OBJECT_TYPE_ARRAY:
              // If iterating an array the loop must define a single variable
              // that will hold the current item. If a different number of
              // variables were defined that's an error.
              if (loop_ctx->vars_count == 1)
              {
                loop_ctx->vars[0].type = EXPRESSION_TYPE_OBJECT;
                loop_ctx->vars[0].value.object = \
                    object_as_array((yyvsp[0].expression).value.object)->prototype_item;

                result = yr_parser_emit(yyscanner, OP_ITER_START_ARRAY, NULL);
              }
              else
              {
                yr_compiler_set_error_extra_info_fmt(
                    compiler,
                    "iterator for \"%s\" yields a single item on each iteration"
                    ", but the loop expects %d",
                    expression_identifier((yyvsp[0].expression)),
                    loop_ctx->vars_count);

                result = ERROR_SYNTAX_ERROR;
              }
              break;

            case OBJECT_TYPE_DICTIONARY:
              // If iterating a dictionary the loop must define exactly two
              // variables, one for the key and another for the value . If a
              // different number of variables were defined that's an error.
              if (loop_ctx->vars_count == 2)
              {
                loop_ctx->vars[0].type = EXPRESSION_TYPE_STRING;
                loop_ctx->vars[0].value.sized_string_ref = YR_ARENA_NULL_REF;
                loop_ctx->vars[1].type = EXPRESSION_TYPE_OBJECT;
                loop_ctx->vars[1].value.object = \
                    object_as_array((yyvsp[0].expression).value.object)->prototype_item;

                result = yr_parser_emit(yyscanner, OP_ITER_START_DICT, NULL);
              }
              else
              {
                yr_compiler_set_error_extra_info_fmt(
                    compiler,
                    "iterator for \"%s\" yields a key,value pair item on each iteration",
                    expression_identifier((yyvsp[0].expression)));

                result = ERROR_SYNTAX_ERROR;
              }
              break;
          }
        }

        if (result == ERROR_WRONG_TYPE)
        {
          yr_compiler_set_error_extra_info_fmt(
              compiler,
              "identifier \"%s\" is not iterable",
              expression_identifier((yyvsp[0].expression)));
        }

        fail_if_error(result);
      }
#line 4161 "libyara/grammar.c"
    break;

  case 117: /* iterator: set  */
#line 2107 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (loop_ctx->vars_count == 1)
        {
          loop_ctx->vars[0].type = (yyvsp[0].enumeration).type;
          loop_ctx->vars[0].value.integer = YR_UNDEFINED;
        }
        else
        {
          yr_compiler_set_error_extra_info_fmt(
              compiler,
              "iterator yields one value on each iteration "
              ", but the loop expects %d",
              loop_ctx->vars_count);

          result = ERROR_SYNTAX_ERROR;
        }

        fail_if_error(result);
      }
#line 4189 "libyara/grammar.c"
    break;

  case 118: /* set: '(' enumeration ')'  */
#line 2135 "libyara/grammar.y"
      {
        // $2.count contains the number of items in the enumeration
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[-1].enumeration).count));

        if ((yyvsp[-1].enumeration).type == EXPRESSION_TYPE_INTEGER)
        {
          fail_if_error(yr_parser_emit(
              yyscanner, OP_ITER_START_INT_ENUM, NULL));
        }
        else
        {
          fail_if_error(yr_parser_emit(
              yyscanner, OP_ITER_START_TEXT_STRING_SET, NULL));
        }

        (yyval.enumeration).type = (yyvsp[-1].enumeration).type;

      }
#line 4212 "libyara/grammar.c"
    break;

  case 119: /* set: range  */
#line 2154 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_RANGE, NULL));

        (yyval.enumeration).type = EXPRESSION_TYPE_INTEGER;
      }
#line 4223 "libyara/grammar.c"
    break;

  case 120: /* range: '(' primary_expression ".." primary_expression ')'  */
#line 2165 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-3].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          result = ERROR_WRONG_TYPE;
        }

        // If we can statically determine lower and upper bounds, ensure
        // lower < upper. Check for upper bound here because some things (like
        // string count) are EXPRESSION_TYPE_INTEGER.
        if ((yyvsp[-3].expression).value.integer != YR_UNDEFINED && (yyvsp[-1].expression).value.integer != YR_UNDEFINED)
        {
          if ((yyvsp[-3].expression).value.integer > (yyvsp[-1].expression).value.integer)
          {
            yr_compiler_set_error_extra_info(
                compiler, "range lower bound must be less than upper bound");
            result = ERROR_INVALID_VALUE;
          }
          else if ((yyvsp[-3].expression).value.integer < 0)
          {
            yr_compiler_set_error_extra_info(
                compiler, "range lower bound can not be negative");
            result = ERROR_INVALID_VALUE;
          }
        }

        fail_if_error(result);
      }
#line 4266 "libyara/grammar.c"
    break;

  case 121: /* enumeration: primary_expression  */
#line 2208 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER && (yyvsp[0].expression).type != EXPRESSION_TYPE_STRING)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        (yyval.enumeration).type = (yyvsp[0].expression).type;
        (yyval.enumeration).count = 1;
      }
#line 4286 "libyara/grammar.c"
    break;

  case 122: /* enumeration: enumeration ',' primary_expression  */
#line 2224 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[0].expression).type != (yyvsp[-2].enumeration).type)
        {
          yr_compiler_set_error_extra_info(
              compiler, "enumerations must be all the same type");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        (yyval.enumeration).type = (yyvsp[-2].enumeration).type;
        (yyval.enumeration).count = (yyvsp[-2].enumeration).count + 1;
      }
#line 4306 "libyara/grammar.c"
    break;

  case 123: /* string_iterator: string_set  */
#line 2244 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[0].integer)));
        fail_if_error(yr_parser_emit(yyscanner, OP_ITER_START_STRING_SET,
            NULL));
      }
#line 4316 "libyara/grammar.c"
    break;

  case 124: /* $@10: %empty  */
#line 2253 "libyara/grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 4325 "libyara/grammar.c"
    break;

  case 125: /* string_set: '(' $@10 string_enumeration ')'  */
#line 2258 "libyara/grammar.y"
      {
        (yyval.integer) = (yyvsp[-1].integer);
      }
#line 4333 "libyara/grammar.c"
    break;

  case 126: /* string_set: "<them>"  */
#line 2262 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, YR_UNDEFINED));

        int count = 0;
        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*", &count));

        (yyval.integer) = count;
      }
#line 4347 "libyara/grammar.c"
    break;

  case 127: /* string_enumeration: string_enumeration_item  */
#line 2275 "libyara/grammar.y"
                              { (yyval.integer) = (yyvsp[0].integer); }
#line 4353 "libyara/grammar.c"
    break;

  case 128: /* string_enumeration: string_enumeration ',' string_enumeration_item  */
#line 2276 "libyara/grammar.y"
                                                     { (yyval.integer) = (yyvsp[-2].integer) + (yyvsp[0].integer); }
#line 4359 "libyara/grammar.c"
    break;

  case 129: /* string_enumeration_item: "string identifier"  */
#line 2282 "libyara/grammar.y"
      {
        int count = 0;
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string), &count);
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.integer) = count;
      }
#line 4373 "libyara/grammar.c"
    break;

  case 130: /* string_enumeration_item: "string identifier with wildcard"  */
#line 2292 "libyara/grammar.y"
      {
        int count = 0;
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string), &count);
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.integer) = count;
      }
#line 4387 "libyara/grammar.c"
    break;

  case 131: /* $@11: %empty  */
#line 2306 "libyara/grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 4396 "libyara/grammar.c"
    break;

  case 132: /* rule_set: '(' $@11 rule_enumeration ')'  */
#line 2311 "libyara/grammar.y"
      {
        (yyval.integer) = (yyvsp[-1].integer);
      }
#line 4404 "libyara/grammar.c"
    break;

  case 133: /* rule_enumeration: rule_enumeration_item  */
#line 2318 "libyara/grammar.y"
                            { (yyval.integer) = (yyvsp[0].integer); }
#line 4410 "libyara/grammar.c"
    break;

  case 134: /* rule_enumeration: rule_enumeration ',' rule_enumeration_item  */
#line 2319 "libyara/grammar.y"
                                                 { (yyval.integer) = (yyvsp[-2].integer) + (yyvsp[0].integer); }
#line 4416 "libyara/grammar.c"
    break;

  case 135: /* rule_enumeration_item: "identifier"  */
#line 2325 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
            compiler->arena,
            YR_NAMESPACES_TABLE,
            compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

        uint32_t rule_idx = yr_hash_table_lookup_uint32(
            compiler->rules_table, (yyvsp[0].c_string), ns->name);

        if (rule_idx != UINT32_MAX)
        {
          result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_RULE,
              rule_idx,
              NULL,
              NULL);
        }
        else
        {
          yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
          result = ERROR_UNDEFINED_IDENTIFIER;
        }

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.integer) = 1;
      }
#line 4453 "libyara/grammar.c"
    break;

  case 136: /* rule_enumeration_item: "identifier" '*'  */
#line 2358 "libyara/grammar.y"
      {
        int count = 0;
        YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
            compiler->arena,
            YR_NAMESPACES_TABLE,
            compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

        yr_hash_table_add_uint32(
            compiler->wildcard_identifiers_table,
            (yyvsp[-1].c_string),
            ns->name,
            1);

        int result = yr_parser_emit_pushes_for_rules(yyscanner, (yyvsp[-1].c_string), &count);
        yr_free((yyvsp[-1].c_string));

        fail_if_error(result);

        (yyval.integer) = count;
      }
#line 4478 "libyara/grammar.c"
    break;

  case 137: /* for_expression: primary_expression  */
#line 2383 "libyara/grammar.y"
      {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER && !IS_UNDEFINED((yyvsp[0].expression).value.integer))
        {
          if ((yyvsp[0].expression).value.integer == 0)
          {
            yywarning(yyscanner,
                "consider using \"none\" keyword, it is less ambiguous.");
          }

          if ((yyvsp[0].expression).value.integer < 0)
          {
            yr_compiler_set_error_extra_info_fmt(compiler,
                "%" PRId64, (yyvsp[0].expression).value.integer);

            fail_with_error(ERROR_INVALID_VALUE);
          }
        }

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_FLOAT)
        {
          yr_compiler_set_error_extra_info_fmt(compiler,
              "%a", (yyvsp[0].expression).value.double_);

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_STRING)
        {
          SIZED_STRING* ss = yr_arena_ref_to_ptr(compiler->arena,
              &(yyvsp[0].expression).value.sized_string_ref);
          // If the expression is an external string variable we need to get
          // it some other way.
          if (ss != NULL)
          {
            yr_compiler_set_error_extra_info_fmt(compiler, "%s", ss->c_string);
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler,
                "string in for_expression is invalid");
          }

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_REGEXP)
        {
          yr_compiler_set_error_extra_info(compiler,
              "regexp in for_expression is invalid");

          fail_with_error(ERROR_INVALID_VALUE);
        }

        (yyval.expression).value.integer = (yyvsp[0].expression).value.integer;
      }
#line 4538 "libyara/grammar.c"
    break;

  case 138: /* for_expression: for_quantifier  */
#line 2439 "libyara/grammar.y"
      {
        (yyval.expression).value.integer = (yyvsp[0].expression).value.integer;
      }
#line 4546 "libyara/grammar.c"
    break;

  case 139: /* for_quantifier: "<all>"  */
#line 2446 "libyara/grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
        (yyval.expression).type = EXPRESSION_TYPE_QUANTIFIER;
        (yyval.expression).value.integer = FOR_EXPRESSION_ALL;
     }
#line 4556 "libyara/grammar.c"
    break;

  case 140: /* for_quantifier: "<any>"  */
#line 2452 "libyara/grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, 1);
        (yyval.expression).type = EXPRESSION_TYPE_QUANTIFIER;
        (yyval.expression).value.integer = FOR_EXPRESSION_ANY;
      }
#line 4566 "libyara/grammar.c"
    break;

  case 141: /* for_quantifier: "<none>"  */
#line 2458 "libyara/grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, 0);
        (yyval.expression).type = EXPRESSION_TYPE_QUANTIFIER;
        (yyval.expression).value.integer = FOR_EXPRESSION_NONE;
      }
#line 4576 "libyara/grammar.c"
    break;

  case 142: /* primary_expression: '(' primary_expression ')'  */
#line 2468 "libyara/grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 4584 "libyara/grammar.c"
    break;

  case 143: /* primary_expression: "<filesize>"  */
#line 2472 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4596 "libyara/grammar.c"
    break;

  case 144: /* primary_expression: "<entrypoint>"  */
#line 2480 "libyara/grammar.y"
      {
        yywarning(yyscanner,
            "using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4612 "libyara/grammar.c"
    break;

  case 145: /* primary_expression: "integer function" '(' primary_expression ')'  */
#line 2492 "libyara/grammar.y"
      {
        check_type((yyvsp[-1].expression), EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_READ_INT results
        // in the proper OP_INTXX opcode.

        fail_if_error(yr_parser_emit(
            yyscanner, (uint8_t) (OP_READ_INT + (yyvsp[-3].integer)), NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4630 "libyara/grammar.c"
    break;

  case 146: /* primary_expression: "integer number"  */
#line 2506 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[0].integer)));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 4641 "libyara/grammar.c"
    break;

  case 147: /* primary_expression: "floating point number"  */
#line 2513 "libyara/grammar.y"
      {
        fail_if_error(yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 4652 "libyara/grammar.c"
    break;

  case 148: /* primary_expression: "text string"  */
#line 2520 "libyara/grammar.y"
      {
        YR_ARENA_REF ref;

        int result = _yr_compiler_store_data(
            compiler,
            (yyvsp[0].sized_string),
            (yyvsp[0].sized_string)->length + sizeof(SIZED_STRING),
            &ref);

        yr_free((yyvsp[0].sized_string));

        if (result == ERROR_SUCCESS)
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              yr_arena_ref_to_ptr(compiler->arena, &ref),
              NULL,
              NULL);

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_STRING;
        (yyval.expression).value.sized_string_ref = ref;
      }
#line 4681 "libyara/grammar.c"
    break;

  case 149: /* primary_expression: "string count" "<in>" range  */
#line 2545 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_COUNT_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4697 "libyara/grammar.c"
    break;

  case 150: /* primary_expression: "string count"  */
#line 2557 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[0].c_string), OP_COUNT, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4713 "libyara/grammar.c"
    break;

  case 151: /* primary_expression: "string offset" '[' primary_expression ']'  */
#line 2569 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_OFFSET, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4729 "libyara/grammar.c"
    break;

  case 152: /* primary_expression: "string offset"  */
#line 2581 "libyara/grammar.y"
      {
        int result = yr_parser_emit_push_const(yyscanner, 1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[0].c_string), OP_OFFSET, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4748 "libyara/grammar.c"
    break;

  case 153: /* primary_expression: "string length" '[' primary_expression ']'  */
#line 2596 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_LENGTH, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4764 "libyara/grammar.c"
    break;

  case 154: /* primary_expression: "string length"  */
#line 2608 "libyara/grammar.y"
      {
        int result = yr_parser_emit_push_const(yyscanner, 1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[0].c_string), OP_LENGTH, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4783 "libyara/grammar.c"
    break;

  case 155: /* primary_expression: identifier  */
#line 2623 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_OBJECT)
        {
          result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch((yyvsp[0].expression).value.object->type)
          {
            case OBJECT_TYPE_INTEGER:
              (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
              (yyval.expression).value.integer = (yyvsp[0].expression).value.object->value.i;
              break;
            case OBJECT_TYPE_FLOAT:
              (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
              break;
            case OBJECT_TYPE_STRING:
              (yyval.expression).type = EXPRESSION_TYPE_STRING;
              (yyval.expression).value.sized_string_ref = YR_ARENA_NULL_REF;
              break;
            default:
              // In a primary expression any identifier that corresponds to an
              // object must be of type integer, float or string. If "foobar" is
              // either a function, structure, dictionary or array you can not
              // use it as:
              //   condition: foobar
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  expression_identifier((yyvsp[0].expression)));

              result = ERROR_WRONG_TYPE;
          }
        }
        else
        {
          (yyval.expression) = (yyvsp[0].expression);
        }

        fail_if_error(result);
      }
#line 4830 "libyara/grammar.c"
    break;

  case 156: /* primary_expression: '-' primary_expression  */
#line 2666 "libyara/grammar.y"
      {
        int result = ERROR_SUCCESS;

        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT, "-");

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == YR_UNDEFINED) ?
              YR_UNDEFINED : -((yyvsp[0].expression).value.integer);
          result = yr_parser_emit(yyscanner, OP_INT_MINUS, NULL);
        }
        else if ((yyvsp[0].expression).type == EXPRESSION_TYPE_FLOAT)
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
          result = yr_parser_emit(yyscanner, OP_DBL_MINUS, NULL);
        }

        fail_if_error(result);
      }
#line 4855 "libyara/grammar.c"
    break;

  case 157: /* primary_expression: primary_expression '+' primary_expression  */
#line 2687 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "+", (yyvsp[-2].expression), (yyvsp[0].expression));

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = (yyvsp[-2].expression).value.integer;
          int64_t i2 = (yyvsp[0].expression).value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                (i2 > 0 && i1 > INT64_MAX - i2) ||
                (i2 < 0 && i1 < INT64_MIN - i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " + %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            (yyval.expression).value.integer = OPERATION(+, i1, i2);
            (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
#line 4894 "libyara/grammar.c"
    break;

  case 158: /* primary_expression: primary_expression '-' primary_expression  */
#line 2722 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "-", (yyvsp[-2].expression), (yyvsp[0].expression));

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = (yyvsp[-2].expression).value.integer;
          int64_t i2 = (yyvsp[0].expression).value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                (i2 < 0 && i1 > INT64_MAX + i2) ||
                (i2 > 0 && i1 < INT64_MIN + i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " - %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            (yyval.expression).value.integer = OPERATION(-, i1, i2);
            (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
#line 4933 "libyara/grammar.c"
    break;

  case 159: /* primary_expression: primary_expression '*' primary_expression  */
#line 2757 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "*", (yyvsp[-2].expression), (yyvsp[0].expression));

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = (yyvsp[-2].expression).value.integer;
          int64_t i2 = (yyvsp[0].expression).value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                i2 != 0 && llabs(i1) > INT64_MAX / llabs(i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " * %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            (yyval.expression).value.integer = OPERATION(*, i1, i2);
            (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
#line 4971 "libyara/grammar.c"
    break;

  case 160: /* primary_expression: primary_expression '\\' primary_expression  */
#line 2791 "libyara/grammar.y"
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "\\", (yyvsp[-2].expression), (yyvsp[0].expression));

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          if ((yyvsp[0].expression).value.integer != 0)
          {
            (yyval.expression).value.integer = OPERATION(/, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
            (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          }
          else
          {
            result = ERROR_DIVISION_BY_ZERO;
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
#line 5000 "libyara/grammar.c"
    break;

  case 161: /* primary_expression: primary_expression '%' primary_expression  */
#line 2816 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "%");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "%");

        fail_if_error(yr_parser_emit(yyscanner, OP_MOD, NULL));

        if ((yyvsp[0].expression).value.integer != 0)
        {
          (yyval.expression).value.integer = OPERATION(%, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          fail_if_error(ERROR_DIVISION_BY_ZERO);
        }
      }
#line 5021 "libyara/grammar.c"
    break;

  case 162: /* primary_expression: primary_expression '^' primary_expression  */
#line 2833 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 5035 "libyara/grammar.c"
    break;

  case 163: /* primary_expression: primary_expression '&' primary_expression  */
#line 2843 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 5049 "libyara/grammar.c"
    break;

  case 164: /* primary_expression: primary_expression '|' primary_expression  */
#line 2853 "libyara/grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 5063 "libyara/grammar.c"
    break;

  case 165: /* primary_expression: '~' primary_expression  */
#line 2863 "libyara/grammar.y"
      {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == YR_UNDEFINED) ?
            YR_UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 5077 "libyara/grammar.c"
    break;

  case 166: /* primary_expression: primary_expression "<<" primary_expression  */
#line 2873 "libyara/grammar.y"
      {
        int result;

        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "<<");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "<<");

        result = yr_parser_emit(yyscanner, OP_SHL, NULL);

        if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer < 0)
          result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer >= 64)
          (yyval.expression).value.integer = 0;
        else
          (yyval.expression).value.integer = OPERATION(<<, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;

        fail_if_error(result);
      }
#line 5101 "libyara/grammar.c"
    break;

  case 167: /* primary_expression: primary_expression ">>" primary_expression  */
#line 2893 "libyara/grammar.y"
      {
        int result;

        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, ">>");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, ">>");

        result = yr_parser_emit(yyscanner, OP_SHR, NULL);

        if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer < 0)
          result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer >= 64)
          (yyval.expression).value.integer = 0;
        else
          (yyval.expression).value.integer = OPERATION(<<, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;

        fail_if_error(result);
      }
#line 5125 "libyara/grammar.c"
    break;

  case 168: /* primary_expression: regexp  */
#line 2913 "libyara/grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 5133 "libyara/grammar.c"
    break;


#line 5137 "libyara/grammar.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (yyscanner, compiler, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= _END_OF_FILE_)
        {
          /* Return failure if at end of input.  */
          if (yychar == _END_OF_FILE_)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, yyscanner, compiler);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, compiler, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, yyscanner, compiler);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 2918 "libyara/grammar.y"

