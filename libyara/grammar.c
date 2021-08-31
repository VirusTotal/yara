/* A Bison parser, made by GNU Bison 3.7.6.  */

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
#define YYBISON 30706

/* Bison version string.  */
#define YYBISON_VERSION "3.7.6"

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
#line 32 "grammar.y"

  
#include <assert.h>
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

#define FOR_EXPRESSION_ALL 1
#define FOR_EXPRESSION_ANY 2

#define fail_with_error(e) \
    { \
      compiler->last_error = e; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }


#define fail_if_error(e) \
    if (e != ERROR_SUCCESS) \
    { \
      fail_with_error(e); \
    } \


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


#line 185 "grammar.c"

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
    _IN_ = 290,                    /* "<in>"  */
    _OF_ = 291,                    /* "<of>"  */
    _FOR_ = 292,                   /* "<for>"  */
    _THEM_ = 293,                  /* "<them>"  */
    _MATCHES_ = 294,               /* "<matches>"  */
    _CONTAINS_ = 295,              /* "<contains>"  */
    _STARTSWITH_ = 296,            /* "<startswith>"  */
    _ENDSWITH_ = 297,              /* "<endswith>"  */
    _ICONTAINS_ = 298,             /* "<icontains>"  */
    _ISTARTSWITH_ = 299,           /* "<istartswith>"  */
    _IENDSWITH_ = 300,             /* "<iendswith>"  */
    _IEQUALS_ = 301,               /* "<iequals>"  */
    _IMPORT_ = 302,                /* "<import>"  */
    _TRUE_ = 303,                  /* "<true>"  */
    _FALSE_ = 304,                 /* "<false>"  */
    _OR_ = 305,                    /* "<or>"  */
    _AND_ = 306,                   /* "<and>"  */
    _NOT_ = 307,                   /* "<not>"  */
    _EQ_ = 308,                    /* "=="  */
    _NEQ_ = 309,                   /* "!="  */
    _LT_ = 310,                    /* "<"  */
    _LE_ = 311,                    /* "<="  */
    _GT_ = 312,                    /* ">"  */
    _GE_ = 313,                    /* ">="  */
    _SHIFT_LEFT_ = 314,            /* "<<"  */
    _SHIFT_RIGHT_ = 315,           /* ">>"  */
    UNARY_MINUS = 316              /* UNARY_MINUS  */
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
#define _IN_ 290
#define _OF_ 291
#define _FOR_ 292
#define _THEM_ 293
#define _MATCHES_ 294
#define _CONTAINS_ 295
#define _STARTSWITH_ 296
#define _ENDSWITH_ 297
#define _ICONTAINS_ 298
#define _ISTARTSWITH_ 299
#define _IENDSWITH_ 300
#define _IEQUALS_ 301
#define _IMPORT_ 302
#define _TRUE_ 303
#define _FALSE_ 304
#define _OR_ 305
#define _AND_ 306
#define _NOT_ 307
#define _EQ_ 308
#define _NEQ_ 309
#define _LT_ 310
#define _LE_ 311
#define _GT_ 312
#define _GE_ 313
#define _SHIFT_LEFT_ 314
#define _SHIFT_RIGHT_ 315
#define UNARY_MINUS 316

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 304 "grammar.y"

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

#line 374 "grammar.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */
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
  YYSYMBOL__IN_ = 35,                      /* "<in>"  */
  YYSYMBOL__OF_ = 36,                      /* "<of>"  */
  YYSYMBOL__FOR_ = 37,                     /* "<for>"  */
  YYSYMBOL__THEM_ = 38,                    /* "<them>"  */
  YYSYMBOL__MATCHES_ = 39,                 /* "<matches>"  */
  YYSYMBOL__CONTAINS_ = 40,                /* "<contains>"  */
  YYSYMBOL__STARTSWITH_ = 41,              /* "<startswith>"  */
  YYSYMBOL__ENDSWITH_ = 42,                /* "<endswith>"  */
  YYSYMBOL__ICONTAINS_ = 43,               /* "<icontains>"  */
  YYSYMBOL__ISTARTSWITH_ = 44,             /* "<istartswith>"  */
  YYSYMBOL__IENDSWITH_ = 45,               /* "<iendswith>"  */
  YYSYMBOL__IEQUALS_ = 46,                 /* "<iequals>"  */
  YYSYMBOL__IMPORT_ = 47,                  /* "<import>"  */
  YYSYMBOL__TRUE_ = 48,                    /* "<true>"  */
  YYSYMBOL__FALSE_ = 49,                   /* "<false>"  */
  YYSYMBOL__OR_ = 50,                      /* "<or>"  */
  YYSYMBOL__AND_ = 51,                     /* "<and>"  */
  YYSYMBOL__NOT_ = 52,                     /* "<not>"  */
  YYSYMBOL__EQ_ = 53,                      /* "=="  */
  YYSYMBOL__NEQ_ = 54,                     /* "!="  */
  YYSYMBOL__LT_ = 55,                      /* "<"  */
  YYSYMBOL__LE_ = 56,                      /* "<="  */
  YYSYMBOL__GT_ = 57,                      /* ">"  */
  YYSYMBOL__GE_ = 58,                      /* ">="  */
  YYSYMBOL__SHIFT_LEFT_ = 59,              /* "<<"  */
  YYSYMBOL__SHIFT_RIGHT_ = 60,             /* ">>"  */
  YYSYMBOL_61_ = 61,                       /* '|'  */
  YYSYMBOL_62_ = 62,                       /* '^'  */
  YYSYMBOL_63_ = 63,                       /* '&'  */
  YYSYMBOL_64_ = 64,                       /* '+'  */
  YYSYMBOL_65_ = 65,                       /* '-'  */
  YYSYMBOL_66_ = 66,                       /* '*'  */
  YYSYMBOL_67_ = 67,                       /* '\\'  */
  YYSYMBOL_68_ = 68,                       /* '%'  */
  YYSYMBOL_69_ = 69,                       /* '~'  */
  YYSYMBOL_UNARY_MINUS = 70,               /* UNARY_MINUS  */
  YYSYMBOL_71_include_ = 71,               /* "include"  */
  YYSYMBOL_72_ = 72,                       /* '{'  */
  YYSYMBOL_73_ = 73,                       /* '}'  */
  YYSYMBOL_74_ = 74,                       /* ':'  */
  YYSYMBOL_75_ = 75,                       /* '='  */
  YYSYMBOL_76_ = 76,                       /* '('  */
  YYSYMBOL_77_ = 77,                       /* ')'  */
  YYSYMBOL_78_ = 78,                       /* '.'  */
  YYSYMBOL_79_ = 79,                       /* '['  */
  YYSYMBOL_80_ = 80,                       /* ']'  */
  YYSYMBOL_81_ = 81,                       /* ','  */
  YYSYMBOL_YYACCEPT = 82,                  /* $accept  */
  YYSYMBOL_rules = 83,                     /* rules  */
  YYSYMBOL_import = 84,                    /* import  */
  YYSYMBOL_rule = 85,                      /* rule  */
  YYSYMBOL_86_1 = 86,                      /* @1  */
  YYSYMBOL_87_2 = 87,                      /* $@2  */
  YYSYMBOL_meta = 88,                      /* meta  */
  YYSYMBOL_strings = 89,                   /* strings  */
  YYSYMBOL_condition = 90,                 /* condition  */
  YYSYMBOL_rule_modifiers = 91,            /* rule_modifiers  */
  YYSYMBOL_rule_modifier = 92,             /* rule_modifier  */
  YYSYMBOL_tags = 93,                      /* tags  */
  YYSYMBOL_tag_list = 94,                  /* tag_list  */
  YYSYMBOL_meta_declarations = 95,         /* meta_declarations  */
  YYSYMBOL_meta_declaration = 96,          /* meta_declaration  */
  YYSYMBOL_string_declarations = 97,       /* string_declarations  */
  YYSYMBOL_string_declaration = 98,        /* string_declaration  */
  YYSYMBOL_99_3 = 99,                      /* $@3  */
  YYSYMBOL_100_4 = 100,                    /* $@4  */
  YYSYMBOL_101_5 = 101,                    /* $@5  */
  YYSYMBOL_string_modifiers = 102,         /* string_modifiers  */
  YYSYMBOL_string_modifier = 103,          /* string_modifier  */
  YYSYMBOL_regexp_modifiers = 104,         /* regexp_modifiers  */
  YYSYMBOL_regexp_modifier = 105,          /* regexp_modifier  */
  YYSYMBOL_hex_modifiers = 106,            /* hex_modifiers  */
  YYSYMBOL_hex_modifier = 107,             /* hex_modifier  */
  YYSYMBOL_identifier = 108,               /* identifier  */
  YYSYMBOL_arguments = 109,                /* arguments  */
  YYSYMBOL_arguments_list = 110,           /* arguments_list  */
  YYSYMBOL_regexp = 111,                   /* regexp  */
  YYSYMBOL_boolean_expression = 112,       /* boolean_expression  */
  YYSYMBOL_expression = 113,               /* expression  */
  YYSYMBOL_114_6 = 114,                    /* $@6  */
  YYSYMBOL_115_7 = 115,                    /* $@7  */
  YYSYMBOL_116_8 = 116,                    /* $@8  */
  YYSYMBOL_117_9 = 117,                    /* $@9  */
  YYSYMBOL_118_10 = 118,                   /* $@10  */
  YYSYMBOL_for_variables = 119,            /* for_variables  */
  YYSYMBOL_iterator = 120,                 /* iterator  */
  YYSYMBOL_integer_set = 121,              /* integer_set  */
  YYSYMBOL_range = 122,                    /* range  */
  YYSYMBOL_integer_enumeration = 123,      /* integer_enumeration  */
  YYSYMBOL_string_set = 124,               /* string_set  */
  YYSYMBOL_125_11 = 125,                   /* $@11  */
  YYSYMBOL_string_enumeration = 126,       /* string_enumeration  */
  YYSYMBOL_string_enumeration_item = 127,  /* string_enumeration_item  */
  YYSYMBOL_for_expression = 128,           /* for_expression  */
  YYSYMBOL_primary_expression = 129        /* primary_expression  */
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

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
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

#if !defined yyoverflow

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
#endif /* !defined yyoverflow */

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
#define YYLAST   445

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  82
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  48
/* YYNRULES -- Number of rules.  */
#define YYNRULES  154
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  259

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   317


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
       2,     2,     2,     2,     2,     2,     2,    68,    63,     2,
      76,    77,    66,    64,    81,    65,    78,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    74,     2,
       2,    75,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    79,    67,    80,    62,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    72,    61,    73,    69,     2,     2,     2,
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
      55,    56,    57,    58,    59,    60,    70,    71
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   322,   322,   323,   324,   325,   326,   327,   328,   336,
     349,   354,   348,   381,   384,   400,   403,   418,   423,   424,
     429,   430,   436,   439,   455,   464,   506,   507,   512,   529,
     543,   557,   571,   589,   590,   596,   595,   612,   611,   632,
     631,   656,   662,   722,   723,   724,   725,   726,   727,   733,
     754,   785,   790,   807,   812,   832,   833,   847,   848,   849,
     850,   851,   855,   856,   870,   874,   969,  1017,  1078,  1125,
    1126,  1130,  1165,  1218,  1260,  1283,  1289,  1295,  1307,  1317,
    1327,  1337,  1347,  1357,  1367,  1377,  1391,  1406,  1417,  1494,
    1532,  1434,  1691,  1690,  1780,  1786,  1806,  1812,  1819,  1818,
    1864,  1863,  1907,  1914,  1921,  1928,  1935,  1942,  1949,  1953,
    1961,  1981,  2009,  2083,  2111,  2119,  2128,  2152,  2167,  2187,
    2186,  2192,  2203,  2204,  2209,  2216,  2227,  2231,  2236,  2245,
    2249,  2257,  2269,  2283,  2290,  2297,  2322,  2334,  2346,  2361,
    2373,  2388,  2431,  2452,  2487,  2522,  2556,  2581,  2598,  2608,
    2618,  2628,  2638,  2658,  2678
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
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
  "\"<all>\"", "\"<any>\"", "\"<in>\"", "\"<of>\"", "\"<for>\"",
  "\"<them>\"", "\"<matches>\"", "\"<contains>\"", "\"<startswith>\"",
  "\"<endswith>\"", "\"<icontains>\"", "\"<istartswith>\"",
  "\"<iendswith>\"", "\"<iequals>\"", "\"<import>\"", "\"<true>\"",
  "\"<false>\"", "\"<or>\"", "\"<and>\"", "\"<not>\"", "\"==\"", "\"!=\"",
  "\"<\"", "\"<=\"", "\">\"", "\">=\"", "\"<<\"", "\">>\"", "'|'", "'^'",
  "'&'", "'+'", "'-'", "'*'", "'\\\\'", "'%'", "'~'", "UNARY_MINUS",
  "\"include\"", "'{'", "'}'", "':'", "'='", "'('", "')'", "'.'", "'['",
  "']'", "','", "$accept", "rules", "import", "rule", "@1", "$@2", "meta",
  "strings", "condition", "rule_modifiers", "rule_modifier", "tags",
  "tag_list", "meta_declarations", "meta_declaration",
  "string_declarations", "string_declaration", "$@3", "$@4", "$@5",
  "string_modifiers", "string_modifier", "regexp_modifiers",
  "regexp_modifier", "hex_modifiers", "hex_modifier", "identifier",
  "arguments", "arguments_list", "regexp", "boolean_expression",
  "expression", "$@6", "$@7", "$@8", "$@9", "$@10", "for_variables",
  "iterator", "integer_set", "range", "integer_enumeration", "string_set",
  "$@11", "string_enumeration", "string_enumeration_item",
  "for_expression", "primary_expression", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   124,    94,    38,    43,    45,    42,    92,    37,   126,
     316,   317,   123,   125,    58,    61,    40,    41,    46,    91,
      93,    44
};
#endif

#define YYPACT_NINF (-193)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-127)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -193,    93,  -193,   -35,  -193,     4,  -193,  -193,    81,  -193,
    -193,  -193,  -193,    19,  -193,  -193,  -193,  -193,    47,    53,
      63,  -193,   125,   131,  -193,    82,   156,   159,    98,  -193,
     100,   159,  -193,   165,   168,    14,  -193,   104,   165,  -193,
     107,   119,  -193,  -193,  -193,  -193,   181,    90,  -193,    58,
    -193,  -193,   179,   183,   180,  -193,    -3,  -193,   127,   130,
    -193,  -193,   132,  -193,  -193,  -193,  -193,  -193,  -193,   111,
    -193,  -193,    58,   171,   171,    58,    85,  -193,   -37,  -193,
     174,   248,  -193,  -193,  -193,   171,   136,   171,   171,   171,
     171,   102,   347,  -193,  -193,  -193,   -37,   157,   209,    58,
     222,   171,  -193,  -193,   -10,   213,   171,   171,   171,   171,
     171,   171,   171,   171,   171,   171,   171,   171,   171,   171,
     171,   171,   171,   171,   171,   171,   171,   171,   135,    91,
     145,   231,   347,   171,  -193,   164,   258,   290,   309,  -193,
     -10,   227,   171,  -193,  -193,   162,   160,   109,  -193,   268,
      58,    58,  -193,  -193,   207,  -193,   347,   347,   347,   347,
     347,   347,   347,   347,   347,   347,   347,   347,   347,    17,
      17,   357,   367,   377,   129,   129,  -193,  -193,   -10,  -193,
    -193,  -193,  -193,   167,   170,   182,  -193,  -193,  -193,  -193,
    -193,  -193,  -193,  -193,  -193,  -193,  -193,   154,  -193,  -193,
    -193,   185,  -193,   -20,  -193,    58,  -193,   205,  -193,    92,
     136,  -193,   240,   241,   259,   171,  -193,    -8,   249,   109,
    -193,  -193,    28,  -193,  -193,   -61,   201,   203,   328,   206,
     171,    85,   211,  -193,  -193,  -193,  -193,    92,   264,  -193,
    -193,  -193,  -193,    58,    60,   154,  -193,  -193,   218,   -42,
    -193,   171,   220,  -193,  -193,   347,    58,   -40,  -193
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
      12,    30,     0,     0,     0,    65,    85,   136,   138,   140,
     133,   134,     0,   135,    73,   130,   131,   127,   128,     0,
      75,    76,     0,     0,     0,     0,   141,   154,    17,    74,
       0,   108,    41,    55,    62,     0,     0,     0,     0,     0,
       0,     0,   126,    97,   142,   151,     0,    74,   108,    69,
       0,     0,   100,    98,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    36,
      38,    40,    86,     0,    87,     0,     0,     0,     0,    88,
       0,     0,     0,   109,   129,     0,    70,    71,    66,     0,
       0,     0,   121,   119,    94,    77,    78,    80,    82,    79,
      81,    83,    84,   106,   107,   102,   104,   103,   105,   152,
     153,   150,   148,   149,   143,   144,   145,   146,     0,   147,
      47,    44,    43,    48,    51,    53,    45,    46,    42,    61,
      58,    57,    59,    60,    56,    64,    63,     0,   137,   139,
     132,     0,   110,     0,    68,     0,    67,   101,    99,     0,
       0,    95,     0,     0,     0,     0,    92,     0,     0,    72,
     124,   125,     0,   122,    96,     0,     0,     0,     0,     0,
       0,   112,     0,   113,   115,   111,   120,     0,     0,    49,
      52,    54,   116,     0,     0,   117,    90,   123,     0,     0,
     114,     0,     0,    50,    93,   118,     0,     0,    91
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -193,  -193,   280,   294,  -193,  -193,  -193,  -193,  -193,  -193,
    -193,  -193,  -193,  -193,   267,  -193,   261,  -193,  -193,  -193,
    -193,  -193,  -193,  -193,  -193,  -193,    83,  -193,  -193,   232,
     -49,   -73,  -193,  -193,  -193,  -193,  -193,  -193,  -193,  -193,
    -192,  -193,  -111,  -193,  -193,   103,   270,   -68
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     1,     6,     7,    18,    34,    26,    29,    41,     8,
      16,    20,    22,    31,    32,    38,    39,    52,    53,    54,
     129,   188,   130,   194,   131,   196,    76,   145,   146,    77,
      96,    79,   141,   252,   229,   151,   150,   203,   232,   233,
     134,   244,   154,   209,   222,   223,    80,    81
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      78,    92,    97,    55,   238,    94,    95,    98,   102,   103,
     102,   103,     5,   102,   103,   217,   239,   132,   224,   135,
     136,   137,   138,    93,    12,   234,   147,    85,   152,   201,
      17,    42,    86,   149,    43,   254,     9,   258,   156,   157,
     158,   159,   160,   161,   162,   163,   164,   165,   166,   167,
     168,   169,   170,   171,   172,   173,   174,   175,   176,   177,
     179,   218,    44,    45,    21,   197,   153,   211,   230,    55,
      56,    57,    58,    59,   179,    60,    61,    62,    63,    46,
      64,   124,   125,   126,   127,   142,    13,    14,    15,    65,
      66,    67,    68,     2,     3,    69,     4,   180,   -18,   -18,
     -18,   207,   208,   139,   220,   236,    70,    71,   221,   237,
      72,   -39,   -37,   -89,   181,   182,   183,   184,   185,   186,
     187,    19,    55,    73,    57,    58,    59,    74,    60,    61,
      62,    63,   219,    64,    75,    23,    24,   250,   140,    25,
       5,   251,    65,    66,    67,    68,    55,   228,    57,    58,
      59,   189,    60,    61,    62,    63,    27,    64,   215,   -74,
     -74,    99,   245,   100,   101,    28,    65,    66,   190,   191,
      30,   178,    33,   192,   193,    35,    73,    37,    40,    47,
      74,    49,    55,   255,    57,    58,    59,    90,    60,    61,
      62,    63,    50,    64,   249,   126,   127,   142,    51,    82,
      73,    84,    65,    66,    74,    83,    87,   257,    89,    88,
     104,    90,   133,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   142,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   142,   148,   143,    64,    73,   195,   202,   204,
      74,   205,   210,   212,   198,  -126,   213,    90,   105,   106,
     107,   108,   109,   110,   111,   112,   103,   225,   214,   216,
     235,   226,   113,   114,   115,   116,   117,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   128,   240,   227,
     241,   248,   243,    10,  -126,   246,   144,   105,   106,   107,
     108,   109,   110,   111,   112,   253,   256,    11,    36,    48,
     231,   113,   114,   115,   116,   117,   118,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   128,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   142,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   142,   155,   199,    91,
     247,     0,     0,     0,     0,     0,     0,     0,   206,   119,
     120,   121,   122,   123,   124,   125,   126,   127,   142,     0,
       0,     0,     0,     0,     0,     0,     0,   200,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   142,     0,     0,
       0,     0,     0,     0,     0,     0,   144,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   142,     0,     0,     0,
       0,     0,     0,     0,     0,   242,   119,   120,   121,   122,
     123,   124,   125,   126,   127,   142,   119,   120,     0,   122,
     123,   124,   125,   126,   127,   142,   119,   120,     0,     0,
     123,   124,   125,   126,   127,   142,   119,   120,     0,     0,
       0,   124,   125,   126,   127,   142
};

static const yytype_int16 yycheck[] =
{
      49,    69,    75,    11,    65,    73,    74,    75,    50,    51,
      50,    51,    47,    50,    51,    35,    77,    85,   210,    87,
      88,    89,    90,    72,    20,   217,    99,    30,    38,   140,
      11,    17,    35,   101,    20,    77,    71,    77,   106,   107,
     108,   109,   110,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127,
     128,    81,    48,    49,    11,   133,    76,   178,    76,    11,
      12,    13,    14,    15,   142,    17,    18,    19,    20,    65,
      22,    64,    65,    66,    67,    68,     5,     6,     7,    31,
      32,    33,    34,     0,     1,    37,     3,     6,     5,     6,
       7,   150,   151,     1,    12,    77,    48,    49,    16,    81,
      52,    21,    22,    11,    23,    24,    25,    26,    27,    28,
      29,    74,    11,    65,    13,    14,    15,    69,    17,    18,
      19,    20,   205,    22,    76,    72,    11,    77,    36,     8,
      47,    81,    31,    32,    33,    34,    11,   215,    13,    14,
      15,     6,    17,    18,    19,    20,    74,    22,     4,    50,
      51,    76,   230,    78,    79,     9,    31,    32,    23,    24,
      11,    36,    74,    28,    29,    75,    65,    12,    10,    75,
      69,    74,    11,   251,    13,    14,    15,    76,    17,    18,
      19,    20,    73,    22,   243,    66,    67,    68,    17,    20,
      65,    21,    31,    32,    69,    22,    79,   256,    76,    79,
      36,    76,    76,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    11,    77,    22,    65,     6,    11,    77,
      69,    81,    35,    76,    80,    36,    76,    76,    39,    40,
      41,    42,    43,    44,    45,    46,    51,    17,    76,    74,
      11,    20,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    77,    20,
      77,    17,    76,     3,    36,    74,    77,    39,    40,    41,
      42,    43,    44,    45,    46,    77,    76,     3,    31,    38,
     217,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,   105,    80,    69,
     237,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    80,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    77,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    77,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    77,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    59,    60,    -1,    62,
      63,    64,    65,    66,    67,    68,    59,    60,    -1,    -1,
      63,    64,    65,    66,    67,    68,    59,    60,    -1,    -1,
      -1,    64,    65,    66,    67,    68
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    83,     0,     1,     3,    47,    84,    85,    91,    71,
      84,    85,    20,     5,     6,     7,    92,    11,    86,    74,
      93,    11,    94,    72,    11,     8,    88,    74,     9,    89,
      11,    95,    96,    74,    87,    75,    96,    12,    97,    98,
      10,    90,    17,    20,    48,    49,    65,    75,    98,    74,
      73,    17,    99,   100,   101,    11,    12,    13,    14,    15,
      17,    18,    19,    20,    22,    31,    32,    33,    34,    37,
      48,    49,    52,    65,    69,    76,   108,   111,   112,   113,
     128,   129,    20,    22,    21,    30,    35,    79,    79,    76,
      76,   128,   129,   112,   129,   129,   112,   113,   129,    76,
      78,    79,    50,    51,    36,    39,    40,    41,    42,    43,
      44,    45,    46,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,   102,
     104,   106,   129,    76,   122,   129,   129,   129,   129,     1,
      36,   114,    68,    77,    77,   109,   110,   113,    11,   129,
     118,   117,    38,    76,   124,   111,   129,   129,   129,   129,
     129,   129,   129,   129,   129,   129,   129,   129,   129,   129,
     129,   129,   129,   129,   129,   129,   129,   129,    36,   129,
       6,    23,    24,    25,    26,    27,    28,    29,   103,     6,
      23,    24,    28,    29,   105,     6,   107,   129,    80,    80,
      77,   124,    11,   119,    77,    81,    80,   112,   112,   125,
      35,   124,    76,    76,    76,     4,    74,    35,    81,   113,
      12,    16,   126,   127,   122,    17,    20,    20,   129,   116,
      76,   108,   120,   121,   122,    11,    77,    81,    65,    77,
      77,    77,    77,    76,   123,   129,    74,   127,    17,   112,
      77,    81,   115,    77,    77,   129,    76,   112,    77
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    82,    83,    83,    83,    83,    83,    83,    83,    84,
      86,    87,    85,    88,    88,    89,    89,    90,    91,    91,
      92,    92,    93,    93,    94,    94,    95,    95,    96,    96,
      96,    96,    96,    97,    97,    99,    98,   100,    98,   101,
      98,   102,   102,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   103,   104,   104,   105,   105,   105,
     105,   105,   106,   106,   107,   108,   108,   108,   108,   109,
     109,   110,   110,   111,   112,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   114,
     115,   113,   116,   113,   113,   113,   113,   113,   117,   113,
     118,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     119,   119,   120,   120,   121,   121,   122,   123,   123,   125,
     124,   124,   126,   126,   127,   127,   128,   128,   128,   129,
     129,   129,   129,   129,   129,   129,   129,   129,   129,   129,
     129,   129,   129,   129,   129,   129,   129,   129,   129,   129,
     129,   129,   129,   129,   129
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
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
       0,    11,     0,     9,     3,     4,     5,     2,     0,     4,
       0,     4,     3,     3,     3,     3,     3,     3,     1,     3,
       1,     3,     1,     1,     3,     1,     5,     1,     3,     0,
       4,     1,     1,     3,     1,     1,     1,     1,     1,     3,
       1,     1,     4,     1,     1,     1,     1,     4,     1,     4,
       1,     1,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     2,     3,     3,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


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

/* This macro is provided for backward compatibility. */
# ifndef YY_LOCATION_PRINT
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif


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
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
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
#line 274 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1475 "grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_: /* "string identifier"  */
#line 278 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1481 "grammar.c"
        break;

    case YYSYMBOL__STRING_COUNT_: /* "string count"  */
#line 275 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1487 "grammar.c"
        break;

    case YYSYMBOL__STRING_OFFSET_: /* "string offset"  */
#line 276 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1493 "grammar.c"
        break;

    case YYSYMBOL__STRING_LENGTH_: /* "string length"  */
#line 277 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1499 "grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_: /* "string identifier with wildcard"  */
#line 279 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1505 "grammar.c"
        break;

    case YYSYMBOL__TEXT_STRING_: /* "text string"  */
#line 280 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1511 "grammar.c"
        break;

    case YYSYMBOL__HEX_STRING_: /* "hex string"  */
#line 281 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1517 "grammar.c"
        break;

    case YYSYMBOL__REGEXP_: /* "regular expression"  */
#line 282 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1523 "grammar.c"
        break;

    case YYSYMBOL_string_modifiers: /* string_modifiers  */
#line 295 "grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1535 "grammar.c"
        break;

    case YYSYMBOL_string_modifier: /* string_modifier  */
#line 287 "grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1547 "grammar.c"
        break;

    case YYSYMBOL_arguments: /* arguments  */
#line 284 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1553 "grammar.c"
        break;

    case YYSYMBOL_arguments_list: /* arguments_list  */
#line 285 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1559 "grammar.c"
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
    goto yyexhaustedlab;
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
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
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
#line 329 "grammar.y"
      {
        _yr_compiler_pop_file_name(compiler);
      }
#line 1835 "grammar.c"
    break;

  case 9: /* import: "<import>" "text string"  */
#line 337 "grammar.y"
      {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        fail_if_error(result);
      }
#line 1847 "grammar.c"
    break;

  case 10: /* @1: %empty  */
#line 349 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[-2].integer), (yyvsp[0].c_string), &(yyval.rule)));
      }
#line 1856 "grammar.c"
    break;

  case 11: /* $@2: %empty  */
#line 354 "grammar.y"
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
#line 1874 "grammar.c"
    break;

  case 12: /* rule: rule_modifiers "<rule>" "identifier" @1 tags '{' meta strings $@2 condition '}'  */
#line 368 "grammar.y"
      {
        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, &(yyvsp[-7].rule)); // rule created in phase 1

        yr_free((yyvsp[-8].c_string));

        fail_if_error(result);
      }
#line 1887 "grammar.c"
    break;

  case 13: /* meta: %empty  */
#line 381 "grammar.y"
      {
        (yyval.meta) = YR_ARENA_NULL_REF;
      }
#line 1895 "grammar.c"
    break;

  case 14: /* meta: "<meta>" ':' meta_declarations  */
#line 385 "grammar.y"
      {
        YR_META* meta = yr_arena_get_ptr(
            compiler->arena,
            YR_METAS_TABLE,
            (compiler->current_meta_idx - 1) * sizeof(YR_META));

        meta->flags |= META_FLAGS_LAST_IN_RULE;

        (yyval.meta) = (yyvsp[0].meta);
      }
#line 1910 "grammar.c"
    break;

  case 15: /* strings: %empty  */
#line 400 "grammar.y"
      {
        (yyval.string) = YR_ARENA_NULL_REF;
      }
#line 1918 "grammar.c"
    break;

  case 16: /* strings: "<strings>" ':' string_declarations  */
#line 404 "grammar.y"
      {
        YR_STRING* string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            (compiler->current_string_idx - 1) * sizeof(YR_STRING));

        string->flags |= STRING_FLAGS_LAST_IN_RULE;

        (yyval.string) = (yyvsp[0].string);
      }
#line 1933 "grammar.c"
    break;

  case 18: /* rule_modifiers: %empty  */
#line 423 "grammar.y"
                                       { (yyval.integer) = 0;  }
#line 1939 "grammar.c"
    break;

  case 19: /* rule_modifiers: rule_modifiers rule_modifier  */
#line 424 "grammar.y"
                                       { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1945 "grammar.c"
    break;

  case 20: /* rule_modifier: "<private>"  */
#line 429 "grammar.y"
                     { (yyval.integer) = RULE_FLAGS_PRIVATE; }
#line 1951 "grammar.c"
    break;

  case 21: /* rule_modifier: "<global>"  */
#line 430 "grammar.y"
                     { (yyval.integer) = RULE_FLAGS_GLOBAL; }
#line 1957 "grammar.c"
    break;

  case 22: /* tags: %empty  */
#line 436 "grammar.y"
      {
        (yyval.tag) = YR_ARENA_NULL_REF;
      }
#line 1965 "grammar.c"
    break;

  case 23: /* tags: ':' tag_list  */
#line 440 "grammar.y"
      {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        fail_if_error(yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, "", NULL));

        (yyval.tag) = (yyvsp[0].tag);
      }
#line 1981 "grammar.c"
    break;

  case 24: /* tag_list: "identifier"  */
#line 456 "grammar.y"
      {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, (yyvsp[0].c_string), &(yyval.tag));

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 1994 "grammar.c"
    break;

  case 25: /* tag_list: tag_list "identifier"  */
#line 465 "grammar.y"
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
#line 2035 "grammar.c"
    break;

  case 26: /* meta_declarations: meta_declaration  */
#line 506 "grammar.y"
                                          {  (yyval.meta) = (yyvsp[0].meta); }
#line 2041 "grammar.c"
    break;

  case 27: /* meta_declarations: meta_declarations meta_declaration  */
#line 507 "grammar.y"
                                          {  (yyval.meta) = (yyvsp[-1].meta); }
#line 2047 "grammar.c"
    break;

  case 28: /* meta_declaration: "identifier" '=' "text string"  */
#line 513 "grammar.y"
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
#line 2068 "grammar.c"
    break;

  case 29: /* meta_declaration: "identifier" '=' "integer number"  */
#line 530 "grammar.y"
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
#line 2086 "grammar.c"
    break;

  case 30: /* meta_declaration: "identifier" '=' '-' "integer number"  */
#line 544 "grammar.y"
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
#line 2104 "grammar.c"
    break;

  case 31: /* meta_declaration: "identifier" '=' "<true>"  */
#line 558 "grammar.y"
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
#line 2122 "grammar.c"
    break;

  case 32: /* meta_declaration: "identifier" '=' "<false>"  */
#line 572 "grammar.y"
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
#line 2140 "grammar.c"
    break;

  case 33: /* string_declarations: string_declaration  */
#line 589 "grammar.y"
                                              { (yyval.string) = (yyvsp[0].string); }
#line 2146 "grammar.c"
    break;

  case 34: /* string_declarations: string_declarations string_declaration  */
#line 590 "grammar.y"
                                              { (yyval.string) = (yyvsp[-1].string); }
#line 2152 "grammar.c"
    break;

  case 35: /* $@3: %empty  */
#line 596 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2160 "grammar.c"
    break;

  case 36: /* string_declaration: "string identifier" '=' $@3 "text string" string_modifiers  */
#line 600 "grammar.y"
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));
        yr_free((yyvsp[0].modifier).alphabet);

        fail_if_error(result);
        compiler->current_line = 0;
      }
#line 2176 "grammar.c"
    break;

  case 37: /* $@4: %empty  */
#line 612 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2184 "grammar.c"
    break;

  case 38: /* string_declaration: "string identifier" '=' $@4 "regular expression" regexp_modifiers  */
#line 616 "grammar.y"
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
#line 2204 "grammar.c"
    break;

  case 39: /* $@5: %empty  */
#line 632 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2212 "grammar.c"
    break;

  case 40: /* string_declaration: "string identifier" '=' $@5 "hex string" hex_modifiers  */
#line 636 "grammar.y"
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
#line 2232 "grammar.c"
    break;

  case 41: /* string_modifiers: %empty  */
#line 656 "grammar.y"
      {
        (yyval.modifier).flags = 0;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 0;
        (yyval.modifier).alphabet = NULL;
      }
#line 2243 "grammar.c"
    break;

  case 42: /* string_modifiers: string_modifiers string_modifier  */
#line 663 "grammar.y"
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
#line 2303 "grammar.c"
    break;

  case 43: /* string_modifier: "<wide>"  */
#line 722 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2309 "grammar.c"
    break;

  case 44: /* string_modifier: "<ascii>"  */
#line 723 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2315 "grammar.c"
    break;

  case 45: /* string_modifier: "<nocase>"  */
#line 724 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2321 "grammar.c"
    break;

  case 46: /* string_modifier: "<fullword>"  */
#line 725 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2327 "grammar.c"
    break;

  case 47: /* string_modifier: "<private>"  */
#line 726 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2333 "grammar.c"
    break;

  case 48: /* string_modifier: "<xor>"  */
#line 728 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 255;
      }
#line 2343 "grammar.c"
    break;

  case 49: /* string_modifier: "<xor>" '(' "integer number" ')'  */
#line 734 "grammar.y"
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
#line 2363 "grammar.c"
    break;

  case 50: /* string_modifier: "<xor>" '(' "integer number" '-' "integer number" ')'  */
#line 755 "grammar.y"
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
#line 2398 "grammar.c"
    break;

  case 51: /* string_modifier: "<base64>"  */
#line 786 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2407 "grammar.c"
    break;

  case 52: /* string_modifier: "<base64>" '(' "text string" ')'  */
#line 791 "grammar.y"
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
#line 2428 "grammar.c"
    break;

  case 53: /* string_modifier: "<base64wide>"  */
#line 808 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64_WIDE;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2437 "grammar.c"
    break;

  case 54: /* string_modifier: "<base64wide>" '(' "text string" ')'  */
#line 813 "grammar.y"
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
#line 2458 "grammar.c"
    break;

  case 55: /* regexp_modifiers: %empty  */
#line 832 "grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2464 "grammar.c"
    break;

  case 56: /* regexp_modifiers: regexp_modifiers regexp_modifier  */
#line 834 "grammar.y"
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
#line 2479 "grammar.c"
    break;

  case 57: /* regexp_modifier: "<wide>"  */
#line 847 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2485 "grammar.c"
    break;

  case 58: /* regexp_modifier: "<ascii>"  */
#line 848 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2491 "grammar.c"
    break;

  case 59: /* regexp_modifier: "<nocase>"  */
#line 849 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2497 "grammar.c"
    break;

  case 60: /* regexp_modifier: "<fullword>"  */
#line 850 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2503 "grammar.c"
    break;

  case 61: /* regexp_modifier: "<private>"  */
#line 851 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2509 "grammar.c"
    break;

  case 62: /* hex_modifiers: %empty  */
#line 855 "grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2515 "grammar.c"
    break;

  case 63: /* hex_modifiers: hex_modifiers hex_modifier  */
#line 857 "grammar.y"
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
#line 2530 "grammar.c"
    break;

  case 64: /* hex_modifier: "<private>"  */
#line 870 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2536 "grammar.c"
    break;

  case 65: /* identifier: "identifier"  */
#line 875 "grammar.y"
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
#line 2635 "grammar.c"
    break;

  case 66: /* identifier: identifier '.' "identifier"  */
#line 970 "grammar.y"
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
#line 2687 "grammar.c"
    break;

  case 67: /* identifier: identifier '[' primary_expression ']'  */
#line 1018 "grammar.y"
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
#line 2751 "grammar.c"
    break;

  case 68: /* identifier: identifier '(' arguments ')'  */
#line 1079 "grammar.y"
      {
        YR_ARENA_REF ref;
        int result = ERROR_SUCCESS;
        YR_OBJECT_FUNCTION* function;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          result = yr_parser_check_types(
              compiler, object_as_function((yyvsp[-3].expression).value.object), (yyvsp[-1].c_string));

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

          function = object_as_function((yyvsp[-3].expression).value.object);

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
#line 2798 "grammar.c"
    break;

  case 69: /* arguments: %empty  */
#line 1125 "grammar.y"
                      { (yyval.c_string) = yr_strdup(""); }
#line 2804 "grammar.c"
    break;

  case 70: /* arguments: arguments_list  */
#line 1126 "grammar.y"
                      { (yyval.c_string) = (yyvsp[0].c_string); }
#line 2810 "grammar.c"
    break;

  case 71: /* arguments_list: expression  */
#line 1131 "grammar.y"
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
#line 2849 "grammar.c"
    break;

  case 72: /* arguments_list: arguments_list ',' expression  */
#line 1166 "grammar.y"
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
#line 2902 "grammar.c"
    break;

  case 73: /* regexp: "regular expression"  */
#line 1219 "grammar.y"
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
#line 2944 "grammar.c"
    break;

  case 74: /* boolean_expression: expression  */
#line 1261 "grammar.y"
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
#line 2968 "grammar.c"
    break;

  case 75: /* expression: "<true>"  */
#line 1284 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 1));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2978 "grammar.c"
    break;

  case 76: /* expression: "<false>"  */
#line 1290 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 0));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2988 "grammar.c"
    break;

  case 77: /* expression: primary_expression "<matches>" regexp  */
#line 1296 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        fail_if_error(yr_parser_emit(
            yyscanner,
            OP_MATCHES,
            NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3004 "grammar.c"
    break;

  case 78: /* expression: primary_expression "<contains>" primary_expression  */
#line 1308 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3018 "grammar.c"
    break;

  case 79: /* expression: primary_expression "<icontains>" primary_expression  */
#line 1318 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "icontains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "icontains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ICONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3032 "grammar.c"
    break;

  case 80: /* expression: primary_expression "<startswith>" primary_expression  */
#line 1328 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "startswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "startswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_STARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3046 "grammar.c"
    break;

  case 81: /* expression: primary_expression "<istartswith>" primary_expression  */
#line 1338 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "istartswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "istartswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ISTARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3060 "grammar.c"
    break;

  case 82: /* expression: primary_expression "<endswith>" primary_expression  */
#line 1348 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "endswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "endswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3074 "grammar.c"
    break;

  case 83: /* expression: primary_expression "<iendswith>" primary_expression  */
#line 1358 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iendswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iendswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3088 "grammar.c"
    break;

  case 84: /* expression: primary_expression "<iequals>" primary_expression  */
#line 1368 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iequals");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iequals");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IEQUALS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3102 "grammar.c"
    break;

  case 85: /* expression: "string identifier"  */
#line 1378 "grammar.y"
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
#line 3120 "grammar.c"
    break;

  case 86: /* expression: "string identifier" "<at>" primary_expression  */
#line 1392 "grammar.y"
      {
        int result;

        check_type_with_cleanup((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at", yr_free((yyvsp[-2].c_string)));

        result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_AT, (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3139 "grammar.c"
    break;

  case 87: /* expression: "string identifier" "<in>" range  */
#line 1407 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3154 "grammar.c"
    break;

  case 88: /* expression: "<for>" for_expression error  */
#line 1418 "grammar.y"
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
#line 3175 "grammar.c"
    break;

  case 89: /* $@6: %empty  */
#line 1494 "grammar.y"
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
#line 3217 "grammar.c"
    break;

  case 90: /* $@7: %empty  */
#line 1532 "grammar.y"
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
#line 3270 "grammar.c"
    break;

  case 91: /* expression: "<for>" for_expression $@6 for_variables "<in>" iterator ':' $@7 '(' boolean_expression ')'  */
#line 1581 "grammar.y"
      {
        int32_t jmp_offset;
        YR_FIXUP* fixup;
        YR_ARENA_REF pop_ref;
        YR_ARENA_REF jmp_offset_ref;

        int var_frame = _yr_compiler_get_var_frame(compiler);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        jmp_offset = \
            compiler->loop[compiler->loop_index].start_ref.offset -
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION);

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JUNDEF_P,
            jmp_offset,
            NULL,
            NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        jmp_offset = \
            compiler->loop[compiler->loop_index].start_ref.offset -
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION);

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JL_P,
            jmp_offset,
            NULL,
            NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_POP, &pop_ref));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JZ,
            0,      // still don't know the jump offset, use 0 for now.
            NULL,
            &jmp_offset_ref));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_POP, NULL));

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
        *jmp_offset_addr = jmp_offset;

        yr_free(fixup);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_INT_GE, NULL));

        jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            jmp_offset_ref.offset + 1;

        jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &jmp_offset_ref);

        *jmp_offset_addr = jmp_offset;

        loop_vars_cleanup(compiler->loop_index);

        compiler->loop_index--;

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3384 "grammar.c"
    break;

  case 92: /* $@8: %empty  */
#line 1691 "grammar.y"
      {
        YR_ARENA_REF ref;

        int result = ERROR_SUCCESS;
        int var_frame;

        if (compiler->loop_index + 1 == YR_MAX_LOOP_NESTING)
          result = ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_var_index != -1)
          result = ERROR_NESTED_FOR_OF_LOOP;

        fail_if_error(result);

        compiler->loop_index++;

        var_frame = _yr_compiler_get_var_frame(compiler);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 1, NULL, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 2, NULL, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, var_frame, &ref, NULL);

        compiler->loop_for_of_var_index = var_frame;
        compiler->loop[compiler->loop_index].start_ref = ref;
        compiler->loop[compiler->loop_index].vars_count = 0;
        compiler->loop[compiler->loop_index].vars_internal_count = \
            YR_INTERNAL_LOOP_VARS;
      }
#line 3423 "grammar.c"
    break;

  case 93: /* expression: "<for>" for_expression "<of>" string_set ':' $@8 '(' boolean_expression ')'  */
#line 1726 "grammar.y"
      {
        int var_frame = 0;

        compiler->loop_for_of_var_index = -1;

        var_frame = _yr_compiler_get_var_frame(compiler);

        // Increment counter by the value returned by the
        // boolean expression (0 or 1). If the boolean expression
        // returned YR_UNDEFINED the OP_ADD_M won't do anything.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, var_frame + 1, NULL, NULL);

        // Increment iterations counter.
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, var_frame + 2, NULL, NULL);

        int32_t jmp_offset = \
            compiler->loop[compiler->loop_index].start_ref.offset -
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION);

        // If next string is not undefined, go back to the
        // beginning of the loop.
        yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JNUNDEF,
            jmp_offset,
            NULL,
            NULL);

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at top of the stack. Check if the quantifier is
        // undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, var_frame + 2, NULL, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to true.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 1, NULL, NULL);

        yr_parser_emit(yyscanner, OP_INT_LE, NULL);

        loop_vars_cleanup(compiler->loop_index);

        compiler->loop_index--;

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3482 "grammar.c"
    break;

  case 94: /* expression: for_expression "<of>" string_set  */
#line 1781 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3492 "grammar.c"
    break;

  case 95: /* expression: primary_expression '%' "<of>" string_set  */
#line 1787 "grammar.y"
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
          compiler->last_error = ERROR_INVALID_PERCENTAGE;
          yyerror(yyscanner, compiler, NULL);
          YYERROR;
        }

        yr_parser_emit(yyscanner, OP_OF_PERCENT, NULL);
      }
#line 3516 "grammar.c"
    break;

  case 96: /* expression: for_expression "<of>" string_set "<in>" range  */
#line 1807 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_OF_FOUND_IN, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3526 "grammar.c"
    break;

  case 97: /* expression: "<not>" boolean_expression  */
#line 1813 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3536 "grammar.c"
    break;

  case 98: /* $@9: %empty  */
#line 1819 "grammar.y"
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
#line 3562 "grammar.c"
    break;

  case 99: /* expression: boolean_expression "<and>" $@9 boolean_expression  */
#line 1841 "grammar.y"
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_AND, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        *jmp_offset_addr = jmp_offset;

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3589 "grammar.c"
    break;

  case 100: /* $@10: %empty  */
#line 1864 "grammar.y"
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
#line 3614 "grammar.c"
    break;

  case 101: /* expression: boolean_expression "<or>" $@10 boolean_expression  */
#line 1885 "grammar.y"
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_OR, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        *jmp_offset_addr = jmp_offset;

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3641 "grammar.c"
    break;

  case 102: /* expression: primary_expression "<" primary_expression  */
#line 1908 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3652 "grammar.c"
    break;

  case 103: /* expression: primary_expression ">" primary_expression  */
#line 1915 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3663 "grammar.c"
    break;

  case 104: /* expression: primary_expression "<=" primary_expression  */
#line 1922 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3674 "grammar.c"
    break;

  case 105: /* expression: primary_expression ">=" primary_expression  */
#line 1929 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3685 "grammar.c"
    break;

  case 106: /* expression: primary_expression "==" primary_expression  */
#line 1936 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3696 "grammar.c"
    break;

  case 107: /* expression: primary_expression "!=" primary_expression  */
#line 1943 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3707 "grammar.c"
    break;

  case 108: /* expression: primary_expression  */
#line 1950 "grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3715 "grammar.c"
    break;

  case 109: /* expression: '(' expression ')'  */
#line 1954 "grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3723 "grammar.c"
    break;

  case 110: /* for_variables: "identifier"  */
#line 1962 "grammar.y"
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
#line 3747 "grammar.c"
    break;

  case 111: /* for_variables: for_variables ',' "identifier"  */
#line 1982 "grammar.y"
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
#line 3776 "grammar.c"
    break;

  case 112: /* iterator: identifier  */
#line 2010 "grammar.y"
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
#line 3854 "grammar.c"
    break;

  case 113: /* iterator: integer_set  */
#line 2084 "grammar.y"
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (loop_ctx->vars_count == 1)
        {
          loop_ctx->vars[0].type = EXPRESSION_TYPE_INTEGER;
          loop_ctx->vars[0].value.integer = YR_UNDEFINED;
        }
        else
        {
          yr_compiler_set_error_extra_info_fmt(
              compiler,
              "iterator yields an integer on each iteration "
              ", but the loop expects %d",
              loop_ctx->vars_count);

          result = ERROR_SYNTAX_ERROR;
        }

        fail_if_error(result);
      }
#line 3882 "grammar.c"
    break;

  case 114: /* integer_set: '(' integer_enumeration ')'  */
#line 2112 "grammar.y"
      {
        // $2 contains the number of integers in the enumeration
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[-1].integer)));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_ENUM, NULL));
      }
#line 3894 "grammar.c"
    break;

  case 115: /* integer_set: range  */
#line 2120 "grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_RANGE, NULL));
      }
#line 3903 "grammar.c"
    break;

  case 116: /* range: '(' primary_expression ".." primary_expression ')'  */
#line 2129 "grammar.y"
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

        fail_if_error(result);
      }
#line 3927 "grammar.c"
    break;

  case 117: /* integer_enumeration: primary_expression  */
#line 2153 "grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        (yyval.integer) = 1;
      }
#line 3946 "grammar.c"
    break;

  case 118: /* integer_enumeration: integer_enumeration ',' primary_expression  */
#line 2168 "grammar.y"
      {
        int result = ERROR_SUCCESS;

        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        (yyval.integer) = (yyvsp[-2].integer) + 1;
      }
#line 3965 "grammar.c"
    break;

  case 119: /* $@11: %empty  */
#line 2187 "grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 3974 "grammar.c"
    break;

  case 121: /* string_set: "<them>"  */
#line 2193 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, YR_UNDEFINED));

        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*"));
      }
#line 3985 "grammar.c"
    break;

  case 124: /* string_enumeration_item: "string identifier"  */
#line 2210 "grammar.y"
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 3996 "grammar.c"
    break;

  case 125: /* string_enumeration_item: "string identifier with wildcard"  */
#line 2217 "grammar.y"
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 4007 "grammar.c"
    break;

  case 126: /* for_expression: primary_expression  */
#line 2228 "grammar.y"
      {
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 4015 "grammar.c"
    break;

  case 127: /* for_expression: "<all>"  */
#line 2232 "grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
        (yyval.integer) = FOR_EXPRESSION_ALL;
      }
#line 4024 "grammar.c"
    break;

  case 128: /* for_expression: "<any>"  */
#line 2237 "grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, 1);
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 4033 "grammar.c"
    break;

  case 129: /* primary_expression: '(' primary_expression ')'  */
#line 2246 "grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 4041 "grammar.c"
    break;

  case 130: /* primary_expression: "<filesize>"  */
#line 2250 "grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4053 "grammar.c"
    break;

  case 131: /* primary_expression: "<entrypoint>"  */
#line 2258 "grammar.y"
      {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4069 "grammar.c"
    break;

  case 132: /* primary_expression: "integer function" '(' primary_expression ')'  */
#line 2270 "grammar.y"
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
#line 4087 "grammar.c"
    break;

  case 133: /* primary_expression: "integer number"  */
#line 2284 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[0].integer)));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 4098 "grammar.c"
    break;

  case 134: /* primary_expression: "floating point number"  */
#line 2291 "grammar.y"
      {
        fail_if_error(yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 4109 "grammar.c"
    break;

  case 135: /* primary_expression: "text string"  */
#line 2298 "grammar.y"
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
#line 4138 "grammar.c"
    break;

  case 136: /* primary_expression: "string count"  */
#line 2323 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[0].c_string), OP_COUNT, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4154 "grammar.c"
    break;

  case 137: /* primary_expression: "string offset" '[' primary_expression ']'  */
#line 2335 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_OFFSET, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4170 "grammar.c"
    break;

  case 138: /* primary_expression: "string offset"  */
#line 2347 "grammar.y"
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
#line 4189 "grammar.c"
    break;

  case 139: /* primary_expression: "string length" '[' primary_expression ']'  */
#line 2362 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_LENGTH, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4205 "grammar.c"
    break;

  case 140: /* primary_expression: "string length"  */
#line 2374 "grammar.y"
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
#line 4224 "grammar.c"
    break;

  case 141: /* primary_expression: identifier  */
#line 2389 "grammar.y"
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
              (yyval.expression).value.integer = YR_UNDEFINED;
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
#line 4271 "grammar.c"
    break;

  case 142: /* primary_expression: '-' primary_expression  */
#line 2432 "grammar.y"
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
#line 4296 "grammar.c"
    break;

  case 143: /* primary_expression: primary_expression '+' primary_expression  */
#line 2453 "grammar.y"
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
#line 4335 "grammar.c"
    break;

  case 144: /* primary_expression: primary_expression '-' primary_expression  */
#line 2488 "grammar.y"
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
#line 4374 "grammar.c"
    break;

  case 145: /* primary_expression: primary_expression '*' primary_expression  */
#line 2523 "grammar.y"
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
#line 4412 "grammar.c"
    break;

  case 146: /* primary_expression: primary_expression '\\' primary_expression  */
#line 2557 "grammar.y"
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
#line 4441 "grammar.c"
    break;

  case 147: /* primary_expression: primary_expression '%' primary_expression  */
#line 2582 "grammar.y"
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
#line 4462 "grammar.c"
    break;

  case 148: /* primary_expression: primary_expression '^' primary_expression  */
#line 2599 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4476 "grammar.c"
    break;

  case 149: /* primary_expression: primary_expression '&' primary_expression  */
#line 2609 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4490 "grammar.c"
    break;

  case 150: /* primary_expression: primary_expression '|' primary_expression  */
#line 2619 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4504 "grammar.c"
    break;

  case 151: /* primary_expression: '~' primary_expression  */
#line 2629 "grammar.y"
      {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == YR_UNDEFINED) ?
            YR_UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 4518 "grammar.c"
    break;

  case 152: /* primary_expression: primary_expression "<<" primary_expression  */
#line 2639 "grammar.y"
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
#line 4542 "grammar.c"
    break;

  case 153: /* primary_expression: primary_expression ">>" primary_expression  */
#line 2659 "grammar.y"
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
#line 4566 "grammar.c"
    break;

  case 154: /* primary_expression: regexp  */
#line 2679 "grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 4574 "grammar.c"
    break;


#line 4578 "grammar.c"

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
      yyerror (yyscanner, compiler, YY_("syntax error"));
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
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, compiler, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
yyreturn:
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

  return yyresult;
}

#line 2684 "grammar.y"

