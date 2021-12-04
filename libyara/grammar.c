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

#define FOR_EXPRESSION_ALL  1
#define FOR_EXPRESSION_ANY  2
#define FOR_EXPRESSION_NONE 3

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


#line 186 "grammar.c"

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
    _IDENTIFIER_WITH_WILDCARD_ = 272, /* "identifier with wildcard"  */
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
    _NONE_ = 291,                  /* "<none>"  */
    _IN_ = 292,                    /* "<in>"  */
    _OF_ = 293,                    /* "<of>"  */
    _FOR_ = 294,                   /* "<for>"  */
    _THEM_ = 295,                  /* "<them>"  */
    _MATCHES_ = 296,               /* "<matches>"  */
    _CONTAINS_ = 297,              /* "<contains>"  */
    _STARTSWITH_ = 298,            /* "<startswith>"  */
    _ENDSWITH_ = 299,              /* "<endswith>"  */
    _ICONTAINS_ = 300,             /* "<icontains>"  */
    _ISTARTSWITH_ = 301,           /* "<istartswith>"  */
    _IENDSWITH_ = 302,             /* "<iendswith>"  */
    _IEQUALS_ = 303,               /* "<iequals>"  */
    _IMPORT_ = 304,                /* "<import>"  */
    _TRUE_ = 305,                  /* "<true>"  */
    _FALSE_ = 306,                 /* "<false>"  */
    _OR_ = 307,                    /* "<or>"  */
    _AND_ = 308,                   /* "<and>"  */
    _NOT_ = 309,                   /* "<not>"  */
    _DEFINED_ = 310,               /* "<defined>"  */
    _EQ_ = 311,                    /* "=="  */
    _NEQ_ = 312,                   /* "!="  */
    _LT_ = 313,                    /* "<"  */
    _LE_ = 314,                    /* "<="  */
    _GT_ = 315,                    /* ">"  */
    _GE_ = 316,                    /* ">="  */
    _SHIFT_LEFT_ = 317,            /* "<<"  */
    _SHIFT_RIGHT_ = 318,           /* ">>"  */
    UNARY_MINUS = 319              /* UNARY_MINUS  */
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
#define _IDENTIFIER_WITH_WILDCARD_ 272
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
#define _NONE_ 291
#define _IN_ 292
#define _OF_ 293
#define _FOR_ 294
#define _THEM_ 295
#define _MATCHES_ 296
#define _CONTAINS_ 297
#define _STARTSWITH_ 298
#define _ENDSWITH_ 299
#define _ICONTAINS_ 300
#define _ISTARTSWITH_ 301
#define _IENDSWITH_ 302
#define _IEQUALS_ 303
#define _IMPORT_ 304
#define _TRUE_ 305
#define _FALSE_ 306
#define _OR_ 307
#define _AND_ 308
#define _NOT_ 309
#define _DEFINED_ 310
#define _EQ_ 311
#define _NEQ_ 312
#define _LT_ 313
#define _LE_ 314
#define _GT_ 315
#define _GE_ 316
#define _SHIFT_LEFT_ 317
#define _SHIFT_RIGHT_ 318
#define UNARY_MINUS 319

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 310 "grammar.y"

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

#line 381 "grammar.c"

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
  YYSYMBOL__IDENTIFIER_WITH_WILDCARD_ = 17, /* "identifier with wildcard"  */
  YYSYMBOL__NUMBER_ = 18,                  /* "integer number"  */
  YYSYMBOL__DOUBLE_ = 19,                  /* "floating point number"  */
  YYSYMBOL__INTEGER_FUNCTION_ = 20,        /* "integer function"  */
  YYSYMBOL__TEXT_STRING_ = 21,             /* "text string"  */
  YYSYMBOL__HEX_STRING_ = 22,              /* "hex string"  */
  YYSYMBOL__REGEXP_ = 23,                  /* "regular expression"  */
  YYSYMBOL__ASCII_ = 24,                   /* "<ascii>"  */
  YYSYMBOL__WIDE_ = 25,                    /* "<wide>"  */
  YYSYMBOL__XOR_ = 26,                     /* "<xor>"  */
  YYSYMBOL__BASE64_ = 27,                  /* "<base64>"  */
  YYSYMBOL__BASE64_WIDE_ = 28,             /* "<base64wide>"  */
  YYSYMBOL__NOCASE_ = 29,                  /* "<nocase>"  */
  YYSYMBOL__FULLWORD_ = 30,                /* "<fullword>"  */
  YYSYMBOL__AT_ = 31,                      /* "<at>"  */
  YYSYMBOL__FILESIZE_ = 32,                /* "<filesize>"  */
  YYSYMBOL__ENTRYPOINT_ = 33,              /* "<entrypoint>"  */
  YYSYMBOL__ALL_ = 34,                     /* "<all>"  */
  YYSYMBOL__ANY_ = 35,                     /* "<any>"  */
  YYSYMBOL__NONE_ = 36,                    /* "<none>"  */
  YYSYMBOL__IN_ = 37,                      /* "<in>"  */
  YYSYMBOL__OF_ = 38,                      /* "<of>"  */
  YYSYMBOL__FOR_ = 39,                     /* "<for>"  */
  YYSYMBOL__THEM_ = 40,                    /* "<them>"  */
  YYSYMBOL__MATCHES_ = 41,                 /* "<matches>"  */
  YYSYMBOL__CONTAINS_ = 42,                /* "<contains>"  */
  YYSYMBOL__STARTSWITH_ = 43,              /* "<startswith>"  */
  YYSYMBOL__ENDSWITH_ = 44,                /* "<endswith>"  */
  YYSYMBOL__ICONTAINS_ = 45,               /* "<icontains>"  */
  YYSYMBOL__ISTARTSWITH_ = 46,             /* "<istartswith>"  */
  YYSYMBOL__IENDSWITH_ = 47,               /* "<iendswith>"  */
  YYSYMBOL__IEQUALS_ = 48,                 /* "<iequals>"  */
  YYSYMBOL__IMPORT_ = 49,                  /* "<import>"  */
  YYSYMBOL__TRUE_ = 50,                    /* "<true>"  */
  YYSYMBOL__FALSE_ = 51,                   /* "<false>"  */
  YYSYMBOL__OR_ = 52,                      /* "<or>"  */
  YYSYMBOL__AND_ = 53,                     /* "<and>"  */
  YYSYMBOL__NOT_ = 54,                     /* "<not>"  */
  YYSYMBOL__DEFINED_ = 55,                 /* "<defined>"  */
  YYSYMBOL__EQ_ = 56,                      /* "=="  */
  YYSYMBOL__NEQ_ = 57,                     /* "!="  */
  YYSYMBOL__LT_ = 58,                      /* "<"  */
  YYSYMBOL__LE_ = 59,                      /* "<="  */
  YYSYMBOL__GT_ = 60,                      /* ">"  */
  YYSYMBOL__GE_ = 61,                      /* ">="  */
  YYSYMBOL__SHIFT_LEFT_ = 62,              /* "<<"  */
  YYSYMBOL__SHIFT_RIGHT_ = 63,             /* ">>"  */
  YYSYMBOL_64_ = 64,                       /* '|'  */
  YYSYMBOL_65_ = 65,                       /* '^'  */
  YYSYMBOL_66_ = 66,                       /* '&'  */
  YYSYMBOL_67_ = 67,                       /* '+'  */
  YYSYMBOL_68_ = 68,                       /* '-'  */
  YYSYMBOL_69_ = 69,                       /* '*'  */
  YYSYMBOL_70_ = 70,                       /* '\\'  */
  YYSYMBOL_71_ = 71,                       /* '%'  */
  YYSYMBOL_72_ = 72,                       /* '~'  */
  YYSYMBOL_UNARY_MINUS = 73,               /* UNARY_MINUS  */
  YYSYMBOL_74_include_ = 74,               /* "include"  */
  YYSYMBOL_75_ = 75,                       /* '{'  */
  YYSYMBOL_76_ = 76,                       /* '}'  */
  YYSYMBOL_77_ = 77,                       /* ':'  */
  YYSYMBOL_78_ = 78,                       /* '='  */
  YYSYMBOL_79_ = 79,                       /* '('  */
  YYSYMBOL_80_ = 80,                       /* ')'  */
  YYSYMBOL_81_ = 81,                       /* '.'  */
  YYSYMBOL_82_ = 82,                       /* '['  */
  YYSYMBOL_83_ = 83,                       /* ']'  */
  YYSYMBOL_84_ = 84,                       /* ','  */
  YYSYMBOL_YYACCEPT = 85,                  /* $accept  */
  YYSYMBOL_rules = 86,                     /* rules  */
  YYSYMBOL_import = 87,                    /* import  */
  YYSYMBOL_rule = 88,                      /* rule  */
  YYSYMBOL_89_1 = 89,                      /* @1  */
  YYSYMBOL_90_2 = 90,                      /* $@2  */
  YYSYMBOL_meta = 91,                      /* meta  */
  YYSYMBOL_strings = 92,                   /* strings  */
  YYSYMBOL_condition = 93,                 /* condition  */
  YYSYMBOL_rule_modifiers = 94,            /* rule_modifiers  */
  YYSYMBOL_rule_modifier = 95,             /* rule_modifier  */
  YYSYMBOL_tags = 96,                      /* tags  */
  YYSYMBOL_tag_list = 97,                  /* tag_list  */
  YYSYMBOL_meta_declarations = 98,         /* meta_declarations  */
  YYSYMBOL_meta_declaration = 99,          /* meta_declaration  */
  YYSYMBOL_string_declarations = 100,      /* string_declarations  */
  YYSYMBOL_string_declaration = 101,       /* string_declaration  */
  YYSYMBOL_102_3 = 102,                    /* $@3  */
  YYSYMBOL_103_4 = 103,                    /* $@4  */
  YYSYMBOL_104_5 = 104,                    /* $@5  */
  YYSYMBOL_string_modifiers = 105,         /* string_modifiers  */
  YYSYMBOL_string_modifier = 106,          /* string_modifier  */
  YYSYMBOL_regexp_modifiers = 107,         /* regexp_modifiers  */
  YYSYMBOL_regexp_modifier = 108,          /* regexp_modifier  */
  YYSYMBOL_hex_modifiers = 109,            /* hex_modifiers  */
  YYSYMBOL_hex_modifier = 110,             /* hex_modifier  */
  YYSYMBOL_identifier = 111,               /* identifier  */
  YYSYMBOL_arguments = 112,                /* arguments  */
  YYSYMBOL_arguments_list = 113,           /* arguments_list  */
  YYSYMBOL_regexp = 114,                   /* regexp  */
  YYSYMBOL_boolean_expression = 115,       /* boolean_expression  */
  YYSYMBOL_expression = 116,               /* expression  */
  YYSYMBOL_117_6 = 117,                    /* $@6  */
  YYSYMBOL_118_7 = 118,                    /* $@7  */
  YYSYMBOL_119_8 = 119,                    /* $@8  */
  YYSYMBOL_120_9 = 120,                    /* $@9  */
  YYSYMBOL_121_10 = 121,                   /* $@10  */
  YYSYMBOL_for_variables = 122,            /* for_variables  */
  YYSYMBOL_iterator = 123,                 /* iterator  */
  YYSYMBOL_integer_set = 124,              /* integer_set  */
  YYSYMBOL_range = 125,                    /* range  */
  YYSYMBOL_integer_enumeration = 126,      /* integer_enumeration  */
  YYSYMBOL_string_set = 127,               /* string_set  */
  YYSYMBOL_128_11 = 128,                   /* $@11  */
  YYSYMBOL_string_enumeration = 129,       /* string_enumeration  */
  YYSYMBOL_string_enumeration_item = 130,  /* string_enumeration_item  */
  YYSYMBOL_rule_set = 131,                 /* rule_set  */
  YYSYMBOL_132_12 = 132,                   /* $@12  */
  YYSYMBOL_rule_enumeration = 133,         /* rule_enumeration  */
  YYSYMBOL_rule_enumeration_item = 134,    /* rule_enumeration_item  */
  YYSYMBOL_for_expression = 135,           /* for_expression  */
  YYSYMBOL_primary_expression = 136        /* primary_expression  */
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
#define YYLAST   470

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  85
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  52
/* YYNRULES -- Number of rules.  */
#define YYNRULES  165
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  275

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   320


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
       2,     2,     2,     2,     2,     2,     2,    71,    66,     2,
      79,    80,    69,    67,    84,    68,    81,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    77,     2,
       2,    78,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    82,    70,    83,    65,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    75,    64,    76,    72,     2,     2,     2,
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
      55,    56,    57,    58,    59,    60,    61,    62,    63,    73,
      74
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   328,   328,   329,   330,   331,   332,   333,   334,   342,
     355,   360,   354,   387,   390,   406,   409,   424,   429,   430,
     435,   436,   442,   445,   461,   470,   512,   513,   518,   535,
     549,   563,   577,   595,   596,   602,   601,   618,   617,   638,
     637,   662,   668,   728,   729,   730,   731,   732,   733,   739,
     760,   791,   796,   813,   818,   838,   839,   853,   854,   855,
     856,   857,   861,   862,   876,   880,   975,  1023,  1084,  1131,
    1132,  1136,  1171,  1224,  1266,  1289,  1295,  1301,  1313,  1323,
    1333,  1343,  1353,  1363,  1373,  1383,  1397,  1412,  1423,  1500,
    1538,  1440,  1697,  1696,  1786,  1792,  1798,  1818,  1838,  1844,
    1850,  1856,  1855,  1901,  1900,  1944,  1951,  1958,  1965,  1972,
    1979,  1986,  1990,  1998,  2018,  2046,  2120,  2148,  2156,  2165,
    2189,  2204,  2224,  2223,  2229,  2240,  2241,  2246,  2253,  2265,
    2264,  2274,  2275,  2280,  2311,  2363,  2367,  2372,  2377,  2386,
    2390,  2398,  2410,  2424,  2431,  2438,  2463,  2475,  2487,  2499,
    2514,  2526,  2541,  2584,  2605,  2640,  2675,  2709,  2734,  2751,
    2761,  2771,  2781,  2791,  2811,  2831
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
  "\"string identifier with wildcard\"", "\"identifier with wildcard\"",
  "\"integer number\"", "\"floating point number\"",
  "\"integer function\"", "\"text string\"", "\"hex string\"",
  "\"regular expression\"", "\"<ascii>\"", "\"<wide>\"", "\"<xor>\"",
  "\"<base64>\"", "\"<base64wide>\"", "\"<nocase>\"", "\"<fullword>\"",
  "\"<at>\"", "\"<filesize>\"", "\"<entrypoint>\"", "\"<all>\"",
  "\"<any>\"", "\"<none>\"", "\"<in>\"", "\"<of>\"", "\"<for>\"",
  "\"<them>\"", "\"<matches>\"", "\"<contains>\"", "\"<startswith>\"",
  "\"<endswith>\"", "\"<icontains>\"", "\"<istartswith>\"",
  "\"<iendswith>\"", "\"<iequals>\"", "\"<import>\"", "\"<true>\"",
  "\"<false>\"", "\"<or>\"", "\"<and>\"", "\"<not>\"", "\"<defined>\"",
  "\"==\"", "\"!=\"", "\"<\"", "\"<=\"", "\">\"", "\">=\"", "\"<<\"",
  "\">>\"", "'|'", "'^'", "'&'", "'+'", "'-'", "'*'", "'\\\\'", "'%'",
  "'~'", "UNARY_MINUS", "\"include\"", "'{'", "'}'", "':'", "'='", "'('",
  "')'", "'.'", "'['", "']'", "','", "$accept", "rules", "import", "rule",
  "@1", "$@2", "meta", "strings", "condition", "rule_modifiers",
  "rule_modifier", "tags", "tag_list", "meta_declarations",
  "meta_declaration", "string_declarations", "string_declaration", "$@3",
  "$@4", "$@5", "string_modifiers", "string_modifier", "regexp_modifiers",
  "regexp_modifier", "hex_modifiers", "hex_modifier", "identifier",
  "arguments", "arguments_list", "regexp", "boolean_expression",
  "expression", "$@6", "$@7", "$@8", "$@9", "$@10", "for_variables",
  "iterator", "integer_set", "range", "integer_enumeration", "string_set",
  "$@11", "string_enumeration", "string_enumeration_item", "rule_set",
  "$@12", "rule_enumeration", "rule_enumeration_item", "for_expression",
  "primary_expression", YY_NULLPTR
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
     315,   316,   317,   318,   124,    94,    38,    43,    45,    42,
      92,    37,   126,   319,   320,   123,   125,    58,    61,    40,
      41,    46,    91,    93,    44
};
#endif

#define YYPACT_NINF (-89)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-136)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -89,    37,   -89,   -40,   -89,   -16,   -89,   -89,   193,   -89,
     -89,   -89,   -89,    -4,   -89,   -89,   -89,   -89,   -58,    20,
       2,   -89,    76,    93,   -89,    26,   111,   130,    73,   -89,
      75,   130,   -89,   139,   144,    84,   -89,    79,   139,   -89,
      78,    82,   -89,   -89,   -89,   -89,   146,   114,   -89,    77,
     -89,   -89,   156,   142,   164,   -89,   -21,   153,    96,   109,
     -89,   -89,   117,   -89,   -89,   -89,   -89,   -89,   -89,   -89,
     148,   -89,   -89,    77,    77,   174,   174,    77,   -46,   -89,
      91,   -89,   163,   253,   -89,   -89,   -89,   174,   123,   123,
     174,   174,   174,   174,     7,   369,   -89,   -89,   -89,   -89,
      91,   124,   213,    77,   194,   174,   -89,   -89,    -8,   185,
     174,   174,   174,   174,   174,   174,   174,   174,   174,   174,
     174,   174,   174,   174,   174,   174,   174,   174,   174,   174,
     174,   174,    61,   238,   301,   207,   369,   174,   -89,   -89,
     270,   280,   312,   331,   -89,    -1,   203,   174,   -89,   -89,
     135,   133,    95,   -89,   302,    77,    77,   -89,     3,   181,
     -89,   -89,   369,   369,   369,   369,   369,   369,   369,   369,
     369,   369,   369,   369,   369,   105,   105,   379,   389,   399,
     141,   141,   -89,   -89,    -8,   -89,   -89,   -89,   -89,   140,
     143,   145,   -89,   -89,   -89,   -89,   -89,   -89,   -89,   -89,
     -89,   -89,   -89,   166,   -89,   -89,   -89,   -89,   149,   -89,
     -15,   -89,    77,   -89,   168,   -89,     5,   106,   123,   -89,
     -89,   220,   204,   218,   174,   -89,    -9,   229,    95,   -89,
     -89,    24,   -89,   -89,   -89,    41,   -89,   -89,   -65,   161,
     165,   350,   169,   174,   -46,   170,   -89,   -89,   -89,   -89,
       5,   -89,   106,   225,   -89,   -89,   -89,   -89,    77,    42,
     166,   -89,   -89,   -89,   172,    62,   -89,   174,   171,   -89,
     -89,   369,    77,    66,   -89
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
      12,    30,     0,     0,     0,    65,    85,   147,   149,   151,
     143,   144,     0,   145,    73,   140,   141,   136,   137,   138,
       0,    75,    76,     0,     0,     0,     0,     0,   152,   165,
      17,    74,     0,   111,    41,    55,    62,     0,     0,     0,
       0,     0,     0,     0,     0,   135,    99,   100,   153,   162,
       0,    74,   111,    69,     0,     0,   103,   101,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    36,    38,    40,    86,     0,    87,   146,
       0,     0,     0,     0,    88,     0,     0,     0,   112,   139,
       0,    70,    71,    66,     0,     0,     0,   124,   122,    94,
      95,    77,    78,    80,    82,    79,    81,    83,    84,   109,
     110,   105,   107,   106,   108,   163,   164,   161,   159,   160,
     154,   155,   156,   157,     0,   158,    47,    44,    43,    48,
      51,    53,    45,    46,    42,    61,    58,    57,    59,    60,
      56,    64,    63,     0,   148,   150,   142,   122,     0,   113,
       0,    68,     0,    67,   104,   102,     0,     0,     0,    96,
      97,     0,     0,     0,     0,    92,     0,     0,    72,   127,
     128,     0,   125,   133,   134,     0,   131,    98,     0,     0,
       0,     0,     0,     0,   115,     0,   116,   118,   114,   123,
       0,   130,     0,     0,    49,    52,    54,   119,     0,     0,
     120,    90,   126,   132,     0,     0,   117,     0,     0,    50,
      93,   121,     0,     0,    91
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -89,   -89,   246,   282,   -89,   -89,   -89,   -89,   -89,   -89,
     -89,   -89,   -89,   -89,   255,   -89,   249,   -89,   -89,   -89,
     -89,   -89,   -89,   -89,   -89,   -89,    63,   -89,   -89,   179,
     -49,   -73,   -89,   -89,   -89,   -89,   -89,   -89,   -89,   -89,
     -88,   -89,   -60,   -89,   -89,    40,   108,   -89,   -89,    50,
     233,   -64
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     1,     6,     7,    18,    34,    26,    29,    41,     8,
      16,    20,    22,    31,    32,    38,    39,    52,    53,    54,
     133,   194,   134,   200,   135,   202,    78,   150,   151,    79,
     100,    81,   146,   268,   242,   156,   155,   210,   245,   246,
     138,   259,   159,   216,   231,   232,   160,   217,   235,   236,
      82,    83
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      80,   139,    55,   253,   101,    12,    95,    17,   144,     5,
      87,    98,    99,   102,  -129,   254,    88,   229,   -89,    19,
    -129,   230,   226,   136,    96,    97,   140,   141,   142,   143,
     152,    21,   157,   103,     9,   104,   105,     2,     3,   157,
       4,   154,   -18,   -18,   -18,   145,   162,   163,   164,   165,
     166,   167,   168,   169,   170,   171,   172,   173,   174,   175,
     176,   177,   178,   179,   180,   181,   182,   183,   185,   227,
     243,   158,    55,   203,    57,    58,    59,    23,   207,    60,
      61,    62,    63,   185,    64,   208,     5,    24,    55,    56,
      57,    58,    59,    65,    66,    60,    61,    62,    63,   184,
      64,    25,    42,    27,   249,    43,   214,   215,   250,    65,
      66,    67,    68,    69,   106,   107,    70,   233,   106,   107,
      28,   251,   266,   234,   219,   252,   267,    71,    72,    75,
     237,    73,    74,    76,    44,    45,   -39,   -37,   247,   228,
      93,    30,   270,   106,   107,    75,   274,   -74,   -74,    76,
      33,    37,    46,    35,    40,    49,    77,    47,    50,    55,
     241,    57,    58,    59,    51,    85,    60,    61,    62,    63,
     224,    64,   128,   129,   130,   131,   147,    84,    90,   260,
      65,    66,    67,    68,    69,    55,    86,    57,    58,    59,
      89,    91,    60,    61,    62,    63,    92,    64,    13,    14,
      15,   108,   137,   271,   148,   153,    65,    66,    64,   265,
     130,   131,   147,   201,   209,   211,    75,   212,   218,   221,
      76,   107,   222,   273,   223,   239,   225,    93,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   147,   238,   240,
     248,   255,    75,   264,   186,   256,    76,   261,   258,    10,
     272,  -135,   269,    93,   109,   110,   111,   112,   113,   114,
     115,   116,   187,   188,   189,   190,   191,   192,   193,   117,
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,    11,    36,    48,   161,   244,
     262,  -135,   220,   149,   109,   110,   111,   112,   113,   114,
     115,   116,   263,    94,     0,     0,     0,   195,     0,   117,
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   196,   197,     0,     0,     0,
     198,   199,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   147,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   147,     0,   204,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   205,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   147,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   147,     0,   213,     0,     0,     0,     0,
       0,     0,   206,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   147,     0,     0,     0,     0,     0,     0,     0,
       0,   149,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   147,     0,     0,     0,     0,     0,     0,     0,     0,
     257,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     147,   123,   124,     0,   126,   127,   128,   129,   130,   131,
     147,   123,   124,     0,     0,   127,   128,   129,   130,   131,
     147,   123,   124,     0,     0,     0,   128,   129,   130,   131,
     147
};

static const yytype_int16 yycheck[] =
{
      49,    89,    11,    68,    77,    21,    70,    11,     1,    49,
      31,    75,    76,    77,    11,    80,    37,    12,    11,    77,
      17,    16,    37,    87,    73,    74,    90,    91,    92,    93,
     103,    11,    40,    79,    74,    81,    82,     0,     1,    40,
       3,   105,     5,     6,     7,    38,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   120,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,    84,
      79,    79,    11,   137,    13,    14,    15,    75,    79,    18,
      19,    20,    21,   147,    23,   145,    49,    11,    11,    12,
      13,    14,    15,    32,    33,    18,    19,    20,    21,    38,
      23,     8,    18,    77,    80,    21,   155,   156,    84,    32,
      33,    34,    35,    36,    52,    53,    39,    11,    52,    53,
       9,    80,    80,    17,   184,    84,    84,    50,    51,    68,
     218,    54,    55,    72,    50,    51,    22,    23,   226,   212,
      79,    11,    80,    52,    53,    68,    80,    52,    53,    72,
      77,    12,    68,    78,    10,    77,    79,    78,    76,    11,
     224,    13,    14,    15,    18,    23,    18,    19,    20,    21,
       4,    23,    67,    68,    69,    70,    71,    21,    82,   243,
      32,    33,    34,    35,    36,    11,    22,    13,    14,    15,
      37,    82,    18,    19,    20,    21,    79,    23,     5,     6,
       7,    38,    79,   267,    80,    11,    32,    33,    23,   258,
      69,    70,    71,     6,    11,    80,    68,    84,    37,    79,
      72,    53,    79,   272,    79,    21,    77,    79,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    18,    21,
      11,    80,    68,    18,     6,    80,    72,    77,    79,     3,
      79,    38,    80,    79,    41,    42,    43,    44,    45,    46,
      47,    48,    24,    25,    26,    27,    28,    29,    30,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,     3,    31,    38,   109,   226,
     250,    38,   184,    80,    41,    42,    43,    44,    45,    46,
      47,    48,   252,    70,    -1,    -1,    -1,     6,    -1,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    24,    25,    -1,    -1,    -1,
      29,    30,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    -1,    83,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    83,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    -1,    83,    -1,    -1,    -1,    -1,
      -1,    -1,    80,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    80,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      80,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    62,    63,    -1,    65,    66,    67,    68,    69,    70,
      71,    62,    63,    -1,    -1,    66,    67,    68,    69,    70,
      71,    62,    63,    -1,    -1,    -1,    67,    68,    69,    70,
      71
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    86,     0,     1,     3,    49,    87,    88,    94,    74,
      87,    88,    21,     5,     6,     7,    95,    11,    89,    77,
      96,    11,    97,    75,    11,     8,    91,    77,     9,    92,
      11,    98,    99,    77,    90,    78,    99,    12,   100,   101,
      10,    93,    18,    21,    50,    51,    68,    78,   101,    77,
      76,    18,   102,   103,   104,    11,    12,    13,    14,    15,
      18,    19,    20,    21,    23,    32,    33,    34,    35,    36,
      39,    50,    51,    54,    55,    68,    72,    79,   111,   114,
     115,   116,   135,   136,    21,    23,    22,    31,    37,    37,
      82,    82,    79,    79,   135,   136,   115,   115,   136,   136,
     115,   116,   136,    79,    81,    82,    52,    53,    38,    41,
      42,    43,    44,    45,    46,    47,    48,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,   105,   107,   109,   136,    79,   125,   125,
     136,   136,   136,   136,     1,    38,   117,    71,    80,    80,
     112,   113,   116,    11,   136,   121,   120,    40,    79,   127,
     131,   114,   136,   136,   136,   136,   136,   136,   136,   136,
     136,   136,   136,   136,   136,   136,   136,   136,   136,   136,
     136,   136,   136,   136,    38,   136,     6,    24,    25,    26,
      27,    28,    29,    30,   106,     6,    24,    25,    29,    30,
     108,     6,   110,   136,    83,    83,    80,    79,   127,    11,
     122,    80,    84,    83,   115,   115,   128,   132,    37,   127,
     131,    79,    79,    79,     4,    77,    37,    84,   116,    12,
      16,   129,   130,    11,    17,   133,   134,   125,    18,    21,
      21,   136,   119,    79,   111,   123,   124,   125,    11,    80,
      84,    80,    84,    68,    80,    80,    80,    80,    79,   126,
     136,    77,   130,   134,    18,   115,    80,    84,   118,    80,
      80,   136,    79,   115,    80
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    85,    86,    86,    86,    86,    86,    86,    86,    87,
      89,    90,    88,    91,    91,    92,    92,    93,    94,    94,
      95,    95,    96,    96,    97,    97,    98,    98,    99,    99,
      99,    99,    99,   100,   100,   102,   101,   103,   101,   104,
     101,   105,   105,   106,   106,   106,   106,   106,   106,   106,
     106,   106,   106,   106,   106,   107,   107,   108,   108,   108,
     108,   108,   109,   109,   110,   111,   111,   111,   111,   112,
     112,   113,   113,   114,   115,   116,   116,   116,   116,   116,
     116,   116,   116,   116,   116,   116,   116,   116,   116,   117,
     118,   116,   119,   116,   116,   116,   116,   116,   116,   116,
     116,   120,   116,   121,   116,   116,   116,   116,   116,   116,
     116,   116,   116,   122,   122,   123,   123,   124,   124,   125,
     126,   126,   128,   127,   127,   129,   129,   130,   130,   132,
     131,   133,   133,   134,   134,   135,   135,   135,   135,   136,
     136,   136,   136,   136,   136,   136,   136,   136,   136,   136,
     136,   136,   136,   136,   136,   136,   136,   136,   136,   136,
     136,   136,   136,   136,   136,   136
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
       0,    11,     0,     9,     3,     3,     4,     4,     5,     2,
       2,     0,     4,     0,     4,     3,     3,     3,     3,     3,
       3,     1,     3,     1,     3,     1,     1,     3,     1,     5,
       1,     3,     0,     4,     1,     1,     3,     1,     1,     0,
       4,     1,     3,     1,     1,     1,     1,     1,     1,     3,
       1,     1,     4,     1,     1,     1,     3,     1,     4,     1,
       4,     1,     1,     2,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     3,     3,     1
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
#line 279 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1509 "grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_: /* "string identifier"  */
#line 283 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1515 "grammar.c"
        break;

    case YYSYMBOL__STRING_COUNT_: /* "string count"  */
#line 280 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1521 "grammar.c"
        break;

    case YYSYMBOL__STRING_OFFSET_: /* "string offset"  */
#line 281 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1527 "grammar.c"
        break;

    case YYSYMBOL__STRING_LENGTH_: /* "string length"  */
#line 282 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1533 "grammar.c"
        break;

    case YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_: /* "string identifier with wildcard"  */
#line 284 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1539 "grammar.c"
        break;

    case YYSYMBOL__IDENTIFIER_WITH_WILDCARD_: /* "identifier with wildcard"  */
#line 285 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1545 "grammar.c"
        break;

    case YYSYMBOL__TEXT_STRING_: /* "text string"  */
#line 286 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1551 "grammar.c"
        break;

    case YYSYMBOL__HEX_STRING_: /* "hex string"  */
#line 287 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1557 "grammar.c"
        break;

    case YYSYMBOL__REGEXP_: /* "regular expression"  */
#line 288 "grammar.y"
            { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1563 "grammar.c"
        break;

    case YYSYMBOL_string_modifiers: /* string_modifiers  */
#line 301 "grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1575 "grammar.c"
        break;

    case YYSYMBOL_string_modifier: /* string_modifier  */
#line 293 "grammar.y"
            {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1587 "grammar.c"
        break;

    case YYSYMBOL_arguments: /* arguments  */
#line 290 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1593 "grammar.c"
        break;

    case YYSYMBOL_arguments_list: /* arguments_list  */
#line 291 "grammar.y"
            { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1599 "grammar.c"
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
#line 335 "grammar.y"
      {
        _yr_compiler_pop_file_name(compiler);
      }
#line 1875 "grammar.c"
    break;

  case 9: /* import: "<import>" "text string"  */
#line 343 "grammar.y"
      {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        fail_if_error(result);
      }
#line 1887 "grammar.c"
    break;

  case 10: /* @1: %empty  */
#line 355 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[-2].integer), (yyvsp[0].c_string), &(yyval.rule)));
      }
#line 1896 "grammar.c"
    break;

  case 11: /* $@2: %empty  */
#line 360 "grammar.y"
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
#line 1914 "grammar.c"
    break;

  case 12: /* rule: rule_modifiers "<rule>" "identifier" @1 tags '{' meta strings $@2 condition '}'  */
#line 374 "grammar.y"
      {
        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, &(yyvsp[-7].rule)); // rule created in phase 1

        yr_free((yyvsp[-8].c_string));

        fail_if_error(result);
      }
#line 1927 "grammar.c"
    break;

  case 13: /* meta: %empty  */
#line 387 "grammar.y"
      {
        (yyval.meta) = YR_ARENA_NULL_REF;
      }
#line 1935 "grammar.c"
    break;

  case 14: /* meta: "<meta>" ':' meta_declarations  */
#line 391 "grammar.y"
      {
        YR_META* meta = yr_arena_get_ptr(
            compiler->arena,
            YR_METAS_TABLE,
            (compiler->current_meta_idx - 1) * sizeof(YR_META));

        meta->flags |= META_FLAGS_LAST_IN_RULE;

        (yyval.meta) = (yyvsp[0].meta);
      }
#line 1950 "grammar.c"
    break;

  case 15: /* strings: %empty  */
#line 406 "grammar.y"
      {
        (yyval.string) = YR_ARENA_NULL_REF;
      }
#line 1958 "grammar.c"
    break;

  case 16: /* strings: "<strings>" ':' string_declarations  */
#line 410 "grammar.y"
      {
        YR_STRING* string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            (compiler->current_string_idx - 1) * sizeof(YR_STRING));

        string->flags |= STRING_FLAGS_LAST_IN_RULE;

        (yyval.string) = (yyvsp[0].string);
      }
#line 1973 "grammar.c"
    break;

  case 18: /* rule_modifiers: %empty  */
#line 429 "grammar.y"
                                       { (yyval.integer) = 0;  }
#line 1979 "grammar.c"
    break;

  case 19: /* rule_modifiers: rule_modifiers rule_modifier  */
#line 430 "grammar.y"
                                       { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1985 "grammar.c"
    break;

  case 20: /* rule_modifier: "<private>"  */
#line 435 "grammar.y"
                     { (yyval.integer) = RULE_FLAGS_PRIVATE; }
#line 1991 "grammar.c"
    break;

  case 21: /* rule_modifier: "<global>"  */
#line 436 "grammar.y"
                     { (yyval.integer) = RULE_FLAGS_GLOBAL; }
#line 1997 "grammar.c"
    break;

  case 22: /* tags: %empty  */
#line 442 "grammar.y"
      {
        (yyval.tag) = YR_ARENA_NULL_REF;
      }
#line 2005 "grammar.c"
    break;

  case 23: /* tags: ':' tag_list  */
#line 446 "grammar.y"
      {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        fail_if_error(yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, "", NULL));

        (yyval.tag) = (yyvsp[0].tag);
      }
#line 2021 "grammar.c"
    break;

  case 24: /* tag_list: "identifier"  */
#line 462 "grammar.y"
      {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, (yyvsp[0].c_string), &(yyval.tag));

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 2034 "grammar.c"
    break;

  case 25: /* tag_list: tag_list "identifier"  */
#line 471 "grammar.y"
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
#line 2075 "grammar.c"
    break;

  case 26: /* meta_declarations: meta_declaration  */
#line 512 "grammar.y"
                                          {  (yyval.meta) = (yyvsp[0].meta); }
#line 2081 "grammar.c"
    break;

  case 27: /* meta_declarations: meta_declarations meta_declaration  */
#line 513 "grammar.y"
                                          {  (yyval.meta) = (yyvsp[-1].meta); }
#line 2087 "grammar.c"
    break;

  case 28: /* meta_declaration: "identifier" '=' "text string"  */
#line 519 "grammar.y"
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
#line 2108 "grammar.c"
    break;

  case 29: /* meta_declaration: "identifier" '=' "integer number"  */
#line 536 "grammar.y"
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
#line 2126 "grammar.c"
    break;

  case 30: /* meta_declaration: "identifier" '=' '-' "integer number"  */
#line 550 "grammar.y"
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
#line 2144 "grammar.c"
    break;

  case 31: /* meta_declaration: "identifier" '=' "<true>"  */
#line 564 "grammar.y"
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
#line 2162 "grammar.c"
    break;

  case 32: /* meta_declaration: "identifier" '=' "<false>"  */
#line 578 "grammar.y"
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
#line 2180 "grammar.c"
    break;

  case 33: /* string_declarations: string_declaration  */
#line 595 "grammar.y"
                                              { (yyval.string) = (yyvsp[0].string); }
#line 2186 "grammar.c"
    break;

  case 34: /* string_declarations: string_declarations string_declaration  */
#line 596 "grammar.y"
                                              { (yyval.string) = (yyvsp[-1].string); }
#line 2192 "grammar.c"
    break;

  case 35: /* $@3: %empty  */
#line 602 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2200 "grammar.c"
    break;

  case 36: /* string_declaration: "string identifier" '=' $@3 "text string" string_modifiers  */
#line 606 "grammar.y"
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));
        yr_free((yyvsp[0].modifier).alphabet);

        fail_if_error(result);
        compiler->current_line = 0;
      }
#line 2216 "grammar.c"
    break;

  case 37: /* $@4: %empty  */
#line 618 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2224 "grammar.c"
    break;

  case 38: /* string_declaration: "string identifier" '=' $@4 "regular expression" regexp_modifiers  */
#line 622 "grammar.y"
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
#line 2244 "grammar.c"
    break;

  case 39: /* $@5: %empty  */
#line 638 "grammar.y"
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2252 "grammar.c"
    break;

  case 40: /* string_declaration: "string identifier" '=' $@5 "hex string" hex_modifiers  */
#line 642 "grammar.y"
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
#line 2272 "grammar.c"
    break;

  case 41: /* string_modifiers: %empty  */
#line 662 "grammar.y"
      {
        (yyval.modifier).flags = 0;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 0;
        (yyval.modifier).alphabet = NULL;
      }
#line 2283 "grammar.c"
    break;

  case 42: /* string_modifiers: string_modifiers string_modifier  */
#line 669 "grammar.y"
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
#line 2343 "grammar.c"
    break;

  case 43: /* string_modifier: "<wide>"  */
#line 728 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2349 "grammar.c"
    break;

  case 44: /* string_modifier: "<ascii>"  */
#line 729 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2355 "grammar.c"
    break;

  case 45: /* string_modifier: "<nocase>"  */
#line 730 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2361 "grammar.c"
    break;

  case 46: /* string_modifier: "<fullword>"  */
#line 731 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2367 "grammar.c"
    break;

  case 47: /* string_modifier: "<private>"  */
#line 732 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2373 "grammar.c"
    break;

  case 48: /* string_modifier: "<xor>"  */
#line 734 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 255;
      }
#line 2383 "grammar.c"
    break;

  case 49: /* string_modifier: "<xor>" '(' "integer number" ')'  */
#line 740 "grammar.y"
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
#line 2403 "grammar.c"
    break;

  case 50: /* string_modifier: "<xor>" '(' "integer number" '-' "integer number" ')'  */
#line 761 "grammar.y"
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
#line 2438 "grammar.c"
    break;

  case 51: /* string_modifier: "<base64>"  */
#line 792 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2447 "grammar.c"
    break;

  case 52: /* string_modifier: "<base64>" '(' "text string" ')'  */
#line 797 "grammar.y"
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
#line 2468 "grammar.c"
    break;

  case 53: /* string_modifier: "<base64wide>"  */
#line 814 "grammar.y"
      {
        (yyval.modifier).flags = STRING_FLAGS_BASE64_WIDE;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2477 "grammar.c"
    break;

  case 54: /* string_modifier: "<base64wide>" '(' "text string" ')'  */
#line 819 "grammar.y"
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
#line 2498 "grammar.c"
    break;

  case 55: /* regexp_modifiers: %empty  */
#line 838 "grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2504 "grammar.c"
    break;

  case 56: /* regexp_modifiers: regexp_modifiers regexp_modifier  */
#line 840 "grammar.y"
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
#line 2519 "grammar.c"
    break;

  case 57: /* regexp_modifier: "<wide>"  */
#line 853 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2525 "grammar.c"
    break;

  case 58: /* regexp_modifier: "<ascii>"  */
#line 854 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2531 "grammar.c"
    break;

  case 59: /* regexp_modifier: "<nocase>"  */
#line 855 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2537 "grammar.c"
    break;

  case 60: /* regexp_modifier: "<fullword>"  */
#line 856 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2543 "grammar.c"
    break;

  case 61: /* regexp_modifier: "<private>"  */
#line 857 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2549 "grammar.c"
    break;

  case 62: /* hex_modifiers: %empty  */
#line 861 "grammar.y"
                                          { (yyval.modifier).flags = 0; }
#line 2555 "grammar.c"
    break;

  case 63: /* hex_modifiers: hex_modifiers hex_modifier  */
#line 863 "grammar.y"
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
#line 2570 "grammar.c"
    break;

  case 64: /* hex_modifier: "<private>"  */
#line 876 "grammar.y"
                    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2576 "grammar.c"
    break;

  case 65: /* identifier: "identifier"  */
#line 881 "grammar.y"
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
#line 2675 "grammar.c"
    break;

  case 66: /* identifier: identifier '.' "identifier"  */
#line 976 "grammar.y"
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
#line 2727 "grammar.c"
    break;

  case 67: /* identifier: identifier '[' primary_expression ']'  */
#line 1024 "grammar.y"
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
#line 2791 "grammar.c"
    break;

  case 68: /* identifier: identifier '(' arguments ')'  */
#line 1085 "grammar.y"
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
#line 2838 "grammar.c"
    break;

  case 69: /* arguments: %empty  */
#line 1131 "grammar.y"
                      { (yyval.c_string) = yr_strdup(""); }
#line 2844 "grammar.c"
    break;

  case 70: /* arguments: arguments_list  */
#line 1132 "grammar.y"
                      { (yyval.c_string) = (yyvsp[0].c_string); }
#line 2850 "grammar.c"
    break;

  case 71: /* arguments_list: expression  */
#line 1137 "grammar.y"
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
#line 2889 "grammar.c"
    break;

  case 72: /* arguments_list: arguments_list ',' expression  */
#line 1172 "grammar.y"
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
#line 2942 "grammar.c"
    break;

  case 73: /* regexp: "regular expression"  */
#line 1225 "grammar.y"
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
#line 2984 "grammar.c"
    break;

  case 74: /* boolean_expression: expression  */
#line 1267 "grammar.y"
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
#line 3008 "grammar.c"
    break;

  case 75: /* expression: "<true>"  */
#line 1290 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 1));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3018 "grammar.c"
    break;

  case 76: /* expression: "<false>"  */
#line 1296 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 0));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3028 "grammar.c"
    break;

  case 77: /* expression: primary_expression "<matches>" regexp  */
#line 1302 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        fail_if_error(yr_parser_emit(
            yyscanner,
            OP_MATCHES,
            NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3044 "grammar.c"
    break;

  case 78: /* expression: primary_expression "<contains>" primary_expression  */
#line 1314 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3058 "grammar.c"
    break;

  case 79: /* expression: primary_expression "<icontains>" primary_expression  */
#line 1324 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "icontains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "icontains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ICONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3072 "grammar.c"
    break;

  case 80: /* expression: primary_expression "<startswith>" primary_expression  */
#line 1334 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "startswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "startswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_STARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3086 "grammar.c"
    break;

  case 81: /* expression: primary_expression "<istartswith>" primary_expression  */
#line 1344 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "istartswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "istartswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ISTARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3100 "grammar.c"
    break;

  case 82: /* expression: primary_expression "<endswith>" primary_expression  */
#line 1354 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "endswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "endswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3114 "grammar.c"
    break;

  case 83: /* expression: primary_expression "<iendswith>" primary_expression  */
#line 1364 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iendswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iendswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3128 "grammar.c"
    break;

  case 84: /* expression: primary_expression "<iequals>" primary_expression  */
#line 1374 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iequals");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iequals");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IEQUALS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3142 "grammar.c"
    break;

  case 85: /* expression: "string identifier"  */
#line 1384 "grammar.y"
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
#line 3160 "grammar.c"
    break;

  case 86: /* expression: "string identifier" "<at>" primary_expression  */
#line 1398 "grammar.y"
      {
        int result;

        check_type_with_cleanup((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at", yr_free((yyvsp[-2].c_string)));

        result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_AT, (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3179 "grammar.c"
    break;

  case 87: /* expression: "string identifier" "<in>" range  */
#line 1413 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3194 "grammar.c"
    break;

  case 88: /* expression: "<for>" for_expression error  */
#line 1424 "grammar.y"
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
#line 3215 "grammar.c"
    break;

  case 89: /* $@6: %empty  */
#line 1500 "grammar.y"
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
#line 3257 "grammar.c"
    break;

  case 90: /* $@7: %empty  */
#line 1538 "grammar.y"
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
#line 3310 "grammar.c"
    break;

  case 91: /* expression: "<for>" for_expression $@6 for_variables "<in>" iterator ':' $@7 '(' boolean_expression ')'  */
#line 1587 "grammar.y"
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
#line 3424 "grammar.c"
    break;

  case 92: /* $@8: %empty  */
#line 1697 "grammar.y"
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
#line 3463 "grammar.c"
    break;

  case 93: /* expression: "<for>" for_expression "<of>" string_set ':' $@8 '(' boolean_expression ')'  */
#line 1732 "grammar.y"
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
#line 3522 "grammar.c"
    break;

  case 94: /* expression: for_expression "<of>" string_set  */
#line 1787 "grammar.y"
      {
        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_STRING_SET, NULL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3532 "grammar.c"
    break;

  case 95: /* expression: for_expression "<of>" rule_set  */
#line 1793 "grammar.y"
      {
        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_RULE_SET, NULL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3542 "grammar.c"
    break;

  case 96: /* expression: primary_expression '%' "<of>" string_set  */
#line 1799 "grammar.y"
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

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_STRING_SET, NULL, NULL);
      }
#line 3566 "grammar.c"
    break;

  case 97: /* expression: primary_expression '%' "<of>" rule_set  */
#line 1819 "grammar.y"
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

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_RULE_SET, NULL, NULL);
      }
#line 3590 "grammar.c"
    break;

  case 98: /* expression: for_expression "<of>" string_set "<in>" range  */
#line 1839 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_OF_FOUND_IN, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3600 "grammar.c"
    break;

  case 99: /* expression: "<not>" boolean_expression  */
#line 1845 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3610 "grammar.c"
    break;

  case 100: /* expression: "<defined>" boolean_expression  */
#line 1851 "grammar.y"
      {
        yr_parser_emit(yyscanner, OP_DEFINED, NULL);
        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3619 "grammar.c"
    break;

  case 101: /* $@9: %empty  */
#line 1856 "grammar.y"
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
#line 3645 "grammar.c"
    break;

  case 102: /* expression: boolean_expression "<and>" $@9 boolean_expression  */
#line 1878 "grammar.y"
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
#line 3672 "grammar.c"
    break;

  case 103: /* $@10: %empty  */
#line 1901 "grammar.y"
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
#line 3697 "grammar.c"
    break;

  case 104: /* expression: boolean_expression "<or>" $@10 boolean_expression  */
#line 1922 "grammar.y"
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
#line 3724 "grammar.c"
    break;

  case 105: /* expression: primary_expression "<" primary_expression  */
#line 1945 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3735 "grammar.c"
    break;

  case 106: /* expression: primary_expression ">" primary_expression  */
#line 1952 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3746 "grammar.c"
    break;

  case 107: /* expression: primary_expression "<=" primary_expression  */
#line 1959 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3757 "grammar.c"
    break;

  case 108: /* expression: primary_expression ">=" primary_expression  */
#line 1966 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3768 "grammar.c"
    break;

  case 109: /* expression: primary_expression "==" primary_expression  */
#line 1973 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3779 "grammar.c"
    break;

  case 110: /* expression: primary_expression "!=" primary_expression  */
#line 1980 "grammar.y"
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3790 "grammar.c"
    break;

  case 111: /* expression: primary_expression  */
#line 1987 "grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3798 "grammar.c"
    break;

  case 112: /* expression: '(' expression ')'  */
#line 1991 "grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3806 "grammar.c"
    break;

  case 113: /* for_variables: "identifier"  */
#line 1999 "grammar.y"
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
#line 3830 "grammar.c"
    break;

  case 114: /* for_variables: for_variables ',' "identifier"  */
#line 2019 "grammar.y"
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
#line 3859 "grammar.c"
    break;

  case 115: /* iterator: identifier  */
#line 2047 "grammar.y"
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
#line 3937 "grammar.c"
    break;

  case 116: /* iterator: integer_set  */
#line 2121 "grammar.y"
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
#line 3965 "grammar.c"
    break;

  case 117: /* integer_set: '(' integer_enumeration ')'  */
#line 2149 "grammar.y"
      {
        // $2 contains the number of integers in the enumeration
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[-1].integer)));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_ENUM, NULL));
      }
#line 3977 "grammar.c"
    break;

  case 118: /* integer_set: range  */
#line 2157 "grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_RANGE, NULL));
      }
#line 3986 "grammar.c"
    break;

  case 119: /* range: '(' primary_expression ".." primary_expression ')'  */
#line 2166 "grammar.y"
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
#line 4010 "grammar.c"
    break;

  case 120: /* integer_enumeration: primary_expression  */
#line 2190 "grammar.y"
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
#line 4029 "grammar.c"
    break;

  case 121: /* integer_enumeration: integer_enumeration ',' primary_expression  */
#line 2205 "grammar.y"
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
#line 4048 "grammar.c"
    break;

  case 122: /* $@11: %empty  */
#line 2224 "grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 4057 "grammar.c"
    break;

  case 124: /* string_set: "<them>"  */
#line 2230 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, YR_UNDEFINED));

        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*"));
      }
#line 4068 "grammar.c"
    break;

  case 127: /* string_enumeration_item: "string identifier"  */
#line 2247 "grammar.y"
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 4079 "grammar.c"
    break;

  case 128: /* string_enumeration_item: "string identifier with wildcard"  */
#line 2254 "grammar.y"
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 4090 "grammar.c"
    break;

  case 129: /* $@12: %empty  */
#line 2265 "grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 4099 "grammar.c"
    break;

  case 133: /* rule_enumeration_item: "identifier"  */
#line 2281 "grammar.y"
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
      }
#line 4134 "grammar.c"
    break;

  case 134: /* rule_enumeration_item: "identifier with wildcard"  */
#line 2312 "grammar.y"
      {
        YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
            compiler->arena,
            YR_NAMESPACES_TABLE,
            compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

        uint32_t idx = yr_hash_table_lookup_uint32(
            compiler->wildcard_identifiers_table, (yyvsp[0].c_string), ns->name);

        if (idx == UINT32_MAX)
        {
          // Add the new identifier with wildcard to the list of identifiers.
          YR_WILDCARD_IDENTIFIER* node = (YR_WILDCARD_IDENTIFIER*) yr_malloc(
              sizeof(YR_WILDCARD_IDENTIFIER));
          if (node == NULL)
          {
            yr_free((yyvsp[0].c_string));
            fail_with_error(ERROR_INSUFFICIENT_MEMORY);
          }

          node->identifier = (char*) yr_malloc(strlen((yyvsp[0].c_string)) + 1);
          if (node->identifier == NULL)
          {
            yr_free((yyvsp[0].c_string));
            fail_with_error(ERROR_INSUFFICIENT_MEMORY);
          }
          memset(node->identifier, 0, strlen((yyvsp[0].c_string)) + 1);

          node->prev = NULL;
          strcpy(node->identifier, (yyvsp[0].c_string));

          if (compiler->wildcard_identifiers_head != NULL)
            node->prev = compiler->wildcard_identifiers_head;
          compiler->wildcard_identifiers_head = node;

          // Add it to the hash table for fast lookup.
          yr_hash_table_add_uint32(
              compiler->wildcard_identifiers_table,
              (yyvsp[0].c_string),
              ns->name,
              1);
        }

        int result = yr_parser_emit_pushes_for_rules(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));
        fail_if_error(result);
      }
#line 4186 "grammar.c"
    break;

  case 135: /* for_expression: primary_expression  */
#line 2364 "grammar.y"
      {
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 4194 "grammar.c"
    break;

  case 136: /* for_expression: "<all>"  */
#line 2368 "grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
        (yyval.integer) = FOR_EXPRESSION_ALL;
      }
#line 4203 "grammar.c"
    break;

  case 137: /* for_expression: "<any>"  */
#line 2373 "grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, 1);
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 4212 "grammar.c"
    break;

  case 138: /* for_expression: "<none>"  */
#line 2378 "grammar.y"
      {
        yr_parser_emit_push_const(yyscanner, 0);
        (yyval.integer) = FOR_EXPRESSION_NONE;
      }
#line 4221 "grammar.c"
    break;

  case 139: /* primary_expression: '(' primary_expression ')'  */
#line 2387 "grammar.y"
      {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 4229 "grammar.c"
    break;

  case 140: /* primary_expression: "<filesize>"  */
#line 2391 "grammar.y"
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4241 "grammar.c"
    break;

  case 141: /* primary_expression: "<entrypoint>"  */
#line 2399 "grammar.y"
      {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4257 "grammar.c"
    break;

  case 142: /* primary_expression: "integer function" '(' primary_expression ')'  */
#line 2411 "grammar.y"
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
#line 4275 "grammar.c"
    break;

  case 143: /* primary_expression: "integer number"  */
#line 2425 "grammar.y"
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[0].integer)));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 4286 "grammar.c"
    break;

  case 144: /* primary_expression: "floating point number"  */
#line 2432 "grammar.y"
      {
        fail_if_error(yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 4297 "grammar.c"
    break;

  case 145: /* primary_expression: "text string"  */
#line 2439 "grammar.y"
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
#line 4326 "grammar.c"
    break;

  case 146: /* primary_expression: "string count" "<in>" range  */
#line 2464 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_COUNT_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4342 "grammar.c"
    break;

  case 147: /* primary_expression: "string count"  */
#line 2476 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[0].c_string), OP_COUNT, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4358 "grammar.c"
    break;

  case 148: /* primary_expression: "string offset" '[' primary_expression ']'  */
#line 2488 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_OFFSET, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4374 "grammar.c"
    break;

  case 149: /* primary_expression: "string offset"  */
#line 2500 "grammar.y"
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
#line 4393 "grammar.c"
    break;

  case 150: /* primary_expression: "string length" '[' primary_expression ']'  */
#line 2515 "grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_LENGTH, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4409 "grammar.c"
    break;

  case 151: /* primary_expression: "string length"  */
#line 2527 "grammar.y"
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
#line 4428 "grammar.c"
    break;

  case 152: /* primary_expression: identifier  */
#line 2542 "grammar.y"
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
#line 4475 "grammar.c"
    break;

  case 153: /* primary_expression: '-' primary_expression  */
#line 2585 "grammar.y"
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
#line 4500 "grammar.c"
    break;

  case 154: /* primary_expression: primary_expression '+' primary_expression  */
#line 2606 "grammar.y"
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
#line 4539 "grammar.c"
    break;

  case 155: /* primary_expression: primary_expression '-' primary_expression  */
#line 2641 "grammar.y"
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
#line 4578 "grammar.c"
    break;

  case 156: /* primary_expression: primary_expression '*' primary_expression  */
#line 2676 "grammar.y"
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
#line 4616 "grammar.c"
    break;

  case 157: /* primary_expression: primary_expression '\\' primary_expression  */
#line 2710 "grammar.y"
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
#line 4645 "grammar.c"
    break;

  case 158: /* primary_expression: primary_expression '%' primary_expression  */
#line 2735 "grammar.y"
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
#line 4666 "grammar.c"
    break;

  case 159: /* primary_expression: primary_expression '^' primary_expression  */
#line 2752 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4680 "grammar.c"
    break;

  case 160: /* primary_expression: primary_expression '&' primary_expression  */
#line 2762 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4694 "grammar.c"
    break;

  case 161: /* primary_expression: primary_expression '|' primary_expression  */
#line 2772 "grammar.y"
      {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4708 "grammar.c"
    break;

  case 162: /* primary_expression: '~' primary_expression  */
#line 2782 "grammar.y"
      {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == YR_UNDEFINED) ?
            YR_UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 4722 "grammar.c"
    break;

  case 163: /* primary_expression: primary_expression "<<" primary_expression  */
#line 2792 "grammar.y"
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
#line 4746 "grammar.c"
    break;

  case 164: /* primary_expression: primary_expression ">>" primary_expression  */
#line 2812 "grammar.y"
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
#line 4770 "grammar.c"
    break;

  case 165: /* primary_expression: regexp  */
#line 2832 "grammar.y"
      {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 4778 "grammar.c"
    break;


#line 4782 "grammar.c"

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

#line 2837 "grammar.y"

