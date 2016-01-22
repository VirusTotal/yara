/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse yara_yyparse
#define yylex   yara_yylex
#define yyerror yara_yyerror
#define yylval  yara_yylval
#define yychar  yara_yychar
#define yydebug yara_yydebug
#define yynerrs yara_yynerrs


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
     _STRING_LENGTH_ = 269,
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 270,
     _NUMBER_ = 271,
     _DOUBLE_ = 272,
     _INTEGER_FUNCTION_ = 273,
     _TEXT_STRING_ = 274,
     _HEX_STRING_ = 275,
     _REGEXP_ = 276,
     _ASCII_ = 277,
     _WIDE_ = 278,
     _NOCASE_ = 279,
     _FULLWORD_ = 280,
     _AT_ = 281,
     _FILESIZE_ = 282,
     _ENTRYPOINT_ = 283,
     _ALL_ = 284,
     _ANY_ = 285,
     _IN_ = 286,
     _OF_ = 287,
     _FOR_ = 288,
     _THEM_ = 289,
     _MATCHES_ = 290,
     _CONTAINS_ = 291,
     _IMPORT_ = 292,
     _TRUE_ = 293,
     _FALSE_ = 294,
     _OR_ = 295,
     _AND_ = 296,
     _NEQ_ = 297,
     _EQ_ = 298,
     _GE_ = 299,
     _GT_ = 300,
     _LE_ = 301,
     _LT_ = 302,
     _SHIFT_RIGHT_ = 303,
     _SHIFT_LEFT_ = 304,
     UNARY_MINUS = 305,
     _NOT_ = 306
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
#define _STRING_LENGTH_ 269
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 270
#define _NUMBER_ 271
#define _DOUBLE_ 272
#define _INTEGER_FUNCTION_ 273
#define _TEXT_STRING_ 274
#define _HEX_STRING_ 275
#define _REGEXP_ 276
#define _ASCII_ 277
#define _WIDE_ 278
#define _NOCASE_ 279
#define _FULLWORD_ 280
#define _AT_ 281
#define _FILESIZE_ 282
#define _ENTRYPOINT_ 283
#define _ALL_ 284
#define _ANY_ 285
#define _IN_ 286
#define _OF_ 287
#define _FOR_ 288
#define _THEM_ 289
#define _MATCHES_ 290
#define _CONTAINS_ 291
#define _IMPORT_ 292
#define _TRUE_ 293
#define _FALSE_ 294
#define _OR_ 295
#define _AND_ 296
#define _NEQ_ 297
#define _EQ_ 298
#define _GE_ 299
#define _GT_ 300
#define _LE_ 301
#define _LT_ 302
#define _SHIFT_RIGHT_ 303
#define _SHIFT_LEFT_ 304
#define UNARY_MINUS 305
#define _NOT_ 306




/* Copy the first part of user declarations.  */
#line 17 "grammar.y"


#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>


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


#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \


#define CHECK_TYPE(expression, expected_type, op) \
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
      compiler->last_result = ERROR_WRONG_TYPE; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 186 "grammar.y"
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
/* Line 193 of yacc.c.  */
#line 283 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 296 "grammar.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

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
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
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
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   392

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  72
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  40
/* YYNRULES -- Number of rules.  */
#define YYNRULES  119
/* YYNRULES -- Number of states.  */
#define YYNSTATES  206

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   307

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    57,    44,     2,
      69,    70,    55,    53,    71,    54,    66,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    64,     2,
       2,    65,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    67,    56,    68,    43,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    62,    42,    63,    58,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41,    45,    46,    47,
      48,    49,    50,    51,    52,    59,    60,    61
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    14,    18,    22,    25,
      26,    27,    39,    40,    44,    45,    49,    53,    54,    57,
      59,    61,    62,    65,    67,    70,    72,    75,    79,    83,
      87,    91,    93,    96,   101,   102,   108,   112,   113,   116,
     118,   120,   122,   124,   126,   130,   135,   140,   141,   143,
     145,   149,   151,   153,   155,   157,   161,   165,   167,   171,
     175,   176,   177,   189,   190,   200,   204,   207,   208,   213,
     214,   219,   223,   227,   231,   235,   239,   243,   245,   249,
     253,   255,   261,   263,   267,   268,   273,   275,   277,   281,
     283,   285,   287,   289,   291,   295,   297,   299,   304,   306,
     308,   310,   312,   317,   319,   324,   326,   328,   331,   335,
     339,   343,   347,   351,   355,   359,   363,   366,   370,   374
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      73,     0,    -1,    -1,    73,    75,    -1,    73,    74,    -1,
      73,     1,    75,    -1,    73,     1,    74,    -1,    73,     1,
      61,    -1,    37,    19,    -1,    -1,    -1,    81,     4,    10,
      76,    83,    62,    78,    79,    77,    80,    63,    -1,    -1,
       7,    64,    85,    -1,    -1,     8,    64,    87,    -1,     9,
      64,    96,    -1,    -1,    81,    82,    -1,     5,    -1,     6,
      -1,    -1,    64,    84,    -1,    10,    -1,    84,    10,    -1,
      86,    -1,    85,    86,    -1,    10,    65,    19,    -1,    10,
      65,    16,    -1,    10,    65,    38,    -1,    10,    65,    39,
      -1,    88,    -1,    87,    88,    -1,    11,    65,    19,    90,
      -1,    -1,    11,    65,    89,    21,    90,    -1,    11,    65,
      20,    -1,    -1,    90,    91,    -1,    23,    -1,    22,    -1,
      24,    -1,    25,    -1,    10,    -1,    92,    66,    10,    -1,
      92,    67,   111,    68,    -1,    92,    69,    93,    70,    -1,
      -1,    94,    -1,    97,    -1,    94,    71,    97,    -1,    21,
      -1,    97,    -1,    38,    -1,    39,    -1,   111,    35,    95,
      -1,   111,    36,   111,    -1,    11,    -1,    11,    26,   111,
      -1,    11,    31,   104,    -1,    -1,    -1,    33,   110,    10,
      31,    98,   103,    64,    99,    69,    96,    70,    -1,    -1,
      33,   110,    32,   106,    64,   100,    69,    96,    70,    -1,
     110,    32,   106,    -1,    60,    96,    -1,    -1,    96,    41,
     101,    96,    -1,    -1,    96,    40,   102,    96,    -1,   111,
      50,   111,    -1,   111,    48,   111,    -1,   111,    49,   111,
      -1,   111,    47,   111,    -1,   111,    46,   111,    -1,   111,
      45,   111,    -1,   111,    -1,    69,    97,    70,    -1,    69,
     105,    70,    -1,   104,    -1,    69,   111,     3,   111,    70,
      -1,   111,    -1,   105,    71,   111,    -1,    -1,    69,   107,
     108,    70,    -1,    34,    -1,   109,    -1,   108,    71,   109,
      -1,    11,    -1,    15,    -1,   111,    -1,    29,    -1,    30,
      -1,    69,   111,    70,    -1,    27,    -1,    28,    -1,    18,
      69,   111,    70,    -1,    16,    -1,    17,    -1,    19,    -1,
      12,    -1,    13,    67,   111,    68,    -1,    13,    -1,    14,
      67,   111,    68,    -1,    14,    -1,    92,    -1,    54,   111,
      -1,   111,    53,   111,    -1,   111,    54,   111,    -1,   111,
      55,   111,    -1,   111,    56,   111,    -1,   111,    57,   111,
      -1,   111,    43,   111,    -1,   111,    44,   111,    -1,   111,
      42,   111,    -1,    58,   111,    -1,   111,    52,   111,    -1,
     111,    51,   111,    -1,    95,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   200,   200,   202,   203,   204,   205,   206,   211,   224,
     233,   223,   256,   259,   287,   290,   317,   322,   323,   328,
     329,   335,   338,   356,   369,   406,   407,   412,   428,   441,
     454,   471,   472,   477,   488,   487,   503,   517,   518,   523,
     524,   525,   526,   531,   616,   662,   720,   765,   766,   770,
     795,   831,   877,   892,   901,   910,   925,   937,   951,   964,
     976,  1006,   975,  1122,  1121,  1201,  1207,  1214,  1213,  1276,
    1275,  1336,  1345,  1354,  1363,  1372,  1381,  1390,  1394,  1402,
    1403,  1408,  1430,  1442,  1458,  1457,  1463,  1474,  1475,  1480,
    1487,  1498,  1499,  1503,  1511,  1515,  1525,  1539,  1555,  1565,
    1574,  1598,  1610,  1622,  1638,  1650,  1666,  1710,  1729,  1747,
    1765,  1783,  1809,  1827,  1837,  1847,  1857,  1867,  1877,  1887
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_DOT_DOT_", "_RULE_", "_PRIVATE_",
  "_GLOBAL_", "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_LENGTH_", "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_",
  "_DOUBLE_", "_INTEGER_FUNCTION_", "_TEXT_STRING_", "_HEX_STRING_",
  "_REGEXP_", "_ASCII_", "_WIDE_", "_NOCASE_", "_FULLWORD_", "_AT_",
  "_FILESIZE_", "_ENTRYPOINT_", "_ALL_", "_ANY_", "_IN_", "_OF_", "_FOR_",
  "_THEM_", "_MATCHES_", "_CONTAINS_", "_IMPORT_", "_TRUE_", "_FALSE_",
  "_OR_", "_AND_", "'|'", "'^'", "'&'", "_NEQ_", "_EQ_", "_GE_", "_GT_",
  "_LE_", "_LT_", "_SHIFT_RIGHT_", "_SHIFT_LEFT_", "'+'", "'-'", "'*'",
  "'\\\\'", "'%'", "'~'", "UNARY_MINUS", "_NOT_", "\"include\"", "'{'",
  "'}'", "':'", "'='", "'.'", "'['", "']'", "'('", "')'", "','", "$accept",
  "rules", "import", "rule", "@1", "@2", "meta", "strings", "condition",
  "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "@3", "string_modifiers", "string_modifier",
  "identifier", "arguments", "arguments_list", "regexp",
  "boolean_expression", "expression", "@4", "@5", "@6", "@7", "@8",
  "integer_set", "range", "integer_enumeration", "string_set", "@9",
  "string_enumeration", "string_enumeration_item", "for_expression",
  "primary_expression", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   124,    94,    38,   297,   298,   299,   300,   301,
     302,   303,   304,    43,    45,    42,    92,    37,   126,   305,
     306,   307,   123,   125,    58,    61,    46,    91,    93,    40,
      41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    72,    73,    73,    73,    73,    73,    73,    74,    76,
      77,    75,    78,    78,    79,    79,    80,    81,    81,    82,
      82,    83,    83,    84,    84,    85,    85,    86,    86,    86,
      86,    87,    87,    88,    89,    88,    88,    90,    90,    91,
      91,    91,    91,    92,    92,    92,    92,    93,    93,    94,
      94,    95,    96,    97,    97,    97,    97,    97,    97,    97,
      98,    99,    97,   100,    97,    97,    97,   101,    97,   102,
      97,    97,    97,    97,    97,    97,    97,    97,    97,   103,
     103,   104,   105,   105,   107,   106,   106,   108,   108,   109,
     109,   110,   110,   110,   111,   111,   111,   111,   111,   111,
     111,   111,   111,   111,   111,   111,   111,   111,   111,   111,
     111,   111,   111,   111,   111,   111,   111,   111,   111,   111
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     0,
       0,    11,     0,     3,     0,     3,     3,     0,     2,     1,
       1,     0,     2,     1,     2,     1,     2,     3,     3,     3,
       3,     1,     2,     4,     0,     5,     3,     0,     2,     1,
       1,     1,     1,     1,     3,     4,     4,     0,     1,     1,
       3,     1,     1,     1,     1,     3,     3,     1,     3,     3,
       0,     0,    11,     0,     9,     3,     2,     0,     4,     0,
       4,     3,     3,     3,     3,     3,     3,     1,     3,     3,
       1,     5,     1,     3,     0,     4,     1,     1,     3,     1,
       1,     1,     1,     1,     3,     1,     1,     4,     1,     1,
       1,     1,     4,     1,     4,     1,     1,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     2,     3,     3,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    17,     0,     4,     3,     0,     7,     6,
       5,     8,     0,    19,    20,    18,     9,    21,     0,     0,
      23,    22,    12,    24,     0,    14,     0,     0,    10,     0,
      13,    25,     0,     0,     0,    26,     0,    15,    31,     0,
       0,    28,    27,    29,    30,    34,    32,     0,    11,    37,
      36,     0,    43,    57,   101,   103,   105,    98,    99,     0,
     100,    51,    95,    96,    92,    93,     0,    53,    54,     0,
       0,     0,     0,   106,   119,    16,    52,     0,    77,    33,
      37,     0,     0,     0,     0,     0,     0,     0,    91,   107,
     116,    66,     0,    52,    77,     0,     0,    47,    69,    67,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    40,
      39,    41,    42,    38,    35,    58,     0,    59,     0,     0,
       0,     0,     0,     0,    78,    94,    44,     0,     0,    48,
      49,     0,     0,    86,    84,    65,    55,    56,   115,   113,
     114,    76,    75,    74,    72,    73,    71,   118,   117,   108,
     109,   110,   111,   112,     0,   102,   104,    97,    60,     0,
      45,    46,     0,    70,    68,     0,     0,     0,    63,    50,
      89,    90,     0,    87,     0,     0,     0,    80,     0,    85,
       0,    81,     0,    82,    61,     0,    88,    79,     0,     0,
       0,    83,     0,    64,     0,    62
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    17,    33,    25,    28,    40,     7,
      15,    19,    21,    30,    31,    37,    38,    51,    79,   123,
      73,   138,   139,    74,    92,    76,   177,   199,   188,   142,
     141,   186,   127,   192,   145,   175,   182,   183,    77,    78
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -71
static const yytype_int16 yypact[] =
{
     -71,    29,   -71,   -29,   -16,   -71,   -71,   166,   -71,   -71,
     -71,   -71,    13,   -71,   -71,   -71,   -71,   -10,    60,    10,
     -71,    91,    71,   -71,    16,    95,   121,    41,   -71,    42,
     121,   -71,   126,   133,    70,   -71,    94,   126,   -71,   111,
     114,   -71,   -71,   -71,   -71,    63,   -71,    46,   -71,   -71,
     -71,   157,   -71,    -9,   -71,   115,   119,   -71,   -71,   112,
     -71,   -71,   -71,   -71,   -71,   -71,   100,   -71,   -71,   122,
     122,    46,    46,    30,   -71,    47,   -71,   155,   290,    68,
     -71,   122,   120,   122,   122,   122,   122,    -4,   306,   -71,
     -71,   -71,    47,   118,   167,   180,   122,    46,   -71,   -71,
       2,   179,   122,   122,   122,   122,   122,   122,   122,   122,
     122,   122,   122,   122,   122,   122,   122,   122,   122,   -71,
     -71,   -71,   -71,   -71,    68,   306,   122,   -71,   227,   245,
     109,   187,   170,     2,   -71,   -71,   -71,   263,   134,   135,
     116,    46,    46,   -71,   -71,   -71,   -71,   306,   321,   335,
     -42,   306,   306,   306,   306,   306,   306,    69,    69,    90,
      90,   -71,   -71,   -71,   141,   -71,   -71,   -71,   -71,   143,
     -71,   -71,    46,   164,   -71,    66,   122,   139,   -71,   116,
     -71,   -71,    97,   -71,   207,   122,   161,   -71,   158,   -71,
      66,   -71,   103,   141,   -71,    46,   -71,   -71,   122,   159,
     -15,   306,    46,   -71,    28,   -71
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -71,   -71,   223,   229,   -71,   -71,   -71,   -71,   -71,   -71,
     -71,   -71,   -71,   -71,   203,   -71,   197,   -71,   156,   -71,
     -71,   -71,   -71,   144,   -47,   -70,   -71,   -71,   -71,   -71,
     -71,   -71,    58,   -71,   113,   -71,   -71,    57,   182,   -65
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -92
static const yytype_int16 yytable[] =
{
      75,    88,    93,    11,    89,    90,   132,    94,     4,   112,
     113,   114,   115,   116,   117,   118,   125,    81,   128,   129,
     130,   131,    82,    16,    91,    98,    99,   140,   133,     2,
       3,   137,     8,   -17,   -17,   -17,   143,   147,   148,   149,
     150,   151,   152,   153,   154,   155,   156,   157,   158,   159,
     160,   161,   162,   163,    18,   203,    52,    53,    54,    55,
      56,   164,    57,    58,    59,    60,     4,    61,    98,    99,
      20,   144,    22,    62,    63,    64,    65,   180,    24,    66,
      26,   181,    49,    50,    67,    68,    41,    98,    99,    42,
     119,   120,   121,   122,   173,   174,    95,    96,   205,    97,
      69,    23,   179,    27,    70,    32,    71,    34,    43,    44,
      52,   184,    54,    55,    56,    72,    57,    58,    59,    60,
     193,    61,   114,   115,   116,   117,   118,    62,    63,    64,
      65,    29,    52,   201,    54,    55,    56,    36,    57,    58,
      59,    60,    39,    61,   176,   116,   117,   118,   200,    62,
      63,   103,   104,   105,    69,   204,   -52,   -52,    70,    45,
     112,   113,   114,   115,   116,   117,   118,   189,   190,    86,
      12,    13,    14,   197,   198,    47,    69,    48,    80,   167,
      70,    85,    83,   103,   104,   105,    84,   100,   134,   126,
     136,    86,   112,   113,   114,   115,   116,   117,   118,   -91,
      61,   168,   101,   102,   171,    99,   172,   178,   185,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   194,     9,   195,   202,   103,
     104,   105,    10,    35,    46,   187,   124,   135,   112,   113,
     114,   115,   116,   117,   118,   146,   169,   196,    87,   103,
     104,   105,     0,     0,     0,     0,     0,   135,   112,   113,
     114,   115,   116,   117,   118,     0,     0,     0,     0,   103,
     104,   105,     0,     0,     0,     0,     0,   191,   112,   113,
     114,   115,   116,   117,   118,     0,     0,   103,   104,   105,
       0,     0,     0,     0,     0,   165,   112,   113,   114,   115,
     116,   117,   118,     0,     0,   103,   104,   105,     0,     0,
       0,     0,     0,   166,   112,   113,   114,   115,   116,   117,
     118,     0,   -91,     0,     0,   101,   102,     0,     0,     0,
       0,   170,   103,   104,   105,   106,   107,   108,   109,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   103,   104,
     105,     0,     0,     0,     0,     0,     0,   112,   113,   114,
     115,   116,   117,   118,   104,   105,     0,     0,     0,     0,
       0,     0,   112,   113,   114,   115,   116,   117,   118,   105,
       0,     0,     0,     0,     0,     0,   112,   113,   114,   115,
     116,   117,   118
};

static const yytype_int16 yycheck[] =
{
      47,    66,    72,    19,    69,    70,    10,    72,    37,    51,
      52,    53,    54,    55,    56,    57,    81,    26,    83,    84,
      85,    86,    31,    10,    71,    40,    41,    97,    32,     0,
       1,    96,    61,     4,     5,     6,    34,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,    64,    70,    10,    11,    12,    13,
      14,   126,    16,    17,    18,    19,    37,    21,    40,    41,
      10,    69,    62,    27,    28,    29,    30,    11,     7,    33,
      64,    15,    19,    20,    38,    39,    16,    40,    41,    19,
      22,    23,    24,    25,   141,   142,    66,    67,    70,    69,
      54,    10,   172,     8,    58,    64,    60,    65,    38,    39,
      10,   176,    12,    13,    14,    69,    16,    17,    18,    19,
     185,    21,    53,    54,    55,    56,    57,    27,    28,    29,
      30,    10,    10,   198,    12,    13,    14,    11,    16,    17,
      18,    19,     9,    21,     3,    55,    56,    57,   195,    27,
      28,    42,    43,    44,    54,   202,    40,    41,    58,    65,
      51,    52,    53,    54,    55,    56,    57,    70,    71,    69,
       4,     5,     6,    70,    71,    64,    54,    63,    21,    70,
      58,    69,    67,    42,    43,    44,    67,    32,    70,    69,
      10,    69,    51,    52,    53,    54,    55,    56,    57,    32,
      21,    31,    35,    36,    70,    41,    71,    64,    69,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    64,     3,    69,    69,    42,
      43,    44,     3,    30,    37,   177,    80,    70,    51,    52,
      53,    54,    55,    56,    57,   101,   133,   190,    66,    42,
      43,    44,    -1,    -1,    -1,    -1,    -1,    70,    51,    52,
      53,    54,    55,    56,    57,    -1,    -1,    -1,    -1,    42,
      43,    44,    -1,    -1,    -1,    -1,    -1,    70,    51,    52,
      53,    54,    55,    56,    57,    -1,    -1,    42,    43,    44,
      -1,    -1,    -1,    -1,    -1,    68,    51,    52,    53,    54,
      55,    56,    57,    -1,    -1,    42,    43,    44,    -1,    -1,
      -1,    -1,    -1,    68,    51,    52,    53,    54,    55,    56,
      57,    -1,    32,    -1,    -1,    35,    36,    -1,    -1,    -1,
      -1,    68,    42,    43,    44,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    42,    43,
      44,    -1,    -1,    -1,    -1,    -1,    -1,    51,    52,    53,
      54,    55,    56,    57,    43,    44,    -1,    -1,    -1,    -1,
      -1,    -1,    51,    52,    53,    54,    55,    56,    57,    44,
      -1,    -1,    -1,    -1,    -1,    -1,    51,    52,    53,    54,
      55,    56,    57
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    73,     0,     1,    37,    74,    75,    81,    61,    74,
      75,    19,     4,     5,     6,    82,    10,    76,    64,    83,
      10,    84,    62,    10,     7,    78,    64,     8,    79,    10,
      85,    86,    64,    77,    65,    86,    11,    87,    88,     9,
      80,    16,    19,    38,    39,    65,    88,    64,    63,    19,
      20,    89,    10,    11,    12,    13,    14,    16,    17,    18,
      19,    21,    27,    28,    29,    30,    33,    38,    39,    54,
      58,    60,    69,    92,    95,    96,    97,   110,   111,    90,
      21,    26,    31,    67,    67,    69,    69,   110,   111,   111,
     111,    96,    96,    97,   111,    66,    67,    69,    40,    41,
      32,    35,    36,    42,    43,    44,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    22,
      23,    24,    25,    91,    90,   111,    69,   104,   111,   111,
     111,   111,    10,    32,    70,    70,    10,   111,    93,    94,
      97,   102,   101,    34,    69,   106,    95,   111,   111,   111,
     111,   111,   111,   111,   111,   111,   111,   111,   111,   111,
     111,   111,   111,   111,   111,    68,    68,    70,    31,   106,
      68,    70,    71,    96,    96,   107,     3,    98,    64,    97,
      11,    15,   108,   109,   111,    69,   103,   104,   100,    70,
      71,    70,   105,   111,    64,    69,   109,    70,    71,    99,
      96,   111,    69,    70,    96,    70
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (yyscanner, compiler, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, yyscanner, compiler)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, yyscanner, compiler); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, compiler)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
    YR_COMPILER* compiler;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yyscanner);
  YYUSE (compiler);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yyscanner, compiler)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
    YR_COMPILER* compiler;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, compiler);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, void *yyscanner, YR_COMPILER* compiler)
#else
static void
yy_reduce_print (yyvsp, yyrule, yyscanner, compiler)
    YYSTYPE *yyvsp;
    int yyrule;
    void *yyscanner;
    YR_COMPILER* compiler;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , yyscanner, compiler);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, yyscanner, compiler); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
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



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
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
	    /* Fall through.  */
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

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner, YR_COMPILER* compiler)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yyscanner, compiler)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    void *yyscanner;
    YR_COMPILER* compiler;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);
  YYUSE (compiler);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {
      case 10: /* "_IDENTIFIER_" */
#line 176 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1438 "grammar.c"
	break;
      case 11: /* "_STRING_IDENTIFIER_" */
#line 180 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1443 "grammar.c"
	break;
      case 12: /* "_STRING_COUNT_" */
#line 177 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1448 "grammar.c"
	break;
      case 13: /* "_STRING_OFFSET_" */
#line 178 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1453 "grammar.c"
	break;
      case 14: /* "_STRING_LENGTH_" */
#line 179 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1458 "grammar.c"
	break;
      case 15: /* "_STRING_IDENTIFIER_WITH_WILDCARD_" */
#line 181 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1463 "grammar.c"
	break;
      case 19: /* "_TEXT_STRING_" */
#line 182 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1468 "grammar.c"
	break;
      case 20: /* "_HEX_STRING_" */
#line 183 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1473 "grammar.c"
	break;
      case 21: /* "_REGEXP_" */
#line 184 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1478 "grammar.c"
	break;

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void *yyscanner, YR_COMPILER* compiler);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *yyscanner, YR_COMPILER* compiler)
#else
int
yyparse (yyscanner, compiler)
    void *yyscanner;
    YR_COMPILER* compiler;
#endif
#endif
{
  /* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;

  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
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
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

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
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 8:
#line 212 "grammar.y"
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[(2) - (2)].sized_string));

        yr_free((yyvsp[(2) - (2)].sized_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
    break;

  case 9:
#line 224 "grammar.y"
    {
        YR_RULE* rule = yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[(1) - (3)].integer), (yyvsp[(3) - (3)].c_string));

        ERROR_IF(rule == NULL);

        (yyval.rule) = rule;
      }
    break;

  case 10:
#line 233 "grammar.y"
    {
        YR_RULE* rule = (yyvsp[(4) - (8)].rule); // rule created in phase 1

        rule->tags = (yyvsp[(5) - (8)].c_string);
        rule->metas = (yyvsp[(7) - (8)].meta);
        rule->strings = (yyvsp[(8) - (8)].string);
      }
    break;

  case 11:
#line 241 "grammar.y"
    {
        YR_RULE* rule = (yyvsp[(4) - (11)].rule); // rule created in phase 1

        compiler->last_result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, rule);

        yr_free((yyvsp[(3) - (11)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 12:
#line 256 "grammar.y"
    {
        (yyval.meta) = NULL;
      }
    break;

  case 13:
#line 260 "grammar.y"
    {
        // Each rule have a list of meta-data info, consisting in a
        // sequence of YR_META structures. The last YR_META structure does
        // not represent a real meta-data, it's just a end-of-list marker
        // identified by a specific type (META_TYPE_NULL). Here we
        // write the end-of-list marker.

        YR_META null_meta;

        memset(&null_meta, 0xFF, sizeof(YR_META));
        null_meta.type = META_TYPE_NULL;

        compiler->last_result = yr_arena_write_data(
            compiler->metas_arena,
            &null_meta,
            sizeof(YR_META),
            NULL);

        (yyval.meta) = (yyvsp[(3) - (3)].meta);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 14:
#line 287 "grammar.y"
    {
        (yyval.string) = NULL;
      }
    break;

  case 15:
#line 291 "grammar.y"
    {
        // Each rule have a list of strings, consisting in a sequence
        // of YR_STRING structures. The last YR_STRING structure does not
        // represent a real string, it's just a end-of-list marker
        // identified by a specific flag (STRING_FLAGS_NULL). Here we
        // write the end-of-list marker.

        YR_STRING null_string;

        memset(&null_string, 0xFF, sizeof(YR_STRING));
        null_string.g_flags = STRING_GFLAGS_NULL;

        compiler->last_result = yr_arena_write_data(
            compiler->strings_arena,
            &null_string,
            sizeof(YR_STRING),
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.string) = (yyvsp[(3) - (3)].string);
      }
    break;

  case 17:
#line 322 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 18:
#line 323 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 19:
#line 328 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
    break;

  case 20:
#line 329 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
    break;

  case 21:
#line 335 "grammar.y"
    {
        (yyval.c_string) = NULL;
      }
    break;

  case 22:
#line 339 "grammar.y"
    {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[(2) - (2)].c_string);
      }
    break;

  case 23:
#line 357 "grammar.y"
    {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[(1) - (1)].c_string), &identifier);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
      }
    break;

  case 24:
#line 370 "grammar.y"
    {
        char* tag_name = (yyvsp[(1) - (2)].c_string);
        size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

        while (tag_length > 0)
        {
          if (strcmp(tag_name, (yyvsp[(2) - (2)].c_string)) == 0)
          {
            yr_compiler_set_error_extra_info(compiler, tag_name);
            compiler->last_result = ERROR_DUPLICATED_TAG_IDENTIFIER;
            break;
          }

          tag_name = (char*) yr_arena_next_address(
              yyget_extra(yyscanner)->sz_arena,
              tag_name,
              tag_length + 1);

          tag_length = tag_name != NULL ? strlen(tag_name) : 0;
        }

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_arena_write_string(
              yyget_extra(yyscanner)->sz_arena, (yyvsp[(2) - (2)].c_string), NULL);

        yr_free((yyvsp[(2) - (2)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[(1) - (2)].c_string);
      }
    break;

  case 25:
#line 406 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (1)].meta); }
    break;

  case 26:
#line 407 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (2)].meta); }
    break;

  case 27:
#line 413 "grammar.y"
    {
        SIZED_STRING* sized_string = (yyvsp[(3) - (3)].sized_string);

        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_STRING,
            (yyvsp[(1) - (3)].c_string),
            sized_string->c_string,
            0);

        yr_free((yyvsp[(1) - (3)].c_string));
        yr_free((yyvsp[(3) - (3)].sized_string));

        ERROR_IF((yyval.meta) == NULL);
      }
    break;

  case 28:
#line 429 "grammar.y"
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[(1) - (3)].c_string),
            NULL,
            (yyvsp[(3) - (3)].integer));

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
    break;

  case 29:
#line 442 "grammar.y"
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[(1) - (3)].c_string),
            NULL,
            TRUE);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
    break;

  case 30:
#line 455 "grammar.y"
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[(1) - (3)].c_string),
            NULL,
            FALSE);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
    break;

  case 31:
#line 471 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 32:
#line 472 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (2)].string); }
    break;

  case 33:
#line 478 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) (yyvsp[(4) - (4)].integer), (yyvsp[(1) - (4)].c_string), (yyvsp[(3) - (4)].sized_string));

        yr_free((yyvsp[(1) - (4)].c_string));
        yr_free((yyvsp[(3) - (4)].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
    break;

  case 34:
#line 488 "grammar.y"
    {
        compiler->error_line = yyget_lineno(yyscanner);
      }
    break;

  case 35:
#line 492 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) (yyvsp[(5) - (5)].integer) | STRING_GFLAGS_REGEXP, (yyvsp[(1) - (5)].c_string), (yyvsp[(4) - (5)].sized_string));

        yr_free((yyvsp[(1) - (5)].c_string));
        yr_free((yyvsp[(4) - (5)].sized_string));

        ERROR_IF((yyval.string) == NULL);

        compiler->error_line = 0;
      }
    break;

  case 36:
#line 504 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, STRING_GFLAGS_HEXADECIMAL, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].sized_string));

        yr_free((yyvsp[(1) - (3)].c_string));
        yr_free((yyvsp[(3) - (3)].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
    break;

  case 37:
#line 517 "grammar.y"
    { (yyval.integer) = 0; }
    break;

  case 38:
#line 518 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 39:
#line 523 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_WIDE; }
    break;

  case 40:
#line 524 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_ASCII; }
    break;

  case 41:
#line 525 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
    break;

  case 42:
#line 526 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
    break;

  case 43:
#line 532 "grammar.y"
    {
        int var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[(1) - (1)].c_string));

        if (var_index >= 0)
        {
          compiler->last_result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_M,
              LOOP_LOCAL_VARS * var_index,
              NULL,
              NULL);

          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = UNDEFINED;
          (yyval.expression).identifier = compiler->loop_identifier[var_index];
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          YR_OBJECT* object = (YR_OBJECT*) yr_hash_table_lookup(
              compiler->objects_table, (yyvsp[(1) - (1)].c_string), NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            char* ns = compiler->current_namespace->name;

            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table, (yyvsp[(1) - (1)].c_string), ns);
          }

          if (object != NULL)
          {
            char* id;

            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena, (yyvsp[(1) - (1)].c_string), &id);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  PTR_TO_INT64(id),
                  NULL,
                  NULL);

            (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
            (yyval.expression).value.object = object;
            (yyval.expression).identifier = object->identifier;
          }
          else
          {
            YR_RULE* rule = (YR_RULE*) yr_hash_table_lookup(
                compiler->rules_table,
                (yyvsp[(1) - (1)].c_string),
                compiler->current_namespace->name);

            if (rule != NULL)
            {
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_PUSH_RULE,
                  PTR_TO_INT64(rule),
                  NULL,
                  NULL);

              (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
              (yyval.expression).value.integer = UNDEFINED;
              (yyval.expression).identifier = rule->identifier;
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, (yyvsp[(1) - (1)].c_string));
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }
          }
        }

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 44:
#line 617 "grammar.y"
    {
        YR_OBJECT* field = NULL;

        if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[(1) - (3)].expression).value.object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field((yyvsp[(1) - (3)].expression).value.object, (yyvsp[(3) - (3)].c_string));

          if (field != NULL)
          {
            char* ident;

            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena, (yyvsp[(3) - (3)].c_string), &ident);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  PTR_TO_INT64(ident),
                  NULL,
                  NULL);

            (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
            (yyval.expression).value.object = field;
            (yyval.expression).identifier = field->identifier;
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, (yyvsp[(3) - (3)].c_string));
            compiler->last_result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[(1) - (3)].expression).identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free((yyvsp[(3) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 45:
#line 663 "grammar.y"
    {
        YR_OBJECT_ARRAY* array;
        YR_OBJECT_DICTIONARY* dict;

        if ((yyvsp[(1) - (4)].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[(1) - (4)].expression).value.object->type == OBJECT_TYPE_ARRAY)
        {
          if ((yyvsp[(3) - (4)].expression).type != EXPRESSION_TYPE_INTEGER)
          {
            yr_compiler_set_error_extra_info(
                compiler, "array indexes must be of integer type");
            compiler->last_result = ERROR_WRONG_TYPE;
          }

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner, OP_INDEX_ARRAY, NULL);

          array = (YR_OBJECT_ARRAY*) (yyvsp[(1) - (4)].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = array->prototype_item;
          (yyval.expression).identifier = array->identifier;
        }
        else if ((yyvsp[(1) - (4)].expression).type == EXPRESSION_TYPE_OBJECT &&
                 (yyvsp[(1) - (4)].expression).value.object->type == OBJECT_TYPE_DICTIONARY)
        {
          if ((yyvsp[(3) - (4)].expression).type != EXPRESSION_TYPE_STRING)
          {
            yr_compiler_set_error_extra_info(
                compiler, "dictionary keys must be of string type");
            compiler->last_result = ERROR_WRONG_TYPE;
          }

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner, OP_LOOKUP_DICT, NULL);

          dict = (YR_OBJECT_DICTIONARY*) (yyvsp[(1) - (4)].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = dict->prototype_item;
          (yyval.expression).identifier = dict->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[(1) - (4)].expression).identifier);

          compiler->last_result = ERROR_NOT_INDEXABLE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 46:
#line 721 "grammar.y"
    {
        YR_OBJECT_FUNCTION* function;
        char* args_fmt;

        if ((yyvsp[(1) - (4)].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[(1) - (4)].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].expression).value.object, (yyvsp[(3) - (4)].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena, (yyvsp[(3) - (4)].c_string), &args_fmt);

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                PTR_TO_INT64(args_fmt),
                NULL,
                NULL);

          function = (YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = function->return_obj;
          (yyval.expression).identifier = function->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[(1) - (4)].expression).identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[(3) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 47:
#line 765 "grammar.y"
    { (yyval.c_string) = yr_strdup(""); }
    break;

  case 48:
#line 766 "grammar.y"
    { (yyval.c_string) = (yyvsp[(1) - (1)].c_string); }
    break;

  case 49:
#line 771 "grammar.y"
    {
        (yyval.c_string) = (char*) yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch((yyvsp[(1) - (1)].expression).type)
        {
          case EXPRESSION_TYPE_INTEGER:
            strlcpy((yyval.c_string), "i", MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_FLOAT:
            strlcpy((yyval.c_string), "f", MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_BOOLEAN:
            strlcpy((yyval.c_string), "b", MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_STRING:
            strlcpy((yyval.c_string), "s", MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_REGEXP:
            strlcpy((yyval.c_string), "r", MAX_FUNCTION_ARGS);
            break;
        }

        ERROR_IF((yyval.c_string) == NULL);
      }
    break;

  case 50:
#line 796 "grammar.y"
    {
        if (strlen((yyvsp[(1) - (3)].c_string)) == MAX_FUNCTION_ARGS)
        {
          compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch((yyvsp[(3) - (3)].expression).type)
          {
            case EXPRESSION_TYPE_INTEGER:
              strlcat((yyvsp[(1) - (3)].c_string), "i", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_FLOAT:
              strlcat((yyvsp[(1) - (3)].c_string), "f", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_BOOLEAN:
              strlcat((yyvsp[(1) - (3)].c_string), "b", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_STRING:
              strlcat((yyvsp[(1) - (3)].c_string), "s", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_REGEXP:
              strlcat((yyvsp[(1) - (3)].c_string), "r", MAX_FUNCTION_ARGS);
              break;
          }
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[(1) - (3)].c_string);
      }
    break;

  case 51:
#line 832 "grammar.y"
    {
        SIZED_STRING* sized_string = (yyvsp[(1) - (1)].sized_string);
        RE* re;
        RE_ERROR error;

        int re_flags = 0;

        if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if (sized_string->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        compiler->last_result = yr_re_compile(
            sized_string->c_string,
            re_flags,
            compiler->re_code_arena,
            &re,
            &error);

        yr_free((yyvsp[(1) - (1)].sized_string));

        if (compiler->last_result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              PTR_TO_INT64(re->root_node->forward_code),
              NULL,
              NULL);

        yr_re_destroy(re);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_REGEXP;
      }
    break;

  case 52:
#line 878 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 53:
#line 893 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 54:
#line 902 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 55:
#line 911 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_STRING, "matches");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_REGEXP, "matches");

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_MATCHES,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 56:
#line 926 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_STRING, "contains");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 57:
#line 938 "grammar.y"
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (1)].c_string),
            OP_FOUND,
            UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 58:
#line 952 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "at");

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[(1) - (3)].c_string), OP_FOUND_AT, (yyvsp[(3) - (3)].expression).value.integer);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 59:
#line 965 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[(1) - (3)].c_string), OP_FOUND_IN, UNDEFINED);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 60:
#line 976 "grammar.y"
    {
        int var_index;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner, (yyvsp[(3) - (4)].c_string));

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[(3) - (4)].c_string));

          compiler->last_result = \
              ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // Push end-of-list marker
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 61:
#line 1006 "grammar.y"
    {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        uint8_t* addr;

        // Clear counter for number of expressions evaluating
        // to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL, NULL);

        // Clear iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL, NULL);

        if ((yyvsp[(6) - (7)].integer) == INTEGER_SET_ENUMERATION)
        {
          // Pop the first integer
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, &addr, NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Pop higher bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset + 3, &addr, NULL);

          // Pop lower bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, NULL, NULL);
        }

        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = (yyvsp[(3) - (7)].c_string);
        compiler->loop_depth++;
      }
    break;

  case 62:
#line 1041 "grammar.y"
    {
        int mem_offset;

        compiler->loop_depth--;
        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // The value at the top of the stack is the result of
        // evaluating the boolean expression, so it could be
        // 0, 1 or UNDEFINED. Add this value to a counter
        // keeping the number of expressions evaluating to true.
        // If the value is UNDEFINED instruction OP_ADD_M
        // does nothing.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL, NULL);

        // Increment iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL, NULL);

        if ((yyvsp[(6) - (11)].integer) == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              PTR_TO_INT64(
                  compiler->loop_address[compiler->loop_depth]),
              NULL,
              NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Increment lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_INCR_M, mem_offset, NULL, NULL);

          // Push lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset, NULL, NULL);

          // Push higher bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset + 3, NULL, NULL);

          // Compare higher bound with lower bound, do loop again
          // if lower bound is still lower or equal than higher bound
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JLE,
              PTR_TO_INT64(
                compiler->loop_address[compiler->loop_depth]),
              NULL,
              NULL);

          yr_parser_emit(yyscanner, OP_POP, NULL);
          yr_parser_emit(yyscanner, OP_POP, NULL);
        }

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at the top of the stack. Check if the quantifier
        // is undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit(yyscanner, OP_INT_LE, NULL);

        compiler->loop_identifier[compiler->loop_depth] = NULL;
        yr_free((yyvsp[(3) - (11)].c_string));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 63:
#line 1122 "grammar.y"
    {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        uint8_t* addr;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          compiler->last_result = \
            ERROR_NESTED_FOR_OF_LOOP;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, mem_offset, &addr, NULL);

        compiler->loop_for_of_mem_offset = mem_offset;
        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = NULL;
        compiler->loop_depth++;
      }
    break;

  case 64:
#line 1152 "grammar.y"
    {
        int mem_offset;

        compiler->loop_depth--;
        compiler->loop_for_of_mem_offset = -1;

        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // Increment counter by the value returned by the
        // boolean expression (0 or 1). If the boolean expression
        // returned UNDEFINED the OP_ADD_M won't do anything.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL, NULL);

        // Increment iterations counter.
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL, NULL);

        // If next string is not undefined, go back to the
        // begining of the loop.
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JNUNDEF,
            PTR_TO_INT64(
                compiler->loop_address[compiler->loop_depth]),
            NULL,
            NULL);

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at top of the stack. Check if the quantifier is
        // undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit(yyscanner, OP_INT_LE, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;

      }
    break;

  case 65:
#line 1202 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 66:
#line 1208 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 67:
#line 1214 "grammar.y"
    {
        YR_FIXUP* fixup;
        int64_t* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // create a fixup entry for the jump and push it in the stack
        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFICIENT_MEMORY;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
    break;

  case 68:
#line 1240 "grammar.y"
    {
        YR_FIXUP* fixup;
        uint8_t* and_addr;

        // Ensure that we have at least two consecutive bytes in the arena's
        // current page, one for the AND opcode and one for opcode following the
        // AND. This is necessary because we need to compute the address for the
        // opcode following the AND, and we don't want the AND in one page and
        // the following opcode in another page.

        compiler->last_result = yr_arena_reserve_memory(
            compiler->code_arena, 2);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        compiler->last_result = yr_parser_emit(yyscanner, OP_AND, &and_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // Now we know the jump destination, which is the address of the
        // instruction following the AND. Let's fixup the jump address.

        fixup = compiler->fixup_stack_head;

        // We know that the AND opcode and the following one are within the same
        // page, so we can compute the address for the opcode following the AND
        // by simply adding one to its address.

        *(fixup->address) = PTR_TO_INT64(and_addr + 1);

        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 69:
#line 1276 "grammar.y"
    {
        YR_FIXUP* fixup;
        int64_t* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFICIENT_MEMORY;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
    break;

  case 70:
#line 1301 "grammar.y"
    {
        YR_FIXUP* fixup;
        uint8_t* or_addr;

        // Ensure that we have at least two consecutive bytes in the arena's
        // current page, one for the OR opcode and one for opcode following the
        // OR. This is necessary because we need to compute the address for the
        // opcode following the OR, and we don't want the OR in one page and
        // the following opcode in another page.

        compiler->last_result = yr_arena_reserve_memory(
            compiler->code_arena, 2);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        compiler->last_result = yr_parser_emit(yyscanner, OP_OR, &or_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // Now we know the jump destination, which is the address of the
        // instruction following the OP_OR. Let's fixup the jump address.

        fixup = compiler->fixup_stack_head;

        // We know that the OR opcode and the following one are within the same
        // page, so we can compute the address for the opcode following the OR
        // by simply adding one to its address.

        *(fixup->address) = PTR_TO_INT64(or_addr + 1);

        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 71:
#line 1337 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 72:
#line 1346 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 73:
#line 1355 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 74:
#line 1364 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 75:
#line 1373 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 76:
#line 1382 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 77:
#line 1391 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(1) - (1)].expression);
      }
    break;

  case 78:
#line 1395 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(2) - (3)].expression);
      }
    break;

  case 79:
#line 1402 "grammar.y"
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
    break;

  case 80:
#line 1403 "grammar.y"
    { (yyval.integer) = INTEGER_SET_RANGE; }
    break;

  case 81:
#line 1409 "grammar.y"
    {
        if ((yyvsp[(2) - (5)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[(4) - (5)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 82:
#line 1431 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;

        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 83:
#line 1443 "grammar.y"
    {
        if ((yyvsp[(3) - (3)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 84:
#line 1458 "grammar.y"
    {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
    break;

  case 86:
#line 1464 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 89:
#line 1481 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 90:
#line 1488 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 92:
#line 1500 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
    break;

  case 93:
#line 1504 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL, NULL);
      }
    break;

  case 94:
#line 1512 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(2) - (3)].expression);
      }
    break;

  case 95:
#line 1516 "grammar.y"
    {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 96:
#line 1526 "grammar.y"
    {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 97:
#line 1540 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression), EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_READ_INT results
        // in the proper OP_INTXX opcode.

        compiler->last_result = yr_parser_emit(
            yyscanner, (uint8_t) (OP_READ_INT + (yyvsp[(1) - (4)].integer)), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 98:
#line 1556 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[(1) - (1)].integer), NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[(1) - (1)].integer);
      }
    break;

  case 99:
#line 1566 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[(1) - (1)].double_), NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
    break;

  case 100:
#line 1575 "grammar.y"
    {
        SIZED_STRING* sized_string;

        compiler->last_result = yr_arena_write_data(
            compiler->sz_arena,
            (yyvsp[(1) - (1)].sized_string),
            (yyvsp[(1) - (1)].sized_string)->length + sizeof(SIZED_STRING),
            (void**) &sized_string);

        yr_free((yyvsp[(1) - (1)].sized_string));

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              PTR_TO_INT64(sized_string),
              NULL,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_STRING;
      }
    break;

  case 101:
#line 1599 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[(1) - (1)].c_string), OP_COUNT, UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 102:
#line 1611 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[(1) - (4)].c_string), OP_OFFSET, UNDEFINED);

        yr_free((yyvsp[(1) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 103:
#line 1623 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[(1) - (1)].c_string), OP_OFFSET, UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 104:
#line 1639 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[(1) - (4)].c_string), OP_LENGTH, UNDEFINED);

        yr_free((yyvsp[(1) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 105:
#line 1651 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[(1) - (1)].c_string), OP_LENGTH, UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 106:
#line 1667 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression).type == EXPRESSION_TYPE_INTEGER)  // loop identifier
        {
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = UNDEFINED;
        }
        else if ((yyvsp[(1) - (1)].expression).type == EXPRESSION_TYPE_BOOLEAN)  // rule identifier
        {
          (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
          (yyval.expression).value.integer = UNDEFINED;
        }
        else if ((yyvsp[(1) - (1)].expression).type == EXPRESSION_TYPE_OBJECT)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch((yyvsp[(1) - (1)].expression).value.object->type)
          {
            case OBJECT_TYPE_INTEGER:
              (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
              (yyval.expression).value.integer = UNDEFINED;
              break;
            case OBJECT_TYPE_FLOAT:
              (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
              break;
            case OBJECT_TYPE_STRING:
              (yyval.expression).type = EXPRESSION_TYPE_STRING;
              break;
            default:
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  (yyvsp[(1) - (1)].expression).identifier);
              compiler->last_result = ERROR_WRONG_TYPE;
          }
        }
        else
        {
          assert(FALSE);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 107:
#line 1711 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(2) - (2)].expression), EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT, "-");

        if ((yyvsp[(2) - (2)].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = ((yyvsp[(2) - (2)].expression).value.integer == UNDEFINED) ?
              UNDEFINED : -((yyvsp[(2) - (2)].expression).value.integer);
          compiler->last_result = yr_parser_emit(yyscanner, OP_INT_MINUS, NULL);
        }
        else if ((yyvsp[(2) - (2)].expression).type == EXPRESSION_TYPE_FLOAT)
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
          compiler->last_result = yr_parser_emit(yyscanner, OP_DBL_MINUS, NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 108:
#line 1730 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "+", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[(3) - (3)].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(+, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
    break;

  case 109:
#line 1748 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "-", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[(3) - (3)].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(-, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
    break;

  case 110:
#line 1766 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "*", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[(3) - (3)].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(*, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
    break;

  case 111:
#line 1784 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "\\", (yyvsp[(1) - (3)].expression), (yyvsp[(3) - (3)].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[(3) - (3)].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          if ((yyvsp[(3) - (3)].expression).value.integer != 0)
          {
            (yyval.expression).value.integer = OPERATION(/, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
            (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          }
          else
          {
            compiler->last_result = ERROR_DIVISION_BY_ZERO;
            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
    break;

  case 112:
#line 1810 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        if ((yyvsp[(3) - (3)].expression).value.integer != 0)
        {
          (yyval.expression).value.integer = OPERATION(%, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          compiler->last_result = ERROR_DIVISION_BY_ZERO;
          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
      }
    break;

  case 113:
#line 1828 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 114:
#line 1838 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 115:
#line 1848 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 116:
#line 1858 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(2) - (2)].expression), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[(2) - (2)].expression).value.integer == UNDEFINED) ?
            UNDEFINED : ~((yyvsp[(2) - (2)].expression).value.integer);
      }
    break;

  case 117:
#line 1868 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(<<, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 118:
#line 1878 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(>>, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 119:
#line 1888 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(1) - (1)].expression);
      }
    break;


/* Line 1267 of yacc.c.  */
#line 3691 "grammar.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (yyscanner, compiler, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yyscanner, compiler, yymsg);
	  }
	else
	  {
	    yyerror (yyscanner, compiler, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, yyscanner, compiler);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
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
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
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
		  yystos[yystate], yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

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

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, compiler, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, yyscanner, compiler);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 1893 "grammar.y"


