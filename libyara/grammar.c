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
     _RULE_ = 258,
     _PRIVATE_ = 259,
     _GLOBAL_ = 260,
     _META_ = 261,
     _STRINGS_ = 262,
     _CONDITION_ = 263,
     _IDENTIFIER_ = 264,
     _STRING_IDENTIFIER_ = 265,
     _STRING_COUNT_ = 266,
     _STRING_OFFSET_ = 267,
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 268,
     _NUMBER_ = 269,
     _INTEGER_FUNCTION_ = 270,
     _TEXT_STRING_ = 271,
     _HEX_STRING_ = 272,
     _REGEXP_ = 273,
     _ASCII_ = 274,
     _WIDE_ = 275,
     _NOCASE_ = 276,
     _FULLWORD_ = 277,
     _AT_ = 278,
     _FILESIZE_ = 279,
     _ENTRYPOINT_ = 280,
     _ALL_ = 281,
     _ANY_ = 282,
     _IN_ = 283,
     _OF_ = 284,
     _FOR_ = 285,
     _THEM_ = 286,
     _MATCHES_ = 287,
     _CONTAINS_ = 288,
     _IMPORT_ = 289,
     _TRUE_ = 290,
     _FALSE_ = 291,
     _OR_ = 292,
     _AND_ = 293,
     _IS_ = 294,
     _NEQ_ = 295,
     _EQ_ = 296,
     _GE_ = 297,
     _GT_ = 298,
     _LE_ = 299,
     _LT_ = 300,
     _SHIFT_RIGHT_ = 301,
     _SHIFT_LEFT_ = 302,
     _NOT_ = 303
   };
#endif
/* Tokens.  */
#define _RULE_ 258
#define _PRIVATE_ 259
#define _GLOBAL_ 260
#define _META_ 261
#define _STRINGS_ 262
#define _CONDITION_ 263
#define _IDENTIFIER_ 264
#define _STRING_IDENTIFIER_ 265
#define _STRING_COUNT_ 266
#define _STRING_OFFSET_ 267
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 268
#define _NUMBER_ 269
#define _INTEGER_FUNCTION_ 270
#define _TEXT_STRING_ 271
#define _HEX_STRING_ 272
#define _REGEXP_ 273
#define _ASCII_ 274
#define _WIDE_ 275
#define _NOCASE_ 276
#define _FULLWORD_ 277
#define _AT_ 278
#define _FILESIZE_ 279
#define _ENTRYPOINT_ 280
#define _ALL_ 281
#define _ANY_ 282
#define _IN_ 283
#define _OF_ 284
#define _FOR_ 285
#define _THEM_ 286
#define _MATCHES_ 287
#define _CONTAINS_ 288
#define _IMPORT_ 289
#define _TRUE_ 290
#define _FALSE_ 291
#define _OR_ 292
#define _AND_ 293
#define _IS_ 294
#define _NEQ_ 295
#define _EQ_ 296
#define _GE_ 297
#define _GT_ 298
#define _LE_ 299
#define _LT_ 300
#define _SHIFT_RIGHT_ 301
#define _SHIFT_LEFT_ 302
#define _NOT_ 303




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

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define EXPRESSION_TYPE_BOOLEAN   1
#define EXPRESSION_TYPE_INTEGER   2
#define EXPRESSION_TYPE_STRING    3
#define EXPRESSION_TYPE_REGEXP    4
#define EXPRESSION_TYPE_OBJECT    5


#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \


#define CHECK_TYPE_WITH_CLEANUP(expression, expected_type, op, cleanup) \
    if (expression.type != expected_type) \
    { \
      switch(expression.type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
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
      cleanup; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }


#define CHECK_TYPE(expression, expected_type, op) \
    CHECK_TYPE_WITH_CLEANUP(expression, expected_type, op, ) \


#define MSG(op)  "wrong type \"string\" for \"" op "\" operator"



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
#line 187 "grammar.y"
{
  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
}
/* Line 193 of yacc.c.  */
#line 284 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 297 "grammar.c"

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
#define YYLAST   334

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  69
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  35
/* YYNRULES -- Number of rules.  */
#define YYNRULES  111
/* YYNRULES -- Number of states.  */
#define YYNSTATES  197

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   304

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    55,    39,     2,
      66,    67,    53,    51,    68,    52,    63,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    61,     2,
       2,    62,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    64,    54,    65,    41,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    59,    40,    60,    57,     2,     2,     2,
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
      35,    36,    37,    38,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    56,    58
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    14,    18,    22,    25,
      35,    36,    40,    41,    45,    49,    50,    53,    55,    57,
      58,    61,    63,    66,    68,    71,    75,    79,    83,    87,
      89,    92,    97,    98,   104,   108,   109,   112,   114,   116,
     118,   120,   122,   126,   131,   136,   137,   139,   143,   145,
     147,   149,   151,   155,   159,   161,   165,   169,   170,   171,
     183,   184,   194,   198,   201,   205,   209,   213,   217,   221,
     225,   229,   233,   237,   239,   243,   247,   249,   256,   258,
     262,   263,   268,   270,   272,   276,   278,   280,   282,   284,
     286,   290,   292,   294,   299,   301,   303,   305,   310,   312,
     314,   318,   322,   326,   330,   334,   338,   342,   346,   349,
     353,   357
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      70,     0,    -1,    -1,    70,    72,    -1,    70,    71,    -1,
      70,     1,    72,    -1,    70,     1,    71,    -1,    70,     1,
      58,    -1,    34,    16,    -1,    76,     3,     9,    78,    59,
      73,    74,    75,    60,    -1,    -1,     6,    61,    80,    -1,
      -1,     7,    61,    82,    -1,     8,    61,    90,    -1,    -1,
      76,    77,    -1,     4,    -1,     5,    -1,    -1,    61,    79,
      -1,     9,    -1,    79,     9,    -1,    81,    -1,    80,    81,
      -1,     9,    62,    16,    -1,     9,    62,    14,    -1,     9,
      62,    35,    -1,     9,    62,    36,    -1,    83,    -1,    82,
      83,    -1,    10,    62,    16,    85,    -1,    -1,    10,    62,
      84,    18,    85,    -1,    10,    62,    17,    -1,    -1,    85,
      86,    -1,    20,    -1,    19,    -1,    21,    -1,    22,    -1,
       9,    -1,    87,    63,     9,    -1,    87,    64,   103,    65,
      -1,    87,    66,    88,    67,    -1,    -1,    91,    -1,    88,
      68,    91,    -1,    18,    -1,    91,    -1,    35,    -1,    36,
      -1,   103,    32,    89,    -1,   103,    33,   103,    -1,    10,
      -1,    10,    23,   103,    -1,    10,    28,    96,    -1,    -1,
      -1,    30,   102,     9,    28,    92,    95,    61,    93,    66,
      90,    67,    -1,    -1,    30,   102,    29,    98,    61,    94,
      66,    90,    67,    -1,   102,    29,    98,    -1,    56,    90,
      -1,    90,    38,    90,    -1,    90,    37,    90,    -1,   103,
      48,   103,    -1,   103,    46,   103,    -1,   103,    47,   103,
      -1,   103,    45,   103,    -1,   103,    44,   103,    -1,   103,
      42,   103,    -1,   103,    43,   103,    -1,   103,    -1,    66,
      91,    67,    -1,    66,    97,    67,    -1,    96,    -1,    66,
     103,    63,    63,   103,    67,    -1,   103,    -1,    97,    68,
     103,    -1,    -1,    66,    99,   100,    67,    -1,    31,    -1,
     101,    -1,   100,    68,   101,    -1,    10,    -1,    13,    -1,
     103,    -1,    26,    -1,    27,    -1,    66,   103,    67,    -1,
      24,    -1,    25,    -1,    15,    66,   103,    67,    -1,    14,
      -1,    16,    -1,    11,    -1,    12,    64,   103,    65,    -1,
      12,    -1,    87,    -1,   103,    51,   103,    -1,   103,    52,
     103,    -1,   103,    53,   103,    -1,   103,    54,   103,    -1,
     103,    55,   103,    -1,   103,    41,   103,    -1,   103,    39,
     103,    -1,   103,    40,   103,    -1,    57,   103,    -1,   103,
      50,   103,    -1,   103,    49,   103,    -1,    89,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   199,   199,   201,   202,   203,   204,   205,   210,   222,
     241,   244,   272,   276,   304,   309,   310,   315,   316,   322,
     325,   343,   356,   393,   394,   399,   415,   428,   441,   458,
     459,   464,   478,   477,   496,   513,   514,   519,   520,   521,
     522,   527,   615,   663,   723,   770,   773,   795,   828,   873,
     890,   899,   908,   923,   937,   951,   967,   982,  1017,   981,
    1131,  1130,  1209,  1215,  1221,  1227,  1235,  1244,  1253,  1262,
    1271,  1298,  1325,  1352,  1356,  1364,  1365,  1370,  1392,  1404,
    1420,  1419,  1425,  1434,  1435,  1440,  1445,  1454,  1455,  1459,
    1467,  1471,  1481,  1495,  1511,  1521,  1544,  1559,  1574,  1596,
    1637,  1647,  1657,  1667,  1677,  1687,  1697,  1707,  1717,  1727,
    1737,  1747
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_", "_INTEGER_FUNCTION_",
  "_TEXT_STRING_", "_HEX_STRING_", "_REGEXP_", "_ASCII_", "_WIDE_",
  "_NOCASE_", "_FULLWORD_", "_AT_", "_FILESIZE_", "_ENTRYPOINT_", "_ALL_",
  "_ANY_", "_IN_", "_OF_", "_FOR_", "_THEM_", "_MATCHES_", "_CONTAINS_",
  "_IMPORT_", "_TRUE_", "_FALSE_", "_OR_", "_AND_", "'&'", "'|'", "'^'",
  "_IS_", "_NEQ_", "_EQ_", "_GE_", "_GT_", "_LE_", "_LT_", "_SHIFT_RIGHT_",
  "_SHIFT_LEFT_", "'+'", "'-'", "'*'", "'\\\\'", "'%'", "_NOT_", "'~'",
  "\"include\"", "'{'", "'}'", "':'", "'='", "'.'", "'['", "']'", "'('",
  "')'", "','", "$accept", "rules", "import", "rule", "meta", "strings",
  "condition", "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "@1", "string_modifiers", "string_modifier",
  "identifier", "arguments_list", "regexp", "boolean_expression",
  "expression", "@2", "@3", "@4", "integer_set", "range",
  "integer_enumeration", "string_set", "@5", "string_enumeration",
  "string_enumeration_item", "for_expression", "primary_expression", 0
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
     285,   286,   287,   288,   289,   290,   291,   292,   293,    38,
     124,    94,   294,   295,   296,   297,   298,   299,   300,   301,
     302,    43,    45,    42,    92,    37,   303,   126,   304,   123,
     125,    58,    61,    46,    91,    93,    40,    41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    69,    70,    70,    70,    70,    70,    70,    71,    72,
      73,    73,    74,    74,    75,    76,    76,    77,    77,    78,
      78,    79,    79,    80,    80,    81,    81,    81,    81,    82,
      82,    83,    84,    83,    83,    85,    85,    86,    86,    86,
      86,    87,    87,    87,    87,    88,    88,    88,    89,    90,
      91,    91,    91,    91,    91,    91,    91,    92,    93,    91,
      94,    91,    91,    91,    91,    91,    91,    91,    91,    91,
      91,    91,    91,    91,    91,    95,    95,    96,    97,    97,
      99,    98,    98,   100,   100,   101,   101,   102,   102,   102,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,   103
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     9,
       0,     3,     0,     3,     3,     0,     2,     1,     1,     0,
       2,     1,     2,     1,     2,     3,     3,     3,     3,     1,
       2,     4,     0,     5,     3,     0,     2,     1,     1,     1,
       1,     1,     3,     4,     4,     0,     1,     3,     1,     1,
       1,     1,     3,     3,     1,     3,     3,     0,     0,    11,
       0,     9,     3,     2,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     1,     3,     3,     1,     6,     1,     3,
       0,     4,     1,     1,     3,     1,     1,     1,     1,     1,
       3,     1,     1,     4,     1,     1,     1,     4,     1,     1,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     3,
       3,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    15,     0,     4,     3,     0,     7,     6,
       5,     8,     0,    17,    18,    16,    19,     0,     0,    21,
      20,    10,    22,     0,    12,     0,     0,     0,     0,    11,
      23,     0,     0,     0,     0,    24,     0,    13,    29,     0,
       9,    26,    25,    27,    28,    32,    30,    41,    54,    96,
      98,    94,     0,    95,    48,    91,    92,    88,    89,     0,
      50,    51,     0,     0,     0,    99,   111,    14,    49,     0,
      73,    35,    34,     0,     0,     0,     0,     0,     0,     0,
      87,    63,   108,     0,    49,    73,     0,     0,    45,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    31,    35,    55,     0,    56,     0,     0,     0,     0,
       0,    74,    90,    42,     0,     0,    46,    65,    64,    82,
      80,    62,    52,    53,   106,   107,   105,    71,    72,    70,
      69,    67,    68,    66,   110,   109,   100,   101,   102,   103,
     104,    38,    37,    39,    40,    36,    33,     0,    97,    93,
      57,     0,    43,    44,     0,     0,     0,     0,    60,    47,
      85,    86,     0,    83,     0,     0,     0,    76,     0,    81,
       0,     0,     0,    78,    58,     0,    84,    77,    75,     0,
       0,     0,    79,     0,    61,     0,    59
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    24,    27,    33,     7,    15,    18,
      20,    29,    30,    37,    38,    73,   111,   155,    65,   125,
      66,    83,    68,   167,   190,   178,   176,   115,   182,   131,
     165,   172,   173,    69,    70
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -62
static const yytype_int16 yypact[] =
{
     -62,     7,   -62,   -28,   -15,   -62,   -62,    85,   -62,   -62,
     -62,   -62,    13,   -62,   -62,   -62,   -37,    19,   -17,   -62,
      45,    67,   -62,    21,    79,   104,    59,   108,    62,   104,
     -62,   121,    72,    74,    17,   -62,    70,   121,   -62,    69,
     -62,   -62,   -62,   -62,   -62,    75,   -62,   -62,    -8,   -62,
      81,   -62,    82,   -62,   -62,   -62,   -62,   -62,   -62,   103,
     -62,   -62,    69,   141,    69,    11,   -62,    60,   -62,   118,
     227,   -62,   -62,   131,   141,    92,   141,   141,   141,     0,
     278,   -62,   -62,    60,    94,   135,   153,   141,    69,    69,
      69,   -29,   145,   141,   141,   141,   141,   141,   141,   141,
     141,   141,   141,   141,   141,   141,   141,   141,   141,   141,
     141,    -3,   -62,   278,   141,   -62,   244,   160,   179,   142,
     -29,   -62,   -62,   -62,   251,    39,    71,   133,   -62,   -62,
     -62,   -62,   -62,   278,    89,    89,    89,   278,   278,   278,
     278,   278,   278,   278,    -7,    -7,    47,    47,   -62,   -62,
     -62,   -62,   -62,   -62,   -62,   -62,    -3,   271,   -62,   -62,
     -62,   111,   -62,   -62,    69,    22,   110,   125,   -62,    71,
     -62,   -62,    43,   -62,   141,   141,   132,   -62,   126,   -62,
      22,   198,    55,   271,   -62,    69,   -62,   -62,   -62,   141,
     128,   -33,   278,    69,   -62,   -24,   -62
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -62,   -62,   192,   193,   -62,   -62,   -62,   -62,   -62,   -62,
     -62,   -62,   168,   -62,   166,   -62,    93,   -62,   -62,   -62,
     112,   -39,   -61,   -62,   -62,   -62,   -62,    41,   -62,    86,
     -62,   -62,    36,   158,   -38
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -88
static const yytype_int16 yytable[] =
{
      67,    11,   129,    84,    89,    90,     4,     2,     3,   119,
     -15,   -15,   -15,    89,    90,    74,   151,   152,   153,   154,
      75,    80,    16,    81,    17,    82,    85,   126,    19,   120,
       8,    41,   170,    42,   194,   171,   113,   130,   116,   117,
     118,     4,    21,   196,   106,   107,   108,   109,   110,   124,
     127,   128,    43,    44,    22,   133,   134,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,    23,    86,    87,   157,    88,    47,    48,
      49,    50,    25,    51,    52,    53,    26,    54,    12,    13,
      14,    71,    72,    55,    56,    57,    58,    89,    90,    59,
     108,   109,   110,   169,    60,    61,   163,   164,   -49,   -49,
     179,   180,    47,    28,    49,    50,    32,    51,    52,    53,
      31,    54,   188,   189,    34,    62,    63,    55,    56,    57,
      58,    36,    45,    39,    40,    64,   181,   183,   104,   105,
     106,   107,   108,   109,   110,    76,   191,    91,    77,   112,
      47,   192,    49,    50,   195,    51,    52,    53,   114,    54,
      63,   121,   123,    54,   -87,    55,    56,    92,    93,    78,
     160,    90,   168,   174,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,   106,   107,   108,   109,
     110,   175,   185,   184,   193,     9,    10,    35,    63,    94,
      95,    96,   122,    46,   132,   156,   161,    78,   177,   104,
     105,   106,   107,   108,   109,   110,   186,    79,    94,    95,
      96,     0,     0,     0,     0,     0,     0,   159,   104,   105,
     106,   107,   108,   109,   110,     0,     0,    94,    95,    96,
       0,     0,     0,     0,     0,     0,   122,   104,   105,   106,
     107,   108,   109,   110,     0,     0,   -87,     0,     0,    92,
      93,     0,     0,     0,     0,   187,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     108,   109,   110,    94,    95,    96,     0,     0,     0,     0,
      94,    95,    96,   104,   105,   106,   107,   108,   109,   110,
     104,   105,   106,   107,   108,   109,   110,     0,     0,   158,
      94,    95,    96,     0,     0,     0,   162,    94,    95,    96,
     104,   105,   106,   107,   108,   109,   110,   104,   105,   106,
     107,   108,   109,   110,   166
};

static const yytype_int16 yycheck[] =
{
      39,    16,    31,    64,    37,    38,    34,     0,     1,     9,
       3,     4,     5,    37,    38,    23,    19,    20,    21,    22,
      28,    59,     9,    62,    61,    63,    64,    88,     9,    29,
      58,    14,    10,    16,    67,    13,    74,    66,    76,    77,
      78,    34,    59,    67,    51,    52,    53,    54,    55,    87,
      89,    90,    35,    36,     9,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     108,   109,   110,     6,    63,    64,   114,    66,     9,    10,
      11,    12,    61,    14,    15,    16,     7,    18,     3,     4,
       5,    16,    17,    24,    25,    26,    27,    37,    38,    30,
      53,    54,    55,   164,    35,    36,    67,    68,    37,    38,
      67,    68,     9,     9,    11,    12,     8,    14,    15,    16,
      61,    18,    67,    68,    62,    56,    57,    24,    25,    26,
      27,    10,    62,    61,    60,    66,   174,   175,    49,    50,
      51,    52,    53,    54,    55,    64,   185,    29,    66,    18,
       9,   189,    11,    12,   193,    14,    15,    16,    66,    18,
      57,    67,     9,    18,    29,    24,    25,    32,    33,    66,
      28,    38,    61,    63,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    66,    66,    61,    66,     3,     3,    29,    57,    39,
      40,    41,    67,    37,    92,   112,   120,    66,   167,    49,
      50,    51,    52,    53,    54,    55,   180,    59,    39,    40,
      41,    -1,    -1,    -1,    -1,    -1,    -1,    67,    49,    50,
      51,    52,    53,    54,    55,    -1,    -1,    39,    40,    41,
      -1,    -1,    -1,    -1,    -1,    -1,    67,    49,    50,    51,
      52,    53,    54,    55,    -1,    -1,    29,    -1,    -1,    32,
      33,    -1,    -1,    -1,    -1,    67,    39,    40,    41,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    39,    40,    41,    -1,    -1,    -1,    -1,
      39,    40,    41,    49,    50,    51,    52,    53,    54,    55,
      49,    50,    51,    52,    53,    54,    55,    -1,    -1,    65,
      39,    40,    41,    -1,    -1,    -1,    65,    39,    40,    41,
      49,    50,    51,    52,    53,    54,    55,    49,    50,    51,
      52,    53,    54,    55,    63
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    70,     0,     1,    34,    71,    72,    76,    58,    71,
      72,    16,     3,     4,     5,    77,     9,    61,    78,     9,
      79,    59,     9,     6,    73,    61,     7,    74,     9,    80,
      81,    61,     8,    75,    62,    81,    10,    82,    83,    61,
      60,    14,    16,    35,    36,    62,    83,     9,    10,    11,
      12,    14,    15,    16,    18,    24,    25,    26,    27,    30,
      35,    36,    56,    57,    66,    87,    89,    90,    91,   102,
     103,    16,    17,    84,    23,    28,    64,    66,    66,   102,
     103,    90,   103,    90,    91,   103,    63,    64,    66,    37,
      38,    29,    32,    33,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    85,    18,   103,    66,    96,   103,   103,   103,     9,
      29,    67,    67,     9,   103,    88,    91,    90,    90,    31,
      66,    98,    89,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,    19,    20,    21,    22,    86,    85,   103,    65,    67,
      28,    98,    65,    67,    68,    99,    63,    92,    61,    91,
      10,    13,   100,   101,    63,    66,    95,    96,    94,    67,
      68,   103,    97,   103,    61,    66,   101,    67,    67,    68,
      93,    90,   103,    66,    67,    90,    67
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
      case 9: /* "_IDENTIFIER_" */
#line 178 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1419 "grammar.c"
	break;
      case 10: /* "_STRING_IDENTIFIER_" */
#line 179 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1424 "grammar.c"
	break;
      case 11: /* "_STRING_COUNT_" */
#line 180 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1429 "grammar.c"
	break;
      case 12: /* "_STRING_OFFSET_" */
#line 181 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1434 "grammar.c"
	break;
      case 13: /* "_STRING_IDENTIFIER_WITH_WILDCARD_" */
#line 182 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1439 "grammar.c"
	break;
      case 16: /* "_TEXT_STRING_" */
#line 183 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1444 "grammar.c"
	break;
      case 17: /* "_HEX_STRING_" */
#line 184 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1449 "grammar.c"
	break;
      case 18: /* "_REGEXP_" */
#line 185 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1454 "grammar.c"
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
#line 211 "grammar.y"
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[(2) - (2)].sized_string));

        yr_free((yyvsp[(2) - (2)].sized_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
    break;

  case 9:
#line 223 "grammar.y"
    {
        int result = yr_parser_reduce_rule_declaration(
            yyscanner,
            (yyvsp[(1) - (9)].integer),
            (yyvsp[(3) - (9)].c_string),
            (yyvsp[(4) - (9)].c_string),
            (yyvsp[(7) - (9)].string),
            (yyvsp[(6) - (9)].meta));

        yr_free((yyvsp[(3) - (9)].c_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
    break;

  case 10:
#line 241 "grammar.y"
    {
        (yyval.meta) = NULL;
      }
    break;

  case 11:
#line 245 "grammar.y"
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

  case 12:
#line 272 "grammar.y"
    {
        (yyval.string) = NULL;
        compiler->current_rule_strings = (yyval.string);
      }
    break;

  case 13:
#line 277 "grammar.y"
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

        compiler->current_rule_strings = (yyvsp[(3) - (3)].string);
        (yyval.string) = (yyvsp[(3) - (3)].string);
      }
    break;

  case 15:
#line 309 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 16:
#line 310 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 17:
#line 315 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
    break;

  case 18:
#line 316 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
    break;

  case 19:
#line 322 "grammar.y"
    {
        (yyval.c_string) = NULL;
      }
    break;

  case 20:
#line 326 "grammar.y"
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

  case 21:
#line 344 "grammar.y"
    {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[(1) - (1)].c_string), &identifier);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
      }
    break;

  case 22:
#line 357 "grammar.y"
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

  case 23:
#line 393 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (1)].meta); }
    break;

  case 24:
#line 394 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (2)].meta); }
    break;

  case 25:
#line 400 "grammar.y"
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

  case 26:
#line 416 "grammar.y"
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

  case 27:
#line 429 "grammar.y"
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

  case 28:
#line 442 "grammar.y"
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

  case 29:
#line 458 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 30:
#line 459 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (2)].string); }
    break;

  case 31:
#line 465 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            (yyvsp[(4) - (4)].integer),
            (yyvsp[(1) - (4)].c_string),
            (yyvsp[(3) - (4)].sized_string));

        yr_free((yyvsp[(1) - (4)].c_string));
        yr_free((yyvsp[(3) - (4)].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
    break;

  case 32:
#line 478 "grammar.y"
    {
        compiler->error_line = yyget_lineno(yyscanner);
      }
    break;

  case 33:
#line 482 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            (yyvsp[(5) - (5)].integer) | STRING_GFLAGS_REGEXP,
            (yyvsp[(1) - (5)].c_string),
            (yyvsp[(4) - (5)].sized_string));

        yr_free((yyvsp[(1) - (5)].c_string));
        yr_free((yyvsp[(4) - (5)].sized_string));

        ERROR_IF((yyval.string) == NULL);

        compiler->error_line = 0;
      }
    break;

  case 34:
#line 497 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            STRING_GFLAGS_HEXADECIMAL,
            (yyvsp[(1) - (3)].c_string),
            (yyvsp[(3) - (3)].sized_string));

        yr_free((yyvsp[(1) - (3)].c_string));
        yr_free((yyvsp[(3) - (3)].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
    break;

  case 35:
#line 513 "grammar.y"
    { (yyval.integer) = 0; }
    break;

  case 36:
#line 514 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 37:
#line 519 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_WIDE; }
    break;

  case 38:
#line 520 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_ASCII; }
    break;

  case 39:
#line 521 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
    break;

  case 40:
#line 522 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
    break;

  case 41:
#line 528 "grammar.y"
    {
        int var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[(1) - (1)].c_string));

        if (var_index >= 0)
        {
          compiler->last_result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_M,
              LOOP_LOCAL_VARS * var_index,
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
              compiler->objects_table,
              (yyvsp[(1) - (1)].c_string),
              NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            char* ns = compiler->current_namespace->name;

            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[(1) - (1)].c_string),
                ns);
          }

          if (object != NULL)
          {
            char* id;

            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                (yyvsp[(1) - (1)].c_string),
                &id);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  PTR_TO_UINT64(id),
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
                  PTR_TO_UINT64(rule),
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

  case 42:
#line 616 "grammar.y"
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
              compiler->sz_arena,
              (yyvsp[(3) - (3)].c_string),
              &ident);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  PTR_TO_UINT64(ident),
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
              compiler,
              (yyvsp[(1) - (3)].expression).identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free((yyvsp[(3) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 43:
#line 664 "grammar.y"
    {
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
              yyscanner,
              OP_INDEX_ARRAY,
              NULL);

          YR_OBJECT_ARRAY* array = (YR_OBJECT_ARRAY*) (yyvsp[(1) - (4)].expression).value.object;

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
              yyscanner,
              OP_LOOKUP_DICT,
              NULL);

          YR_OBJECT_DICTIONARY* dict = (YR_OBJECT_DICTIONARY*) (yyvsp[(1) - (4)].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = dict->prototype_item;
          (yyval.expression).identifier = dict->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[(1) - (4)].expression).identifier);

          compiler->last_result = ERROR_NOT_INDEXABLE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 44:
#line 724 "grammar.y"
    {
        char* args_fmt;

        if ((yyvsp[(1) - (4)].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[(1) - (4)].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].expression).value.object, (yyvsp[(3) - (4)].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena,
              (yyvsp[(3) - (4)].c_string),
              &args_fmt);

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                PTR_TO_UINT64(args_fmt),
                NULL);

          YR_OBJECT_FUNCTION* function = (YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = function->return_obj;
          (yyval.expression).identifier = function->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[(1) - (4)].expression).identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[(3) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 45:
#line 770 "grammar.y"
    {
        (yyval.c_string) = yr_strdup("");
      }
    break;

  case 46:
#line 774 "grammar.y"
    {
        (yyval.c_string) = (char*) yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch((yyvsp[(1) - (1)].expression).type)
        {
          case EXPRESSION_TYPE_INTEGER:
            strlcpy((yyval.c_string), "i", MAX_FUNCTION_ARGS);
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

  case 47:
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

  case 48:
#line 829 "grammar.y"
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
              PTR_TO_UINT64(re->root_node->forward_code),
              NULL);

        yr_re_destroy(re);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_REGEXP;
      }
    break;

  case 49:
#line 874 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_STR_TO_BOOL,
              NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 50:
#line 891 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 51:
#line 900 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 52:
#line 909 "grammar.y"
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

  case 53:
#line 924 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_STRING, "contains");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner,
            OP_CONTAINS,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 54:
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

  case 55:
#line 952 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "at");

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (3)].c_string),
            OP_FOUND_AT,
            (yyvsp[(3) - (3)].expression).value.integer);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 56:
#line 968 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (3)].c_string),
            OP_FOUND_IN,
            UNDEFINED);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 57:
#line 982 "grammar.y"
    {
        int var_index;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner,
            (yyvsp[(3) - (4)].c_string));

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[(3) - (4)].c_string));

          compiler->last_result = \
              ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // Push end-of-list marker
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            UNDEFINED,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 58:
#line 1017 "grammar.y"
    {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        int8_t* addr;

        // Clear counter for number of expressions evaluating
        // to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

        // Clear iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

        if ((yyvsp[(6) - (7)].integer) == INTEGER_SET_ENUMERATION)
        {
          // Pop the first integer
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, &addr);
        }
        else // INTEGER_SET_RANGE
        {
          // Pop higher bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset + 3, &addr);

          // Pop lower bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, NULL);
        }

        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = (yyvsp[(3) - (7)].c_string);
        compiler->loop_depth++;
      }
    break;

  case 59:
#line 1052 "grammar.y"
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
            yyscanner, OP_ADD_M, mem_offset + 1, NULL);

        // Increment iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL);

        if ((yyvsp[(6) - (11)].integer) == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              PTR_TO_UINT64(
                  compiler->loop_address[compiler->loop_depth]),
              NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Increment lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_INCR_M, mem_offset, NULL);

          // Push lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset, NULL);

          // Push higher bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset + 3, NULL);

          // Compare higher bound with lower bound, do loop again
          // if lower bound is still lower or equal than higher bound
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JLE,
              PTR_TO_UINT64(
                compiler->loop_address[compiler->loop_depth]),
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
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

        yr_parser_emit(yyscanner, OP_LE, NULL);

        compiler->loop_identifier[compiler->loop_depth] = NULL;
        yr_free((yyvsp[(3) - (11)].c_string));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 60:
#line 1131 "grammar.y"
    {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        int8_t* addr;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          compiler->last_result = \
            ERROR_NESTED_FOR_OF_LOOP;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, mem_offset, &addr);

        compiler->loop_for_of_mem_offset = mem_offset;
        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = NULL;
        compiler->loop_depth++;
      }
    break;

  case 61:
#line 1161 "grammar.y"
    {
        int mem_offset;

        compiler->loop_depth--;
        compiler->loop_for_of_mem_offset = -1;

        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // Increment counter by the value returned by the
        // boolean expression (0 or 1). If the boolean expression
        // returned UNDEFINED the OP_ADD_M won't do anything.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL);

        // Increment iterations counter.
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL);

        // If next string is not undefined, go back to the
        // begining of the loop.
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JNUNDEF,
            PTR_TO_UINT64(
                compiler->loop_address[compiler->loop_depth]),
            NULL);

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at top of the stack. Check if the quantifier is
        // undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

        yr_parser_emit(yyscanner, OP_LE, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;

      }
    break;

  case 62:
#line 1210 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 63:
#line 1216 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 64:
#line 1222 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_AND, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 65:
#line 1228 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_BOOLEAN, "or");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 66:
#line 1236 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<");

        yr_parser_emit(yyscanner, OP_LT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 67:
#line 1245 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">");

        yr_parser_emit(yyscanner, OP_GT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 68:
#line 1254 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<=");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<=");

        yr_parser_emit(yyscanner, OP_LE, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 69:
#line 1263 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">=");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">=");

        yr_parser_emit(yyscanner, OP_GE, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 70:
#line 1272 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression).type != (yyvsp[(3) - (3)].expression).type)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_STR_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 71:
#line 1299 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression).type != (yyvsp[(3) - (3)].expression).type)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_STR_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 72:
#line 1326 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression).type != (yyvsp[(3) - (3)].expression).type)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for != operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_STR_NEQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_NEQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 73:
#line 1353 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(1) - (1)].expression);
      }
    break;

  case 74:
#line 1357 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(2) - (3)].expression);
      }
    break;

  case 75:
#line 1364 "grammar.y"
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
    break;

  case 76:
#line 1365 "grammar.y"
    { (yyval.integer) = INTEGER_SET_RANGE; }
    break;

  case 77:
#line 1371 "grammar.y"
    {
        if ((yyvsp[(2) - (6)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[(5) - (6)].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 78:
#line 1393 "grammar.y"
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

  case 79:
#line 1405 "grammar.y"
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

  case 80:
#line 1420 "grammar.y"
    {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
    break;

  case 82:
#line 1426 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");
      }
    break;

  case 85:
#line 1441 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));
      }
    break;

  case 86:
#line 1446 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));
      }
    break;

  case 88:
#line 1456 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
    break;

  case 89:
#line 1460 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL);
      }
    break;

  case 90:
#line 1468 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(2) - (3)].expression);
      }
    break;

  case 91:
#line 1472 "grammar.y"
    {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 92:
#line 1482 "grammar.y"
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

  case 93:
#line 1496 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression), EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_INT results
        // in the proper OP_INTXX opcode.

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT + (yyvsp[(1) - (4)].integer), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 94:
#line 1512 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[(1) - (1)].integer), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[(1) - (1)].integer);
      }
    break;

  case 95:
#line 1522 "grammar.y"
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
              PTR_TO_UINT64(sized_string),
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_STRING;
      }
    break;

  case 96:
#line 1545 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (1)].c_string),
            OP_COUNT,
            UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 97:
#line 1560 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (4)].c_string),
            OP_OFFSET,
            UNDEFINED);

        yr_free((yyvsp[(1) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 98:
#line 1575 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            1,
            NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner,
              (yyvsp[(1) - (1)].c_string),
              OP_OFFSET,
              UNDEFINED);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
    break;

  case 99:
#line 1597 "grammar.y"
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

  case 100:
#line 1638 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "+");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "+");

        yr_parser_emit(yyscanner, OP_ADD, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(+, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 101:
#line 1648 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "-");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "-");

        yr_parser_emit(yyscanner, OP_SUB, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(-, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 102:
#line 1658 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "*");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "*");

        yr_parser_emit(yyscanner, OP_MUL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(*, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 103:
#line 1668 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "\\");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "\\");

        yr_parser_emit(yyscanner, OP_DIV, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(/, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 104:
#line 1678 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(%, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 105:
#line 1688 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 106:
#line 1698 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 107:
#line 1708 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 108:
#line 1718 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(2) - (2)].expression), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[(2) - (2)].expression).value.integer == UNDEFINED) ?
                              UNDEFINED : (yyvsp[(2) - (2)].expression).value.integer;
      }
    break;

  case 109:
#line 1728 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(<<, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 110:
#line 1738 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE((yyvsp[(3) - (3)].expression), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(>>, (yyvsp[(1) - (3)].expression).value.integer, (yyvsp[(3) - (3)].expression).value.integer);
      }
    break;

  case 111:
#line 1748 "grammar.y"
    {
        (yyval.expression) = (yyvsp[(1) - (1)].expression);
      }
    break;


/* Line 1267 of yacc.c.  */
#line 3505 "grammar.c"
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


#line 1753 "grammar.y"


