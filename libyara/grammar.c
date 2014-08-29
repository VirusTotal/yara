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
     _TEXT_STRING_ = 270,
     _HEX_STRING_ = 271,
     _REGEXP_ = 272,
     _ASCII_ = 273,
     _WIDE_ = 274,
     _NOCASE_ = 275,
     _FULLWORD_ = 276,
     _AT_ = 277,
     _FILESIZE_ = 278,
     _ENTRYPOINT_ = 279,
     _ALL_ = 280,
     _ANY_ = 281,
     _IN_ = 282,
     _OF_ = 283,
     _FOR_ = 284,
     _THEM_ = 285,
     _INT8_ = 286,
     _INT16_ = 287,
     _INT32_ = 288,
     _UINT8_ = 289,
     _UINT16_ = 290,
     _UINT32_ = 291,
     _MATCHES_ = 292,
     _CONTAINS_ = 293,
     _IMPORT_ = 294,
     _TRUE_ = 295,
     _FALSE_ = 296,
     _OR_ = 297,
     _AND_ = 298,
     _IS_ = 299,
     _NEQ_ = 300,
     _EQ_ = 301,
     _GE_ = 302,
     _GT_ = 303,
     _LE_ = 304,
     _LT_ = 305,
     _SHIFT_RIGHT_ = 306,
     _SHIFT_LEFT_ = 307,
     _NOT_ = 308
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
#define _TEXT_STRING_ 270
#define _HEX_STRING_ 271
#define _REGEXP_ 272
#define _ASCII_ 273
#define _WIDE_ 274
#define _NOCASE_ 275
#define _FULLWORD_ 276
#define _AT_ 277
#define _FILESIZE_ 278
#define _ENTRYPOINT_ 279
#define _ALL_ 280
#define _ANY_ 281
#define _IN_ 282
#define _OF_ 283
#define _FOR_ 284
#define _THEM_ 285
#define _INT8_ 286
#define _INT16_ 287
#define _INT32_ 288
#define _UINT8_ 289
#define _UINT16_ 290
#define _UINT32_ 291
#define _MATCHES_ 292
#define _CONTAINS_ 293
#define _IMPORT_ 294
#define _TRUE_ 295
#define _FALSE_ 296
#define _OR_ 297
#define _AND_ 298
#define _IS_ 299
#define _NEQ_ 300
#define _EQ_ 301
#define _GE_ 302
#define _GT_ 303
#define _LE_ 304
#define _LT_ 305
#define _SHIFT_RIGHT_ 306
#define _SHIFT_LEFT_ 307
#define _NOT_ 308




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


#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \


#define CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, cleanup) \
    if (actual_type != expected_type) \
    { \
      switch(actual_type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_STRING: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"string\" for \"" op "\" operator"); \
          break; \
      } \
      compiler->last_result = ERROR_WRONG_TYPE; \
      cleanup; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }

#define CHECK_TYPE(actual_type, expected_type, op) \
    CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, ) \


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
#line 186 "grammar.y"
{
  SIZED_STRING*   sized_string;
  char*           c_string;
  int8_t          expression_type;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
  YR_OBJECT*      object;
}
/* Line 193 of yacc.c.  */
#line 289 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 302 "grammar.c"

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
#define YYLAST   433

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  74
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  35
/* YYNRULES -- Number of rules.  */
#define YYNRULES  115
/* YYNRULES -- Number of states.  */
#define YYNSTATES  216

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   308

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    60,    44,     2,
      71,    72,    58,    56,    73,    57,    68,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    66,     2,
       2,    67,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    69,    59,    70,    46,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    63,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    64,    45,    65,    62,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41,    42,    43,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    61
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    14,    18,    21,    31,
      32,    36,    37,    41,    45,    46,    49,    51,    53,    54,
      57,    59,    62,    64,    67,    71,    75,    79,    83,    85,
      88,    93,    94,   100,   104,   105,   108,   110,   112,   114,
     116,   118,   122,   127,   132,   133,   135,   139,   141,   143,
     145,   147,   151,   155,   157,   161,   165,   166,   167,   179,
     180,   190,   194,   197,   201,   205,   209,   213,   217,   221,
     225,   229,   233,   235,   239,   243,   245,   252,   254,   258,
     259,   264,   266,   268,   272,   274,   276,   278,   280,   282,
     286,   288,   290,   295,   300,   305,   310,   315,   320,   322,
     324,   326,   331,   333,   335,   339,   343,   347,   351,   355,
     359,   363,   367,   370,   374,   378
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      75,     0,    -1,    -1,    75,    77,    -1,    75,    76,    -1,
      75,     1,    77,    -1,    75,     1,    63,    -1,    39,    15,
      -1,    81,     3,     9,    83,    64,    78,    79,    80,    65,
      -1,    -1,     6,    66,    85,    -1,    -1,     7,    66,    87,
      -1,     8,    66,    95,    -1,    -1,    81,    82,    -1,     4,
      -1,     5,    -1,    -1,    66,    84,    -1,     9,    -1,    84,
       9,    -1,    86,    -1,    85,    86,    -1,     9,    67,    15,
      -1,     9,    67,    14,    -1,     9,    67,    40,    -1,     9,
      67,    41,    -1,    88,    -1,    87,    88,    -1,    10,    67,
      15,    90,    -1,    -1,    10,    67,    89,    17,    90,    -1,
      10,    67,    16,    -1,    -1,    90,    91,    -1,    19,    -1,
      18,    -1,    20,    -1,    21,    -1,     9,    -1,    92,    68,
       9,    -1,    92,    69,   108,    70,    -1,    92,    71,    93,
      72,    -1,    -1,    96,    -1,    93,    73,    96,    -1,    17,
      -1,    96,    -1,    40,    -1,    41,    -1,   108,    37,    94,
      -1,   108,    38,   108,    -1,    10,    -1,    10,    22,   108,
      -1,    10,    27,   101,    -1,    -1,    -1,    29,   107,     9,
      27,    97,   100,    66,    98,    71,    95,    72,    -1,    -1,
      29,   107,    28,   103,    66,    99,    71,    95,    72,    -1,
     107,    28,   103,    -1,    61,    95,    -1,    95,    43,    95,
      -1,    95,    42,    95,    -1,   108,    53,   108,    -1,   108,
      51,   108,    -1,   108,    52,   108,    -1,   108,    50,   108,
      -1,   108,    49,   108,    -1,   108,    47,   108,    -1,   108,
      48,   108,    -1,   108,    -1,    71,    96,    72,    -1,    71,
     102,    72,    -1,   101,    -1,    71,   108,    68,    68,   108,
      72,    -1,   108,    -1,   102,    73,   108,    -1,    -1,    71,
     104,   105,    72,    -1,    30,    -1,   106,    -1,   105,    73,
     106,    -1,    10,    -1,    13,    -1,   108,    -1,    25,    -1,
      26,    -1,    71,   108,    72,    -1,    23,    -1,    24,    -1,
      31,    71,   108,    72,    -1,    32,    71,   108,    72,    -1,
      33,    71,   108,    72,    -1,    34,    71,   108,    72,    -1,
      35,    71,   108,    72,    -1,    36,    71,   108,    72,    -1,
      14,    -1,    15,    -1,    11,    -1,    12,    69,   108,    70,
      -1,    12,    -1,    92,    -1,   108,    56,   108,    -1,   108,
      57,   108,    -1,   108,    58,   108,    -1,   108,    59,   108,
      -1,   108,    60,   108,    -1,   108,    46,   108,    -1,   108,
      44,   108,    -1,   108,    45,   108,    -1,    62,   108,    -1,
     108,    55,   108,    -1,   108,    54,   108,    -1,    94,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   199,   199,   201,   202,   203,   204,   209,   221,   240,
     243,   271,   275,   303,   308,   309,   314,   315,   321,   324,
     342,   355,   392,   393,   398,   414,   427,   440,   457,   458,
     463,   477,   476,   493,   510,   511,   516,   517,   518,   519,
     524,   612,   661,   684,   724,   727,   749,   782,   827,   845,
     854,   863,   878,   892,   905,   920,   934,   969,   933,  1080,
    1079,  1156,  1162,  1168,  1174,  1182,  1191,  1200,  1209,  1218,
    1245,  1272,  1299,  1303,  1311,  1312,  1317,  1339,  1351,  1367,
    1366,  1372,  1381,  1382,  1387,  1392,  1401,  1402,  1406,  1414,
    1418,  1427,  1439,  1450,  1461,  1472,  1483,  1494,  1505,  1514,
    1537,  1550,  1563,  1583,  1618,  1627,  1636,  1645,  1654,  1663,
    1672,  1681,  1690,  1698,  1707,  1716
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
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_", "_TEXT_STRING_",
  "_HEX_STRING_", "_REGEXP_", "_ASCII_", "_WIDE_", "_NOCASE_",
  "_FULLWORD_", "_AT_", "_FILESIZE_", "_ENTRYPOINT_", "_ALL_", "_ANY_",
  "_IN_", "_OF_", "_FOR_", "_THEM_", "_INT8_", "_INT16_", "_INT32_",
  "_UINT8_", "_UINT16_", "_UINT32_", "_MATCHES_", "_CONTAINS_", "_IMPORT_",
  "_TRUE_", "_FALSE_", "_OR_", "_AND_", "'&'", "'|'", "'^'", "_IS_",
  "_NEQ_", "_EQ_", "_GE_", "_GT_", "_LE_", "_LT_", "_SHIFT_RIGHT_",
  "_SHIFT_LEFT_", "'+'", "'-'", "'*'", "'\\\\'", "'%'", "_NOT_", "'~'",
  "'include'", "'{'", "'}'", "':'", "'='", "'.'", "'['", "']'", "'('",
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
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,    38,   124,    94,   299,   300,   301,
     302,   303,   304,   305,   306,   307,    43,    45,    42,    92,
      37,   308,   126,   105,   123,   125,    58,    61,    46,    91,
      93,    40,    41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    74,    75,    75,    75,    75,    75,    76,    77,    78,
      78,    79,    79,    80,    81,    81,    82,    82,    83,    83,
      84,    84,    85,    85,    86,    86,    86,    86,    87,    87,
      88,    89,    88,    88,    90,    90,    91,    91,    91,    91,
      92,    92,    92,    92,    93,    93,    93,    94,    95,    96,
      96,    96,    96,    96,    96,    96,    97,    98,    96,    99,
      96,    96,    96,    96,    96,    96,    96,    96,    96,    96,
      96,    96,    96,    96,   100,   100,   101,   102,   102,   104,
     103,   103,   105,   105,   106,   106,   107,   107,   107,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     2,     9,     0,
       3,     0,     3,     3,     0,     2,     1,     1,     0,     2,
       1,     2,     1,     2,     3,     3,     3,     3,     1,     2,
       4,     0,     5,     3,     0,     2,     1,     1,     1,     1,
       1,     3,     4,     4,     0,     1,     3,     1,     1,     1,
       1,     3,     3,     1,     3,     3,     0,     0,    11,     0,
       9,     3,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     1,     3,     3,     1,     6,     1,     3,     0,
       4,     1,     1,     3,     1,     1,     1,     1,     1,     3,
       1,     1,     4,     4,     4,     4,     4,     4,     1,     1,
       1,     4,     1,     1,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     3,     3,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    14,     0,     4,     3,     0,     6,     5,
       7,     0,    16,    17,    15,    18,     0,     0,    20,    19,
       9,    21,     0,    11,     0,     0,     0,     0,    10,    22,
       0,     0,     0,     0,    23,     0,    12,    28,     0,     8,
      25,    24,    26,    27,    31,    29,    40,    53,   100,   102,
      98,    99,    47,    90,    91,    87,    88,     0,     0,     0,
       0,     0,     0,     0,    49,    50,     0,     0,     0,   103,
     115,    13,    48,     0,    72,    34,    33,     0,     0,     0,
       0,     0,     0,    86,     0,     0,     0,     0,     0,     0,
      62,   112,     0,    48,    72,     0,     0,    44,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      30,    34,    54,     0,    55,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    73,    89,    41,     0,     0,
      45,    64,    63,    81,    79,    61,    51,    52,   110,   111,
     109,    70,    71,    69,    68,    66,    67,    65,   114,   113,
     104,   105,   106,   107,   108,    37,    36,    38,    39,    35,
      32,     0,   101,    56,     0,    92,    93,    94,    95,    96,
      97,    42,    43,     0,     0,     0,     0,    59,    46,    84,
      85,     0,    82,     0,     0,     0,    75,     0,    80,     0,
       0,     0,    77,    57,     0,    83,    76,    74,     0,     0,
       0,    78,     0,    60,     0,    58
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    23,    26,    32,     7,    14,    17,
      19,    28,    29,    36,    37,    77,   120,   169,    69,   139,
      70,    92,    72,   186,   209,   197,   195,   124,   201,   145,
     184,   191,   192,    73,    74
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -66
static const yytype_int16 yypact[] =
{
     -66,     6,   -66,   -59,     0,   -66,   -66,    59,   -66,   -66,
     -66,     9,   -66,   -66,   -66,   -44,    16,   -24,   -66,    49,
      81,   -66,    26,    88,    92,    43,   115,    54,    92,   -66,
     116,    63,    66,    -2,   -66,    75,   116,   -66,    79,   -66,
     -66,   -66,   -66,   -66,    82,   -66,   -66,    -8,   -66,    83,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   113,    72,    80,
      84,    94,    96,    97,   -66,   -66,    79,   168,    79,   -42,
     -66,    57,   -66,   125,   205,   -66,   -66,   137,   168,    98,
     168,   168,    -7,   372,   168,   168,   168,   168,   168,   168,
     -66,   -66,    57,   100,   169,   161,   168,    79,    79,    79,
     -29,   156,   168,   168,   168,   168,   168,   168,   168,   168,
     168,   168,   168,   168,   168,   168,   168,   168,   168,   168,
      36,   -66,   372,   168,   -66,   338,   222,   149,   -29,   229,
     251,   258,   280,   287,   309,   -66,   -66,   -66,   345,    34,
      74,   135,   -66,   -66,   -66,   -66,   -66,   372,   104,   104,
     104,   372,   372,   372,   372,   372,   372,   372,   -23,   -23,
      25,    25,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
      36,   365,   -66,   -66,   120,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,    79,    -5,   119,   110,   -66,    74,   -66,
     -66,    60,   -66,   168,   168,   122,   -66,   118,   -66,    -5,
     316,    62,   365,   -66,    79,   -66,   -66,   -66,   168,   123,
     -26,   372,    79,   -66,   -19,   -66
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -66,   -66,   -66,   187,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   165,   -66,   159,   -66,    77,   -66,   -66,   -66,
      95,   -38,   -65,   -66,   -66,   -66,   -66,    19,   -66,   103,
     -66,   -66,    10,   151,   -37
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -87
static const yytype_int16 yytable[] =
{
      71,   143,   127,    93,     8,   189,     2,     3,   190,   -14,
     -14,   -14,    40,    41,    78,    10,    98,    99,    15,    79,
      83,   128,    16,    98,    99,    18,    95,    96,    90,    97,
      91,    94,   140,   115,   116,   117,   118,   119,    42,    43,
      20,   122,   144,   125,   126,     4,   213,   129,   130,   131,
     132,   133,   134,   215,   165,   166,   167,   168,    21,   138,
     141,   142,    11,    12,    13,   147,   148,   149,   150,   151,
     152,   153,   154,   155,   156,   157,   158,   159,   160,   161,
     162,   163,   164,   117,   118,   119,   171,    22,    46,    47,
      48,    49,    24,    50,    51,    25,    52,    75,    76,    98,
      99,    27,    53,    54,    55,    56,   182,   183,    57,    30,
      58,    59,    60,    61,    62,    63,   -48,   -48,   188,    64,
      65,    33,    46,    31,    48,    49,    35,    50,    51,    38,
      52,    39,   198,   199,   207,   208,    53,    54,    55,    56,
      66,    67,    44,    84,    58,    59,    60,    61,    62,    63,
      68,    85,    80,   100,   121,    86,   200,   202,   113,   114,
     115,   116,   117,   118,   119,    87,   210,    88,    89,   123,
     137,   211,   135,    52,   214,    67,   173,    46,    99,    48,
      49,   194,    50,    51,    81,    52,   187,   193,   203,   204,
       9,    53,    54,    34,   212,    45,   146,   -86,   170,    58,
      59,    60,    61,    62,    63,   196,   101,   102,    82,   205,
       0,     0,     0,   103,   104,   105,   106,   107,   108,   109,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
      67,   174,     0,   -86,     0,     0,     0,     0,     0,    81,
       0,   136,   101,   102,     0,     0,     0,     0,     0,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   103,   104,   105,     0,
       0,     0,     0,   103,   104,   105,   113,   114,   115,   116,
     117,   118,   119,   113,   114,   115,   116,   117,   118,   119,
       0,     0,     0,     0,   136,   103,   104,   105,     0,     0,
       0,   175,   103,   104,   105,   113,   114,   115,   116,   117,
     118,   119,   113,   114,   115,   116,   117,   118,   119,     0,
       0,     0,     0,   176,   103,   104,   105,     0,     0,     0,
     177,   103,   104,   105,   113,   114,   115,   116,   117,   118,
     119,   113,   114,   115,   116,   117,   118,   119,     0,     0,
       0,     0,   178,   103,   104,   105,     0,     0,     0,   179,
     103,   104,   105,   113,   114,   115,   116,   117,   118,   119,
     113,   114,   115,   116,   117,   118,   119,     0,     0,     0,
       0,   180,   103,   104,   105,     0,     0,     0,   206,   103,
     104,   105,   113,   114,   115,   116,   117,   118,   119,   113,
     114,   115,   116,   117,   118,   119,     0,     0,   172,   103,
     104,   105,     0,     0,     0,   181,   103,   104,   105,   113,
     114,   115,   116,   117,   118,   119,   113,   114,   115,   116,
     117,   118,   119,   185
};

static const yytype_int16 yycheck[] =
{
      38,    30,     9,    68,    63,    10,     0,     1,    13,     3,
       4,     5,    14,    15,    22,    15,    42,    43,     9,    27,
      57,    28,    66,    42,    43,     9,    68,    69,    66,    71,
      67,    68,    97,    56,    57,    58,    59,    60,    40,    41,
      64,    78,    71,    80,    81,    39,    72,    84,    85,    86,
      87,    88,    89,    72,    18,    19,    20,    21,     9,    96,
      98,    99,     3,     4,     5,   102,   103,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    58,    59,    60,   123,     6,     9,    10,
      11,    12,    66,    14,    15,     7,    17,    15,    16,    42,
      43,     9,    23,    24,    25,    26,    72,    73,    29,    66,
      31,    32,    33,    34,    35,    36,    42,    43,   183,    40,
      41,    67,     9,     8,    11,    12,    10,    14,    15,    66,
      17,    65,    72,    73,    72,    73,    23,    24,    25,    26,
      61,    62,    67,    71,    31,    32,    33,    34,    35,    36,
      71,    71,    69,    28,    17,    71,   193,   194,    54,    55,
      56,    57,    58,    59,    60,    71,   204,    71,    71,    71,
       9,   208,    72,    17,   212,    62,    27,     9,    43,    11,
      12,    71,    14,    15,    71,    17,    66,    68,    66,    71,
       3,    23,    24,    28,    71,    36,   101,    28,   121,    31,
      32,    33,    34,    35,    36,   186,    37,    38,    57,   199,
      -1,    -1,    -1,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      62,   128,    -1,    28,    -1,    -1,    -1,    -1,    -1,    71,
      -1,    72,    37,    38,    -1,    -1,    -1,    -1,    -1,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    44,    45,    46,    -1,
      -1,    -1,    -1,    44,    45,    46,    54,    55,    56,    57,
      58,    59,    60,    54,    55,    56,    57,    58,    59,    60,
      -1,    -1,    -1,    -1,    72,    44,    45,    46,    -1,    -1,
      -1,    72,    44,    45,    46,    54,    55,    56,    57,    58,
      59,    60,    54,    55,    56,    57,    58,    59,    60,    -1,
      -1,    -1,    -1,    72,    44,    45,    46,    -1,    -1,    -1,
      72,    44,    45,    46,    54,    55,    56,    57,    58,    59,
      60,    54,    55,    56,    57,    58,    59,    60,    -1,    -1,
      -1,    -1,    72,    44,    45,    46,    -1,    -1,    -1,    72,
      44,    45,    46,    54,    55,    56,    57,    58,    59,    60,
      54,    55,    56,    57,    58,    59,    60,    -1,    -1,    -1,
      -1,    72,    44,    45,    46,    -1,    -1,    -1,    72,    44,
      45,    46,    54,    55,    56,    57,    58,    59,    60,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    70,    44,
      45,    46,    -1,    -1,    -1,    70,    44,    45,    46,    54,
      55,    56,    57,    58,    59,    60,    54,    55,    56,    57,
      58,    59,    60,    68
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    75,     0,     1,    39,    76,    77,    81,    63,    77,
      15,     3,     4,     5,    82,     9,    66,    83,     9,    84,
      64,     9,     6,    78,    66,     7,    79,     9,    85,    86,
      66,     8,    80,    67,    86,    10,    87,    88,    66,    65,
      14,    15,    40,    41,    67,    88,     9,    10,    11,    12,
      14,    15,    17,    23,    24,    25,    26,    29,    31,    32,
      33,    34,    35,    36,    40,    41,    61,    62,    71,    92,
      94,    95,    96,   107,   108,    15,    16,    89,    22,    27,
      69,    71,   107,   108,    71,    71,    71,    71,    71,    71,
      95,   108,    95,    96,   108,    68,    69,    71,    42,    43,
      28,    37,    38,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      90,    17,   108,    71,   101,   108,   108,     9,    28,   108,
     108,   108,   108,   108,   108,    72,    72,     9,   108,    93,
      96,    95,    95,    30,    71,   103,    94,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,    18,    19,    20,    21,    91,
      90,   108,    70,    27,   103,    72,    72,    72,    72,    72,
      72,    70,    72,    73,   104,    68,    97,    66,    96,    10,
      13,   105,   106,    68,    71,   100,   101,    99,    72,    73,
     108,   102,   108,    66,    71,   106,    72,    72,    73,    98,
      95,   108,    71,    72,    95,    72
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
#line 177 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1454 "grammar.c"
	break;
      case 10: /* "_STRING_IDENTIFIER_" */
#line 178 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1459 "grammar.c"
	break;
      case 11: /* "_STRING_COUNT_" */
#line 179 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1464 "grammar.c"
	break;
      case 12: /* "_STRING_OFFSET_" */
#line 180 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1469 "grammar.c"
	break;
      case 13: /* "_STRING_IDENTIFIER_WITH_WILDCARD_" */
#line 181 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1474 "grammar.c"
	break;
      case 15: /* "_TEXT_STRING_" */
#line 182 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1479 "grammar.c"
	break;
      case 16: /* "_HEX_STRING_" */
#line 183 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1484 "grammar.c"
	break;
      case 17: /* "_REGEXP_" */
#line 184 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1489 "grammar.c"
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
        case 7:
#line 210 "grammar.y"
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[(2) - (2)].sized_string));

        yr_free((yyvsp[(2) - (2)].sized_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
    break;

  case 8:
#line 222 "grammar.y"
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

  case 9:
#line 240 "grammar.y"
    {
        (yyval.meta) = NULL;
      }
    break;

  case 10:
#line 244 "grammar.y"
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

  case 11:
#line 271 "grammar.y"
    {
        (yyval.string) = NULL;
        compiler->current_rule_strings = (yyval.string);
      }
    break;

  case 12:
#line 276 "grammar.y"
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

  case 14:
#line 308 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 15:
#line 309 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 16:
#line 314 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
    break;

  case 17:
#line 315 "grammar.y"
    { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
    break;

  case 18:
#line 321 "grammar.y"
    {
        (yyval.c_string) = NULL;
      }
    break;

  case 19:
#line 325 "grammar.y"
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

  case 20:
#line 343 "grammar.y"
    {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[(1) - (1)].c_string), &identifier);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
      }
    break;

  case 21:
#line 356 "grammar.y"
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

          tag_name = yr_arena_next_address(
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

  case 22:
#line 392 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (1)].meta); }
    break;

  case 23:
#line 393 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (2)].meta); }
    break;

  case 24:
#line 399 "grammar.y"
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

  case 25:
#line 415 "grammar.y"
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

  case 26:
#line 428 "grammar.y"
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

  case 27:
#line 441 "grammar.y"
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

  case 28:
#line 457 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 29:
#line 458 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (2)].string); }
    break;

  case 30:
#line 464 "grammar.y"
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

  case 31:
#line 477 "grammar.y"
    {
        compiler->error_line = yyget_lineno(yyscanner);
      }
    break;

  case 32:
#line 481 "grammar.y"
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            (yyvsp[(5) - (5)].integer) | STRING_GFLAGS_REGEXP,
            (yyvsp[(1) - (5)].c_string),
            (yyvsp[(4) - (5)].sized_string));

        yr_free((yyvsp[(1) - (5)].c_string));
        yr_free((yyvsp[(4) - (5)].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
    break;

  case 33:
#line 494 "grammar.y"
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

  case 34:
#line 510 "grammar.y"
    { (yyval.integer) = 0; }
    break;

  case 35:
#line 511 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 36:
#line 516 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_WIDE; }
    break;

  case 37:
#line 517 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_ASCII; }
    break;

  case 38:
#line 518 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
    break;

  case 39:
#line 519 "grammar.y"
    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
    break;

  case 40:
#line 525 "grammar.y"
    {
        YR_OBJECT* object = NULL;
        YR_RULE* rule;

        char* id;
        char* ns = NULL;

        int var_index;

        var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[(1) - (1)].c_string));

        if (var_index >= 0)
        {
          compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH_M,
            LOOP_LOCAL_VARS * var_index,
            NULL);

          (yyval.object) = (YR_OBJECT*) -1;
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[(1) - (1)].c_string),
                NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.

            ns = compiler->current_namespace->name;
            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[(1) - (1)].c_string),
                ns);
          }

          if (object != NULL)
          {
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

            (yyval.object) = object;
          }
          else
          {
            rule = (YR_RULE*) yr_hash_table_lookup(
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
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, (yyvsp[(1) - (1)].c_string));
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }

            (yyval.object) = (YR_OBJECT*) -2;
          }
        }

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 41:
#line 613 "grammar.y"
    {
        YR_OBJECT* object = (yyvsp[(1) - (3)].object);
        YR_OBJECT* field = NULL;

        char* ident;

        if (object != NULL &&
            object != (YR_OBJECT*) -1 &&    // not a loop variable identifier
            object != (YR_OBJECT*) -2 &&    // not a rule identifier
            object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field(object, (yyvsp[(3) - (3)].c_string));

          if (field != NULL)
          {
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
              object->identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        (yyval.object) = field;

        yr_free((yyvsp[(3) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 42:
#line 662 "grammar.y"
    {
        if ((yyvsp[(1) - (4)].object) != NULL && (yyvsp[(1) - (4)].object)->type == OBJECT_TYPE_ARRAY)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_INDEX_ARRAY,
              NULL);

          (yyval.object) = ((YR_OBJECT_ARRAY*) (yyvsp[(1) - (4)].object))->items->objects[0];
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[(1) - (4)].object)->identifier);

          compiler->last_result = ERROR_NOT_AN_ARRAY;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 43:
#line 685 "grammar.y"
    {
        int args_count;

        if ((yyvsp[(1) - (4)].object) != NULL && (yyvsp[(1) - (4)].object)->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].object), (yyvsp[(3) - (4)].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
          {
            args_count = strlen((yyvsp[(3) - (4)].c_string));

            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner,
                OP_CALL,
                args_count,
                NULL);
          }

          (yyval.object) = ((YR_OBJECT_FUNCTION*) (yyvsp[(1) - (4)].object))->return_obj;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[(1) - (4)].object)->identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[(3) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 44:
#line 724 "grammar.y"
    {
        (yyval.c_string) = yr_strdup("");
      }
    break;

  case 45:
#line 728 "grammar.y"
    {
        (yyval.c_string) = yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch((yyvsp[(1) - (1)].expression_type))
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

  case 46:
#line 750 "grammar.y"
    {
        if (strlen((yyvsp[(1) - (3)].c_string)) == MAX_FUNCTION_ARGS)
        {
          compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch((yyvsp[(3) - (3)].expression_type))
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

  case 47:
#line 783 "grammar.y"
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

        (yyval.expression_type) = EXPRESSION_TYPE_REGEXP;
      }
    break;

  case 48:
#line 828 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_TO_BOOL,
              NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }


        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 49:
#line 846 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 50:
#line 855 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 51:
#line 864 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_STRING, "matches");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_REGEXP, "matches");

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_MATCHES,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 52:
#line 879 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_STRING, "contains");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner,
            OP_CONTAINS,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 53:
#line 893 "grammar.y"
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (1)].c_string),
            OP_STR_FOUND);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 54:
#line 906 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "at");

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (3)].c_string),
            OP_STR_FOUND_AT);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 55:
#line 921 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (3)].c_string),
            OP_STR_FOUND_IN);

        yr_free((yyvsp[(1) - (3)].c_string));

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 56:
#line 934 "grammar.y"
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

  case 57:
#line 969 "grammar.y"
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

  case 58:
#line 1004 "grammar.y"
    {
        int mem_offset;

        compiler->loop_depth--;
        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // The value at the top of the stack is 1 if latest
        // expression was true or 0 otherwise. Add this value
        // to the counter for number of expressions evaluating
        // to true.
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

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 59:
#line 1080 "grammar.y"
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

  case 60:
#line 1110 "grammar.y"
    {
        int mem_offset;

        compiler->loop_depth--;
        compiler->loop_for_of_mem_offset = -1;

        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // Increment counter by the value returned by the
        // boolean expression (0 or 1).
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

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;

      }
    break;

  case 61:
#line 1157 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 62:
#line 1163 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 63:
#line 1169 "grammar.y"
    {
        yr_parser_emit(yyscanner, OP_AND, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 64:
#line 1175 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_BOOLEAN, "or");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 65:
#line 1183 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<");

        yr_parser_emit(yyscanner, OP_LT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 66:
#line 1192 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">");

        yr_parser_emit(yyscanner, OP_GT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 67:
#line 1201 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<=");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<=");

        yr_parser_emit(yyscanner, OP_LE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 68:
#line 1210 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">=");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">=");

        yr_parser_emit(yyscanner, OP_GE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 69:
#line 1219 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression_type) != (yyvsp[(3) - (3)].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
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

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 70:
#line 1246 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression_type) != (yyvsp[(3) - (3)].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
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

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 71:
#line 1273 "grammar.y"
    {
        if ((yyvsp[(1) - (3)].expression_type) != (yyvsp[(3) - (3)].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for != operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[(1) - (3)].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_NEQ,
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

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
    break;

  case 72:
#line 1300 "grammar.y"
    {
        (yyval.expression_type) = (yyvsp[(1) - (1)].expression_type);
      }
    break;

  case 73:
#line 1304 "grammar.y"
    {
        (yyval.expression_type) = (yyvsp[(2) - (3)].expression_type);
      }
    break;

  case 74:
#line 1311 "grammar.y"
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
    break;

  case 75:
#line 1312 "grammar.y"
    { (yyval.integer) = INTEGER_SET_RANGE; }
    break;

  case 76:
#line 1318 "grammar.y"
    {
        if ((yyvsp[(2) - (6)].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[(5) - (6)].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 77:
#line 1340 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;

        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 78:
#line 1352 "grammar.y"
    {
        if ((yyvsp[(3) - (3)].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 79:
#line 1367 "grammar.y"
    {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
    break;

  case 81:
#line 1373 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");
      }
    break;

  case 84:
#line 1388 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));
      }
    break;

  case 85:
#line 1393 "grammar.y"
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
        yr_free((yyvsp[(1) - (1)].c_string));
      }
    break;

  case 87:
#line 1403 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
    break;

  case 88:
#line 1407 "grammar.y"
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL);
      }
    break;

  case 89:
#line 1415 "grammar.y"
    {
        (yyval.expression_type) = (yyvsp[(2) - (3)].expression_type);
      }
    break;

  case 90:
#line 1419 "grammar.y"
    {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 91:
#line 1428 "grammar.y"
    {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" " "function from PE module instead.");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 92:
#line 1440 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "int8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 93:
#line 1451 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "int16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 94:
#line 1462 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "int32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 95:
#line 1473 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "uint8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 96:
#line 1484 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "uint16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 97:
#line 1495 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(3) - (4)].expression_type), EXPRESSION_TYPE_INTEGER, "uint32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 98:
#line 1506 "grammar.y"
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[(1) - (1)].integer), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 99:
#line 1515 "grammar.y"
    {
        SIZED_STRING* sized_string = (yyvsp[(1) - (1)].sized_string);
        char* string;

        compiler->last_result = yr_arena_write_string(
            compiler->sz_arena,
            sized_string->c_string,
            &string);

        yr_free((yyvsp[(1) - (1)].sized_string));

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              PTR_TO_UINT64(string),
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_STRING;
      }
    break;

  case 100:
#line 1538 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (1)].c_string),
            OP_STR_COUNT);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 101:
#line 1551 "grammar.y"
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[(1) - (4)].c_string),
            OP_STR_OFFSET);

        yr_free((yyvsp[(1) - (4)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 102:
#line 1564 "grammar.y"
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
              OP_STR_OFFSET);

        yr_free((yyvsp[(1) - (1)].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 103:
#line 1584 "grammar.y"
    {
        if ((yyvsp[(1) - (1)].object) == (YR_OBJECT*) -1)  // loop identifier
        {
          (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
        else if ((yyvsp[(1) - (1)].object) == (YR_OBJECT*) -2)  // rule identifier
        {
          (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
        else if ((yyvsp[(1) - (1)].object) != NULL)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch((yyvsp[(1) - (1)].object)->type)
          {
            case OBJECT_TYPE_INTEGER:
              (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
              break;
            case OBJECT_TYPE_STRING:
              (yyval.expression_type) = EXPRESSION_TYPE_STRING;
              break;
            default:
              assert(FALSE);
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(compiler, (yyvsp[(1) - (1)].object)->identifier);
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    break;

  case 104:
#line 1619 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "+");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "+");

        yr_parser_emit(yyscanner, OP_ADD, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 105:
#line 1628 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "-");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "-");

        yr_parser_emit(yyscanner, OP_SUB, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 106:
#line 1637 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "*");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "*");

        yr_parser_emit(yyscanner, OP_MUL, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 107:
#line 1646 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "\\");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "\\");

        yr_parser_emit(yyscanner, OP_DIV, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 108:
#line 1655 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 109:
#line 1664 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_XOR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 110:
#line 1673 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_AND, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 111:
#line 1682 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 112:
#line 1691 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(2) - (2)].expression_type), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_NEG, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 113:
#line 1699 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 114:
#line 1708 "grammar.y"
    {
        CHECK_TYPE((yyvsp[(1) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE((yyvsp[(3) - (3)].expression_type), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
    break;

  case 115:
#line 1717 "grammar.y"
    {
        (yyval.expression_type) = (yyvsp[(1) - (1)].expression_type);
      }
    break;


/* Line 1267 of yacc.c.  */
#line 3525 "grammar.c"
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


#line 1722 "grammar.y"


