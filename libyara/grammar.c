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
     _END_ = 264,
     _IDENTIFIER_ = 265,
     _STRING_IDENTIFIER_ = 266,
     _STRING_COUNT_ = 267,
     _STRING_OFFSET_ = 268,
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 269,
     _ANONYMOUS_STRING_ = 270,
     _NUMBER_ = 271,
     _UNKNOWN_ = 272,
     _TEXTSTRING_ = 273,
     _HEXSTRING_ = 274,
     _REGEXP_ = 275,
     _ASCII_ = 276,
     _WIDE_ = 277,
     _NOCASE_ = 278,
     _FULLWORD_ = 279,
     _AT_ = 280,
     _SIZE_ = 281,
     _ENTRYPOINT_ = 282,
     _ALL_ = 283,
     _ANY_ = 284,
     _RVA_ = 285,
     _OFFSET_ = 286,
     _FILE_ = 287,
     _IN_ = 288,
     _OF_ = 289,
     _FOR_ = 290,
     _THEM_ = 291,
     _SECTION_ = 292,
     _INT8_ = 293,
     _INT16_ = 294,
     _INT32_ = 295,
     _UINT8_ = 296,
     _UINT16_ = 297,
     _UINT32_ = 298,
     _MATCHES_ = 299,
     _CONTAINS_ = 300,
     _INDEX_ = 301,
     _MZ_ = 302,
     _PE_ = 303,
     _DLL_ = 304,
     _TRUE_ = 305,
     _FALSE_ = 306,
     _OR_ = 307,
     _AND_ = 308,
     _IS_ = 309,
     _NEQ_ = 310,
     _EQ_ = 311,
     _GE_ = 312,
     _GT_ = 313,
     _LE_ = 314,
     _LT_ = 315,
     _SHIFT_RIGHT_ = 316,
     _SHIFT_LEFT_ = 317,
     _NOT_ = 318
   };
#endif
/* Tokens.  */
#define _RULE_ 258
#define _PRIVATE_ 259
#define _GLOBAL_ 260
#define _META_ 261
#define _STRINGS_ 262
#define _CONDITION_ 263
#define _END_ 264
#define _IDENTIFIER_ 265
#define _STRING_IDENTIFIER_ 266
#define _STRING_COUNT_ 267
#define _STRING_OFFSET_ 268
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 269
#define _ANONYMOUS_STRING_ 270
#define _NUMBER_ 271
#define _UNKNOWN_ 272
#define _TEXTSTRING_ 273
#define _HEXSTRING_ 274
#define _REGEXP_ 275
#define _ASCII_ 276
#define _WIDE_ 277
#define _NOCASE_ 278
#define _FULLWORD_ 279
#define _AT_ 280
#define _SIZE_ 281
#define _ENTRYPOINT_ 282
#define _ALL_ 283
#define _ANY_ 284
#define _RVA_ 285
#define _OFFSET_ 286
#define _FILE_ 287
#define _IN_ 288
#define _OF_ 289
#define _FOR_ 290
#define _THEM_ 291
#define _SECTION_ 292
#define _INT8_ 293
#define _INT16_ 294
#define _INT32_ 295
#define _UINT8_ 296
#define _UINT16_ 297
#define _UINT32_ 298
#define _MATCHES_ 299
#define _CONTAINS_ 300
#define _INDEX_ 301
#define _MZ_ 302
#define _PE_ 303
#define _DLL_ 304
#define _TRUE_ 305
#define _FALSE_ 306
#define _OR_ 307
#define _AND_ 308
#define _IS_ 309
#define _NEQ_ 310
#define _EQ_ 311
#define _GE_ 312
#define _GT_ 313
#define _LE_ 314
#define _LT_ 315
#define _SHIFT_RIGHT_ 316
#define _SHIFT_LEFT_ 317
#define _NOT_ 318




/* Copy the first part of user declarations.  */
#line 17 "grammar.y"


#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#include "exec.h"
#include "hash.h"
#include "sizedstr.h"
#include "mem.h"
#include "lex.h"
#include "regex.h"
#include "parser.h"
#include "utils.h"
#include "yara.h"

#define YYERROR_VERBOSE
#define YYDEBUG 1

#define INTEGER_SET_ENUMERATION 1
#define INTEGER_SET_RANGE 2

#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, NULL); \
      YYERROR; \
    } \



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
#line 148 "grammar.y"
{
  void*           sized_string;
  char*           c_string;
  int64_t         integer;
  void*           string;
  void*           meta;
}
/* Line 193 of yacc.c.  */
#line 262 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 275 "grammar.c"

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
#define YYLAST   425

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  84
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  31
/* YYNRULES -- Number of rules.  */
#define YYNRULES  109
/* YYNRULES -- Number of states.  */
#define YYNSTATES  211

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   318

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    70,    54,     2,
      78,    79,    68,    66,    81,    67,    80,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    76,     2,
       2,    77,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    82,    69,    83,    56,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    73,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    74,    55,    75,    72,     2,     2,     2,
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
      45,    46,    47,    48,    49,    50,    51,    52,    53,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    71
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    11,    15,    25,    26,    30,
      31,    35,    39,    40,    43,    45,    47,    48,    51,    53,
      56,    58,    61,    65,    69,    73,    77,    79,    82,    87,
      92,    96,    97,   100,   102,   104,   106,   108,   112,   114,
     116,   118,   122,   126,   128,   132,   137,   141,   148,   149,
     150,   162,   163,   173,   177,   181,   184,   188,   192,   196,
     200,   204,   208,   212,   216,   220,   222,   224,   228,   230,
     237,   239,   243,   244,   249,   251,   253,   257,   259,   261,
     263,   265,   267,   271,   273,   275,   280,   285,   290,   295,
     300,   305,   307,   309,   314,   316,   318,   322,   326,   330,
     334,   338,   342,   346,   350,   353,   357,   361,   363,   365
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      85,     0,    -1,    -1,    85,    86,    -1,    85,     1,    86,
      -1,    85,     1,    73,    -1,    90,     3,    10,    92,    74,
      87,    88,    89,    75,    -1,    -1,     6,    76,    94,    -1,
      -1,     7,    76,    96,    -1,     8,    76,   100,    -1,    -1,
      90,    91,    -1,     4,    -1,     5,    -1,    -1,    76,    93,
      -1,    10,    -1,    93,    10,    -1,    95,    -1,    94,    95,
      -1,    10,    77,    18,    -1,    10,    77,    16,    -1,    10,
      77,    50,    -1,    10,    77,    51,    -1,    97,    -1,    96,
      97,    -1,    11,    77,    18,    98,    -1,    11,    77,    20,
      98,    -1,    11,    77,    19,    -1,    -1,    98,    99,    -1,
      22,    -1,    21,    -1,    23,    -1,    24,    -1,    78,   100,
      79,    -1,    50,    -1,    51,    -1,    10,    -1,   104,    44,
      20,    -1,   104,    45,   104,    -1,    11,    -1,    11,    25,
     113,    -1,    11,    25,    30,   113,    -1,    11,    33,   106,
      -1,    11,    33,    37,    78,    18,    79,    -1,    -1,    -1,
      35,   112,    10,    33,   101,   105,    76,   102,    78,   100,
      79,    -1,    -1,    35,   112,    34,   108,    76,   103,    78,
     100,    79,    -1,   112,    34,   108,    -1,    32,    57,   114,
      -1,    71,   100,    -1,   100,    53,   100,    -1,   100,    52,
     100,    -1,   113,    63,   113,    -1,   113,    61,   113,    -1,
     113,    62,   113,    -1,   113,    60,   113,    -1,   113,    59,
     113,    -1,   113,    57,   113,    -1,   113,    58,   113,    -1,
      18,    -1,    10,    -1,    78,   107,    79,    -1,   106,    -1,
      78,   113,    80,    80,   113,    79,    -1,   113,    -1,   107,
      81,   113,    -1,    -1,    78,   109,   110,    79,    -1,    36,
      -1,   111,    -1,   110,    81,   111,    -1,    11,    -1,    14,
      -1,   113,    -1,    28,    -1,    29,    -1,    78,   113,    79,
      -1,    26,    -1,    27,    -1,    38,    78,   113,    79,    -1,
      39,    78,   113,    79,    -1,    40,    78,   113,    79,    -1,
      41,    78,   113,    79,    -1,    42,    78,   113,    79,    -1,
      43,    78,   113,    79,    -1,    16,    -1,    12,    -1,    13,
      82,   113,    83,    -1,    13,    -1,    10,    -1,   113,    66,
     113,    -1,   113,    67,   113,    -1,   113,    68,   113,    -1,
     113,    69,   113,    -1,   113,    70,   113,    -1,   113,    56,
     113,    -1,   113,    54,   113,    -1,   113,    55,   113,    -1,
      72,   113,    -1,   113,    65,   113,    -1,   113,    64,   113,
      -1,    47,    -1,    48,    -1,    49,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   159,   159,   160,   161,   162,   166,   183,   184,   212,
     216,   244,   248,   249,   253,   254,   258,   259,   274,   284,
     318,   319,   323,   339,   352,   365,   381,   382,   386,   399,
     412,   428,   429,   433,   434,   435,   436,   440,   441,   445,
     449,   480,   522,   526,   537,   548,   552,   563,   569,   573,
     568,   638,   637,   670,   674,   677,   681,   685,   689,   693,
     697,   701,   705,   709,   713,   720,   739,   753,   754,   758,
     762,   763,   767,   766,   771,   778,   779,   782,   787,   794,
     795,   799,   806,   807,   811,   815,   819,   823,   827,   831,
     835,   839,   843,   854,   865,   879,   901,   905,   909,   913,
     917,   921,   925,   929,   933,   937,   941,   947,   948,   949
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_META_", "_STRINGS_", "_CONDITION_", "_END_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_ANONYMOUS_STRING_", "_NUMBER_",
  "_UNKNOWN_", "_TEXTSTRING_", "_HEXSTRING_", "_REGEXP_", "_ASCII_",
  "_WIDE_", "_NOCASE_", "_FULLWORD_", "_AT_", "_SIZE_", "_ENTRYPOINT_",
  "_ALL_", "_ANY_", "_RVA_", "_OFFSET_", "_FILE_", "_IN_", "_OF_", "_FOR_",
  "_THEM_", "_SECTION_", "_INT8_", "_INT16_", "_INT32_", "_UINT8_",
  "_UINT16_", "_UINT32_", "_MATCHES_", "_CONTAINS_", "_INDEX_", "_MZ_",
  "_PE_", "_DLL_", "_TRUE_", "_FALSE_", "_OR_", "_AND_", "'&'", "'|'",
  "'^'", "_IS_", "_NEQ_", "_EQ_", "_GE_", "_GT_", "_LE_", "_LT_",
  "_SHIFT_RIGHT_", "_SHIFT_LEFT_", "'+'", "'-'", "'*'", "'\\\\'", "'%'",
  "_NOT_", "'~'", "'include'", "'{'", "'}'", "':'", "'='", "'('", "')'",
  "'.'", "','", "'['", "']'", "$accept", "rules", "rule", "meta",
  "strings", "condition", "rule_modifiers", "rule_modifier", "tags",
  "tag_list", "meta_declarations", "meta_declaration",
  "string_declarations", "string_declaration", "string_modifiers",
  "string_modifier", "boolean_expression", "@1", "@2", "@3", "text",
  "integer_set", "range", "integer_enumeration", "string_set", "@4",
  "string_enumeration", "string_enumeration_item", "for_expression",
  "expression", "type", 0
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
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,    38,   124,    94,   309,   310,   311,
     312,   313,   314,   315,   316,   317,    43,    45,    42,    92,
      37,   318,   126,   105,   123,   125,    58,    61,    40,    41,
      46,    44,    91,    93
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    84,    85,    85,    85,    85,    86,    87,    87,    88,
      88,    89,    90,    90,    91,    91,    92,    92,    93,    93,
      94,    94,    95,    95,    95,    95,    96,    96,    97,    97,
      97,    98,    98,    99,    99,    99,    99,   100,   100,   100,
     100,   100,   100,   100,   100,   100,   100,   100,   101,   102,
     100,   103,   100,   100,   100,   100,   100,   100,   100,   100,
     100,   100,   100,   100,   100,   104,   104,   105,   105,   106,
     107,   107,   109,   108,   108,   110,   110,   111,   111,   112,
     112,   112,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   114,   114,   114
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     3,     3,     9,     0,     3,     0,
       3,     3,     0,     2,     1,     1,     0,     2,     1,     2,
       1,     2,     3,     3,     3,     3,     1,     2,     4,     4,
       3,     0,     2,     1,     1,     1,     1,     3,     1,     1,
       1,     3,     3,     1,     3,     4,     3,     6,     0,     0,
      11,     0,     9,     3,     3,     2,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     1,     3,     1,     6,
       1,     3,     0,     4,     1,     1,     3,     1,     1,     1,
       1,     1,     3,     1,     1,     4,     4,     4,     4,     4,
       4,     1,     1,     4,     1,     1,     3,     3,     3,     3,
       3,     3,     3,     3,     2,     3,     3,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    12,     3,     0,     5,     4,     0,    14,
      15,    13,    16,     0,     0,    18,    17,     7,    19,     0,
       9,     0,     0,     0,     0,     8,    20,     0,     0,     0,
       0,    21,     0,    10,    26,     0,     6,    23,    22,    24,
      25,     0,    27,    95,    43,    92,    94,    91,    65,    83,
      84,    80,    81,     0,     0,     0,     0,     0,     0,     0,
       0,    38,    39,     0,     0,     0,    11,     0,     0,    79,
      31,    30,    31,     0,     0,     0,     0,    95,     0,     0,
      79,     0,     0,     0,     0,     0,     0,    55,   104,     0,
      79,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    28,    29,     0,    44,     0,     0,    46,
       0,   107,   108,   109,    54,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    37,    82,    57,    56,    41,    66,
      42,    74,    72,    53,   102,   103,   101,    63,    64,    62,
      61,    59,    60,    58,   106,   105,    96,    97,    98,    99,
     100,    34,    33,    35,    36,    32,    45,     0,     0,    93,
      48,     0,    85,    86,    87,    88,    89,    90,     0,     0,
       0,     0,    51,    77,    78,     0,    75,    47,     0,     0,
       0,    68,     0,    73,     0,     0,     0,    70,    49,     0,
      76,    69,    67,     0,     0,     0,    71,     0,    52,     0,
      50
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     4,    20,    23,    29,     5,    11,    14,    16,
      25,    26,    33,    34,   113,   165,    66,   181,   204,   192,
      67,   190,   119,   196,   143,   178,   185,   186,    68,    69,
     124
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -77
static const yytype_int16 yypact[] =
{
     -77,   119,   -77,   -35,   -77,    71,   -77,   -77,     6,   -77,
     -77,   -77,   -43,    30,   -12,   -77,    50,    73,   -77,    23,
     114,   115,    52,   121,    54,   115,   -77,   125,    56,    63,
     -14,   -77,    64,   125,   -77,    55,   -77,   -77,   -77,   -77,
     -77,   173,   -77,    25,    -7,   -77,    69,   -77,   -77,   -77,
     -77,   -77,   -77,    95,   127,    80,    83,    84,    93,    94,
      97,   -77,   -77,    55,   168,    55,    33,    44,   130,   338,
     -77,   -77,   -77,   147,   -15,   168,   149,   -77,   168,    -9,
     355,   168,   168,   168,   168,   168,   168,   -77,   -77,   -40,
     193,    55,    55,   156,    62,   -19,   168,   168,   168,   168,
     168,   168,   168,   168,   168,   168,   168,   168,   168,   168,
     168,   168,   168,    86,    86,   168,   355,   101,   168,   -77,
      47,   -77,   -77,   -77,   -77,   166,   150,   -19,   210,   227,
     244,   261,   278,   295,   -77,   -77,   129,   -77,   -77,   -77,
     -77,   -77,   -77,   -77,   319,   319,   319,   355,   355,   355,
     355,   355,   355,   355,    78,    78,   169,   169,   -77,   -77,
     -77,   -77,   -77,   -77,   -77,   -77,   355,   182,   148,   -77,
     -77,   151,   -77,   -77,   -77,   -77,   -77,   -77,     9,   122,
     143,   146,   -77,   -77,   -77,   -76,   -77,   -77,   168,   168,
     153,   -77,   163,   -77,     9,   312,   -72,   148,   -77,    55,
     -77,   -77,   -77,   168,   164,   -38,   355,    55,   -77,    39,
     -77
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -77,   -77,   223,   -77,   -77,   -77,   -77,   -77,   -77,   -77,
     -77,   218,   -77,   211,   195,   -77,   -57,   -77,   -77,   -77,
     174,   -77,    88,   -77,   144,   -77,   -77,    76,   219,   -54,
     -77
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -67
static const yytype_int16 yytable[] =
{
      80,   126,    37,   193,    38,   194,    87,   202,    89,   203,
      88,    90,    91,    92,    91,    92,    12,   141,    73,   116,
     183,   120,   117,   184,   125,   127,    74,   128,   129,   130,
     131,   132,   133,    13,   136,   137,    39,    40,     6,   134,
      15,   208,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   154,   155,   156,   157,   158,   159,   160,   142,
      18,   166,    17,   118,   168,    43,    44,    45,    46,   -66,
     -66,    47,   139,    48,     8,     9,    10,   -40,   -40,    19,
      48,    49,    50,    51,    52,    91,    92,    53,    93,    94,
      54,    91,    92,    55,    56,    57,    58,    59,    60,    21,
     -40,    96,    97,    98,   -40,    61,    62,   161,   162,   163,
     164,   106,   107,   108,   109,   110,   111,   112,   210,     2,
       3,    22,   -12,   -12,   -12,    24,    63,    64,    27,    28,
     169,    30,    35,    65,   195,   197,    32,    77,    36,    45,
      46,    41,   205,    47,   108,   109,   110,   111,   112,   206,
     209,    75,    76,    49,    50,    51,    52,    77,    81,    45,
      46,    82,    83,    47,    95,    55,    56,    57,    58,    59,
      60,    84,    85,    49,    50,    86,   138,   115,    77,   167,
      45,    46,    92,   170,    47,    55,    56,    57,    58,    59,
      60,    70,    71,    72,    49,    50,   121,   122,   123,    64,
     179,   187,    96,    97,    98,    78,    55,    56,    57,    58,
      59,    60,   106,   107,   108,   109,   110,   111,   112,    64,
      96,    97,    98,   188,   189,    78,     7,   182,   180,   198,
     106,   107,   108,   109,   110,   111,   112,   110,   111,   112,
      64,   199,   207,    31,    42,   135,    78,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,   108,
     109,   110,   111,   112,    96,    97,    98,   114,   140,   191,
     200,   171,   135,    79,   106,   107,   108,   109,   110,   111,
     112,    96,    97,    98,     0,     0,     0,     0,     0,   172,
       0,   106,   107,   108,   109,   110,   111,   112,    96,    97,
      98,     0,     0,     0,     0,     0,   173,     0,   106,   107,
     108,   109,   110,   111,   112,    96,    97,    98,     0,     0,
       0,     0,     0,   174,     0,   106,   107,   108,   109,   110,
     111,   112,    96,    97,    98,     0,     0,     0,     0,     0,
     175,     0,   106,   107,   108,   109,   110,   111,   112,    96,
      97,    98,     0,     0,     0,     0,     0,   176,     0,   106,
     107,   108,   109,   110,   111,   112,    96,    97,    98,     0,
       0,     0,     0,     0,   177,     0,   106,   107,   108,   109,
     110,   111,   112,   106,   107,   108,   109,   110,   111,   112,
       0,   201,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,    96,
      97,    98,     0,     0,     0,     0,     0,     0,     0,   106,
     107,   108,   109,   110,   111,   112
};

static const yytype_int16 yycheck[] =
{
      54,    10,    16,    79,    18,    81,    63,    79,    65,    81,
      64,    65,    52,    53,    52,    53,    10,    36,    25,    73,
      11,    75,    37,    14,    78,    34,    33,    81,    82,    83,
      84,    85,    86,    76,    91,    92,    50,    51,    73,    79,
      10,    79,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,    78,
      10,   115,    74,    78,   118,    10,    11,    12,    13,    44,
      45,    16,    10,    18,     3,     4,     5,    52,    53,     6,
      18,    26,    27,    28,    29,    52,    53,    32,    44,    45,
      35,    52,    53,    38,    39,    40,    41,    42,    43,    76,
      75,    54,    55,    56,    79,    50,    51,    21,    22,    23,
      24,    64,    65,    66,    67,    68,    69,    70,    79,     0,
       1,     7,     3,     4,     5,    10,    71,    72,    76,     8,
      83,    77,    76,    78,   188,   189,    11,    10,    75,    12,
      13,    77,   199,    16,    66,    67,    68,    69,    70,   203,
     207,    82,    57,    26,    27,    28,    29,    10,    78,    12,
      13,    78,    78,    16,    34,    38,    39,    40,    41,    42,
      43,    78,    78,    26,    27,    78,    20,    30,    10,    78,
      12,    13,    53,    33,    16,    38,    39,    40,    41,    42,
      43,    18,    19,    20,    26,    27,    47,    48,    49,    72,
      18,    79,    54,    55,    56,    78,    38,    39,    40,    41,
      42,    43,    64,    65,    66,    67,    68,    69,    70,    72,
      54,    55,    56,    80,    78,    78,     3,    76,    80,    76,
      64,    65,    66,    67,    68,    69,    70,    68,    69,    70,
      72,    78,    78,    25,    33,    79,    78,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    54,    55,    56,    72,    94,   181,
     194,   127,    79,    54,    64,    65,    66,    67,    68,    69,
      70,    54,    55,    56,    -1,    -1,    -1,    -1,    -1,    79,
      -1,    64,    65,    66,    67,    68,    69,    70,    54,    55,
      56,    -1,    -1,    -1,    -1,    -1,    79,    -1,    64,    65,
      66,    67,    68,    69,    70,    54,    55,    56,    -1,    -1,
      -1,    -1,    -1,    79,    -1,    64,    65,    66,    67,    68,
      69,    70,    54,    55,    56,    -1,    -1,    -1,    -1,    -1,
      79,    -1,    64,    65,    66,    67,    68,    69,    70,    54,
      55,    56,    -1,    -1,    -1,    -1,    -1,    79,    -1,    64,
      65,    66,    67,    68,    69,    70,    54,    55,    56,    -1,
      -1,    -1,    -1,    -1,    79,    -1,    64,    65,    66,    67,
      68,    69,    70,    64,    65,    66,    67,    68,    69,    70,
      -1,    79,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    54,
      55,    56,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    64,
      65,    66,    67,    68,    69,    70
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    85,     0,     1,    86,    90,    73,    86,     3,     4,
       5,    91,    10,    76,    92,    10,    93,    74,    10,     6,
      87,    76,     7,    88,    10,    94,    95,    76,     8,    89,
      77,    95,    11,    96,    97,    76,    75,    16,    18,    50,
      51,    77,    97,    10,    11,    12,    13,    16,    18,    26,
      27,    28,    29,    32,    35,    38,    39,    40,    41,    42,
      43,    50,    51,    71,    72,    78,   100,   104,   112,   113,
      18,    19,    20,    25,    33,    82,    57,    10,    78,   112,
     113,    78,    78,    78,    78,    78,    78,   100,   113,   100,
     113,    52,    53,    44,    45,    34,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    98,    98,    30,   113,    37,    78,   106,
     113,    47,    48,    49,   114,   113,    10,    34,   113,   113,
     113,   113,   113,   113,    79,    79,   100,   100,    20,    10,
     104,    36,    78,   108,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,    21,    22,    23,    24,    99,   113,    78,   113,    83,
      33,   108,    79,    79,    79,    79,    79,    79,   109,    18,
      80,   101,    76,    11,    14,   110,   111,    79,    80,    78,
     105,   106,   103,    79,    81,   113,   107,   113,    76,    78,
     111,    79,    79,    81,   102,   100,   113,    78,    79,   100,
      79
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
      yyerror (yyscanner, YY_("syntax error: cannot back up")); \
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
# define YYLEX yylex (&yylval, yyscanner)
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
		  Type, Value, yyscanner); \
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
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yyscanner);
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
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yyscanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner);
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
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, void *yyscanner)
#else
static void
yy_reduce_print (yyvsp, yyrule, yyscanner)
    YYSTYPE *yyvsp;
    int yyrule;
    void *yyscanner;
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
		       		       , yyscanner);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, yyscanner); \
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
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yyscanner)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    void *yyscanner;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {
      case 10: /* "_IDENTIFIER_" */
#line 138 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1417 "grammar.c"
	break;
      case 11: /* "_STRING_IDENTIFIER_" */
#line 139 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1422 "grammar.c"
	break;
      case 12: /* "_STRING_COUNT_" */
#line 140 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1427 "grammar.c"
	break;
      case 13: /* "_STRING_OFFSET_" */
#line 141 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1432 "grammar.c"
	break;
      case 14: /* "_STRING_IDENTIFIER_WITH_WILDCARD_" */
#line 142 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1437 "grammar.c"
	break;
      case 15: /* "_ANONYMOUS_STRING_" */
#line 143 "grammar.y"
	{ yr_free((yyvaluep->c_string)); };
#line 1442 "grammar.c"
	break;
      case 18: /* "_TEXTSTRING_" */
#line 144 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1447 "grammar.c"
	break;
      case 19: /* "_HEXSTRING_" */
#line 145 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1452 "grammar.c"
	break;
      case 20: /* "_REGEXP_" */
#line 146 "grammar.y"
	{ yr_free((yyvaluep->sized_string)); };
#line 1457 "grammar.c"
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
int yyparse (void *yyscanner);
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
yyparse (void *yyscanner)
#else
int
yyparse (yyscanner)
    void *yyscanner;
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
        case 6:
#line 167 "grammar.y"
    {
          int result = reduce_rule_declaration(
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

  case 7:
#line 183 "grammar.y"
    {  (yyval.meta) = NULL; }
    break;

  case 8:
#line 185 "grammar.y"
    {
          // Each rule have a list of meta-data info, consisting in a
          // sequence of META structures. The last META structure does
          // not represent a real meta-data, it's just a end-of-list marker
          // identified by a specific type (META_TYPE_NULL). Here we
          // write the end-of-list marker.

          META null_meta;
          YARA_COMPILER* compiler;

          compiler = yyget_extra(yyscanner);

          memset(&null_meta, 0xFF, sizeof(META));
          null_meta.type = META_TYPE_NULL;

          yr_arena_write_data(
              compiler->metas_arena,
              &null_meta,
              sizeof(META),
              NULL);

          (yyval.meta) = (yyvsp[(3) - (3)].meta);
        }
    break;

  case 9:
#line 212 "grammar.y"
    {
          (yyval.string) = NULL;
          yyget_extra(yyscanner)->current_rule_strings = (yyval.string);
        }
    break;

  case 10:
#line 217 "grammar.y"
    {
          // Each rule have a list of strings, consisting in a sequence
          // of STRING structures. The last STRING structure does not
          // represent a real string, it's just a end-of-list marker
          // identified by a specific flag (STRING_FLAGS_NULL). Here we
          // write the end-of-list marker.

          STRING null_string;
          YARA_COMPILER* compiler;

          compiler = yyget_extra(yyscanner);

          memset(&null_string, 0xFF, sizeof(STRING));
          null_string.flags = STRING_FLAGS_NULL;

          yr_arena_write_data(
              compiler->strings_arena,
              &null_string,
              sizeof(STRING),
              NULL);

          (yyval.string) = (yyvsp[(3) - (3)].string);
          compiler->current_rule_strings = (yyval.string);
        }
    break;

  case 12:
#line 248 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 13:
#line 249 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 14:
#line 253 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 15:
#line 254 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 16:
#line 258 "grammar.y"
    { (yyval.c_string) = NULL; }
    break;

  case 17:
#line 260 "grammar.y"
    {
          // Tags list is represented in the arena as a sequence
          // of null-terminated strings, the sequence ends with an
          // additional null character. Here we write the ending null
          //character. Example: tag1\0tag2\0tag3\0\0

          yr_arena_write_string(
              yyget_extra(yyscanner)->sz_arena, "", NULL);

          (yyval.c_string) = (yyvsp[(2) - (2)].c_string);
        }
    break;

  case 18:
#line 275 "grammar.y"
    {
              char* identifier;

              yr_arena_write_string(
                  yyget_extra(yyscanner)->sz_arena, (yyvsp[(1) - (1)].c_string), &identifier);

              yr_free((yyvsp[(1) - (1)].c_string));
              (yyval.c_string) = identifier;
            }
    break;

  case 19:
#line 285 "grammar.y"
    {
              YARA_COMPILER* compiler = yyget_extra(yyscanner);
              char* tag_name = (yyvsp[(1) - (2)].c_string);
              size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

              while (tag_length > 0)
              {
                if (strcmp(tag_name, (yyvsp[(2) - (2)].c_string)) == 0)
                {
                  yr_compiler_set_error_extra_info(compiler, tag_name);
                  compiler->last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
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
              (yyval.c_string) = (yyvsp[(1) - (2)].c_string);

              ERROR_IF(compiler->last_result != ERROR_SUCCESS);
            }
    break;

  case 20:
#line 318 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (1)].meta); }
    break;

  case 21:
#line 319 "grammar.y"
    {  (yyval.meta) = (yyvsp[(1) - (2)].meta); }
    break;

  case 22:
#line 324 "grammar.y"
    {
                      SIZED_STRING* sized_string = (yyvsp[(3) - (3)].sized_string);

                      (yyval.meta) = reduce_meta_declaration(
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

  case 23:
#line 340 "grammar.y"
    {
                      (yyval.meta) = reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_INTEGER,
                          (yyvsp[(1) - (3)].c_string),
                          NULL,
                          (yyvsp[(3) - (3)].integer));

                      yr_free((yyvsp[(1) - (3)].c_string));

                      ERROR_IF((yyval.meta) == NULL);
                    }
    break;

  case 24:
#line 353 "grammar.y"
    {
                      (yyval.meta) = reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_BOOLEAN,
                          (yyvsp[(1) - (3)].c_string),
                          NULL,
                          TRUE);

                      yr_free((yyvsp[(1) - (3)].c_string));

                      ERROR_IF((yyval.meta) == NULL);
                    }
    break;

  case 25:
#line 366 "grammar.y"
    {
                      (yyval.meta) = reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_BOOLEAN,
                          (yyvsp[(1) - (3)].c_string),
                          NULL,
                          FALSE);

                      yr_free((yyvsp[(1) - (3)].c_string));

                      ERROR_IF((yyval.meta) == NULL);
                    }
    break;

  case 26:
#line 381 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 27:
#line 382 "grammar.y"
    { (yyval.string) = (yyvsp[(1) - (2)].string); }
    break;

  case 28:
#line 387 "grammar.y"
    {
                        (yyval.string) = reduce_string_declaration(
                            yyscanner,
                            (yyvsp[(4) - (4)].integer),
                            (yyvsp[(1) - (4)].c_string),
                            (yyvsp[(3) - (4)].sized_string));

                        yr_free((yyvsp[(1) - (4)].c_string));
                        yr_free((yyvsp[(3) - (4)].sized_string));

                        ERROR_IF((yyval.string) == NULL);
                      }
    break;

  case 29:
#line 400 "grammar.y"
    {
                        (yyval.string) = reduce_string_declaration(
                            yyscanner,
                            (yyvsp[(4) - (4)].integer) | STRING_FLAGS_REGEXP,
                            (yyvsp[(1) - (4)].c_string),
                            (yyvsp[(3) - (4)].sized_string));

                        yr_free((yyvsp[(1) - (4)].c_string));
                        yr_free((yyvsp[(3) - (4)].sized_string));

                        ERROR_IF((yyval.string) == NULL);
                      }
    break;

  case 30:
#line 413 "grammar.y"
    {
                        (yyval.string) = reduce_string_declaration(
                            yyscanner,
                            STRING_FLAGS_HEXADECIMAL,
                            (yyvsp[(1) - (3)].c_string),
                            (yyvsp[(3) - (3)].sized_string));

                        yr_free((yyvsp[(1) - (3)].c_string));
                        yr_free((yyvsp[(3) - (3)].sized_string));

                        ERROR_IF((yyval.string) == NULL);
                      }
    break;

  case 31:
#line 428 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 32:
#line 429 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 33:
#line 433 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 34:
#line 434 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 35:
#line 435 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 36:
#line 436 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 38:
#line 442 "grammar.y"
    {
                        emit_with_arg(yyscanner, PUSH, 1, NULL);
                      }
    break;

  case 39:
#line 446 "grammar.y"
    {
                        emit_with_arg(yyscanner, PUSH, 0, NULL);
                      }
    break;

  case 40:
#line 450 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);
                        RULE* rule;
                        EXTERNAL_VARIABLE* external;

                        rule = (RULE*) yr_hash_table_lookup(
                            compiler->rules_table,
                            (yyvsp[(1) - (1)].c_string),
                            compiler->current_namespace->name);

                        if (rule != NULL)
                        {
                          compiler->last_result = emit_with_arg_reloc(
                              yyscanner,
                              RULE_PUSH,
                              PTR_TO_UINT64(rule),
                              NULL);
                        }
                        else
                        {
                          compiler->last_result = reduce_external(
                              yyscanner,
                              (yyvsp[(1) - (1)].c_string),
                              EXT_BOOL);
                        }

                        yr_free((yyvsp[(1) - (1)].c_string));

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
                      }
    break;

  case 41:
#line 481 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);
                        SIZED_STRING* sized_string = (yyvsp[(3) - (3)].sized_string);
                        REGEXP re;

                        char* string;
                        int error_offset;
                        int result;

                        result = regex_compile(&re,
                            sized_string->c_string,
                            FALSE,
                            compiler->last_error_extra_info,
                            sizeof(compiler->last_error_extra_info),
                            &error_offset);

                        if (result > 0)
                        {
                          yr_arena_write_string(
                            compiler->sz_arena,
                            sized_string->c_string,
                            &string);

                          emit_with_arg_reloc(
                              yyscanner,
                              PUSH,
                              PTR_TO_UINT64(string),
                              NULL);

                          emit(yyscanner, MATCHES, NULL);
                        }
                        else
                        {
                          compiler->last_result = \
                            ERROR_INVALID_REGULAR_EXPRESSION;
                        }

                        yr_free((yyvsp[(3) - (3)].sized_string));

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
                      }
    break;

  case 42:
#line 523 "grammar.y"
    {
                        emit(yyscanner, CONTAINS, NULL);
                      }
    break;

  case 43:
#line 527 "grammar.y"
    {
                        int result = reduce_string_identifier(
                            yyscanner,
                            (yyvsp[(1) - (1)].c_string),
                            SFOUND);

                        yr_free((yyvsp[(1) - (1)].c_string));

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
    break;

  case 44:
#line 538 "grammar.y"
    {
                        int result = reduce_string_identifier(
                            yyscanner,
                            (yyvsp[(1) - (3)].c_string),
                            SFOUND_AT);

                        yr_free((yyvsp[(1) - (3)].c_string));

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
    break;

  case 45:
#line 549 "grammar.y"
    {
                        yr_free((yyvsp[(1) - (4)].c_string));
                      }
    break;

  case 46:
#line 553 "grammar.y"
    {
                        int result = reduce_string_identifier(
                            yyscanner,
                            (yyvsp[(1) - (3)].c_string),
                            SFOUND_IN);

                        yr_free((yyvsp[(1) - (3)].c_string));

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
    break;

  case 47:
#line 564 "grammar.y"
    {
                        yr_free((yyvsp[(1) - (6)].c_string));
                        yr_free((yyvsp[(5) - (6)].sized_string));
                      }
    break;

  case 48:
#line 569 "grammar.y"
    {
                        emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
                      }
    break;

  case 49:
#line 573 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);

                        if ((yyvsp[(6) - (7)].integer) == INTEGER_SET_ENUMERATION)
                        {
                          emit(yyscanner, CLEAR_B, NULL);
                          emit(yyscanner, CLEAR_C, NULL);
                          emit(yyscanner, POP_A, &compiler->loop_address);
                        }
                        else // INTEGER_SET_RANGE
                        {
                          emit(yyscanner, POP_B, NULL);
                          emit(yyscanner, POP_A, NULL);
                          emit(yyscanner, POP_C, NULL);
                          emit(yyscanner, CLEAR_C, NULL);
                          emit(yyscanner, PUSH_B, NULL);
                          emit(yyscanner, PUSH_A, NULL);
                          emit(yyscanner, SUB, &compiler->loop_address);
                        }

                        compiler->loop_address++;
                        compiler->loop_identifier = (yyvsp[(3) - (7)].c_string);
                      }
    break;

  case 50:
#line 597 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);

                        if ((yyvsp[(6) - (11)].integer) == INTEGER_SET_ENUMERATION)
                        {
                          emit(yyscanner, INCR_C, NULL);
                          emit_with_arg(yyscanner, PUSH, 1, NULL);
                          emit(yyscanner, INCR_B, NULL);
                          emit(yyscanner, POP_A, NULL);

                          emit_with_arg_reloc(
                              yyscanner,
                              JNUNDEF_A,
                              PTR_TO_UINT64(compiler->loop_address),
                              NULL);
                        }
                        else // INTEGER_SET_RANGE
                        {
                          emit(yyscanner, INCR_C, NULL);
                          emit_with_arg(yyscanner, PUSH, 1, NULL);
                          emit(yyscanner, INCR_A, NULL);

                          emit_with_arg_reloc(
                              yyscanner,
                              JLE_A_B,
                              PTR_TO_UINT64(compiler->loop_address),
                              NULL);

                          emit(yyscanner, POP_B, NULL);
                        }

                        emit(yyscanner, POP_A, NULL);
                        emit(yyscanner, PNUNDEF_A_B, NULL);
                        emit(yyscanner, PUSH_C, NULL);
                        emit(yyscanner, LE, NULL);

                        compiler->loop_identifier = NULL;

                        yr_free((yyvsp[(3) - (11)].c_string));
                      }
    break;

  case 51:
#line 638 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);

                        emit(yyscanner, CLEAR_B, NULL);
                        emit(yyscanner, CLEAR_C, NULL);
                        emit(yyscanner, POP_A, &compiler->loop_address);

                        compiler->loop_address++;
                        compiler->inside_for++;
                      }
    break;

  case 52:
#line 649 "grammar.y"
    {
                        YARA_COMPILER* compiler = yyget_extra(yyscanner);

                        emit(yyscanner, INCR_C, NULL);
                        emit_with_arg(yyscanner, PUSH, 1, NULL);
                        emit(yyscanner, INCR_B, NULL);
                        emit(yyscanner, POP_A, NULL);

                        emit_with_arg_reloc(
                            yyscanner,
                            JNUNDEF_A,
                            PTR_TO_UINT64(compiler->loop_address),
                            NULL);

                        emit(yyscanner, POP_A, NULL);
                        emit(yyscanner, PNUNDEF_A_B, NULL);
                        emit(yyscanner, PUSH_C, NULL);
                        emit(yyscanner, LE, NULL);

                        compiler->inside_for--;
                      }
    break;

  case 53:
#line 671 "grammar.y"
    {
                        emit(yyscanner, OF, NULL);
                      }
    break;

  case 54:
#line 675 "grammar.y"
    {
                      }
    break;

  case 55:
#line 678 "grammar.y"
    {
                        emit(yyscanner, NOT, NULL);
                      }
    break;

  case 56:
#line 682 "grammar.y"
    {
                        emit(yyscanner, AND, NULL);
                      }
    break;

  case 57:
#line 686 "grammar.y"
    {
                        emit(yyscanner, OR, NULL);
                      }
    break;

  case 58:
#line 690 "grammar.y"
    {
                        emit(yyscanner, LT, NULL);
                      }
    break;

  case 59:
#line 694 "grammar.y"
    {
                        emit(yyscanner, GT, NULL);
                      }
    break;

  case 60:
#line 698 "grammar.y"
    {
                        emit(yyscanner, LE, NULL);
                      }
    break;

  case 61:
#line 702 "grammar.y"
    {
                        emit(yyscanner, GE, NULL);
                      }
    break;

  case 62:
#line 706 "grammar.y"
    {
                        emit(yyscanner, EQ, NULL);
                      }
    break;

  case 63:
#line 710 "grammar.y"
    {
                        emit(yyscanner, EQ, NULL);
                      }
    break;

  case 64:
#line 714 "grammar.y"
    {
                        emit(yyscanner, NEQ, NULL);
                      }
    break;

  case 65:
#line 721 "grammar.y"
    {
          YARA_COMPILER* compiler = yyget_extra(yyscanner);
          SIZED_STRING* sized_string = (yyvsp[(1) - (1)].sized_string);
          char* string;

          yr_arena_write_string(
            compiler->sz_arena,
            sized_string->c_string,
            &string);

          emit_with_arg_reloc(
              yyscanner,
              PUSH,
              PTR_TO_UINT64(string),
              NULL);

          yr_free((yyvsp[(1) - (1)].sized_string));
        }
    break;

  case 66:
#line 740 "grammar.y"
    {
          int result = reduce_external(
              yyscanner,
              (yyvsp[(1) - (1)].c_string),
              EXT_STR);

          yr_free((yyvsp[(1) - (1)].c_string));

          ERROR_IF(result != ERROR_SUCCESS);
        }
    break;

  case 67:
#line 753 "grammar.y"
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
    break;

  case 68:
#line 754 "grammar.y"
    { (yyval.integer) = INTEGER_SET_RANGE; }
    break;

  case 72:
#line 767 "grammar.y"
    {
                emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
              }
    break;

  case 74:
#line 772 "grammar.y"
    {
                emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
                emit_pushes_for_strings(yyscanner, "$*");
              }
    break;

  case 77:
#line 783 "grammar.y"
    {
                            emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
                            yr_free((yyvsp[(1) - (1)].c_string));
                          }
    break;

  case 78:
#line 788 "grammar.y"
    {
                            emit_pushes_for_strings(yyscanner, (yyvsp[(1) - (1)].c_string));
                            yr_free((yyvsp[(1) - (1)].c_string));
                          }
    break;

  case 80:
#line 796 "grammar.y"
    {
                    emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
                  }
    break;

  case 81:
#line 800 "grammar.y"
    {
                    emit_with_arg(yyscanner, PUSH, 1, NULL);
                  }
    break;

  case 83:
#line 808 "grammar.y"
    {
                emit(yyscanner, SIZE, NULL);
              }
    break;

  case 84:
#line 812 "grammar.y"
    {
                emit(yyscanner, ENTRYPOINT, NULL);
              }
    break;

  case 85:
#line 816 "grammar.y"
    {
                emit(yyscanner, INT8, NULL);
              }
    break;

  case 86:
#line 820 "grammar.y"
    {
                emit(yyscanner, INT16, NULL);
              }
    break;

  case 87:
#line 824 "grammar.y"
    {
                emit(yyscanner, INT32, NULL);
              }
    break;

  case 88:
#line 828 "grammar.y"
    {
                emit(yyscanner, UINT8, NULL);
              }
    break;

  case 89:
#line 832 "grammar.y"
    {
                emit(yyscanner, UINT16, NULL);
              }
    break;

  case 90:
#line 836 "grammar.y"
    {
                emit(yyscanner, UINT32, NULL);
              }
    break;

  case 91:
#line 840 "grammar.y"
    {
                emit_with_arg(yyscanner, PUSH, (yyvsp[(1) - (1)].integer), NULL);
              }
    break;

  case 92:
#line 844 "grammar.y"
    {
                int result = reduce_string_identifier(
                    yyscanner,
                    (yyvsp[(1) - (1)].c_string),
                    SCOUNT);

                yr_free((yyvsp[(1) - (1)].c_string));

                ERROR_IF(result != ERROR_SUCCESS);
              }
    break;

  case 93:
#line 855 "grammar.y"
    {
                int result = reduce_string_identifier(
                    yyscanner,
                    (yyvsp[(1) - (4)].c_string),
                    SOFFSET);

                yr_free((yyvsp[(1) - (4)].c_string));

                ERROR_IF(result != ERROR_SUCCESS);
              }
    break;

  case 94:
#line 866 "grammar.y"
    {
                int result = emit_with_arg(yyscanner, PUSH, 0, NULL);

                if (result == ERROR_SUCCESS)
                  result = reduce_string_identifier(
                      yyscanner,
                      (yyvsp[(1) - (1)].c_string),
                      SOFFSET);

                yr_free((yyvsp[(1) - (1)].c_string));

                ERROR_IF(result != ERROR_SUCCESS);
              }
    break;

  case 95:
#line 880 "grammar.y"
    {
                YARA_COMPILER* compiler = yyget_extra(yyscanner);
                EXTERNAL_VARIABLE* external;

                if (compiler->loop_identifier != NULL &&
                    strcmp((yyvsp[(1) - (1)].c_string), compiler->loop_identifier) == 0)
                {
                  emit(yyscanner, PUSH_A, NULL);
                }
                else
                {
                  compiler->last_result = reduce_external(
                      yyscanner,
                      (yyvsp[(1) - (1)].c_string),
                      EXT_INT);
                }

                yr_free((yyvsp[(1) - (1)].c_string));

                ERROR_IF(compiler->last_result != ERROR_SUCCESS);
              }
    break;

  case 96:
#line 902 "grammar.y"
    {
                emit(yyscanner, ADD, NULL);
              }
    break;

  case 97:
#line 906 "grammar.y"
    {
                emit(yyscanner, SUB, NULL);
              }
    break;

  case 98:
#line 910 "grammar.y"
    {
                emit(yyscanner, MUL, NULL);
              }
    break;

  case 99:
#line 914 "grammar.y"
    {
                emit(yyscanner, DIV, NULL);
              }
    break;

  case 100:
#line 918 "grammar.y"
    {
                emit(yyscanner, MOD, NULL);
              }
    break;

  case 101:
#line 922 "grammar.y"
    {
                emit(yyscanner, XOR, NULL);
              }
    break;

  case 102:
#line 926 "grammar.y"
    {
                emit(yyscanner, AND, NULL);
              }
    break;

  case 103:
#line 930 "grammar.y"
    {
                emit(yyscanner, OR, NULL);
              }
    break;

  case 104:
#line 934 "grammar.y"
    {
                emit(yyscanner, NEG, NULL);
              }
    break;

  case 105:
#line 938 "grammar.y"
    {
                emit(yyscanner, SHL, NULL);
              }
    break;

  case 106:
#line 942 "grammar.y"
    {
                emit(yyscanner, SHR, NULL);
              }
    break;


/* Line 1267 of yacc.c.  */
#line 2763 "grammar.c"
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
      yyerror (yyscanner, YY_("syntax error"));
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
	    yyerror (yyscanner, yymsg);
	  }
	else
	  {
	    yyerror (yyscanner, YY_("syntax error"));
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
		      yytoken, &yylval, yyscanner);
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
		  yystos[yystate], yyvsp, yyscanner);
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
  yyerror (yyscanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, yyscanner);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yyscanner);
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


#line 952 "grammar.y"
















