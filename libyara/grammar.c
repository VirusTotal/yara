/* A Bison parser, made by GNU Bison 3.0.5.  */

/* Bison implementation for Yacc-like parsers in C

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
#define YYBISON_VERSION "3.0.5"

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


/* Copy the first part of user declarations.  */
#line 30 "grammar.y" /* yacc.c:339  */



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


#line 182 "grammar.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YARA_YY_GRAMMAR_H_INCLUDED
# define YY_YARA_YY_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    _END_OF_FILE_ = 0,
    _END_OF_INCLUDED_FILE_ = 258,
    _DOT_DOT_ = 259,
    _RULE_ = 260,
    _PRIVATE_ = 261,
    _GLOBAL_ = 262,
    _META_ = 263,
    _STRINGS_ = 264,
    _CONDITION_ = 265,
    _IDENTIFIER_ = 266,
    _STRING_IDENTIFIER_ = 267,
    _STRING_COUNT_ = 268,
    _STRING_OFFSET_ = 269,
    _STRING_LENGTH_ = 270,
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 271,
    _NUMBER_ = 272,
    _DOUBLE_ = 273,
    _INTEGER_FUNCTION_ = 274,
    _TEXT_STRING_ = 275,
    _HEX_STRING_ = 276,
    _REGEXP_ = 277,
    _ASCII_ = 278,
    _WIDE_ = 279,
    _XOR_ = 280,
    _BASE64_ = 281,
    _BASE64_WIDE_ = 282,
    _NOCASE_ = 283,
    _FULLWORD_ = 284,
    _AT_ = 285,
    _FILESIZE_ = 286,
    _ENTRYPOINT_ = 287,
    _ALL_ = 288,
    _ANY_ = 289,
    _IN_ = 290,
    _OF_ = 291,
    _FOR_ = 292,
    _THEM_ = 293,
    _MATCHES_ = 294,
    _CONTAINS_ = 295,
    _STARTSWITH_ = 296,
    _ENDSWITH_ = 297,
    _ICONTAINS_ = 298,
    _ISTARTSWITH_ = 299,
    _IENDSWITH_ = 300,
    _IMPORT_ = 301,
    _TRUE_ = 302,
    _FALSE_ = 303,
    _OR_ = 304,
    _AND_ = 305,
    _NOT_ = 306,
    _EQ_ = 307,
    _NEQ_ = 308,
    _LT_ = 309,
    _LE_ = 310,
    _GT_ = 311,
    _GE_ = 312,
    _SHIFT_LEFT_ = 313,
    _SHIFT_RIGHT_ = 314,
    UNARY_MINUS = 315
  };
#endif
/* Tokens.  */
#define _END_OF_FILE_ 0
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
#define _IMPORT_ 301
#define _TRUE_ 302
#define _FALSE_ 303
#define _OR_ 304
#define _AND_ 305
#define _NOT_ 306
#define _EQ_ 307
#define _NEQ_ 308
#define _LT_ 309
#define _LE_ 310
#define _GT_ 311
#define _GE_ 312
#define _SHIFT_LEFT_ 313
#define _SHIFT_RIGHT_ 314
#define UNARY_MINUS 315

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 302 "grammar.y" /* yacc.c:355  */

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

#line 358 "grammar.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 374 "grammar.c" /* yacc.c:358  */

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
#else
typedef signed char yytype_int8;
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
# elif ! defined YYSIZE_T
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
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
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
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
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
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
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
#define YYNTOKENS  81
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  48
/* YYNRULES -- Number of rules.  */
#define YYNRULES  152
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  255

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   316

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    67,    62,     2,
      75,    76,    65,    63,    80,    64,    77,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    73,     2,
       2,    74,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    78,    66,    79,    61,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    71,    60,    72,    68,     2,     2,     2,
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
      55,    56,    57,    58,    59,    69,    70
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   319,   319,   321,   322,   323,   324,   325,   326,   334,
     347,   352,   346,   379,   382,   398,   401,   416,   421,   422,
     427,   428,   434,   437,   453,   462,   504,   505,   510,   527,
     541,   555,   569,   587,   588,   594,   593,   610,   609,   630,
     629,   654,   660,   720,   721,   722,   723,   724,   725,   731,
     752,   783,   788,   805,   810,   830,   831,   845,   846,   847,
     848,   849,   853,   854,   868,   872,   967,  1015,  1076,  1123,
    1124,  1128,  1163,  1216,  1259,  1282,  1288,  1294,  1306,  1316,
    1326,  1336,  1346,  1356,  1366,  1380,  1395,  1406,  1483,  1521,
    1423,  1680,  1679,  1769,  1775,  1797,  1804,  1803,  1849,  1848,
    1892,  1899,  1906,  1913,  1920,  1927,  1934,  1938,  1946,  1966,
    1994,  2068,  2096,  2104,  2113,  2137,  2152,  2172,  2171,  2177,
    2188,  2189,  2194,  2201,  2212,  2216,  2221,  2230,  2234,  2242,
    2254,  2268,  2275,  2282,  2307,  2319,  2331,  2346,  2358,  2373,
    2416,  2437,  2472,  2507,  2541,  2566,  2583,  2593,  2603,  2613,
    2623,  2643,  2663
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "$undefined", "\"end of included file\"",
  "\"..\"", "\"<rule>\"", "\"<private>\"", "\"<global>\"", "\"<meta>\"",
  "\"<strings>\"", "\"<condition>\"", "\"identifier\"",
  "\"string identifier\"", "\"string count\"", "\"string offset\"",
  "\"string length\"", "\"string identifier with wildcard\"",
  "\"integer number\"", "\"floating point number\"",
  "\"integer function\"", "\"text string\"", "\"hex string\"",
  "\"regular expression\"", "\"<ascii>\"", "\"<wide>\"", "\"<xor>\"",
  "\"<base64>\"", "\"<base64wide>\"", "\"<nocase>\"", "\"<fullword>\"",
  "\"<at>\"", "\"<filesize>\"", "\"<entrypoint>\"", "\"<all>\"",
  "\"<any>\"", "\"<in>\"", "\"<of>\"", "\"<for>\"", "\"<them>\"",
  "\"<matches>\"", "\"<contains>\"", "\"<startswith>\"", "\"<endswith>\"",
  "\"<icontains>\"", "\"<istartswith>\"", "\"<iendswith>\"",
  "\"<import>\"", "\"<true>\"", "\"<false\"", "\"<or>\"", "\"<and>\"",
  "\"<not>\"", "\"==\"", "\"!=\"", "\"<\"", "\"<=\"", "\">\"", "\">=\"",
  "\"<<\"", "\">>\"", "'|'", "'^'", "'&'", "'+'", "'-'", "'*'", "'\\\\'",
  "'%'", "'~'", "UNARY_MINUS", "\"include\"", "'{'", "'}'", "':'", "'='",
  "'('", "')'", "'.'", "'['", "']'", "','", "$accept", "rules", "import",
  "rule", "@1", "$@2", "meta", "strings", "condition", "rule_modifiers",
  "rule_modifier", "tags", "tag_list", "meta_declarations",
  "meta_declaration", "string_declarations", "string_declaration", "$@3",
  "$@4", "$@5", "string_modifiers", "string_modifier", "regexp_modifiers",
  "regexp_modifier", "hex_modifiers", "hex_modifier", "identifier",
  "arguments", "arguments_list", "regexp", "boolean_expression",
  "expression", "$@6", "$@7", "$@8", "$@9", "$@10", "for_variables",
  "iterator", "integer_set", "range", "integer_enumeration", "string_set",
  "$@11", "string_enumeration", "string_enumeration_item",
  "for_expression", "primary_expression", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     124,    94,    38,    43,    45,    42,    92,    37,   126,   315,
     316,   123,   125,    58,    61,    40,    41,    46,    91,    93,
      44
};
# endif

#define YYPACT_NINF -111

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-111)))

#define YYTABLE_NINF -125

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -111,    92,  -111,   -34,  -111,    -6,  -111,  -111,    80,  -111,
    -111,  -111,  -111,    16,  -111,  -111,  -111,  -111,   -43,    21,
      38,  -111,    52,   103,  -111,    60,   127,   123,    77,  -111,
      81,   123,  -111,   148,   157,    14,  -111,   102,   148,  -111,
     105,   111,  -111,  -111,  -111,  -111,   169,     3,  -111,    57,
    -111,  -111,   175,   177,   176,  -111,   -17,  -111,   126,   129,
    -111,  -111,   133,  -111,  -111,  -111,  -111,  -111,  -111,   109,
    -111,  -111,    57,   174,   174,    57,    84,  -111,   122,  -111,
     165,   249,  -111,  -111,  -111,   174,   135,   174,   174,   174,
     174,   101,   348,  -111,  -111,  -111,   122,   124,   211,    57,
     210,   174,  -111,  -111,   -10,   212,   174,   174,   174,   174,
     174,   174,   174,   174,   174,   174,   174,   174,   174,   174,
     174,   174,   174,   174,   174,   174,   174,   134,    90,   140,
     226,   348,   174,  -111,   164,   259,   291,   310,  -111,   -10,
     222,   174,  -111,  -111,   159,   156,   125,  -111,   269,    57,
      57,  -111,  -111,  -111,  -111,   348,   348,   348,   348,   348,
     348,   348,   348,   348,   348,   348,   348,    17,    17,   358,
     368,   378,   115,   115,  -111,  -111,   -10,  -111,  -111,  -111,
    -111,   162,   166,   170,  -111,  -111,  -111,  -111,  -111,  -111,
    -111,  -111,  -111,  -111,  -111,   153,  -111,  -111,  -111,   167,
    -111,   -20,  -111,    57,  -111,   189,  -111,    91,  -111,   227,
     228,   237,   174,  -111,    -8,   235,   125,  -111,  -111,    30,
    -111,   -60,   182,   183,   329,   185,   174,    84,   188,  -111,
    -111,  -111,  -111,    91,   245,  -111,  -111,  -111,  -111,    57,
      59,   153,  -111,  -111,   203,   -41,  -111,   174,   205,  -111,
    -111,   348,    57,   -39,  -111
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
      12,    30,     0,     0,     0,    65,    84,   134,   136,   138,
     131,   132,     0,   133,    73,   128,   129,   125,   126,     0,
      75,    76,     0,     0,     0,     0,   139,   152,    17,    74,
       0,   106,    41,    55,    62,     0,     0,     0,     0,     0,
       0,     0,   124,    95,   140,   149,     0,    74,   106,    69,
       0,     0,    98,    96,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    36,    38,
      40,    85,     0,    86,     0,     0,     0,     0,    87,     0,
       0,     0,   107,   127,     0,    70,    71,    66,     0,     0,
       0,   119,   117,    93,    77,    78,    80,    82,    79,    81,
      83,   104,   105,   100,   102,   101,   103,   150,   151,   148,
     146,   147,   141,   142,   143,   144,     0,   145,    47,    44,
      43,    48,    51,    53,    45,    46,    42,    61,    58,    57,
      59,    60,    56,    64,    63,     0,   135,   137,   130,     0,
     108,     0,    68,     0,    67,    99,    97,     0,    94,     0,
       0,     0,     0,    91,     0,     0,    72,   122,   123,     0,
     120,     0,     0,     0,     0,     0,     0,   110,     0,   111,
     113,   109,   118,     0,     0,    49,    52,    54,   114,     0,
       0,   115,    89,   121,     0,     0,   112,     0,     0,    50,
      92,   116,     0,     0,    90
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -111,  -111,   278,   279,  -111,  -111,  -111,  -111,  -111,  -111,
    -111,  -111,  -111,  -111,   252,  -111,   246,  -111,  -111,  -111,
    -111,  -111,  -111,  -111,  -111,  -111,    72,  -111,  -111,   190,
     -49,   -73,  -111,  -111,  -111,  -111,  -111,  -111,  -111,  -111,
      82,  -111,  -110,  -111,  -111,    64,   229,   -68
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     6,     7,    18,    34,    26,    29,    41,     8,
      16,    20,    22,    31,    32,    38,    39,    52,    53,    54,
     128,   186,   129,   192,   130,   194,    76,   144,   145,    77,
      96,    79,   140,   248,   225,   150,   149,   201,   228,   229,
     133,   240,   153,   207,   219,   220,    80,    81
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      78,    92,    97,    55,   234,    94,    95,    98,   102,   103,
     102,   103,     5,    85,    12,   214,   235,   131,    86,   134,
     135,   136,   137,    93,   -39,   -37,   146,    17,   151,   199,
      19,    42,    21,   148,    43,   250,     9,   254,   155,   156,
     157,   158,   159,   160,   161,   162,   163,   164,   165,   166,
     167,   168,   169,   170,   171,   172,   173,   174,   175,   177,
     215,    44,    45,    24,   195,   152,   208,   226,    55,    56,
      57,    58,    59,   177,    60,    61,    62,    63,    46,    64,
     123,   124,   125,   126,   141,    13,    14,    15,    65,    66,
      67,    68,     2,     3,    69,     4,   178,   -18,   -18,   -18,
     205,   206,   138,   217,    70,    71,   232,   218,    72,    23,
     233,    25,   -88,   179,   180,   181,   182,   183,   184,   185,
      55,    73,    57,    58,    59,    74,    60,    61,    62,    63,
     216,    64,    75,    27,    30,   246,    28,   139,     5,   247,
      65,    66,    67,    68,   224,    55,   187,    57,    58,    59,
      33,    60,    61,    62,    63,    35,    64,   212,   241,    99,
      37,   100,   101,   188,   189,    65,    66,    40,   190,   191,
     176,   102,   103,    73,   -74,   -74,    47,    74,    49,   251,
     125,   126,   141,    50,    90,    55,    51,    57,    58,    59,
     245,    60,    61,    62,    63,    82,    64,    84,    73,    83,
     142,   104,    74,   253,    87,    65,    66,    88,    89,    90,
     132,   118,   119,   120,   121,   122,   123,   124,   125,   126,
     141,   147,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   141,   193,   200,    64,   202,   203,   209,    73,   103,
     213,   210,    74,   196,   221,   211,   231,  -124,   222,    90,
     105,   106,   107,   108,   109,   110,   111,   223,   236,   237,
     239,   242,   244,   112,   113,   114,   115,   116,   117,   118,
     119,   120,   121,   122,   123,   124,   125,   126,   127,   249,
     252,    10,    11,    36,    48,  -124,   227,   143,   105,   106,
     107,   108,   109,   110,   111,   154,   230,   243,    91,     0,
       0,   112,   113,   114,   115,   116,   117,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   141,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   141,     0,   197,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   204,   118,
     119,   120,   121,   122,   123,   124,   125,   126,   141,     0,
       0,     0,     0,     0,     0,     0,     0,   198,   118,   119,
     120,   121,   122,   123,   124,   125,   126,   141,     0,     0,
       0,     0,     0,     0,     0,     0,   143,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   141,     0,     0,     0,
       0,     0,     0,     0,     0,   238,   118,   119,   120,   121,
     122,   123,   124,   125,   126,   141,   118,   119,     0,   121,
     122,   123,   124,   125,   126,   141,   118,   119,     0,     0,
     122,   123,   124,   125,   126,   141,   118,   119,     0,     0,
       0,   123,   124,   125,   126,   141
};

static const yytype_int16 yycheck[] =
{
      49,    69,    75,    11,    64,    73,    74,    75,    49,    50,
      49,    50,    46,    30,    20,    35,    76,    85,    35,    87,
      88,    89,    90,    72,    21,    22,    99,    11,    38,   139,
      73,    17,    11,   101,    20,    76,    70,    76,   106,   107,
     108,   109,   110,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   120,   121,   122,   123,   124,   125,   126,   127,
      80,    47,    48,    11,   132,    75,   176,    75,    11,    12,
      13,    14,    15,   141,    17,    18,    19,    20,    64,    22,
      63,    64,    65,    66,    67,     5,     6,     7,    31,    32,
      33,    34,     0,     1,    37,     3,     6,     5,     6,     7,
     149,   150,     1,    12,    47,    48,    76,    16,    51,    71,
      80,     8,    11,    23,    24,    25,    26,    27,    28,    29,
      11,    64,    13,    14,    15,    68,    17,    18,    19,    20,
     203,    22,    75,    73,    11,    76,     9,    36,    46,    80,
      31,    32,    33,    34,   212,    11,     6,    13,    14,    15,
      73,    17,    18,    19,    20,    74,    22,     4,   226,    75,
      12,    77,    78,    23,    24,    31,    32,    10,    28,    29,
      36,    49,    50,    64,    49,    50,    74,    68,    73,   247,
      65,    66,    67,    72,    75,    11,    17,    13,    14,    15,
     239,    17,    18,    19,    20,    20,    22,    21,    64,    22,
      76,    36,    68,   252,    78,    31,    32,    78,    75,    75,
      75,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    11,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,     6,    11,    22,    76,    80,    75,    64,    50,
      73,    75,    68,    79,    17,    75,    11,    36,    20,    75,
      39,    40,    41,    42,    43,    44,    45,    20,    76,    76,
      75,    73,    17,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    76,
      75,     3,     3,    31,    38,    36,   214,    76,    39,    40,
      41,    42,    43,    44,    45,   105,   214,   233,    69,    -1,
      -1,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    -1,    79,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    79,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    76,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    76,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    76,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    58,    59,    -1,    61,
      62,    63,    64,    65,    66,    67,    58,    59,    -1,    -1,
      62,    63,    64,    65,    66,    67,    58,    59,    -1,    -1,
      -1,    63,    64,    65,    66,    67
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    82,     0,     1,     3,    46,    83,    84,    90,    70,
      83,    84,    20,     5,     6,     7,    91,    11,    85,    73,
      92,    11,    93,    71,    11,     8,    87,    73,     9,    88,
      11,    94,    95,    73,    86,    74,    95,    12,    96,    97,
      10,    89,    17,    20,    47,    48,    64,    74,    97,    73,
      72,    17,    98,    99,   100,    11,    12,    13,    14,    15,
      17,    18,    19,    20,    22,    31,    32,    33,    34,    37,
      47,    48,    51,    64,    68,    75,   107,   110,   111,   112,
     127,   128,    20,    22,    21,    30,    35,    78,    78,    75,
      75,   127,   128,   111,   128,   128,   111,   112,   128,    75,
      77,    78,    49,    50,    36,    39,    40,    41,    42,    43,
      44,    45,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,   101,   103,
     105,   128,    75,   121,   128,   128,   128,   128,     1,    36,
     113,    67,    76,    76,   108,   109,   112,    11,   128,   117,
     116,    38,    75,   123,   110,   128,   128,   128,   128,   128,
     128,   128,   128,   128,   128,   128,   128,   128,   128,   128,
     128,   128,   128,   128,   128,   128,    36,   128,     6,    23,
      24,    25,    26,    27,    28,    29,   102,     6,    23,    24,
      28,    29,   104,     6,   106,   128,    79,    79,    76,   123,
      11,   118,    76,    80,    79,   111,   111,   124,   123,    75,
      75,    75,     4,    73,    35,    80,   112,    12,    16,   125,
     126,    17,    20,    20,   128,   115,    75,   107,   119,   120,
     121,    11,    76,    80,    64,    76,    76,    76,    76,    75,
     122,   128,    73,   126,    17,   111,    76,    80,   114,    76,
      76,   128,    75,   111,    76
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    81,    82,    82,    82,    82,    82,    82,    82,    83,
      85,    86,    84,    87,    87,    88,    88,    89,    90,    90,
      91,    91,    92,    92,    93,    93,    94,    94,    95,    95,
      95,    95,    95,    96,    96,    98,    97,    99,    97,   100,
      97,   101,   101,   102,   102,   102,   102,   102,   102,   102,
     102,   102,   102,   102,   102,   103,   103,   104,   104,   104,
     104,   104,   105,   105,   106,   107,   107,   107,   107,   108,
     108,   109,   109,   110,   111,   112,   112,   112,   112,   112,
     112,   112,   112,   112,   112,   112,   112,   112,   113,   114,
     112,   115,   112,   112,   112,   112,   116,   112,   117,   112,
     112,   112,   112,   112,   112,   112,   112,   112,   118,   118,
     119,   119,   120,   120,   121,   122,   122,   124,   123,   123,
     125,   125,   126,   126,   127,   127,   127,   128,   128,   128,
     128,   128,   128,   128,   128,   128,   128,   128,   128,   128,
     128,   128,   128,   128,   128,   128,   128,   128,   128,   128,
     128,   128,   128
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     2,
       0,     0,    11,     0,     3,     0,     3,     3,     0,     2,
       1,     1,     0,     2,     1,     2,     1,     2,     3,     3,
       4,     3,     3,     1,     2,     0,     5,     0,     5,     0,
       5,     0,     2,     1,     1,     1,     1,     1,     1,     4,
       6,     1,     4,     1,     4,     0,     2,     1,     1,     1,
       1,     1,     0,     2,     1,     1,     3,     4,     4,     0,
       1,     1,     3,     1,     1,     1,     1,     3,     3,     3,
       3,     3,     3,     3,     1,     3,     3,     3,     0,     0,
      11,     0,     9,     3,     4,     2,     0,     4,     0,     4,
       3,     3,     3,     3,     3,     3,     1,     3,     1,     3,
       1,     1,     3,     1,     5,     1,     3,     0,     4,     1,
       1,     3,     1,     1,     1,     1,     1,     3,     1,     1,
       4,     1,     1,     1,     1,     4,     1,     4,     1,     1,
       2,     3,     3,     3,     3,     3,     3,     3,     3,     2,
       3,     3,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
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

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



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
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, yyscanner, compiler); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yyscanner);
  YYUSE (compiler);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, compiler);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
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
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, void *yyscanner, YR_COMPILER* compiler)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , yyscanner, compiler);
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
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
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


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
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
static char *
yystpcpy (char *yydest, const char *yysrc)
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

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
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
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
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
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
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
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
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
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);
  YYUSE (compiler);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yytype)
    {
          case 11: /* "identifier"  */
#line 272 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1447 "grammar.c" /* yacc.c:1258  */
        break;

    case 12: /* "string identifier"  */
#line 276 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1453 "grammar.c" /* yacc.c:1258  */
        break;

    case 13: /* "string count"  */
#line 273 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1459 "grammar.c" /* yacc.c:1258  */
        break;

    case 14: /* "string offset"  */
#line 274 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1465 "grammar.c" /* yacc.c:1258  */
        break;

    case 15: /* "string length"  */
#line 275 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1471 "grammar.c" /* yacc.c:1258  */
        break;

    case 16: /* "string identifier with wildcard"  */
#line 277 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1477 "grammar.c" /* yacc.c:1258  */
        break;

    case 20: /* "text string"  */
#line 278 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1483 "grammar.c" /* yacc.c:1258  */
        break;

    case 21: /* "hex string"  */
#line 279 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1489 "grammar.c" /* yacc.c:1258  */
        break;

    case 22: /* "regular expression"  */
#line 280 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1495 "grammar.c" /* yacc.c:1258  */
        break;

    case 101: /* string_modifiers  */
#line 293 "grammar.y" /* yacc.c:1258  */
      {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1507 "grammar.c" /* yacc.c:1258  */
        break;

    case 102: /* string_modifier  */
#line 285 "grammar.y" /* yacc.c:1258  */
      {
  if (((*yyvaluep).modifier).alphabet != NULL)
  {
    yr_free(((*yyvaluep).modifier).alphabet);
    ((*yyvaluep).modifier).alphabet = NULL;
  }
}
#line 1519 "grammar.c" /* yacc.c:1258  */
        break;

    case 108: /* arguments  */
#line 282 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1525 "grammar.c" /* yacc.c:1258  */
        break;

    case 109: /* arguments_list  */
#line 283 "grammar.y" /* yacc.c:1258  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1531 "grammar.c" /* yacc.c:1258  */
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
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
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
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
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

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, yyscanner, compiler);
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

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

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
        case 8:
#line 327 "grammar.y" /* yacc.c:1663  */
    {
        _yr_compiler_pop_file_name(compiler);
      }
#line 1801 "grammar.c" /* yacc.c:1663  */
    break;

  case 9:
#line 335 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        fail_if_error(result);
      }
#line 1813 "grammar.c" /* yacc.c:1663  */
    break;

  case 10:
#line 347 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[-2].integer), (yyvsp[0].c_string), &(yyval.rule)));
      }
#line 1822 "grammar.c" /* yacc.c:1663  */
    break;

  case 11:
#line 352 "grammar.y" /* yacc.c:1663  */
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
#line 1840 "grammar.c" /* yacc.c:1663  */
    break;

  case 12:
#line 366 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, &(yyvsp[-7].rule)); // rule created in phase 1

        yr_free((yyvsp[-8].c_string));

        fail_if_error(result);
      }
#line 1853 "grammar.c" /* yacc.c:1663  */
    break;

  case 13:
#line 379 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.meta) = YR_ARENA_NULL_REF;
      }
#line 1861 "grammar.c" /* yacc.c:1663  */
    break;

  case 14:
#line 383 "grammar.y" /* yacc.c:1663  */
    {
        YR_META* meta = yr_arena_get_ptr(
            compiler->arena,
            YR_METAS_TABLE,
            (compiler->current_meta_idx - 1) * sizeof(YR_META));

        meta->flags |= META_FLAGS_LAST_IN_RULE;

        (yyval.meta) = (yyvsp[0].meta);
      }
#line 1876 "grammar.c" /* yacc.c:1663  */
    break;

  case 15:
#line 398 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.string) = YR_ARENA_NULL_REF;
      }
#line 1884 "grammar.c" /* yacc.c:1663  */
    break;

  case 16:
#line 402 "grammar.y" /* yacc.c:1663  */
    {
        YR_STRING* string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            (compiler->current_string_idx - 1) * sizeof(YR_STRING));

        string->flags |= STRING_FLAGS_LAST_IN_RULE;

        (yyval.string) = (yyvsp[0].string);
      }
#line 1899 "grammar.c" /* yacc.c:1663  */
    break;

  case 18:
#line 421 "grammar.y" /* yacc.c:1663  */
    { (yyval.integer) = 0;  }
#line 1905 "grammar.c" /* yacc.c:1663  */
    break;

  case 19:
#line 422 "grammar.y" /* yacc.c:1663  */
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1911 "grammar.c" /* yacc.c:1663  */
    break;

  case 20:
#line 427 "grammar.y" /* yacc.c:1663  */
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
#line 1917 "grammar.c" /* yacc.c:1663  */
    break;

  case 21:
#line 428 "grammar.y" /* yacc.c:1663  */
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
#line 1923 "grammar.c" /* yacc.c:1663  */
    break;

  case 22:
#line 434 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.tag) = YR_ARENA_NULL_REF;
      }
#line 1931 "grammar.c" /* yacc.c:1663  */
    break;

  case 23:
#line 438 "grammar.y" /* yacc.c:1663  */
    {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        fail_if_error(yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, "", NULL));

        (yyval.tag) = (yyvsp[0].tag);
      }
#line 1947 "grammar.c" /* yacc.c:1663  */
    break;

  case 24:
#line 454 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, (yyvsp[0].c_string), &(yyval.tag));

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 1960 "grammar.c" /* yacc.c:1663  */
    break;

  case 25:
#line 463 "grammar.y" /* yacc.c:1663  */
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
#line 2001 "grammar.c" /* yacc.c:1663  */
    break;

  case 26:
#line 504 "grammar.y" /* yacc.c:1663  */
    {  (yyval.meta) = (yyvsp[0].meta); }
#line 2007 "grammar.c" /* yacc.c:1663  */
    break;

  case 27:
#line 505 "grammar.y" /* yacc.c:1663  */
    {  (yyval.meta) = (yyvsp[-1].meta); }
#line 2013 "grammar.c" /* yacc.c:1663  */
    break;

  case 28:
#line 511 "grammar.y" /* yacc.c:1663  */
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
#line 2034 "grammar.c" /* yacc.c:1663  */
    break;

  case 29:
#line 528 "grammar.y" /* yacc.c:1663  */
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
#line 2052 "grammar.c" /* yacc.c:1663  */
    break;

  case 30:
#line 542 "grammar.y" /* yacc.c:1663  */
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
#line 2070 "grammar.c" /* yacc.c:1663  */
    break;

  case 31:
#line 556 "grammar.y" /* yacc.c:1663  */
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
#line 2088 "grammar.c" /* yacc.c:1663  */
    break;

  case 32:
#line 570 "grammar.y" /* yacc.c:1663  */
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
#line 2106 "grammar.c" /* yacc.c:1663  */
    break;

  case 33:
#line 587 "grammar.y" /* yacc.c:1663  */
    { (yyval.string) = (yyvsp[0].string); }
#line 2112 "grammar.c" /* yacc.c:1663  */
    break;

  case 34:
#line 588 "grammar.y" /* yacc.c:1663  */
    { (yyval.string) = (yyvsp[-1].string); }
#line 2118 "grammar.c" /* yacc.c:1663  */
    break;

  case 35:
#line 594 "grammar.y" /* yacc.c:1663  */
    {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2126 "grammar.c" /* yacc.c:1663  */
    break;

  case 36:
#line 598 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (yyvsp[0].modifier), (yyvsp[-4].c_string), (yyvsp[-1].sized_string), &(yyval.string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));
        yr_free((yyvsp[0].modifier).alphabet);

        fail_if_error(result);
        compiler->current_line = 0;
      }
#line 2142 "grammar.c" /* yacc.c:1663  */
    break;

  case 37:
#line 610 "grammar.y" /* yacc.c:1663  */
    {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2150 "grammar.c" /* yacc.c:1663  */
    break;

  case 38:
#line 614 "grammar.y" /* yacc.c:1663  */
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
#line 2170 "grammar.c" /* yacc.c:1663  */
    break;

  case 39:
#line 630 "grammar.y" /* yacc.c:1663  */
    {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2178 "grammar.c" /* yacc.c:1663  */
    break;

  case 40:
#line 634 "grammar.y" /* yacc.c:1663  */
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
#line 2198 "grammar.c" /* yacc.c:1663  */
    break;

  case 41:
#line 654 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.modifier).flags = 0;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 0;
        (yyval.modifier).alphabet = NULL;
      }
#line 2209 "grammar.c" /* yacc.c:1663  */
    break;

  case 42:
#line 661 "grammar.y" /* yacc.c:1663  */
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
#line 2269 "grammar.c" /* yacc.c:1663  */
    break;

  case 43:
#line 720 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2275 "grammar.c" /* yacc.c:1663  */
    break;

  case 44:
#line 721 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2281 "grammar.c" /* yacc.c:1663  */
    break;

  case 45:
#line 722 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2287 "grammar.c" /* yacc.c:1663  */
    break;

  case 46:
#line 723 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2293 "grammar.c" /* yacc.c:1663  */
    break;

  case 47:
#line 724 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2299 "grammar.c" /* yacc.c:1663  */
    break;

  case 48:
#line 726 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = 0;
        (yyval.modifier).xor_max = 255;
      }
#line 2309 "grammar.c" /* yacc.c:1663  */
    break;

  case 49:
#line 732 "grammar.y" /* yacc.c:1663  */
    {
        int result = ERROR_SUCCESS;

        if ((yyvsp[-1].integer) < 0 || (yyvsp[-1].integer) > 255)
        {
          yr_compiler_set_error_extra_info(compiler, "invalid xor range");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        (yyval.modifier).flags = STRING_FLAGS_XOR;
        (yyval.modifier).xor_min = (yyvsp[-1].integer);
        (yyval.modifier).xor_max = (yyvsp[-1].integer);
      }
#line 2329 "grammar.c" /* yacc.c:1663  */
    break;

  case 50:
#line 753 "grammar.y" /* yacc.c:1663  */
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
        (yyval.modifier).xor_min = (yyvsp[-3].integer);
        (yyval.modifier).xor_max = (yyvsp[-1].integer);
      }
#line 2364 "grammar.c" /* yacc.c:1663  */
    break;

  case 51:
#line 784 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.modifier).flags = STRING_FLAGS_BASE64;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2373 "grammar.c" /* yacc.c:1663  */
    break;

  case 52:
#line 789 "grammar.y" /* yacc.c:1663  */
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
#line 2394 "grammar.c" /* yacc.c:1663  */
    break;

  case 53:
#line 806 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.modifier).flags = STRING_FLAGS_BASE64_WIDE;
        (yyval.modifier).alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
#line 2403 "grammar.c" /* yacc.c:1663  */
    break;

  case 54:
#line 811 "grammar.y" /* yacc.c:1663  */
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
#line 2424 "grammar.c" /* yacc.c:1663  */
    break;

  case 55:
#line 830 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = 0; }
#line 2430 "grammar.c" /* yacc.c:1663  */
    break;

  case 56:
#line 832 "grammar.y" /* yacc.c:1663  */
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
#line 2445 "grammar.c" /* yacc.c:1663  */
    break;

  case 57:
#line 845 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_WIDE; }
#line 2451 "grammar.c" /* yacc.c:1663  */
    break;

  case 58:
#line 846 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_ASCII; }
#line 2457 "grammar.c" /* yacc.c:1663  */
    break;

  case 59:
#line 847 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_NO_CASE; }
#line 2463 "grammar.c" /* yacc.c:1663  */
    break;

  case 60:
#line 848 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_FULL_WORD; }
#line 2469 "grammar.c" /* yacc.c:1663  */
    break;

  case 61:
#line 849 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2475 "grammar.c" /* yacc.c:1663  */
    break;

  case 62:
#line 853 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = 0; }
#line 2481 "grammar.c" /* yacc.c:1663  */
    break;

  case 63:
#line 855 "grammar.y" /* yacc.c:1663  */
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
#line 2496 "grammar.c" /* yacc.c:1663  */
    break;

  case 64:
#line 868 "grammar.y" /* yacc.c:1663  */
    { (yyval.modifier).flags = STRING_FLAGS_PRIVATE; }
#line 2502 "grammar.c" /* yacc.c:1663  */
    break;

  case 65:
#line 873 "grammar.y" /* yacc.c:1663  */
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
#line 2601 "grammar.c" /* yacc.c:1663  */
    break;

  case 66:
#line 968 "grammar.y" /* yacc.c:1663  */
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
#line 2653 "grammar.c" /* yacc.c:1663  */
    break;

  case 67:
#line 1016 "grammar.y" /* yacc.c:1663  */
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
#line 2717 "grammar.c" /* yacc.c:1663  */
    break;

  case 68:
#line 1077 "grammar.y" /* yacc.c:1663  */
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
#line 2764 "grammar.c" /* yacc.c:1663  */
    break;

  case 69:
#line 1123 "grammar.y" /* yacc.c:1663  */
    { (yyval.c_string) = yr_strdup(""); }
#line 2770 "grammar.c" /* yacc.c:1663  */
    break;

  case 70:
#line 1124 "grammar.y" /* yacc.c:1663  */
    { (yyval.c_string) = (yyvsp[0].c_string); }
#line 2776 "grammar.c" /* yacc.c:1663  */
    break;

  case 71:
#line 1129 "grammar.y" /* yacc.c:1663  */
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
#line 2815 "grammar.c" /* yacc.c:1663  */
    break;

  case 72:
#line 1164 "grammar.y" /* yacc.c:1663  */
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
#line 2868 "grammar.c" /* yacc.c:1663  */
    break;

  case 73:
#line 1217 "grammar.y" /* yacc.c:1663  */
    {
        SIZED_STRING* sized_string = (yyvsp[0].sized_string);
        YR_ARENA_REF re_ref;
        RE_ERROR error;

        int result = ERROR_SUCCESS;
        int re_flags = 0;

        if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if (sized_string->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        result = yr_re_compile(
            sized_string->c_string,
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
#line 2911 "grammar.c" /* yacc.c:1663  */
    break;

  case 74:
#line 1260 "grammar.y" /* yacc.c:1663  */
    {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_STRING)
        {
          if (!YR_ARENA_IS_NULL_REF((yyvsp[0].expression).value.sized_string_ref))
          {
            SIZED_STRING* sized_string = yr_arena_ref_to_ptr(
                compiler->arena, &(yyvsp[0].expression).value.sized_string_ref);

            yywarning(yyscanner,
                "Using literal string \"%s\" in a boolean operation.",
                sized_string->c_string);
          }

          fail_if_error(yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL));
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2935 "grammar.c" /* yacc.c:1663  */
    break;

  case 75:
#line 1283 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 1));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2945 "grammar.c" /* yacc.c:1663  */
    break;

  case 76:
#line 1289 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 0));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2955 "grammar.c" /* yacc.c:1663  */
    break;

  case 77:
#line 1295 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        fail_if_error(yr_parser_emit(
            yyscanner,
            OP_MATCHES,
            NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2971 "grammar.c" /* yacc.c:1663  */
    break;

  case 78:
#line 1307 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2985 "grammar.c" /* yacc.c:1663  */
    break;

  case 79:
#line 1317 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "icontains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "icontains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ICONTAINS, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2999 "grammar.c" /* yacc.c:1663  */
    break;

  case 80:
#line 1327 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "startswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "startswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_STARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3013 "grammar.c" /* yacc.c:1663  */
    break;

  case 81:
#line 1337 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "istartswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "istartswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ISTARTSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3027 "grammar.c" /* yacc.c:1663  */
    break;

  case 82:
#line 1347 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "endswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "endswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3041 "grammar.c" /* yacc.c:1663  */
    break;

  case 83:
#line 1357 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "iendswith");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "iendswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IENDSWITH, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3055 "grammar.c" /* yacc.c:1663  */
    break;

  case 84:
#line 1367 "grammar.y" /* yacc.c:1663  */
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
#line 3073 "grammar.c" /* yacc.c:1663  */
    break;

  case 85:
#line 1381 "grammar.y" /* yacc.c:1663  */
    {
        int result;

        check_type_with_cleanup((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at", yr_free((yyvsp[-2].c_string)));

        result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_AT, (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3092 "grammar.c" /* yacc.c:1663  */
    break;

  case 86:
#line 1396 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_IN, YR_UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3107 "grammar.c" /* yacc.c:1663  */
    break;

  case 87:
#line 1407 "grammar.y" /* yacc.c:1663  */
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
#line 3128 "grammar.c" /* yacc.c:1663  */
    break;

  case 88:
#line 1483 "grammar.y" /* yacc.c:1663  */
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
#line 3170 "grammar.c" /* yacc.c:1663  */
    break;

  case 89:
#line 1521 "grammar.y" /* yacc.c:1663  */
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
#line 3223 "grammar.c" /* yacc.c:1663  */
    break;

  case 90:
#line 1570 "grammar.y" /* yacc.c:1663  */
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
#line 3337 "grammar.c" /* yacc.c:1663  */
    break;

  case 91:
#line 1680 "grammar.y" /* yacc.c:1663  */
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
#line 3376 "grammar.c" /* yacc.c:1663  */
    break;

  case 92:
#line 1715 "grammar.y" /* yacc.c:1663  */
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
#line 3435 "grammar.c" /* yacc.c:1663  */
    break;

  case 93:
#line 1770 "grammar.y" /* yacc.c:1663  */
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3445 "grammar.c" /* yacc.c:1663  */
    break;

  case 94:
#line 1776 "grammar.y" /* yacc.c:1663  */
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

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3471 "grammar.c" /* yacc.c:1663  */
    break;

  case 95:
#line 1798 "grammar.y" /* yacc.c:1663  */
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3481 "grammar.c" /* yacc.c:1663  */
    break;

  case 96:
#line 1804 "grammar.y" /* yacc.c:1663  */
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
#line 3507 "grammar.c" /* yacc.c:1663  */
    break;

  case 97:
#line 1826 "grammar.y" /* yacc.c:1663  */
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
#line 3534 "grammar.c" /* yacc.c:1663  */
    break;

  case 98:
#line 1849 "grammar.y" /* yacc.c:1663  */
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
#line 3559 "grammar.c" /* yacc.c:1663  */
    break;

  case 99:
#line 1870 "grammar.y" /* yacc.c:1663  */
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
#line 3586 "grammar.c" /* yacc.c:1663  */
    break;

  case 100:
#line 1893 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3597 "grammar.c" /* yacc.c:1663  */
    break;

  case 101:
#line 1900 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3608 "grammar.c" /* yacc.c:1663  */
    break;

  case 102:
#line 1907 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3619 "grammar.c" /* yacc.c:1663  */
    break;

  case 103:
#line 1914 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3630 "grammar.c" /* yacc.c:1663  */
    break;

  case 104:
#line 1921 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3641 "grammar.c" /* yacc.c:1663  */
    break;

  case 105:
#line 1928 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression)));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3652 "grammar.c" /* yacc.c:1663  */
    break;

  case 106:
#line 1935 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3660 "grammar.c" /* yacc.c:1663  */
    break;

  case 107:
#line 1939 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3668 "grammar.c" /* yacc.c:1663  */
    break;

  case 108:
#line 1947 "grammar.y" /* yacc.c:1663  */
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
#line 3692 "grammar.c" /* yacc.c:1663  */
    break;

  case 109:
#line 1967 "grammar.y" /* yacc.c:1663  */
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
#line 3721 "grammar.c" /* yacc.c:1663  */
    break;

  case 110:
#line 1995 "grammar.y" /* yacc.c:1663  */
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
#line 3799 "grammar.c" /* yacc.c:1663  */
    break;

  case 111:
#line 2069 "grammar.y" /* yacc.c:1663  */
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
#line 3827 "grammar.c" /* yacc.c:1663  */
    break;

  case 112:
#line 2097 "grammar.y" /* yacc.c:1663  */
    {
        // $2 contains the number of integers in the enumeration
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[-1].integer)));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_ENUM, NULL));
      }
#line 3839 "grammar.c" /* yacc.c:1663  */
    break;

  case 113:
#line 2105 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_RANGE, NULL));
      }
#line 3848 "grammar.c" /* yacc.c:1663  */
    break;

  case 114:
#line 2114 "grammar.y" /* yacc.c:1663  */
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
#line 3872 "grammar.c" /* yacc.c:1663  */
    break;

  case 115:
#line 2138 "grammar.y" /* yacc.c:1663  */
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
#line 3891 "grammar.c" /* yacc.c:1663  */
    break;

  case 116:
#line 2153 "grammar.y" /* yacc.c:1663  */
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
#line 3910 "grammar.c" /* yacc.c:1663  */
    break;

  case 117:
#line 2172 "grammar.y" /* yacc.c:1663  */
    {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
#line 3919 "grammar.c" /* yacc.c:1663  */
    break;

  case 119:
#line 2178 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit_push_const(yyscanner, YR_UNDEFINED));

        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*"));
      }
#line 3930 "grammar.c" /* yacc.c:1663  */
    break;

  case 122:
#line 2195 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 3941 "grammar.c" /* yacc.c:1663  */
    break;

  case 123:
#line 2202 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if_error(result);
      }
#line 3952 "grammar.c" /* yacc.c:1663  */
    break;

  case 124:
#line 2213 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 3960 "grammar.c" /* yacc.c:1663  */
    break;

  case 125:
#line 2217 "grammar.y" /* yacc.c:1663  */
    {
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
        (yyval.integer) = FOR_EXPRESSION_ALL;
      }
#line 3969 "grammar.c" /* yacc.c:1663  */
    break;

  case 126:
#line 2222 "grammar.y" /* yacc.c:1663  */
    {
        yr_parser_emit_push_const(yyscanner, 1);
        (yyval.integer) = FOR_EXPRESSION_ANY;
      }
#line 3978 "grammar.c" /* yacc.c:1663  */
    break;

  case 127:
#line 2231 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3986 "grammar.c" /* yacc.c:1663  */
    break;

  case 128:
#line 2235 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 3998 "grammar.c" /* yacc.c:1663  */
    break;

  case 129:
#line 2243 "grammar.y" /* yacc.c:1663  */
    {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4014 "grammar.c" /* yacc.c:1663  */
    break;

  case 130:
#line 2255 "grammar.y" /* yacc.c:1663  */
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
#line 4032 "grammar.c" /* yacc.c:1663  */
    break;

  case 131:
#line 2269 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit_push_const(yyscanner, (yyvsp[0].integer)));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 4043 "grammar.c" /* yacc.c:1663  */
    break;

  case 132:
#line 2276 "grammar.y" /* yacc.c:1663  */
    {
        fail_if_error(yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 4054 "grammar.c" /* yacc.c:1663  */
    break;

  case 133:
#line 2283 "grammar.y" /* yacc.c:1663  */
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
#line 4083 "grammar.c" /* yacc.c:1663  */
    break;

  case 134:
#line 2308 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[0].c_string), OP_COUNT, YR_UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4099 "grammar.c" /* yacc.c:1663  */
    break;

  case 135:
#line 2320 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_OFFSET, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4115 "grammar.c" /* yacc.c:1663  */
    break;

  case 136:
#line 2332 "grammar.y" /* yacc.c:1663  */
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
#line 4134 "grammar.c" /* yacc.c:1663  */
    break;

  case 137:
#line 2347 "grammar.y" /* yacc.c:1663  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_LENGTH, YR_UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if_error(result);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = YR_UNDEFINED;
      }
#line 4150 "grammar.c" /* yacc.c:1663  */
    break;

  case 138:
#line 2359 "grammar.y" /* yacc.c:1663  */
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
#line 4169 "grammar.c" /* yacc.c:1663  */
    break;

  case 139:
#line 2374 "grammar.y" /* yacc.c:1663  */
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
#line 4216 "grammar.c" /* yacc.c:1663  */
    break;

  case 140:
#line 2417 "grammar.y" /* yacc.c:1663  */
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
#line 4241 "grammar.c" /* yacc.c:1663  */
    break;

  case 141:
#line 2438 "grammar.y" /* yacc.c:1663  */
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
#line 4280 "grammar.c" /* yacc.c:1663  */
    break;

  case 142:
#line 2473 "grammar.y" /* yacc.c:1663  */
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
#line 4319 "grammar.c" /* yacc.c:1663  */
    break;

  case 143:
#line 2508 "grammar.y" /* yacc.c:1663  */
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
#line 4357 "grammar.c" /* yacc.c:1663  */
    break;

  case 144:
#line 2542 "grammar.y" /* yacc.c:1663  */
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
#line 4386 "grammar.c" /* yacc.c:1663  */
    break;

  case 145:
#line 2567 "grammar.y" /* yacc.c:1663  */
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
#line 4407 "grammar.c" /* yacc.c:1663  */
    break;

  case 146:
#line 2584 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4421 "grammar.c" /* yacc.c:1663  */
    break;

  case 147:
#line 2594 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4435 "grammar.c" /* yacc.c:1663  */
    break;

  case 148:
#line 2604 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 4449 "grammar.c" /* yacc.c:1663  */
    break;

  case 149:
#line 2614 "grammar.y" /* yacc.c:1663  */
    {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL));

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == YR_UNDEFINED) ?
            YR_UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 4463 "grammar.c" /* yacc.c:1663  */
    break;

  case 150:
#line 2624 "grammar.y" /* yacc.c:1663  */
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
#line 4487 "grammar.c" /* yacc.c:1663  */
    break;

  case 151:
#line 2644 "grammar.y" /* yacc.c:1663  */
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
#line 4511 "grammar.c" /* yacc.c:1663  */
    break;

  case 152:
#line 2664 "grammar.y" /* yacc.c:1663  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 4519 "grammar.c" /* yacc.c:1663  */
    break;


#line 4523 "grammar.c" /* yacc.c:1663  */
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
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (yyscanner, compiler, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yyscanner, compiler, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
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

  /* Else will try to reuse lookahead token after shifting the error
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

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
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

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


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

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, compiler, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

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
  return yyresult;
}
#line 2669 "grammar.y" /* yacc.c:1907  */

