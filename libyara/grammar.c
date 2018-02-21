/* A Bison parser, made by GNU Bison 3.0.4.18-9674.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

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
#define YYBISON_VERSION "3.0.4.18-9674"

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

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define fail_if(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
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
      compiler->last_result = ERROR_WRONG_TYPE; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }


#define check_type(expression, expected_type, op) \
    check_type_with_cleanup(expression, expected_type, op, )


#line 148 "grammar.c" /* yacc.c:339  */

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
    _XOR_ = 279,
    _NOCASE_ = 280,
    _FULLWORD_ = 281,
    _AT_ = 282,
    _FILESIZE_ = 283,
    _ENTRYPOINT_ = 284,
    _ALL_ = 285,
    _ANY_ = 286,
    _IN_ = 287,
    _OF_ = 288,
    _FOR_ = 289,
    _THEM_ = 290,
    _MATCHES_ = 291,
    _CONTAINS_ = 292,
    _IMPORT_ = 293,
    _TRUE_ = 294,
    _FALSE_ = 295,
    _OR_ = 296,
    _AND_ = 297,
    _EQ_ = 298,
    _NEQ_ = 299,
    _LT_ = 300,
    _LE_ = 301,
    _GT_ = 302,
    _GE_ = 303,
    _SHIFT_LEFT_ = 304,
    _SHIFT_RIGHT_ = 305,
    _NOT_ = 306,
    UNARY_MINUS = 307
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
#define _XOR_ 279
#define _NOCASE_ 280
#define _FULLWORD_ 281
#define _AT_ 282
#define _FILESIZE_ 283
#define _ENTRYPOINT_ 284
#define _ALL_ 285
#define _ANY_ 286
#define _IN_ 287
#define _OF_ 288
#define _FOR_ 289
#define _THEM_ 290
#define _MATCHES_ 291
#define _CONTAINS_ 292
#define _IMPORT_ 293
#define _TRUE_ 294
#define _FALSE_ 295
#define _OR_ 296
#define _AND_ 297
#define _EQ_ 298
#define _NEQ_ 299
#define _LT_ 300
#define _LE_ 301
#define _GT_ 302
#define _GE_ 303
#define _SHIFT_LEFT_ 304
#define _SHIFT_RIGHT_ 305
#define _NOT_ 306
#define UNARY_MINUS 307

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 216 "grammar.y" /* yacc.c:355  */

  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;
  YR_RULE*        rule;

#line 303 "grammar.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 319 "grammar.c" /* yacc.c:358  */

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
#define YYLAST   396

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  73
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  41
/* YYNRULES -- Number of rules.  */
#define YYNRULES  123
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  211

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   308

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    58,    45,     2,
      70,    71,    56,    54,    72,    55,    67,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    65,     2,
       2,    66,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    68,    57,    69,    44,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    63,    43,    64,    60,     2,     2,     2,
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
      35,    36,    37,    38,    39,    40,    41,    42,    46,    47,
      48,    49,    50,    51,    52,    53,    59,    61,    62
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   230,   230,   232,   233,   234,   235,   236,   241,   254,
     263,   253,   286,   289,   317,   320,   347,   352,   353,   358,
     359,   365,   368,   386,   399,   436,   437,   442,   458,   471,
     484,   497,   514,   515,   521,   520,   536,   535,   551,   565,
     566,   571,   572,   573,   574,   575,   580,   665,   711,   769,
     814,   815,   819,   846,   884,   926,   948,   957,   966,   981,
     993,  1007,  1020,  1031,  1042,  1072,  1041,  1186,  1185,  1264,
    1270,  1277,  1276,  1330,  1329,  1381,  1390,  1399,  1408,  1417,
    1426,  1435,  1439,  1447,  1448,  1453,  1475,  1487,  1503,  1502,
    1508,  1519,  1520,  1525,  1532,  1543,  1544,  1548,  1556,  1560,
    1570,  1584,  1600,  1610,  1619,  1644,  1656,  1668,  1684,  1696,
    1712,  1757,  1776,  1811,  1846,  1880,  1905,  1923,  1933,  1943,
    1953,  1963,  1981,  1999
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_DOT_DOT_", "_RULE_", "_PRIVATE_",
  "_GLOBAL_", "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_LENGTH_", "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_",
  "_DOUBLE_", "_INTEGER_FUNCTION_", "_TEXT_STRING_", "_HEX_STRING_",
  "_REGEXP_", "_ASCII_", "_WIDE_", "_XOR_", "_NOCASE_", "_FULLWORD_",
  "_AT_", "_FILESIZE_", "_ENTRYPOINT_", "_ALL_", "_ANY_", "_IN_", "_OF_",
  "_FOR_", "_THEM_", "_MATCHES_", "_CONTAINS_", "_IMPORT_", "_TRUE_",
  "_FALSE_", "_OR_", "_AND_", "'|'", "'^'", "'&'", "_EQ_", "_NEQ_", "_LT_",
  "_LE_", "_GT_", "_GE_", "_SHIFT_LEFT_", "_SHIFT_RIGHT_", "'+'", "'-'",
  "'*'", "'\\\\'", "'%'", "_NOT_", "'~'", "UNARY_MINUS", "\"include\"",
  "'{'", "'}'", "':'", "'='", "'.'", "'['", "']'", "'('", "')'", "','",
  "$accept", "rules", "import", "rule", "@1", "$@2", "meta", "strings",
  "condition", "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "$@3", "$@4", "string_modifiers",
  "string_modifier", "identifier", "arguments", "arguments_list", "regexp",
  "boolean_expression", "expression", "$@5", "$@6", "$@7", "$@8", "$@9",
  "integer_set", "range", "integer_enumeration", "string_set", "$@10",
  "string_enumeration", "string_enumeration_item", "for_expression",
  "primary_expression", YY_NULLPTR
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
     295,   296,   297,   124,    94,    38,   298,   299,   300,   301,
     302,   303,   304,   305,    43,    45,    42,    92,    37,   306,
     126,   307,   308,   123,   125,    58,    61,    46,    91,    93,
      40,    41,    44
};
# endif

#define YYPACT_NINF -73

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-73)))

#define YYTABLE_NINF -96

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -73,    90,   -73,   -33,   -16,   -73,   -73,    69,   -73,   -73,
     -73,   -73,     5,   -73,   -73,   -73,   -73,   -42,    44,   -38,
     -73,    60,    61,   -73,    21,    72,    79,    41,   -73,    64,
      79,   -73,   129,   141,    16,   -73,    85,   129,   -73,    80,
      96,   -73,   -73,   -73,   -73,   145,    81,   -73,    48,   -73,
     -73,   -73,   143,   150,   -73,   -10,   -73,   104,   111,   -73,
     -73,   114,   -73,   -73,   -73,   -73,   -73,   -73,   103,   -73,
     -73,   125,    48,   125,    48,   -34,   -73,    68,   -73,   148,
     293,   -73,   -73,   125,   116,   125,   125,   125,   125,    71,
     309,   -73,   -73,   -73,    68,   133,   170,   172,   125,    48,
     -73,   -73,    -7,   184,   125,   125,   125,   125,   125,   125,
     125,   125,   125,   125,   125,   125,   125,   125,   125,   125,
     125,   152,   152,   309,   125,   -73,   230,   248,   112,   190,
     -73,   176,    -7,   -73,   -73,   -73,   266,   138,   139,    70,
      48,    48,   -73,   -73,   -73,   -73,   309,   324,   338,   -44,
     309,   309,   309,   309,   309,   309,   136,   136,    27,    27,
     -73,   -73,   -73,   -73,   -73,   -73,   -73,   -73,   -73,   144,
     -73,   -73,   -73,   -73,   147,   -73,   -73,    48,   168,   -73,
      15,   125,   159,   -73,    70,   -73,   -73,    54,   -73,   210,
     125,   165,   -73,   161,   -73,    15,   -73,    77,   144,   -73,
      48,   -73,   -73,   125,   162,    56,   309,    48,   -73,    58,
     -73
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    17,     0,     4,     3,     0,     7,     6,
       5,     8,     0,    19,    20,    18,     9,    21,     0,     0,
      23,    22,    12,    24,     0,    14,     0,     0,    10,     0,
      13,    25,     0,     0,     0,    26,     0,    15,    32,     0,
       0,    28,    27,    30,    31,     0,    34,    33,     0,    11,
      29,    38,     0,     0,    46,    60,   105,   107,   109,   102,
     103,     0,   104,    54,    99,   100,    96,    97,     0,    56,
      57,     0,     0,     0,     0,   110,   123,    16,    55,     0,
      81,    39,    39,     0,     0,     0,     0,     0,     0,     0,
      95,   111,    70,   120,     0,    55,    81,     0,     0,    50,
      73,    71,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    35,    37,    61,     0,    62,     0,     0,     0,     0,
      63,     0,     0,    82,    98,    47,     0,     0,    51,    52,
       0,     0,    90,    88,    69,    58,    59,   119,   117,   118,
      79,    80,    75,    77,    76,    78,   121,   122,   112,   113,
     114,   115,   116,    42,    41,    45,    43,    44,    40,     0,
     106,   108,   101,    64,     0,    48,    49,     0,    74,    72,
       0,     0,     0,    67,    53,    93,    94,     0,    91,     0,
       0,     0,    84,     0,    89,     0,    85,     0,    86,    65,
       0,    92,    83,     0,     0,     0,    87,     0,    68,     0,
      66
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -73,   -73,   233,   234,   -73,   -73,   -73,   -73,   -73,   -73,
     -73,   -73,   -73,   -73,   208,   -73,   202,   -73,   -73,   158,
     -73,   -73,   -73,   -73,   146,   -48,   -72,   -73,   -73,   -73,
     -73,   -73,   -73,    74,   -73,   118,   -73,   -73,    57,   183,
     -67
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    17,    33,    25,    28,    40,     7,
      15,    19,    21,    30,    31,    37,    38,    52,    53,   121,
     168,    75,   137,   138,    76,    94,    78,   182,   204,   193,
     141,   140,   191,   125,   197,   144,   180,   187,   188,    79,
      80
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      77,    90,    95,    11,    91,     4,    93,    96,   114,   115,
     116,   117,   118,   119,   120,    16,   123,    83,   126,   127,
     128,   129,    84,    18,    92,    22,   185,   139,   142,     8,
     186,   136,    41,    97,    98,    42,    99,   146,   147,   148,
     149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
     159,   160,   161,   162,    20,    43,    44,   169,    54,    55,
      56,    57,    58,   143,    59,    60,    61,    62,    24,    63,
      23,    45,   130,    12,    13,    14,    64,    65,    66,    67,
      27,   131,    68,   118,   119,   120,    26,    69,    70,    29,
       2,     3,   178,   179,   -17,   -17,   -17,   100,   101,   100,
     101,    51,   -36,    71,   132,   184,    32,    72,    73,   100,
     101,   -55,   -55,    54,   189,    56,    57,    58,    74,    59,
      60,    61,    62,   198,    63,   194,   195,   208,     4,   210,
      34,    64,    65,    66,    67,    54,   206,    56,    57,    58,
      36,    59,    60,    61,    62,    48,    63,   181,   202,   203,
      39,    46,   205,    64,    65,   105,   106,   107,    71,   209,
      49,    50,    81,    73,   114,   115,   116,   117,   118,   119,
     120,    82,    85,    88,   163,   164,   165,   166,   167,    86,
      71,   102,   135,   172,    87,    73,   124,   105,   106,   107,
     116,   117,   118,   119,   120,    88,   114,   115,   116,   117,
     118,   119,   120,   -95,   133,    63,   103,   104,   173,   176,
     101,   177,   183,   105,   106,   107,   108,   109,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,   120,   190,
     199,   200,   207,   105,   106,   107,     9,    10,    35,    47,
     122,   134,   114,   115,   116,   117,   118,   119,   120,   145,
     174,    89,   201,   105,   106,   107,   192,     0,     0,     0,
       0,   134,   114,   115,   116,   117,   118,   119,   120,     0,
       0,     0,     0,   105,   106,   107,     0,     0,     0,     0,
       0,   196,   114,   115,   116,   117,   118,   119,   120,     0,
       0,   105,   106,   107,     0,     0,     0,     0,     0,   170,
     114,   115,   116,   117,   118,   119,   120,     0,     0,   105,
     106,   107,     0,     0,     0,     0,     0,   171,   114,   115,
     116,   117,   118,   119,   120,     0,   -95,     0,     0,   103,
     104,     0,     0,     0,     0,   175,   105,   106,   107,   108,
     109,   110,   111,   112,   113,   114,   115,   116,   117,   118,
     119,   120,   105,   106,   107,     0,     0,     0,     0,     0,
       0,   114,   115,   116,   117,   118,   119,   120,   106,   107,
       0,     0,     0,     0,     0,     0,   114,   115,   116,   117,
     118,   119,   120,   107,     0,     0,     0,     0,     0,     0,
     114,   115,   116,   117,   118,   119,   120
};

static const yytype_int16 yycheck[] =
{
      48,    68,    74,    19,    71,    38,    73,    74,    52,    53,
      54,    55,    56,    57,    58,    10,    83,    27,    85,    86,
      87,    88,    32,    65,    72,    63,    11,    99,    35,    62,
      15,    98,    16,    67,    68,    19,    70,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,    10,    39,    40,   124,    10,    11,
      12,    13,    14,    70,    16,    17,    18,    19,     7,    21,
      10,    55,     1,     4,     5,     6,    28,    29,    30,    31,
       8,    10,    34,    56,    57,    58,    65,    39,    40,    10,
       0,     1,   140,   141,     4,     5,     6,    41,    42,    41,
      42,    20,    21,    55,    33,   177,    65,    59,    60,    41,
      42,    41,    42,    10,   181,    12,    13,    14,    70,    16,
      17,    18,    19,   190,    21,    71,    72,    71,    38,    71,
      66,    28,    29,    30,    31,    10,   203,    12,    13,    14,
      11,    16,    17,    18,    19,    65,    21,     3,    71,    72,
       9,    66,   200,    28,    29,    43,    44,    45,    55,   207,
      64,    16,    19,    60,    52,    53,    54,    55,    56,    57,
      58,    21,    68,    70,    22,    23,    24,    25,    26,    68,
      55,    33,    10,    71,    70,    60,    70,    43,    44,    45,
      54,    55,    56,    57,    58,    70,    52,    53,    54,    55,
      56,    57,    58,    33,    71,    21,    36,    37,    32,    71,
      42,    72,    65,    43,    44,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    70,
      65,    70,    70,    43,    44,    45,     3,     3,    30,    37,
      82,    71,    52,    53,    54,    55,    56,    57,    58,   103,
     132,    68,   195,    43,    44,    45,   182,    -1,    -1,    -1,
      -1,    71,    52,    53,    54,    55,    56,    57,    58,    -1,
      -1,    -1,    -1,    43,    44,    45,    -1,    -1,    -1,    -1,
      -1,    71,    52,    53,    54,    55,    56,    57,    58,    -1,
      -1,    43,    44,    45,    -1,    -1,    -1,    -1,    -1,    69,
      52,    53,    54,    55,    56,    57,    58,    -1,    -1,    43,
      44,    45,    -1,    -1,    -1,    -1,    -1,    69,    52,    53,
      54,    55,    56,    57,    58,    -1,    33,    -1,    -1,    36,
      37,    -1,    -1,    -1,    -1,    69,    43,    44,    45,    46,
      47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    43,    44,    45,    -1,    -1,    -1,    -1,    -1,
      -1,    52,    53,    54,    55,    56,    57,    58,    44,    45,
      -1,    -1,    -1,    -1,    -1,    -1,    52,    53,    54,    55,
      56,    57,    58,    45,    -1,    -1,    -1,    -1,    -1,    -1,
      52,    53,    54,    55,    56,    57,    58
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    74,     0,     1,    38,    75,    76,    82,    62,    75,
      76,    19,     4,     5,     6,    83,    10,    77,    65,    84,
      10,    85,    63,    10,     7,    79,    65,     8,    80,    10,
      86,    87,    65,    78,    66,    87,    11,    88,    89,     9,
      81,    16,    19,    39,    40,    55,    66,    89,    65,    64,
      16,    20,    90,    91,    10,    11,    12,    13,    14,    16,
      17,    18,    19,    21,    28,    29,    30,    31,    34,    39,
      40,    55,    59,    60,    70,    94,    97,    98,    99,   112,
     113,    19,    21,    27,    32,    68,    68,    70,    70,   112,
     113,   113,    98,   113,    98,    99,   113,    67,    68,    70,
      41,    42,    33,    36,    37,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    92,    92,   113,    70,   106,   113,   113,   113,   113,
       1,    10,    33,    71,    71,    10,   113,    95,    96,    99,
     104,   103,    35,    70,   108,    97,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,    22,    23,    24,    25,    26,    93,   113,
      69,    69,    71,    32,   108,    69,    71,    72,    98,    98,
     109,     3,   100,    65,    99,    11,    15,   110,   111,   113,
      70,   105,   106,   102,    71,    72,    71,   107,   113,    65,
      70,   111,    71,    72,   101,    98,   113,    70,    71,    98,
      71
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    73,    74,    74,    74,    74,    74,    74,    75,    77,
      78,    76,    79,    79,    80,    80,    81,    82,    82,    83,
      83,    84,    84,    85,    85,    86,    86,    87,    87,    87,
      87,    87,    88,    88,    90,    89,    91,    89,    89,    92,
      92,    93,    93,    93,    93,    93,    94,    94,    94,    94,
      95,    95,    96,    96,    97,    98,    99,    99,    99,    99,
      99,    99,    99,    99,   100,   101,    99,   102,    99,    99,
      99,   103,    99,   104,    99,    99,    99,    99,    99,    99,
      99,    99,    99,   105,   105,   106,   107,   107,   109,   108,
     108,   110,   110,   111,   111,   112,   112,   112,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113,   113,   113,   113,   113,   113,   113,
     113,   113,   113,   113
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     0,
       0,    11,     0,     3,     0,     3,     3,     0,     2,     1,
       1,     0,     2,     1,     2,     1,     2,     3,     3,     4,
       3,     3,     1,     2,     0,     5,     0,     5,     3,     0,
       2,     1,     1,     1,     1,     1,     1,     3,     4,     4,
       0,     1,     1,     3,     1,     1,     1,     1,     3,     3,
       1,     3,     3,     3,     0,     0,    11,     0,     9,     3,
       2,     0,     4,     0,     4,     3,     3,     3,     3,     3,
       3,     1,     3,     3,     1,     5,     1,     3,     0,     4,
       1,     1,     3,     1,     1,     1,     1,     1,     3,     1,
       1,     4,     1,     1,     1,     1,     4,     1,     4,     1,
       1,     2,     3,     3,     3,     3,     3,     3,     3,     3,
       2,     3,     3,     1
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
          case 10: /* _IDENTIFIER_  */
#line 203 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1351 "grammar.c" /* yacc.c:1257  */
        break;

    case 11: /* _STRING_IDENTIFIER_  */
#line 207 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1357 "grammar.c" /* yacc.c:1257  */
        break;

    case 12: /* _STRING_COUNT_  */
#line 204 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1363 "grammar.c" /* yacc.c:1257  */
        break;

    case 13: /* _STRING_OFFSET_  */
#line 205 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1369 "grammar.c" /* yacc.c:1257  */
        break;

    case 14: /* _STRING_LENGTH_  */
#line 206 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1375 "grammar.c" /* yacc.c:1257  */
        break;

    case 15: /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
#line 208 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1381 "grammar.c" /* yacc.c:1257  */
        break;

    case 19: /* _TEXT_STRING_  */
#line 209 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1387 "grammar.c" /* yacc.c:1257  */
        break;

    case 20: /* _HEX_STRING_  */
#line 210 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1393 "grammar.c" /* yacc.c:1257  */
        break;

    case 21: /* _REGEXP_  */
#line 211 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); ((*yyvaluep).sized_string) = NULL; }
#line 1399 "grammar.c" /* yacc.c:1257  */
        break;

    case 95: /* arguments  */
#line 213 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1405 "grammar.c" /* yacc.c:1257  */
        break;

    case 96: /* arguments_list  */
#line 214 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); ((*yyvaluep).c_string) = NULL; }
#line 1411 "grammar.c" /* yacc.c:1257  */
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
#line 242 "grammar.y" /* yacc.c:1662  */
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        fail_if(result != ERROR_SUCCESS);
      }
#line 1685 "grammar.c" /* yacc.c:1662  */
    break;

  case 9:
#line 254 "grammar.y" /* yacc.c:1662  */
    {
        YR_RULE* rule = yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) (yyvsp[-2].integer), (yyvsp[0].c_string));

        fail_if(rule == NULL);

        (yyval.rule) = rule;
      }
#line 1698 "grammar.c" /* yacc.c:1662  */
    break;

  case 10:
#line 263 "grammar.y" /* yacc.c:1662  */
    {
        YR_RULE* rule = (yyvsp[-4].rule); // rule created in phase 1

        rule->tags = (yyvsp[-3].c_string);
        rule->metas = (yyvsp[-1].meta);
        rule->strings = (yyvsp[0].string);
      }
#line 1710 "grammar.c" /* yacc.c:1662  */
    break;

  case 11:
#line 271 "grammar.y" /* yacc.c:1662  */
    {
        YR_RULE* rule = (yyvsp[-7].rule); // rule created in phase 1

        compiler->last_result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, rule);

        yr_free((yyvsp[-8].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 1725 "grammar.c" /* yacc.c:1662  */
    break;

  case 12:
#line 286 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.meta) = NULL;
      }
#line 1733 "grammar.c" /* yacc.c:1662  */
    break;

  case 13:
#line 290 "grammar.y" /* yacc.c:1662  */
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

        (yyval.meta) = (yyvsp[0].meta);

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 1760 "grammar.c" /* yacc.c:1662  */
    break;

  case 14:
#line 317 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.string) = NULL;
      }
#line 1768 "grammar.c" /* yacc.c:1662  */
    break;

  case 15:
#line 321 "grammar.y" /* yacc.c:1662  */
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

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.string) = (yyvsp[0].string);
      }
#line 1795 "grammar.c" /* yacc.c:1662  */
    break;

  case 17:
#line 352 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = 0;  }
#line 1801 "grammar.c" /* yacc.c:1662  */
    break;

  case 18:
#line 353 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1807 "grammar.c" /* yacc.c:1662  */
    break;

  case 19:
#line 358 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
#line 1813 "grammar.c" /* yacc.c:1662  */
    break;

  case 20:
#line 359 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
#line 1819 "grammar.c" /* yacc.c:1662  */
    break;

  case 21:
#line 365 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.c_string) = NULL;
      }
#line 1827 "grammar.c" /* yacc.c:1662  */
    break;

  case 22:
#line 369 "grammar.y" /* yacc.c:1662  */
    {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[0].c_string);
      }
#line 1845 "grammar.c" /* yacc.c:1662  */
    break;

  case 23:
#line 387 "grammar.y" /* yacc.c:1662  */
    {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), &identifier);

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
      }
#line 1862 "grammar.c" /* yacc.c:1662  */
    break;

  case 24:
#line 400 "grammar.y" /* yacc.c:1662  */
    {
        char* tag_name = (yyvsp[-1].c_string);
        size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

        while (tag_length > 0)
        {
          if (strcmp(tag_name, (yyvsp[0].c_string)) == 0)
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
              yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), NULL);

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[-1].c_string);
      }
#line 1898 "grammar.c" /* yacc.c:1662  */
    break;

  case 25:
#line 436 "grammar.y" /* yacc.c:1662  */
    {  (yyval.meta) = (yyvsp[0].meta); }
#line 1904 "grammar.c" /* yacc.c:1662  */
    break;

  case 26:
#line 437 "grammar.y" /* yacc.c:1662  */
    {  (yyval.meta) = (yyvsp[-1].meta); }
#line 1910 "grammar.c" /* yacc.c:1662  */
    break;

  case 27:
#line 443 "grammar.y" /* yacc.c:1662  */
    {
        SIZED_STRING* sized_string = (yyvsp[0].sized_string);

        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_STRING,
            (yyvsp[-2].c_string),
            sized_string->c_string,
            0);

        yr_free((yyvsp[-2].c_string));
        yr_free((yyvsp[0].sized_string));

        fail_if((yyval.meta) == NULL);
      }
#line 1930 "grammar.c" /* yacc.c:1662  */
    break;

  case 28:
#line 459 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[-2].c_string),
            NULL,
            (yyvsp[0].integer));

        yr_free((yyvsp[-2].c_string));

        fail_if((yyval.meta) == NULL);
      }
#line 1947 "grammar.c" /* yacc.c:1662  */
    break;

  case 29:
#line 472 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[-3].c_string),
            NULL,
            -(yyvsp[0].integer));

        yr_free((yyvsp[-3].c_string));

        fail_if((yyval.meta) == NULL);
      }
#line 1964 "grammar.c" /* yacc.c:1662  */
    break;

  case 30:
#line 485 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            TRUE);

        yr_free((yyvsp[-2].c_string));

        fail_if((yyval.meta) == NULL);
      }
#line 1981 "grammar.c" /* yacc.c:1662  */
    break;

  case 31:
#line 498 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            FALSE);

        yr_free((yyvsp[-2].c_string));

        fail_if((yyval.meta) == NULL);
      }
#line 1998 "grammar.c" /* yacc.c:1662  */
    break;

  case 32:
#line 514 "grammar.y" /* yacc.c:1662  */
    { (yyval.string) = (yyvsp[0].string); }
#line 2004 "grammar.c" /* yacc.c:1662  */
    break;

  case 33:
#line 515 "grammar.y" /* yacc.c:1662  */
    { (yyval.string) = (yyvsp[-1].string); }
#line 2010 "grammar.c" /* yacc.c:1662  */
    break;

  case 34:
#line 521 "grammar.y" /* yacc.c:1662  */
    {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2018 "grammar.c" /* yacc.c:1662  */
    break;

  case 35:
#line 525 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) (yyvsp[0].integer), (yyvsp[-4].c_string), (yyvsp[-1].sized_string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));

        fail_if((yyval.string) == NULL);
        compiler->current_line = 0;
      }
#line 2033 "grammar.c" /* yacc.c:1662  */
    break;

  case 36:
#line 536 "grammar.y" /* yacc.c:1662  */
    {
        compiler->current_line = yyget_lineno(yyscanner);
      }
#line 2041 "grammar.c" /* yacc.c:1662  */
    break;

  case 37:
#line 540 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) (yyvsp[0].integer) | STRING_GFLAGS_REGEXP, (yyvsp[-4].c_string), (yyvsp[-1].sized_string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));

        fail_if((yyval.string) == NULL);

        compiler->current_line = 0;
      }
#line 2057 "grammar.c" /* yacc.c:1662  */
    break;

  case 38:
#line 552 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner, STRING_GFLAGS_HEXADECIMAL, (yyvsp[-2].c_string), (yyvsp[0].sized_string));

        yr_free((yyvsp[-2].c_string));
        yr_free((yyvsp[0].sized_string));

        fail_if((yyval.string) == NULL);
      }
#line 2071 "grammar.c" /* yacc.c:1662  */
    break;

  case 39:
#line 565 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = 0; }
#line 2077 "grammar.c" /* yacc.c:1662  */
    break;

  case 40:
#line 566 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 2083 "grammar.c" /* yacc.c:1662  */
    break;

  case 41:
#line 571 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = STRING_GFLAGS_WIDE; }
#line 2089 "grammar.c" /* yacc.c:1662  */
    break;

  case 42:
#line 572 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = STRING_GFLAGS_ASCII; }
#line 2095 "grammar.c" /* yacc.c:1662  */
    break;

  case 43:
#line 573 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
#line 2101 "grammar.c" /* yacc.c:1662  */
    break;

  case 44:
#line 574 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
#line 2107 "grammar.c" /* yacc.c:1662  */
    break;

  case 45:
#line 575 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = STRING_GFLAGS_XOR; }
#line 2113 "grammar.c" /* yacc.c:1662  */
    break;

  case 46:
#line 581 "grammar.y" /* yacc.c:1662  */
    {
        int var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string));

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
              compiler->objects_table, (yyvsp[0].c_string), NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            char* ns = compiler->current_namespace->name;

            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table, (yyvsp[0].c_string), ns);
          }

          if (object != NULL)
          {
            char* id;

            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena, (yyvsp[0].c_string), &id);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  id,
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
                (yyvsp[0].c_string),
                compiler->current_namespace->name);

            if (rule != NULL)
            {
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_PUSH_RULE,
                  rule,
                  NULL,
                  NULL);

              (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
              (yyval.expression).value.integer = UNDEFINED;
              (yyval.expression).identifier = rule->identifier;
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }
          }
        }

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 2202 "grammar.c" /* yacc.c:1662  */
    break;

  case 47:
#line 666 "grammar.y" /* yacc.c:1662  */
    {
        YR_OBJECT* field = NULL;

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-2].expression).value.object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field((yyvsp[-2].expression).value.object, (yyvsp[0].c_string));

          if (field != NULL)
          {
            char* ident;

            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena, (yyvsp[0].c_string), &ident);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  ident,
                  NULL,
                  NULL);

            (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
            (yyval.expression).value.object = field;
            (yyval.expression).identifier = field->identifier;
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
            compiler->last_result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[-2].expression).identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 2252 "grammar.c" /* yacc.c:1662  */
    break;

  case 48:
#line 712 "grammar.y" /* yacc.c:1662  */
    {
        YR_OBJECT_ARRAY* array;
        YR_OBJECT_DICTIONARY* dict;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_ARRAY)
        {
          if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
          {
            yr_compiler_set_error_extra_info(
                compiler, "array indexes must be of integer type");
            compiler->last_result = ERROR_WRONG_TYPE;
          }

          fail_if(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner, OP_INDEX_ARRAY, NULL);

          array = object_as_array((yyvsp[-3].expression).value.object);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = array->prototype_item;
          (yyval.expression).identifier = array->identifier;
        }
        else if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
                 (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_DICTIONARY)
        {
          if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_STRING)
          {
            yr_compiler_set_error_extra_info(
                compiler, "dictionary keys must be of string type");
            compiler->last_result = ERROR_WRONG_TYPE;
          }

          fail_if(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner, OP_LOOKUP_DICT, NULL);

          dict = object_as_dictionary((yyvsp[-3].expression).value.object);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = dict->prototype_item;
          (yyval.expression).identifier = dict->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[-3].expression).identifier);

          compiler->last_result = ERROR_NOT_INDEXABLE;
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 2313 "grammar.c" /* yacc.c:1662  */
    break;

  case 49:
#line 770 "grammar.y" /* yacc.c:1662  */
    {
        YR_OBJECT_FUNCTION* function;
        char* args_fmt;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, object_as_function((yyvsp[-3].expression).value.object), (yyvsp[-1].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena, (yyvsp[-1].c_string), &args_fmt);

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                args_fmt,
                NULL,
                NULL);

          function = object_as_function((yyvsp[-3].expression).value.object);

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = function->return_obj;
          (yyval.expression).identifier = function->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[-3].expression).identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[-1].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 2358 "grammar.c" /* yacc.c:1662  */
    break;

  case 50:
#line 814 "grammar.y" /* yacc.c:1662  */
    { (yyval.c_string) = yr_strdup(""); }
#line 2364 "grammar.c" /* yacc.c:1662  */
    break;

  case 51:
#line 815 "grammar.y" /* yacc.c:1662  */
    { (yyval.c_string) = (yyvsp[0].c_string); }
#line 2370 "grammar.c" /* yacc.c:1662  */
    break;

  case 52:
#line 820 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.c_string) = (char*) yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch((yyvsp[0].expression).type)
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
          default:
            assert(FALSE);
        }

        fail_if((yyval.c_string) == NULL);
      }
#line 2401 "grammar.c" /* yacc.c:1662  */
    break;

  case 53:
#line 847 "grammar.y" /* yacc.c:1662  */
    {
        if (strlen((yyvsp[-2].c_string)) == MAX_FUNCTION_ARGS)
        {
          compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch((yyvsp[0].expression).type)
          {
            case EXPRESSION_TYPE_INTEGER:
              strlcat((yyvsp[-2].c_string), "i", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_FLOAT:
              strlcat((yyvsp[-2].c_string), "f", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_BOOLEAN:
              strlcat((yyvsp[-2].c_string), "b", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_STRING:
              strlcat((yyvsp[-2].c_string), "s", MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_REGEXP:
              strlcat((yyvsp[-2].c_string), "r", MAX_FUNCTION_ARGS);
              break;
            default:
              assert(FALSE);
          }
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[-2].c_string);
      }
#line 2439 "grammar.c" /* yacc.c:1662  */
    break;

  case 54:
#line 885 "grammar.y" /* yacc.c:1662  */
    {
        SIZED_STRING* sized_string = (yyvsp[0].sized_string);
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

        yr_free((yyvsp[0].sized_string));

        if (compiler->last_result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              re,
              NULL,
              NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_REGEXP;
      }
#line 2481 "grammar.c" /* yacc.c:1662  */
    break;

  case 55:
#line 927 "grammar.y" /* yacc.c:1662  */
    {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_STRING)
        {
          if ((yyvsp[0].expression).value.sized_string != NULL)
          {
            yywarning(yyscanner,
              "Using literal string \"%s\" in a boolean operation.",
              (yyvsp[0].expression).value.sized_string->c_string);
          }

          compiler->last_result = yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL);

          fail_if(compiler->last_result != ERROR_SUCCESS);
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2504 "grammar.c" /* yacc.c:1662  */
    break;

  case 56:
#line 949 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2517 "grammar.c" /* yacc.c:1662  */
    break;

  case 57:
#line 958 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2530 "grammar.c" /* yacc.c:1662  */
    break;

  case 58:
#line 967 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_MATCHES,
              NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2549 "grammar.c" /* yacc.c:1662  */
    break;

  case 59:
#line 982 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2565 "grammar.c" /* yacc.c:1662  */
    break;

  case 60:
#line 994 "grammar.y" /* yacc.c:1662  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_FOUND,
            UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if(result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2583 "grammar.c" /* yacc.c:1662  */
    break;

  case 61:
#line 1008 "grammar.y" /* yacc.c:1662  */
    {
        check_type_with_cleanup((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at", yr_free((yyvsp[-2].c_string)));

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_AT, (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2600 "grammar.c" /* yacc.c:1662  */
    break;

  case 62:
#line 1021 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-2].c_string), OP_FOUND_IN, UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        fail_if(compiler->last_result!= ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2615 "grammar.c" /* yacc.c:1662  */
    break;

  case 63:
#line 1032 "grammar.y" /* yacc.c:1662  */
    {
        if (compiler->loop_depth > 0)
        {
          compiler->loop_depth--;
          compiler->loop_identifier[compiler->loop_depth] = NULL;
        }

        YYERROR;
      }
#line 2629 "grammar.c" /* yacc.c:1662  */
    break;

  case 64:
#line 1042 "grammar.y" /* yacc.c:1662  */
    {
        int var_index;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        fail_if(compiler->last_result != ERROR_SUCCESS);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner, (yyvsp[-1].c_string));

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler, (yyvsp[-1].c_string));

          compiler->last_result = \
              ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);

        // Push end-of-list marker
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 2663 "grammar.c" /* yacc.c:1662  */
    break;

  case 65:
#line 1072 "grammar.y" /* yacc.c:1662  */
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

        if ((yyvsp[-1].integer) == INTEGER_SET_ENUMERATION)
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
        compiler->loop_identifier[compiler->loop_depth] = (yyvsp[-4].c_string);
        compiler->loop_depth++;
      }
#line 2702 "grammar.c" /* yacc.c:1662  */
    break;

  case 66:
#line 1107 "grammar.y" /* yacc.c:1662  */
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

        if ((yyvsp[-5].integer) == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              compiler->loop_address[compiler->loop_depth],
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
              compiler->loop_address[compiler->loop_depth],
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
        yr_free((yyvsp[-8].c_string));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2785 "grammar.c" /* yacc.c:1662  */
    break;

  case 67:
#line 1186 "grammar.y" /* yacc.c:1662  */
    {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        uint8_t* addr;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          compiler->last_result = \
            ERROR_NESTED_FOR_OF_LOOP;

        fail_if(compiler->last_result != ERROR_SUCCESS);

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
#line 2819 "grammar.c" /* yacc.c:1662  */
    break;

  case 68:
#line 1216 "grammar.y" /* yacc.c:1662  */
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
        // beginning of the loop.
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JNUNDEF,
            compiler->loop_address[compiler->loop_depth],
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
#line 2872 "grammar.c" /* yacc.c:1662  */
    break;

  case 69:
#line 1265 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2882 "grammar.c" /* yacc.c:1662  */
    break;

  case 70:
#line 1271 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2892 "grammar.c" /* yacc.c:1662  */
    break;

  case 71:
#line 1277 "grammar.y" /* yacc.c:1662  */
    {
        YR_FIXUP* fixup;
        void* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        // create a fixup entry for the jump and push it in the stack
        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFFICIENT_MEMORY;

        fail_if(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 2922 "grammar.c" /* yacc.c:1662  */
    break;

  case 72:
#line 1303 "grammar.y" /* yacc.c:1662  */
    {
        YR_FIXUP* fixup;
        uint8_t* nop_addr;

        compiler->last_result = yr_parser_emit(yyscanner, OP_AND, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        // Generate a do-nothing instruction (NOP) in order to get its address
        // and use it as the destination for the OP_JFALSE. We can not simply
        // use the address of the OP_AND instruction +1 because we can't be
        // sure that the instruction following the OP_AND is going to be in
        // the same arena page. As we don't have a reliable way of getting the
        // address of the next instruction we generate the OP_NOP.

        compiler->last_result = yr_parser_emit(yyscanner, OP_NOP, &nop_addr);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        fixup = compiler->fixup_stack_head;
        *(void**)(fixup->address) = (void*) nop_addr;
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2953 "grammar.c" /* yacc.c:1662  */
    break;

  case 73:
#line 1330 "grammar.y" /* yacc.c:1662  */
    {
        YR_FIXUP* fixup;
        void* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFFICIENT_MEMORY;

        fail_if(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 2982 "grammar.c" /* yacc.c:1662  */
    break;

  case 74:
#line 1355 "grammar.y" /* yacc.c:1662  */
    {
        YR_FIXUP* fixup;
        uint8_t* nop_addr;

        compiler->last_result = yr_parser_emit(yyscanner, OP_OR, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        // Generate a do-nothing instruction (NOP) in order to get its address
        // and use it as the destination for the OP_JFALSE. We can not simply
        // use the address of the OP_OR instruction +1 because we can't be
        // sure that the instruction following the OP_AND is going to be in
        // the same arena page. As we don't have a reliable way of getting the
        // address of the next instruction we generate the OP_NOP.

        compiler->last_result = yr_parser_emit(yyscanner, OP_NOP, &nop_addr);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        fixup = compiler->fixup_stack_head;
        *(void**)(fixup->address) = (void*)(nop_addr);
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3013 "grammar.c" /* yacc.c:1662  */
    break;

  case 75:
#line 1382 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3026 "grammar.c" /* yacc.c:1662  */
    break;

  case 76:
#line 1391 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3039 "grammar.c" /* yacc.c:1662  */
    break;

  case 77:
#line 1400 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3052 "grammar.c" /* yacc.c:1662  */
    break;

  case 78:
#line 1409 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3065 "grammar.c" /* yacc.c:1662  */
    break;

  case 79:
#line 1418 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3078 "grammar.c" /* yacc.c:1662  */
    break;

  case 80:
#line 1427 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3091 "grammar.c" /* yacc.c:1662  */
    break;

  case 81:
#line 1436 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3099 "grammar.c" /* yacc.c:1662  */
    break;

  case 82:
#line 1440 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3107 "grammar.c" /* yacc.c:1662  */
    break;

  case 83:
#line 1447 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
#line 3113 "grammar.c" /* yacc.c:1662  */
    break;

  case 84:
#line 1448 "grammar.y" /* yacc.c:1662  */
    { (yyval.integer) = INTEGER_SET_RANGE; }
#line 3119 "grammar.c" /* yacc.c:1662  */
    break;

  case 85:
#line 1454 "grammar.y" /* yacc.c:1662  */
    {
        if ((yyvsp[-3].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3141 "grammar.c" /* yacc.c:1662  */
    break;

  case 86:
#line 1476 "grammar.y" /* yacc.c:1662  */
    {
        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;

        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3157 "grammar.c" /* yacc.c:1662  */
    break;

  case 87:
#line 1488 "grammar.y" /* yacc.c:1662  */
    {
        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3172 "grammar.c" /* yacc.c:1662  */
    break;

  case 88:
#line 1503 "grammar.y" /* yacc.c:1662  */
    {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
#line 3181 "grammar.c" /* yacc.c:1662  */
    break;

  case 90:
#line 1509 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3192 "grammar.c" /* yacc.c:1662  */
    break;

  case 93:
#line 1526 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3203 "grammar.c" /* yacc.c:1662  */
    break;

  case 94:
#line 1533 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3214 "grammar.c" /* yacc.c:1662  */
    break;

  case 96:
#line 1545 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
#line 3222 "grammar.c" /* yacc.c:1662  */
    break;

  case 97:
#line 1549 "grammar.y" /* yacc.c:1662  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL, NULL);
      }
#line 3230 "grammar.c" /* yacc.c:1662  */
    break;

  case 98:
#line 1557 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3238 "grammar.c" /* yacc.c:1662  */
    break;

  case 99:
#line 1561 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3252 "grammar.c" /* yacc.c:1662  */
    break;

  case 100:
#line 1571 "grammar.y" /* yacc.c:1662  */
    {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3270 "grammar.c" /* yacc.c:1662  */
    break;

  case 101:
#line 1585 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-1].expression), EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_READ_INT results
        // in the proper OP_INTXX opcode.

        compiler->last_result = yr_parser_emit(
            yyscanner, (uint8_t) (OP_READ_INT + (yyvsp[-3].integer)), NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3290 "grammar.c" /* yacc.c:1662  */
    break;

  case 102:
#line 1601 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[0].integer), NULL, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 3304 "grammar.c" /* yacc.c:1662  */
    break;

  case 103:
#line 1611 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 3317 "grammar.c" /* yacc.c:1662  */
    break;

  case 104:
#line 1620 "grammar.y" /* yacc.c:1662  */
    {
        SIZED_STRING* sized_string;

        compiler->last_result = yr_arena_write_data(
            compiler->sz_arena,
            (yyvsp[0].sized_string),
            (yyvsp[0].sized_string)->length + sizeof(SIZED_STRING),
            (void**) &sized_string);

        yr_free((yyvsp[0].sized_string));

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              sized_string,
              NULL,
              NULL);

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_STRING;
        (yyval.expression).value.sized_string = sized_string;
      }
#line 3346 "grammar.c" /* yacc.c:1662  */
    break;

  case 105:
#line 1645 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[0].c_string), OP_COUNT, UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3362 "grammar.c" /* yacc.c:1662  */
    break;

  case 106:
#line 1657 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_OFFSET, UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3378 "grammar.c" /* yacc.c:1662  */
    break;

  case 107:
#line 1669 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[0].c_string), OP_OFFSET, UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3398 "grammar.c" /* yacc.c:1662  */
    break;

  case 108:
#line 1685 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner, (yyvsp[-3].c_string), OP_LENGTH, UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3414 "grammar.c" /* yacc.c:1662  */
    break;

  case 109:
#line 1697 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner, (yyvsp[0].c_string), OP_LENGTH, UNDEFINED);

        yr_free((yyvsp[0].c_string));

        fail_if(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3434 "grammar.c" /* yacc.c:1662  */
    break;

  case 110:
#line 1713 "grammar.y" /* yacc.c:1662  */
    {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)  // loop identifier
        {
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = UNDEFINED;
        }
        else if ((yyvsp[0].expression).type == EXPRESSION_TYPE_BOOLEAN)  // rule identifier
        {
          (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
          (yyval.expression).value.integer = UNDEFINED;
        }
        else if ((yyvsp[0].expression).type == EXPRESSION_TYPE_OBJECT)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch((yyvsp[0].expression).value.object->type)
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
              (yyval.expression).value.sized_string = NULL;
              break;
            default:
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  (yyvsp[0].expression).identifier);
              compiler->last_result = ERROR_WRONG_TYPE;
          }
        }
        else
        {
          assert(FALSE);
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3483 "grammar.c" /* yacc.c:1662  */
    break;

  case 111:
#line 1758 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT, "-");

        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
          (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == UNDEFINED) ?
              UNDEFINED : -((yyvsp[0].expression).value.integer);
          compiler->last_result = yr_parser_emit(yyscanner, OP_INT_MINUS, NULL);
        }
        else if ((yyvsp[0].expression).type == EXPRESSION_TYPE_FLOAT)
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
          compiler->last_result = yr_parser_emit(yyscanner, OP_DBL_MINUS, NULL);
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3506 "grammar.c" /* yacc.c:1662  */
    break;

  case 112:
#line 1777 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
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

            compiler->last_result = ERROR_INTEGER_OVERFLOW;
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

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3545 "grammar.c" /* yacc.c:1662  */
    break;

  case 113:
#line 1812 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
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

            compiler->last_result = ERROR_INTEGER_OVERFLOW;
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

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3584 "grammar.c" /* yacc.c:1662  */
    break;

  case 114:
#line 1847 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
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

            compiler->last_result = ERROR_INTEGER_OVERFLOW;
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

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3622 "grammar.c" /* yacc.c:1662  */
    break;

  case 115:
#line 1881 "grammar.y" /* yacc.c:1662  */
    {
        compiler->last_result = yr_parser_reduce_operation(
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
            compiler->last_result = ERROR_DIVISION_BY_ZERO;
          }
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3651 "grammar.c" /* yacc.c:1662  */
    break;

  case 116:
#line 1906 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "%");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        if ((yyvsp[0].expression).value.integer != 0)
        {
          (yyval.expression).value.integer = OPERATION(%, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          compiler->last_result = ERROR_DIVISION_BY_ZERO;
          fail_if(compiler->last_result != ERROR_SUCCESS);
        }
      }
#line 3673 "grammar.c" /* yacc.c:1662  */
    break;

  case 117:
#line 1924 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3687 "grammar.c" /* yacc.c:1662  */
    break;

  case 118:
#line 1934 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3701 "grammar.c" /* yacc.c:1662  */
    break;

  case 119:
#line 1944 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3715 "grammar.c" /* yacc.c:1662  */
    break;

  case 120:
#line 1954 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == UNDEFINED) ?
            UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 3729 "grammar.c" /* yacc.c:1662  */
    break;

  case 121:
#line 1964 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "<<");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer < 0)
          compiler->last_result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer >= 64)
          (yyval.expression).value.integer = 0;
        else
          (yyval.expression).value.integer = OPERATION(<<, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;

        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3751 "grammar.c" /* yacc.c:1662  */
    break;

  case 122:
#line 1982 "grammar.y" /* yacc.c:1662  */
    {
        check_type((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, ">>");
        check_type((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer < 0)
          compiler->last_result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED((yyvsp[0].expression).value.integer) && (yyvsp[0].expression).value.integer >= 64)
          (yyval.expression).value.integer = 0;
        else
          (yyval.expression).value.integer = OPERATION(<<, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        
        fail_if(compiler->last_result != ERROR_SUCCESS);
      }
#line 3773 "grammar.c" /* yacc.c:1662  */
    break;

  case 123:
#line 2000 "grammar.y" /* yacc.c:1662  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3781 "grammar.c" /* yacc.c:1662  */
    break;


#line 3785 "grammar.c" /* yacc.c:1662  */
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
#line 2005 "grammar.y" /* yacc.c:1906  */

