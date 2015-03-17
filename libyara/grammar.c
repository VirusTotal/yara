/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

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
#define YYBISON_VERSION "3.0.2"

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
#line 17 "grammar.y" /* yacc.c:339  */


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
      compiler->last_result = ERROR_YARA_WRONG_TYPE; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }

#line 135 "grammar.c" /* yacc.c:339  */

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
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
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
    _DOUBLE_ = 270,
    _INTEGER_FUNCTION_ = 271,
    _TEXT_STRING_ = 272,
    _HEX_STRING_ = 273,
    _REGEXP_ = 274,
    _ASCII_ = 275,
    _WIDE_ = 276,
    _NOCASE_ = 277,
    _FULLWORD_ = 278,
    _AT_ = 279,
    _FILESIZE_ = 280,
    _ENTRYPOINT_ = 281,
    _ALL_ = 282,
    _ANY_ = 283,
    _IN_ = 284,
    _OF_ = 285,
    _FOR_ = 286,
    _THEM_ = 287,
    _MATCHES_ = 288,
    _CONTAINS_ = 289,
    _IMPORT_ = 290,
    _TRUE_ = 291,
    _FALSE_ = 292,
    _OR_ = 293,
    _AND_ = 294,
    _EQ_ = 295,
    _NEQ_ = 296,
    _LT_ = 297,
    _LE_ = 298,
    _GT_ = 299,
    _GE_ = 300,
    _SHIFT_LEFT_ = 301,
    _SHIFT_RIGHT_ = 302,
    _NOT_ = 303,
    UNARY_MINUS = 304
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
#define _DOUBLE_ 270
#define _INTEGER_FUNCTION_ 271
#define _TEXT_STRING_ 272
#define _HEX_STRING_ 273
#define _REGEXP_ 274
#define _ASCII_ 275
#define _WIDE_ 276
#define _NOCASE_ 277
#define _FULLWORD_ 278
#define _AT_ 279
#define _FILESIZE_ 280
#define _ENTRYPOINT_ 281
#define _ALL_ 282
#define _ANY_ 283
#define _IN_ 284
#define _OF_ 285
#define _FOR_ 286
#define _THEM_ 287
#define _MATCHES_ 288
#define _CONTAINS_ 289
#define _IMPORT_ 290
#define _TRUE_ 291
#define _FALSE_ 292
#define _OR_ 293
#define _AND_ 294
#define _EQ_ 295
#define _NEQ_ 296
#define _LT_ 297
#define _LE_ 298
#define _GT_ 299
#define _GE_ 300
#define _SHIFT_LEFT_ 301
#define _SHIFT_RIGHT_ 302
#define _NOT_ 303
#define UNARY_MINUS 304

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 178 "grammar.y" /* yacc.c:355  */

  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;

#line 283 "grammar.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_GRAMMAR_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 297 "grammar.c" /* yacc.c:358  */

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
#define YYLAST   385

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  70
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  37
/* YYNRULES -- Number of rules.  */
#define YYNRULES  114
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  200

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   305

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    55,    42,     2,
      67,    68,    53,    51,    69,    52,    64,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    62,     2,
       2,    63,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    65,    54,    66,    41,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    60,    40,    61,    57,     2,     2,     2,
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
      35,    36,    37,    38,    39,    43,    44,    45,    46,    47,
      48,    49,    50,    56,    58,    59
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   191,   191,   193,   194,   195,   196,   197,   202,   214,
     233,   236,   264,   268,   296,   301,   302,   307,   308,   314,
     317,   335,   348,   385,   386,   391,   407,   420,   433,   450,
     451,   456,   470,   469,   488,   505,   506,   511,   512,   513,
     514,   519,   610,   659,   719,   767,   770,   795,   831,   877,
     894,   903,   912,   927,   941,   955,   971,   986,  1022,   985,
    1138,  1137,  1217,  1223,  1230,  1229,  1290,  1289,  1348,  1357,
    1366,  1375,  1384,  1393,  1402,  1406,  1414,  1415,  1420,  1442,
    1454,  1470,  1469,  1475,  1484,  1485,  1490,  1495,  1504,  1505,
    1509,  1517,  1521,  1531,  1545,  1561,  1571,  1580,  1604,  1619,
    1634,  1657,  1701,  1720,  1738,  1756,  1774,  1792,  1802,  1812,
    1822,  1832,  1842,  1852,  1862
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_", "_DOUBLE_",
  "_INTEGER_FUNCTION_", "_TEXT_STRING_", "_HEX_STRING_", "_REGEXP_",
  "_ASCII_", "_WIDE_", "_NOCASE_", "_FULLWORD_", "_AT_", "_FILESIZE_",
  "_ENTRYPOINT_", "_ALL_", "_ANY_", "_IN_", "_OF_", "_FOR_", "_THEM_",
  "_MATCHES_", "_CONTAINS_", "_IMPORT_", "_TRUE_", "_FALSE_", "_OR_",
  "_AND_", "'|'", "'^'", "'&'", "_EQ_", "_NEQ_", "_LT_", "_LE_", "_GT_",
  "_GE_", "_SHIFT_LEFT_", "_SHIFT_RIGHT_", "'+'", "'-'", "'*'", "'\\\\'",
  "'%'", "_NOT_", "'~'", "UNARY_MINUS", "\"include\"", "'{'", "'}'", "':'",
  "'='", "'.'", "'['", "']'", "'('", "')'", "','", "$accept", "rules",
  "import", "rule", "meta", "strings", "condition", "rule_modifiers",
  "rule_modifier", "tags", "tag_list", "meta_declarations",
  "meta_declaration", "string_declarations", "string_declaration", "$@1",
  "string_modifiers", "string_modifier", "identifier", "arguments_list",
  "regexp", "boolean_expression", "expression", "$@2", "$@3", "$@4", "$@5",
  "$@6", "integer_set", "range", "integer_enumeration", "string_set",
  "$@7", "string_enumeration", "string_enumeration_item", "for_expression",
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
     124,    94,    38,   295,   296,   297,   298,   299,   300,   301,
     302,    43,    45,    42,    92,    37,   303,   126,   304,   305,
     123,   125,    58,    61,    46,    91,    93,    40,    41,    44
};
# endif

#define YYPACT_NINF -65

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-65)))

#define YYTABLE_NINF -89

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -65,    79,   -65,   -30,    -7,   -65,   -65,   100,   -65,   -65,
     -65,   -65,     3,   -65,   -65,   -65,   -47,     9,   -38,   -65,
      21,    20,   -65,   -34,    25,    45,     6,   108,    58,    45,
     -65,   114,    67,    85,    -1,   -65,    91,   114,   -65,    50,
     -65,   -65,   -65,   -65,   -65,    71,   -65,   -65,   -15,   -65,
      95,   -65,   -65,    89,   -65,   -65,   -65,   -65,   -65,   -65,
     111,   -65,   -65,   136,    50,   136,    50,    48,   -65,    61,
     -65,   134,   269,   -65,   -65,   146,   136,    99,   136,   136,
     136,    -6,   301,   -65,   -65,   -65,    61,   101,   164,   158,
     136,    50,   -65,   -65,    -9,   151,   136,   136,   136,   136,
     136,   136,   136,   136,   136,   136,   136,   136,   136,   136,
     136,   136,   136,    88,   -65,   301,   136,   -65,   224,   131,
     184,   145,    -9,   -65,   -65,   -65,   242,    63,    96,    50,
      50,   -65,   -65,   -65,   -65,   301,   316,   330,    43,   301,
     301,   301,   301,   301,   301,    19,    19,    87,    87,   -65,
     -65,   -65,   -65,   -65,   -65,   -65,   -65,    88,   285,   -65,
     -65,   -65,   113,   -65,   -65,    50,   137,   -65,    -2,   115,
     110,   -65,    96,   -65,   -65,    75,   -65,   136,   136,   125,
     -65,   122,   -65,    -2,   204,    90,   285,   -65,    50,   -65,
     -65,   -65,   136,   123,    -5,   301,    50,   -65,    17,   -65
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    15,     0,     4,     3,     0,     7,     6,
       5,     8,     0,    17,    18,    16,    19,     0,     0,    21,
      20,    10,    22,     0,    12,     0,     0,     0,     0,    11,
      23,     0,     0,     0,     0,    24,     0,    13,    29,     0,
       9,    26,    25,    27,    28,    32,    30,    41,    54,    98,
     100,    95,    96,     0,    97,    48,    92,    93,    89,    90,
       0,    50,    51,     0,     0,     0,     0,   101,   114,    14,
      49,     0,    74,    35,    34,     0,     0,     0,     0,     0,
       0,     0,    88,   102,    63,   111,     0,    49,    74,     0,
       0,    45,    66,    64,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    35,    55,     0,    56,     0,     0,
       0,     0,     0,    75,    91,    42,     0,     0,    46,     0,
       0,    83,    81,    62,    52,    53,   110,   108,   109,    72,
      73,    68,    70,    69,    71,   112,   113,   103,   104,   105,
     106,   107,    38,    37,    39,    40,    36,    33,     0,    99,
      94,    57,     0,    43,    44,     0,    67,    65,     0,     0,
       0,    60,    47,    86,    87,     0,    84,     0,     0,     0,
      77,     0,    82,     0,     0,     0,    79,    58,     0,    85,
      78,    76,     0,     0,     0,    80,     0,    61,     0,    59
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -65,   -65,   188,   189,   -65,   -65,   -65,   -65,   -65,   -65,
     -65,   -65,   166,   -65,   159,   -65,    86,   -65,   -65,   -65,
     106,   -39,   -64,   -65,   -65,   -65,   -65,   -65,   -65,    32,
     -65,    98,   -65,   -65,    38,   162,   -59
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    24,    27,    33,     7,    15,    18,
      20,    29,    30,    37,    38,    75,   113,   156,    67,   127,
      68,    86,    70,   170,   193,   181,   130,   129,   179,   117,
     185,   133,   168,   175,   176,    71,    72
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      69,    82,    87,   121,    83,     4,    85,    88,   173,    76,
      11,   174,    16,    41,    77,    17,    42,   115,    19,   118,
     119,   120,    21,   131,   122,    84,    23,   128,    25,     8,
      22,   126,    26,    92,    93,    43,    44,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,    28,    92,    93,   158,   132,    47,
      48,    49,    50,   197,    51,    52,    53,    54,    31,    55,
     108,   109,   110,   111,   112,    56,    57,    58,    59,     2,
       3,    60,   -15,   -15,   -15,   199,    61,    62,    73,    74,
     166,   167,   106,   107,   108,   109,   110,   111,   112,    92,
      93,   172,    63,    12,    13,    14,    64,    65,   152,   153,
     154,   155,    89,    90,     4,    91,    32,    66,   184,   186,
      47,    34,    49,    50,    36,    51,    52,    53,    54,    39,
      55,   164,   165,   195,   -49,   -49,    56,    57,    58,    59,
     110,   111,   112,   182,   183,    47,    40,    49,    50,   194,
      51,    52,    53,    54,    45,    55,    79,   198,   191,   192,
      78,    56,    57,    63,    94,   114,   116,   125,    65,   123,
      55,    97,    98,    99,   161,   171,    93,   178,    80,   177,
     106,   107,   108,   109,   110,   111,   112,   187,    63,   188,
     196,     9,    10,    65,   -88,    35,    46,    95,    96,   160,
     157,   134,   180,    80,    97,    98,    99,   100,   101,   102,
     103,   104,   105,   106,   107,   108,   109,   110,   111,   112,
     162,   189,    81,     0,    97,    98,    99,     0,     0,     0,
       0,     0,   124,   106,   107,   108,   109,   110,   111,   112,
       0,     0,     0,     0,    97,    98,    99,     0,     0,     0,
       0,     0,   124,   106,   107,   108,   109,   110,   111,   112,
       0,     0,     0,     0,    97,    98,    99,     0,     0,     0,
       0,     0,   190,   106,   107,   108,   109,   110,   111,   112,
       0,     0,    97,    98,    99,     0,     0,     0,     0,     0,
     159,   106,   107,   108,   109,   110,   111,   112,     0,   -88,
       0,     0,    95,    96,     0,     0,     0,     0,   163,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     108,   109,   110,   111,   112,    97,    98,    99,     0,     0,
       0,     0,     0,     0,   106,   107,   108,   109,   110,   111,
     112,    97,    98,    99,     0,     0,     0,     0,     0,   169,
     106,   107,   108,   109,   110,   111,   112,    98,    99,     0,
       0,     0,     0,     0,     0,   106,   107,   108,   109,   110,
     111,   112,    99,     0,     0,     0,     0,     0,     0,   106,
     107,   108,   109,   110,   111,   112
};

static const yytype_int16 yycheck[] =
{
      39,    60,    66,     9,    63,    35,    65,    66,    10,    24,
      17,    13,     9,    14,    29,    62,    17,    76,     9,    78,
      79,    80,    60,    32,    30,    64,     6,    91,    62,    59,
       9,    90,     7,    38,    39,    36,    37,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,   108,
     109,   110,   111,   112,     9,    38,    39,   116,    67,     9,
      10,    11,    12,    68,    14,    15,    16,    17,    62,    19,
      51,    52,    53,    54,    55,    25,    26,    27,    28,     0,
       1,    31,     3,     4,     5,    68,    36,    37,    17,    18,
     129,   130,    49,    50,    51,    52,    53,    54,    55,    38,
      39,   165,    52,     3,     4,     5,    56,    57,    20,    21,
      22,    23,    64,    65,    35,    67,     8,    67,   177,   178,
       9,    63,    11,    12,    10,    14,    15,    16,    17,    62,
      19,    68,    69,   192,    38,    39,    25,    26,    27,    28,
      53,    54,    55,    68,    69,     9,    61,    11,    12,   188,
      14,    15,    16,    17,    63,    19,    67,   196,    68,    69,
      65,    25,    26,    52,    30,    19,    67,     9,    57,    68,
      19,    40,    41,    42,    29,    62,    39,    67,    67,    64,
      49,    50,    51,    52,    53,    54,    55,    62,    52,    67,
      67,     3,     3,    57,    30,    29,    37,    33,    34,    68,
     114,    95,   170,    67,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
     122,   183,    60,    -1,    40,    41,    42,    -1,    -1,    -1,
      -1,    -1,    68,    49,    50,    51,    52,    53,    54,    55,
      -1,    -1,    -1,    -1,    40,    41,    42,    -1,    -1,    -1,
      -1,    -1,    68,    49,    50,    51,    52,    53,    54,    55,
      -1,    -1,    -1,    -1,    40,    41,    42,    -1,    -1,    -1,
      -1,    -1,    68,    49,    50,    51,    52,    53,    54,    55,
      -1,    -1,    40,    41,    42,    -1,    -1,    -1,    -1,    -1,
      66,    49,    50,    51,    52,    53,    54,    55,    -1,    30,
      -1,    -1,    33,    34,    -1,    -1,    -1,    -1,    66,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    40,    41,    42,    -1,    -1,
      -1,    -1,    -1,    -1,    49,    50,    51,    52,    53,    54,
      55,    40,    41,    42,    -1,    -1,    -1,    -1,    -1,    64,
      49,    50,    51,    52,    53,    54,    55,    41,    42,    -1,
      -1,    -1,    -1,    -1,    -1,    49,    50,    51,    52,    53,
      54,    55,    42,    -1,    -1,    -1,    -1,    -1,    -1,    49,
      50,    51,    52,    53,    54,    55
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    71,     0,     1,    35,    72,    73,    77,    59,    72,
      73,    17,     3,     4,     5,    78,     9,    62,    79,     9,
      80,    60,     9,     6,    74,    62,     7,    75,     9,    81,
      82,    62,     8,    76,    63,    82,    10,    83,    84,    62,
      61,    14,    17,    36,    37,    63,    84,     9,    10,    11,
      12,    14,    15,    16,    17,    19,    25,    26,    27,    28,
      31,    36,    37,    52,    56,    57,    67,    88,    90,    91,
      92,   105,   106,    17,    18,    85,    24,    29,    65,    67,
      67,   105,   106,   106,    91,   106,    91,    92,   106,    64,
      65,    67,    38,    39,    30,    33,    34,    40,    41,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    86,    19,   106,    67,    99,   106,   106,
     106,     9,    30,    68,    68,     9,   106,    89,    92,    97,
      96,    32,    67,   101,    90,   106,   106,   106,   106,   106,
     106,   106,   106,   106,   106,   106,   106,   106,   106,   106,
     106,   106,    20,    21,    22,    23,    87,    86,   106,    66,
      68,    29,   101,    66,    68,    69,    91,    91,   102,    64,
      93,    62,    92,    10,    13,   103,   104,    64,    67,    98,
      99,    95,    68,    69,   106,   100,   106,    62,    67,   104,
      68,    68,    69,    94,    91,   106,    67,    68,    91,    68
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    70,    71,    71,    71,    71,    71,    71,    72,    73,
      74,    74,    75,    75,    76,    77,    77,    78,    78,    79,
      79,    80,    80,    81,    81,    82,    82,    82,    82,    83,
      83,    84,    85,    84,    84,    86,    86,    87,    87,    87,
      87,    88,    88,    88,    88,    89,    89,    89,    90,    91,
      92,    92,    92,    92,    92,    92,    92,    93,    94,    92,
      95,    92,    92,    92,    96,    92,    97,    92,    92,    92,
      92,    92,    92,    92,    92,    92,    98,    98,    99,   100,
     100,   102,   101,   101,   103,   103,   104,   104,   105,   105,
     105,   106,   106,   106,   106,   106,   106,   106,   106,   106,
     106,   106,   106,   106,   106,   106,   106,   106,   106,   106,
     106,   106,   106,   106,   106
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     3,     2,     9,
       0,     3,     0,     3,     3,     0,     2,     1,     1,     0,
       2,     1,     2,     1,     2,     3,     3,     3,     3,     1,
       2,     4,     0,     5,     3,     0,     2,     1,     1,     1,
       1,     1,     3,     4,     4,     0,     1,     3,     1,     1,
       1,     1,     3,     3,     1,     3,     3,     0,     0,    11,
       0,     9,     3,     2,     0,     4,     0,     4,     3,     3,
       3,     3,     3,     3,     1,     3,     3,     1,     6,     1,
       3,     0,     4,     1,     1,     3,     1,     1,     1,     1,
       1,     3,     1,     1,     4,     1,     1,     1,     1,     4,
       1,     1,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     2,     3,     3,     1
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
          case 9: /* _IDENTIFIER_  */
#line 169 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); }
#line 1314 "grammar.c" /* yacc.c:1257  */
        break;

    case 10: /* _STRING_IDENTIFIER_  */
#line 170 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); }
#line 1320 "grammar.c" /* yacc.c:1257  */
        break;

    case 11: /* _STRING_COUNT_  */
#line 171 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); }
#line 1326 "grammar.c" /* yacc.c:1257  */
        break;

    case 12: /* _STRING_OFFSET_  */
#line 172 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); }
#line 1332 "grammar.c" /* yacc.c:1257  */
        break;

    case 13: /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
#line 173 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).c_string)); }
#line 1338 "grammar.c" /* yacc.c:1257  */
        break;

    case 17: /* _TEXT_STRING_  */
#line 174 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); }
#line 1344 "grammar.c" /* yacc.c:1257  */
        break;

    case 18: /* _HEX_STRING_  */
#line 175 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); }
#line 1350 "grammar.c" /* yacc.c:1257  */
        break;

    case 19: /* _REGEXP_  */
#line 176 "grammar.y" /* yacc.c:1257  */
      { yr_free(((*yyvaluep).sized_string)); }
#line 1356 "grammar.c" /* yacc.c:1257  */
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
#line 203 "grammar.y" /* yacc.c:1646  */
    {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
#line 1630 "grammar.c" /* yacc.c:1646  */
    break;

  case 9:
#line 215 "grammar.y" /* yacc.c:1646  */
    {
        int result = yr_parser_reduce_rule_declaration(
            yyscanner,
            (yyvsp[-8].integer),
            (yyvsp[-6].c_string),
            (yyvsp[-5].c_string),
            (yyvsp[-2].string),
            (yyvsp[-3].meta));

        yr_free((yyvsp[-6].c_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
#line 1648 "grammar.c" /* yacc.c:1646  */
    break;

  case 10:
#line 233 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.meta) = NULL;
      }
#line 1656 "grammar.c" /* yacc.c:1646  */
    break;

  case 11:
#line 237 "grammar.y" /* yacc.c:1646  */
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

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 1683 "grammar.c" /* yacc.c:1646  */
    break;

  case 12:
#line 264 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.string) = NULL;
        compiler->current_rule_strings = (yyval.string);
      }
#line 1692 "grammar.c" /* yacc.c:1646  */
    break;

  case 13:
#line 269 "grammar.y" /* yacc.c:1646  */
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

        compiler->current_rule_strings = (yyvsp[0].string);
        (yyval.string) = (yyvsp[0].string);
      }
#line 1720 "grammar.c" /* yacc.c:1646  */
    break;

  case 15:
#line 301 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = 0;  }
#line 1726 "grammar.c" /* yacc.c:1646  */
    break;

  case 16:
#line 302 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1732 "grammar.c" /* yacc.c:1646  */
    break;

  case 17:
#line 307 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
#line 1738 "grammar.c" /* yacc.c:1646  */
    break;

  case 18:
#line 308 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
#line 1744 "grammar.c" /* yacc.c:1646  */
    break;

  case 19:
#line 314 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.c_string) = NULL;
      }
#line 1752 "grammar.c" /* yacc.c:1646  */
    break;

  case 20:
#line 318 "grammar.y" /* yacc.c:1646  */
    {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[0].c_string);
      }
#line 1770 "grammar.c" /* yacc.c:1646  */
    break;

  case 21:
#line 336 "grammar.y" /* yacc.c:1646  */
    {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), &identifier);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
      }
#line 1787 "grammar.c" /* yacc.c:1646  */
    break;

  case 22:
#line 349 "grammar.y" /* yacc.c:1646  */
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

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[-1].c_string);
      }
#line 1823 "grammar.c" /* yacc.c:1646  */
    break;

  case 23:
#line 385 "grammar.y" /* yacc.c:1646  */
    {  (yyval.meta) = (yyvsp[0].meta); }
#line 1829 "grammar.c" /* yacc.c:1646  */
    break;

  case 24:
#line 386 "grammar.y" /* yacc.c:1646  */
    {  (yyval.meta) = (yyvsp[-1].meta); }
#line 1835 "grammar.c" /* yacc.c:1646  */
    break;

  case 25:
#line 392 "grammar.y" /* yacc.c:1646  */
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

        ERROR_IF((yyval.meta) == NULL);
      }
#line 1855 "grammar.c" /* yacc.c:1646  */
    break;

  case 26:
#line 408 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            (yyvsp[-2].c_string),
            NULL,
            (yyvsp[0].integer));

        yr_free((yyvsp[-2].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
#line 1872 "grammar.c" /* yacc.c:1646  */
    break;

  case 27:
#line 421 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            TRUE);

        yr_free((yyvsp[-2].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
#line 1889 "grammar.c" /* yacc.c:1646  */
    break;

  case 28:
#line 434 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.meta) = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            (yyvsp[-2].c_string),
            NULL,
            FALSE);

        yr_free((yyvsp[-2].c_string));

        ERROR_IF((yyval.meta) == NULL);
      }
#line 1906 "grammar.c" /* yacc.c:1646  */
    break;

  case 29:
#line 450 "grammar.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[0].string); }
#line 1912 "grammar.c" /* yacc.c:1646  */
    break;

  case 30:
#line 451 "grammar.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[-1].string); }
#line 1918 "grammar.c" /* yacc.c:1646  */
    break;

  case 31:
#line 457 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            (yyvsp[0].integer),
            (yyvsp[-3].c_string),
            (yyvsp[-1].sized_string));

        yr_free((yyvsp[-3].c_string));
        yr_free((yyvsp[-1].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
#line 1935 "grammar.c" /* yacc.c:1646  */
    break;

  case 32:
#line 470 "grammar.y" /* yacc.c:1646  */
    {
        compiler->error_line = yyget_lineno(yyscanner);
      }
#line 1943 "grammar.c" /* yacc.c:1646  */
    break;

  case 33:
#line 474 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            (yyvsp[0].integer) | STRING_GFLAGS_REGEXP,
            (yyvsp[-4].c_string),
            (yyvsp[-1].sized_string));

        yr_free((yyvsp[-4].c_string));
        yr_free((yyvsp[-1].sized_string));

        ERROR_IF((yyval.string) == NULL);

        compiler->error_line = 0;
      }
#line 1962 "grammar.c" /* yacc.c:1646  */
    break;

  case 34:
#line 489 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            STRING_GFLAGS_HEXADECIMAL,
            (yyvsp[-2].c_string),
            (yyvsp[0].sized_string));

        yr_free((yyvsp[-2].c_string));
        yr_free((yyvsp[0].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
#line 1979 "grammar.c" /* yacc.c:1646  */
    break;

  case 35:
#line 505 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = 0; }
#line 1985 "grammar.c" /* yacc.c:1646  */
    break;

  case 36:
#line 506 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1991 "grammar.c" /* yacc.c:1646  */
    break;

  case 37:
#line 511 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = STRING_GFLAGS_WIDE; }
#line 1997 "grammar.c" /* yacc.c:1646  */
    break;

  case 38:
#line 512 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = STRING_GFLAGS_ASCII; }
#line 2003 "grammar.c" /* yacc.c:1646  */
    break;

  case 39:
#line 513 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
#line 2009 "grammar.c" /* yacc.c:1646  */
    break;

  case 40:
#line 514 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
#line 2015 "grammar.c" /* yacc.c:1646  */
    break;

  case 41:
#line 520 "grammar.y" /* yacc.c:1646  */
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
              compiler->objects_table,
              (yyvsp[0].c_string),
              NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            char* ns = compiler->current_namespace->name;

            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[0].c_string),
                ns);
          }

          if (object != NULL)
          {
            char* id;

            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                (yyvsp[0].c_string),
                &id);

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
                (yyvsp[0].c_string),
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
              yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }
          }
        }

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2110 "grammar.c" /* yacc.c:1646  */
    break;

  case 42:
#line 611 "grammar.y" /* yacc.c:1646  */
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
              compiler->sz_arena,
              (yyvsp[0].c_string),
              &ident);

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
            yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
            compiler->last_result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-2].expression).identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2163 "grammar.c" /* yacc.c:1646  */
    break;

  case 43:
#line 660 "grammar.y" /* yacc.c:1646  */
    {
        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_ARRAY)
        {
          if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
          {
            yr_compiler_set_error_extra_info(
                compiler, "array indexes must be of integer type");
            compiler->last_result = ERROR_YARA_WRONG_TYPE;
          }

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_INDEX_ARRAY,
              NULL);

          YR_OBJECT_ARRAY* array = (YR_OBJECT_ARRAY*) (yyvsp[-3].expression).value.object;

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
            compiler->last_result = ERROR_YARA_WRONG_TYPE;
          }

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);

          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_LOOKUP_DICT,
              NULL);

          YR_OBJECT_DICTIONARY* dict = (YR_OBJECT_DICTIONARY*) (yyvsp[-3].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = dict->prototype_item;
          (yyval.expression).identifier = dict->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-3].expression).identifier);

          compiler->last_result = ERROR_NOT_INDEXABLE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2226 "grammar.c" /* yacc.c:1646  */
    break;

  case 44:
#line 720 "grammar.y" /* yacc.c:1646  */
    {
        char* args_fmt;

        if ((yyvsp[-3].expression).type == EXPRESSION_TYPE_OBJECT &&
            (yyvsp[-3].expression).value.object->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) (yyvsp[-3].expression).value.object, (yyvsp[-1].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena,
              (yyvsp[-1].c_string),
              &args_fmt);

          if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                PTR_TO_INT64(args_fmt),
                NULL,
                NULL);

          YR_OBJECT_FUNCTION* function = (YR_OBJECT_FUNCTION*) (yyvsp[-3].expression).value.object;

          (yyval.expression).type = EXPRESSION_TYPE_OBJECT;
          (yyval.expression).value.object = function->return_obj;
          (yyval.expression).identifier = function->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-3].expression).identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[-1].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2273 "grammar.c" /* yacc.c:1646  */
    break;

  case 45:
#line 767 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.c_string) = yr_strdup("");
      }
#line 2281 "grammar.c" /* yacc.c:1646  */
    break;

  case 46:
#line 771 "grammar.y" /* yacc.c:1646  */
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
        }

        ERROR_IF((yyval.c_string) == NULL);
      }
#line 2310 "grammar.c" /* yacc.c:1646  */
    break;

  case 47:
#line 796 "grammar.y" /* yacc.c:1646  */
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
          }
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = (yyvsp[-2].c_string);
      }
#line 2346 "grammar.c" /* yacc.c:1646  */
    break;

  case 48:
#line 832 "grammar.y" /* yacc.c:1646  */
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
#line 2392 "grammar.c" /* yacc.c:1646  */
    break;

  case 49:
#line 878 "grammar.y" /* yacc.c:1646  */
    {
        if ((yyvsp[0].expression).type == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_STR_TO_BOOL,
              NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2410 "grammar.c" /* yacc.c:1646  */
    break;

  case 50:
#line 895 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2423 "grammar.c" /* yacc.c:1646  */
    break;

  case 51:
#line 904 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2436 "grammar.c" /* yacc.c:1646  */
    break;

  case 52:
#line 913 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "matches");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_REGEXP, "matches");

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_MATCHES,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2455 "grammar.c" /* yacc.c:1646  */
    break;

  case 53:
#line 928 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_STRING, "contains");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner,
            OP_CONTAINS,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2473 "grammar.c" /* yacc.c:1646  */
    break;

  case 54:
#line 942 "grammar.y" /* yacc.c:1646  */
    {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_FOUND,
            UNDEFINED);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2491 "grammar.c" /* yacc.c:1646  */
    break;

  case 55:
#line 956 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "at");

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[-2].c_string),
            OP_FOUND_AT,
            (yyvsp[0].expression).value.integer);

        yr_free((yyvsp[-2].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2511 "grammar.c" /* yacc.c:1646  */
    break;

  case 56:
#line 972 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[-2].c_string),
            OP_FOUND_IN,
            UNDEFINED);

        yr_free((yyvsp[-2].c_string));

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2529 "grammar.c" /* yacc.c:1646  */
    break;

  case 57:
#line 986 "grammar.y" /* yacc.c:1646  */
    {
        int var_index;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner,
            (yyvsp[-1].c_string));

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-1].c_string));

          compiler->last_result = \
              ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // Push end-of-list marker
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            UNDEFINED,
            NULL,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2569 "grammar.c" /* yacc.c:1646  */
    break;

  case 58:
#line 1022 "grammar.y" /* yacc.c:1646  */
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
#line 2608 "grammar.c" /* yacc.c:1646  */
    break;

  case 59:
#line 1057 "grammar.y" /* yacc.c:1646  */
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
        yr_free((yyvsp[-8].c_string));

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2693 "grammar.c" /* yacc.c:1646  */
    break;

  case 60:
#line 1138 "grammar.y" /* yacc.c:1646  */
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
#line 2727 "grammar.c" /* yacc.c:1646  */
    break;

  case 61:
#line 1168 "grammar.y" /* yacc.c:1646  */
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
#line 2781 "grammar.c" /* yacc.c:1646  */
    break;

  case 62:
#line 1218 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2791 "grammar.c" /* yacc.c:1646  */
    break;

  case 63:
#line 1224 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2801 "grammar.c" /* yacc.c:1646  */
    break;

  case 64:
#line 1230 "grammar.y" /* yacc.c:1646  */
    {
        int64_t* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        // create a fixup entry for the jump and push it in the stack
        YR_FIXUP* fixup = yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFICIENT_MEMORY;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 2830 "grammar.c" /* yacc.c:1646  */
    break;

  case 65:
#line 1255 "grammar.y" /* yacc.c:1646  */
    {
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

        YR_FIXUP* fixup = compiler->fixup_stack_head;

        // We know that the AND opcode and the following one are within the same
        // page, so we can compute the address for the opcode following the AND
        // by simply adding one to its address.
        
        *(fixup->address) = PTR_TO_INT64(and_addr + 1);
        
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2869 "grammar.c" /* yacc.c:1646  */
    break;

  case 66:
#line 1290 "grammar.y" /* yacc.c:1646  */
    {
        int64_t* jmp_destination_addr;

        compiler->last_result = yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination
            NULL,
            &jmp_destination_addr);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        YR_FIXUP* fixup = yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          compiler->last_error = ERROR_INSUFICIENT_MEMORY;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
#line 2897 "grammar.c" /* yacc.c:1646  */
    break;

  case 67:
#line 1314 "grammar.y" /* yacc.c:1646  */
    {
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

        YR_FIXUP* fixup = compiler->fixup_stack_head;

        // We know that the OR opcode and the following one are within the same
        // page, so we can compute the address for the opcode following the OR
        // by simply adding one to its address.

        *(fixup->address) = PTR_TO_INT64(or_addr + 1);

        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2936 "grammar.c" /* yacc.c:1646  */
    break;

  case 68:
#line 1349 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2949 "grammar.c" /* yacc.c:1646  */
    break;

  case 69:
#line 1358 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2962 "grammar.c" /* yacc.c:1646  */
    break;

  case 70:
#line 1367 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "<=", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2975 "grammar.c" /* yacc.c:1646  */
    break;

  case 71:
#line 1376 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, ">=", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2988 "grammar.c" /* yacc.c:1646  */
    break;

  case 72:
#line 1385 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "==", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3001 "grammar.c" /* yacc.c:1646  */
    break;

  case 73:
#line 1394 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "!=", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_BOOLEAN;
      }
#line 3014 "grammar.c" /* yacc.c:1646  */
    break;

  case 74:
#line 1403 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3022 "grammar.c" /* yacc.c:1646  */
    break;

  case 75:
#line 1407 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3030 "grammar.c" /* yacc.c:1646  */
    break;

  case 76:
#line 1414 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = INTEGER_SET_ENUMERATION; }
#line 3036 "grammar.c" /* yacc.c:1646  */
    break;

  case 77:
#line 1415 "grammar.y" /* yacc.c:1646  */
    { (yyval.integer) = INTEGER_SET_RANGE; }
#line 3042 "grammar.c" /* yacc.c:1646  */
    break;

  case 78:
#line 1421 "grammar.y" /* yacc.c:1646  */
    {
        if ((yyvsp[-4].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_YARA_WRONG_TYPE;
        }

        if ((yyvsp[-1].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_YARA_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3064 "grammar.c" /* yacc.c:1646  */
    break;

  case 79:
#line 1443 "grammar.y" /* yacc.c:1646  */
    {
        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_YARA_WRONG_TYPE;

        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3080 "grammar.c" /* yacc.c:1646  */
    break;

  case 80:
#line 1455 "grammar.y" /* yacc.c:1646  */
    {
        if ((yyvsp[0].expression).type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_YARA_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3095 "grammar.c" /* yacc.c:1646  */
    break;

  case 81:
#line 1470 "grammar.y" /* yacc.c:1646  */
    {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
#line 3104 "grammar.c" /* yacc.c:1646  */
    break;

  case 83:
#line 1476 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");
      }
#line 3113 "grammar.c" /* yacc.c:1646  */
    break;

  case 86:
#line 1491 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));
      }
#line 3122 "grammar.c" /* yacc.c:1646  */
    break;

  case 87:
#line 1496 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));
      }
#line 3131 "grammar.c" /* yacc.c:1646  */
    break;

  case 89:
#line 1506 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
#line 3139 "grammar.c" /* yacc.c:1646  */
    break;

  case 90:
#line 1510 "grammar.y" /* yacc.c:1646  */
    {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL, NULL);
      }
#line 3147 "grammar.c" /* yacc.c:1646  */
    break;

  case 91:
#line 1518 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.expression) = (yyvsp[-1].expression);
      }
#line 3155 "grammar.c" /* yacc.c:1646  */
    break;

  case 92:
#line 1522 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3169 "grammar.c" /* yacc.c:1646  */
    break;

  case 93:
#line 1532 "grammar.y" /* yacc.c:1646  */
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
#line 3187 "grammar.c" /* yacc.c:1646  */
    break;

  case 94:
#line 1546 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-1].expression), EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_READ_INT results
        // in the proper OP_INTXX opcode.

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_READ_INT + (yyvsp[-3].integer), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3207 "grammar.c" /* yacc.c:1646  */
    break;

  case 95:
#line 1562 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[0].integer), NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = (yyvsp[0].integer);
      }
#line 3221 "grammar.c" /* yacc.c:1646  */
    break;

  case 96:
#line 1572 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, (yyvsp[0].double_), NULL, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
      }
#line 3234 "grammar.c" /* yacc.c:1646  */
    break;

  case 97:
#line 1581 "grammar.y" /* yacc.c:1646  */
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
              PTR_TO_INT64(sized_string),
              NULL,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_STRING;
      }
#line 3262 "grammar.c" /* yacc.c:1646  */
    break;

  case 98:
#line 1605 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_COUNT,
            UNDEFINED);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3281 "grammar.c" /* yacc.c:1646  */
    break;

  case 99:
#line 1620 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[-3].c_string),
            OP_OFFSET,
            UNDEFINED);

        yr_free((yyvsp[-3].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3300 "grammar.c" /* yacc.c:1646  */
    break;

  case 100:
#line 1635 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            1,
            NULL,
            NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner,
              (yyvsp[0].c_string),
              OP_OFFSET,
              UNDEFINED);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = UNDEFINED;
      }
#line 3327 "grammar.c" /* yacc.c:1646  */
    break;

  case 101:
#line 1658 "grammar.y" /* yacc.c:1646  */
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
              break;
            default:
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  (yyvsp[0].expression).identifier);
              compiler->last_result = ERROR_YARA_WRONG_TYPE;
          }
        }
        else
        {
          assert(FALSE);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3375 "grammar.c" /* yacc.c:1646  */
    break;

  case 102:
#line 1702 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT, "-");

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

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3398 "grammar.c" /* yacc.c:1646  */
    break;

  case 103:
#line 1721 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "+", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(+, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
#line 3420 "grammar.c" /* yacc.c:1646  */
    break;

  case 104:
#line 1739 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "-", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(-, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
#line 3442 "grammar.c" /* yacc.c:1646  */
    break;

  case 105:
#line 1757 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "*", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(*, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
#line 3464 "grammar.c" /* yacc.c:1646  */
    break;

  case 106:
#line 1775 "grammar.y" /* yacc.c:1646  */
    {
        compiler->last_result = yr_parser_reduce_operation(
            yyscanner, "\\", (yyvsp[-2].expression), (yyvsp[0].expression));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if ((yyvsp[-2].expression).type == EXPRESSION_TYPE_INTEGER &&
            (yyvsp[0].expression).type == EXPRESSION_TYPE_INTEGER)
        {
          (yyval.expression).value.integer = OPERATION(/, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
          (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          (yyval.expression).type = EXPRESSION_TYPE_FLOAT;
        }
      }
#line 3486 "grammar.c" /* yacc.c:1646  */
    break;

  case 107:
#line 1793 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(%, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3500 "grammar.c" /* yacc.c:1646  */
    break;

  case 108:
#line 1803 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(^, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3514 "grammar.c" /* yacc.c:1646  */
    break;

  case 109:
#line 1813 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(&, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3528 "grammar.c" /* yacc.c:1646  */
    break;

  case 110:
#line 1823 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(|, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3542 "grammar.c" /* yacc.c:1646  */
    break;

  case 111:
#line 1833 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = ((yyvsp[0].expression).value.integer == UNDEFINED) ?
            UNDEFINED : ~((yyvsp[0].expression).value.integer);
      }
#line 3556 "grammar.c" /* yacc.c:1646  */
    break;

  case 112:
#line 1843 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(<<, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3570 "grammar.c" /* yacc.c:1646  */
    break;

  case 113:
#line 1853 "grammar.y" /* yacc.c:1646  */
    {
        CHECK_TYPE((yyvsp[-2].expression), EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE((yyvsp[0].expression), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        (yyval.expression).type = EXPRESSION_TYPE_INTEGER;
        (yyval.expression).value.integer = OPERATION(>>, (yyvsp[-2].expression).value.integer, (yyvsp[0].expression).value.integer);
      }
#line 3584 "grammar.c" /* yacc.c:1646  */
    break;

  case 114:
#line 1863 "grammar.y" /* yacc.c:1646  */
    {
        (yyval.expression) = (yyvsp[0].expression);
      }
#line 3592 "grammar.c" /* yacc.c:1646  */
    break;


#line 3596 "grammar.c" /* yacc.c:1646  */
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
#line 1868 "grammar.y" /* yacc.c:1906  */

