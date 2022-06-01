/* A Bison parser, made by GNU Bison 3.8.  */

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
#define YYBISON 30800

/* Bison version string.  */
#define YYBISON_VERSION "3.8"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         re_yyparse
#define yylex           re_yylex
#define yyerror         re_yyerror
#define yydebug         re_yydebug
#define yynerrs         re_yynerrs

/* First part of user prologue.  */
#line 32 "re_grammar.y"


#include <yara/integers.h>
#include <yara/utils.h>
#include <yara/error.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/re_lexer.h>


#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define mark_as_not_fast_regexp() \
    ((RE_AST*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_REGEXP

#define fail_if(x, error) \
    if (x) \
    { \
      lex_env->last_error = error; \
      YYABORT; \
    } \

#define destroy_node_if(x, node) \
    if (x) \
    { \
      yr_re_node_destroy(node); \
    } \


#line 110 "re_grammar.c"

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

#include "re_grammar.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL__CHAR_ = 3,                     /* _CHAR_  */
  YYSYMBOL__ANY_ = 4,                      /* _ANY_  */
  YYSYMBOL__RANGE_ = 5,                    /* _RANGE_  */
  YYSYMBOL__CLASS_ = 6,                    /* _CLASS_  */
  YYSYMBOL__WORD_CHAR_ = 7,                /* _WORD_CHAR_  */
  YYSYMBOL__NON_WORD_CHAR_ = 8,            /* _NON_WORD_CHAR_  */
  YYSYMBOL__SPACE_ = 9,                    /* _SPACE_  */
  YYSYMBOL__NON_SPACE_ = 10,               /* _NON_SPACE_  */
  YYSYMBOL__DIGIT_ = 11,                   /* _DIGIT_  */
  YYSYMBOL__NON_DIGIT_ = 12,               /* _NON_DIGIT_  */
  YYSYMBOL__WORD_BOUNDARY_ = 13,           /* _WORD_BOUNDARY_  */
  YYSYMBOL__NON_WORD_BOUNDARY_ = 14,       /* _NON_WORD_BOUNDARY_  */
  YYSYMBOL_15_ = 15,                       /* '|'  */
  YYSYMBOL_16_ = 16,                       /* '*'  */
  YYSYMBOL_17_ = 17,                       /* '?'  */
  YYSYMBOL_18_ = 18,                       /* '+'  */
  YYSYMBOL_19_ = 19,                       /* '^'  */
  YYSYMBOL_20_ = 20,                       /* '$'  */
  YYSYMBOL_21_ = 21,                       /* '('  */
  YYSYMBOL_22_ = 22,                       /* ')'  */
  YYSYMBOL_23_ = 23,                       /* '.'  */
  YYSYMBOL_YYACCEPT = 24,                  /* $accept  */
  YYSYMBOL_re = 25,                        /* re  */
  YYSYMBOL_alternative = 26,               /* alternative  */
  YYSYMBOL_concatenation = 27,             /* concatenation  */
  YYSYMBOL_repeat = 28,                    /* repeat  */
  YYSYMBOL_single = 29                     /* single  */
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
typedef yytype_int8 yy_state_t;

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
#define YYFINAL  22
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   45

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  24
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  6
/* YYNRULES -- Number of rules.  */
#define YYNRULES  31
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  35

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   269


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
       2,     2,     2,     2,     2,     2,    20,     2,     2,     2,
      21,    22,    16,    18,     2,     2,    23,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    17,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    19,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    15,     2,     2,     2,     2,     2,
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
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   106,   106,   111,   115,   119,   133,   157,   166,   174,
     190,   208,   224,   241,   264,   288,   311,   335,   339,   345,
     351,   357,   366,   370,   379,   388,   394,   400,   406,   412,
     418,   424
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
  "\"end of file\"", "error", "\"invalid token\"", "_CHAR_", "_ANY_",
  "_RANGE_", "_CLASS_", "_WORD_CHAR_", "_NON_WORD_CHAR_", "_SPACE_",
  "_NON_SPACE_", "_DIGIT_", "_NON_DIGIT_", "_WORD_BOUNDARY_",
  "_NON_WORD_BOUNDARY_", "'|'", "'*'", "'?'", "'+'", "'^'", "'$'", "'('",
  "')'", "'.'", "$accept", "re", "alternative", "concatenation", "repeat",
  "single", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-12)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      -1,   -12,   -12,   -12,   -12,   -12,   -12,   -12,   -12,   -12,
     -12,   -12,   -12,   -12,    18,   -12,     1,   -11,    18,   -12,
      -2,    21,   -12,    18,   -12,     0,    16,    17,    23,   -12,
      18,   -12,   -12,   -12,   -12
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     3,    24,    31,    25,    26,    27,    28,    29,    30,
      18,    19,    20,    21,     0,    23,     0,     2,     4,     7,
      17,     0,     1,     6,     8,    15,     9,    13,    11,    22,
       5,    16,    10,    14,    12
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -12,   -12,    28,    22,     5,   -12
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,    16,    17,    18,    19,    20
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
       1,    22,     2,    25,    23,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    26,    27,    28,    31,    12,    13,
      14,     2,    15,    24,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    32,    33,    24,    23,    12,    13,    14,
      34,    15,    21,    29,     0,    30
};

static const yytype_int8 yycheck[] =
{
       1,     0,     3,     5,    15,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    16,    17,    18,    17,    19,    20,
      21,     3,    23,    18,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    17,    17,    30,    15,    19,    20,    21,
      17,    23,    14,    22,    -1,    23
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     1,     3,     6,     7,     8,     9,    10,    11,    12,
      13,    14,    19,    20,    21,    23,    25,    26,    27,    28,
      29,    26,     0,    15,    28,     5,    16,    17,    18,    22,
      27,    17,    17,    17,    17
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    24,    25,    25,    26,    26,    26,    27,    27,    28,
      28,    28,    28,    28,    28,    28,    28,    28,    28,    28,
      28,    28,    29,    29,    29,    29,    29,    29,    29,    29,
      29,    29
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     1,     1,     3,     2,     1,     2,     2,
       3,     2,     3,     2,     3,     2,     3,     1,     1,     1,
       1,     1,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1
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
        yyerror (yyscanner, lex_env, YY_("syntax error: cannot back up")); \
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
                  Kind, Value, yyscanner, lex_env); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, void *yyscanner, RE_LEX_ENVIRONMENT *lex_env)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yyscanner);
  YY_USE (lex_env);
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
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, void *yyscanner, RE_LEX_ENVIRONMENT *lex_env)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep, yyscanner, lex_env);
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
                 int yyrule, void *yyscanner, RE_LEX_ENVIRONMENT *lex_env)
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
                       &yyvsp[(yyi + 1) - (yynrhs)], yyscanner, lex_env);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, yyscanner, lex_env); \
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
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, void *yyscanner, RE_LEX_ENVIRONMENT *lex_env)
{
  YY_USE (yyvaluep);
  YY_USE (yyscanner);
  YY_USE (lex_env);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL__CLASS_: /* _CLASS_  */
#line 98 "re_grammar.y"
            { yr_free(((*yyvaluep).re_class)); ((*yyvaluep).re_class) = NULL; }
#line 887 "re_grammar.c"
        break;

    case YYSYMBOL_alternative: /* alternative  */
#line 99 "re_grammar.y"
            { yr_re_node_destroy(((*yyvaluep).re_node)); ((*yyvaluep).re_node) = NULL; }
#line 893 "re_grammar.c"
        break;

    case YYSYMBOL_concatenation: /* concatenation  */
#line 100 "re_grammar.y"
            { yr_re_node_destroy(((*yyvaluep).re_node)); ((*yyvaluep).re_node) = NULL; }
#line 899 "re_grammar.c"
        break;

    case YYSYMBOL_repeat: /* repeat  */
#line 101 "re_grammar.y"
            { yr_re_node_destroy(((*yyvaluep).re_node)); ((*yyvaluep).re_node) = NULL; }
#line 905 "re_grammar.c"
        break;

    case YYSYMBOL_single: /* single  */
#line 102 "re_grammar.y"
            { yr_re_node_destroy(((*yyvaluep).re_node)); ((*yyvaluep).re_node) = NULL; }
#line 911 "re_grammar.c"
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
yyparse (void *yyscanner, RE_LEX_ENVIRONMENT *lex_env)
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
      yychar = yylex (&yylval, yyscanner, lex_env);
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
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
  case 2: /* re: alternative  */
#line 107 "re_grammar.y"
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->root_node = (yyvsp[0].re_node);
      }
#line 1190 "re_grammar.c"
    break;

  case 4: /* alternative: concatenation  */
#line 116 "re_grammar.y"
      {
        (yyval.re_node) = (yyvsp[0].re_node);
      }
#line 1198 "re_grammar.c"
    break;

  case 5: /* alternative: alternative '|' concatenation  */
#line 120 "re_grammar.y"
      {
        mark_as_not_fast_regexp();

        (yyval.re_node) = yr_re_node_create(RE_NODE_ALT);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-2].re_node));
        destroy_node_if((yyval.re_node) == NULL, (yyvsp[0].re_node));

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-2].re_node));
        yr_re_node_append_child((yyval.re_node), (yyvsp[0].re_node));
      }
#line 1216 "re_grammar.c"
    break;

  case 6: /* alternative: alternative '|'  */
#line 134 "re_grammar.y"
      {
        RE_NODE* node;

        mark_as_not_fast_regexp();

        node = yr_re_node_create(RE_NODE_EMPTY);

        destroy_node_if(node == NULL, (yyvsp[-1].re_node));
        fail_if(node == NULL, ERROR_INSUFFICIENT_MEMORY);

        (yyval.re_node) = yr_re_node_create(RE_NODE_ALT);

        destroy_node_if((yyval.re_node) == NULL, node);
        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-1].re_node));

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-1].re_node));
        yr_re_node_append_child((yyval.re_node), node);
      }
#line 1241 "re_grammar.c"
    break;

  case 7: /* concatenation: repeat  */
#line 158 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_CONCAT);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[0].re_node));
        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[0].re_node));
      }
#line 1254 "re_grammar.c"
    break;

  case 8: /* concatenation: concatenation repeat  */
#line 167 "re_grammar.y"
      {
        yr_re_node_append_child((yyvsp[-1].re_node), (yyvsp[0].re_node));
        (yyval.re_node) = (yyvsp[-1].re_node);
      }
#line 1263 "re_grammar.c"
    break;

  case 9: /* repeat: single '*'  */
#line 175 "re_grammar.y"
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        (yyval.re_node) = yr_re_node_create(RE_NODE_STAR);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-1].re_node));
        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-1].re_node));
      }
#line 1283 "re_grammar.c"
    break;

  case 10: /* repeat: single '*' '?'  */
#line 191 "re_grammar.y"
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        (yyval.re_node) = yr_re_node_create(RE_NODE_STAR);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-2].re_node));
        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-2].re_node));

        (yyval.re_node)->greedy = false;
      }
#line 1305 "re_grammar.c"
    break;

  case 11: /* repeat: single '+'  */
#line 209 "re_grammar.y"
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        (yyval.re_node) = yr_re_node_create(RE_NODE_PLUS);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-1].re_node));
        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-1].re_node));
      }
#line 1325 "re_grammar.c"
    break;

  case 12: /* repeat: single '+' '?'  */
#line 225 "re_grammar.y"
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        (yyval.re_node) = yr_re_node_create(RE_NODE_PLUS);

        destroy_node_if((yyval.re_node) == NULL, (yyvsp[-2].re_node));
        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        yr_re_node_append_child((yyval.re_node), (yyvsp[-2].re_node));
        (yyval.re_node)->greedy = false;
      }
#line 1346 "re_grammar.c"
    break;

  case 13: /* repeat: single '?'  */
#line 242 "re_grammar.y"
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        if ((yyvsp[-1].re_node)->type == RE_NODE_ANY)
        {
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE_ANY);
          destroy_node_if(true, (yyvsp[-1].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
        }
        else
        {
          mark_as_not_fast_regexp();
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE);
          destroy_node_if((yyval.re_node) == NULL, (yyvsp[-1].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
          yr_re_node_append_child((yyval.re_node), (yyvsp[-1].re_node));
        }

        (yyval.re_node)->start = 0;
        (yyval.re_node)->end = 1;
      }
#line 1373 "re_grammar.c"
    break;

  case 14: /* repeat: single '?' '?'  */
#line 265 "re_grammar.y"
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        if ((yyvsp[-2].re_node)->type == RE_NODE_ANY)
        {
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE_ANY);
          destroy_node_if(true, (yyvsp[-2].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
        }
        else
        {
          mark_as_not_fast_regexp();
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE);
          destroy_node_if((yyval.re_node) == NULL, (yyvsp[-2].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
          yr_re_node_append_child((yyval.re_node), (yyvsp[-2].re_node));
        }

        (yyval.re_node)->start = 0;
        (yyval.re_node)->end = 1;
        (yyval.re_node)->greedy = false;
      }
#line 1401 "re_grammar.c"
    break;

  case 15: /* repeat: single _RANGE_  */
#line 289 "re_grammar.y"
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        if ((yyvsp[-1].re_node)->type == RE_NODE_ANY)
        {
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE_ANY);
          destroy_node_if(true, (yyvsp[-1].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
        }
        else
        {
          mark_as_not_fast_regexp();
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE);
          destroy_node_if((yyval.re_node) == NULL, (yyvsp[-1].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
          yr_re_node_append_child((yyval.re_node), (yyvsp[-1].re_node));
        }

        (yyval.re_node)->start = (yyvsp[0].range) & 0xFFFF;;
        (yyval.re_node)->end = (yyvsp[0].range) >> 16;;
      }
#line 1428 "re_grammar.c"
    break;

  case 16: /* repeat: single _RANGE_ '?'  */
#line 312 "re_grammar.y"
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        if ((yyvsp[-2].re_node)->type == RE_NODE_ANY)
        {
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE_ANY);
          destroy_node_if(true, (yyvsp[-2].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
        }
        else
        {
          mark_as_not_fast_regexp();
          (yyval.re_node) = yr_re_node_create(RE_NODE_RANGE);
          destroy_node_if((yyval.re_node) == NULL, (yyvsp[-2].re_node));
          fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
          yr_re_node_append_child((yyval.re_node), (yyvsp[-2].re_node));
        }

        (yyval.re_node)->start = (yyvsp[-1].range) & 0xFFFF;;
        (yyval.re_node)->end = (yyvsp[-1].range) >> 16;;
        (yyval.re_node)->greedy = false;
      }
#line 1456 "re_grammar.c"
    break;

  case 17: /* repeat: single  */
#line 336 "re_grammar.y"
      {
        (yyval.re_node) = (yyvsp[0].re_node);
      }
#line 1464 "re_grammar.c"
    break;

  case 18: /* repeat: _WORD_BOUNDARY_  */
#line 340 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_WORD_BOUNDARY);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1474 "re_grammar.c"
    break;

  case 19: /* repeat: _NON_WORD_BOUNDARY_  */
#line 346 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_NON_WORD_BOUNDARY);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1484 "re_grammar.c"
    break;

  case 20: /* repeat: '^'  */
#line 352 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_ANCHOR_START);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1494 "re_grammar.c"
    break;

  case 21: /* repeat: '$'  */
#line 358 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_ANCHOR_END);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1504 "re_grammar.c"
    break;

  case 22: /* single: '(' alternative ')'  */
#line 367 "re_grammar.y"
      {
        (yyval.re_node) = (yyvsp[-1].re_node);
      }
#line 1512 "re_grammar.c"
    break;

  case 23: /* single: '.'  */
#line 371 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_ANY);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        (yyval.re_node)->value = 0x00;
        (yyval.re_node)->mask = 0x00;
      }
#line 1525 "re_grammar.c"
    break;

  case 24: /* single: _CHAR_  */
#line 380 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_LITERAL);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        (yyval.re_node)->value = (yyvsp[0].integer);
        (yyval.re_node)->mask = 0xFF;
      }
#line 1538 "re_grammar.c"
    break;

  case 25: /* single: _WORD_CHAR_  */
#line 389 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_WORD_CHAR);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1548 "re_grammar.c"
    break;

  case 26: /* single: _NON_WORD_CHAR_  */
#line 395 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_NON_WORD_CHAR);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1558 "re_grammar.c"
    break;

  case 27: /* single: _SPACE_  */
#line 401 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_SPACE);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1568 "re_grammar.c"
    break;

  case 28: /* single: _NON_SPACE_  */
#line 407 "re_grammar.y"
      {
         (yyval.re_node) = yr_re_node_create(RE_NODE_NON_SPACE);

         fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1578 "re_grammar.c"
    break;

  case 29: /* single: _DIGIT_  */
#line 413 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_DIGIT);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1588 "re_grammar.c"
    break;

  case 30: /* single: _NON_DIGIT_  */
#line 419 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_NON_DIGIT);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
#line 1598 "re_grammar.c"
    break;

  case 31: /* single: _CLASS_  */
#line 425 "re_grammar.y"
      {
        (yyval.re_node) = yr_re_node_create(RE_NODE_CLASS);

        fail_if((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);

        (yyval.re_node)->re_class = (yyvsp[0].re_class);
        (yyval.re_node)->mask = 0xCC;
      }
#line 1611 "re_grammar.c"
    break;


#line 1615 "re_grammar.c"

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
      yyerror (yyscanner, lex_env, YY_("syntax error"));
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
                      yytoken, &yylval, yyscanner, lex_env);
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
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yyscanner, lex_env);
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
  yyerror (yyscanner, lex_env, YY_("memory exhausted"));
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
                  yytoken, &yylval, yyscanner, lex_env);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yyscanner, lex_env);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 434 "re_grammar.y"

