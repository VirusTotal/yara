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
     _MATCH_ = 299,
     _CONTAINS_ = 300,
     _MZ_ = 301,
     _PE_ = 302,
     _DLL_ = 303,
     _TRUE_ = 304,
     _FALSE_ = 305,
     _OR_ = 306,
     _AND_ = 307,
     _NOT_ = 308,
     _IS_ = 309,
     _NEQ_ = 310,
     _EQ_ = 311,
     _GE_ = 312,
     _GT_ = 313,
     _LE_ = 314,
     _LT_ = 315
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
#define _MATCH_ 299
#define _CONTAINS_ 300
#define _MZ_ 301
#define _PE_ 302
#define _DLL_ 303
#define _TRUE_ 304
#define _FALSE_ 305
#define _OR_ 306
#define _AND_ 307
#define _NOT_ 308
#define _IS_ 309
#define _NEQ_ 310
#define _EQ_ 311
#define _GE_ 312
#define _GT_ 313
#define _LE_ 314
#define _LT_ 315




/* Copy the first part of user declarations.  */
#line 2 "grammar.y"
 
    
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ast.h"
#include "sizedstr.h"
#include "mem.h"
#include "lex.h"

#define YYERROR_VERBOSE
//#define YYDEBUG 1



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
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
#line 105 "grammar.y"
{
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;
    void*           meta;

}
/* Line 193 of yacc.c.  */
#line 244 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */
#line 120 "grammar.y"
 

/* Function declarations */

int reduce_rule_declaration(    yyscan_t yyscanner, 
                                char* identifier, 
                                int flags, 
                                TAG* tag_list_head, 
                                META* meta_list_head,
                                STRING* string_list_head, 
                                TERM* condition);
                            
TAG* reduce_tags(   yyscan_t yyscanner,
                    TAG* tag_list_head,
                    char* identifier);
                    
                    
META* reduce_meta_declaration(  yyscan_t yyscanner,
                                int type,
                                char* identifier,
                                unsigned int integer_value,					
                                SIZED_STRING* string_value);
                    
META* reduce_metas( yyscan_t yyscanner, 
                    META* meta_list_head,
                    META* meta);

STRING* reduce_string_declaration(  yyscan_t yyscanner,
                                    char* identifier, 
                                    SIZED_STRING* str, 
                                    int flags);
                                
STRING* reduce_strings( yyscan_t yyscanner, 
                        STRING* string_list_head, 
                        STRING* string);

TERM* reduce_string_enumeration(    yyscan_t yyscanner,
                                    TERM* string_list_head, 
                                    TERM* string_identifier);
                                    
TERM* reduce_string_with_wildcard(  yyscan_t yyscanner,
                                    char* identifier);

TERM* reduce_string(    yyscan_t yyscanner, 
                        char* identifier);
                        
TERM* reduce_string_at( yyscan_t yyscanner,
                        char* identifier, 
                        TERM* offset);
                        
TERM* reduce_string_in_range(   yyscan_t yyscanner,
                                char* identifier, 
                                TERM* lower_offset, 
                                TERM* upper_offset);
                                
TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, 
                                        SIZED_STRING* section_name);
                                        
TERM* reduce_string_count(  yyscan_t yyscanner, 
                            char* identifier);
                            
TERM* reduce_string_offset( yyscan_t yyscanner,  
                            char* identifier); 

TERM* reduce_filesize(yyscan_t yyscanner);

TERM* reduce_entrypoint(yyscan_t yyscanner);

TERM* reduce_term(  yyscan_t yyscanner, 
                    int type, 
                    TERM* op1, 
                    TERM* op2, 
                    TERM* op3);
                    
TERM* reduce_constant(  yyscan_t yyscanner,
                        unsigned int constant);

TERM* reduce_identifier( yyscan_t yyscanner,
                         char* identifier);
                         
TERM* reduce_external_string_operation( yyscan_t yyscanner,
                                        int type,
                                        char* identifier,
                                        SIZED_STRING* string);

int count_strings(TERM_STRING* st);



/* Line 216 of yacc.c.  */
#line 346 "grammar.c"

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
#define YYLAST   287

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  74
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  26
/* YYNRULES -- Number of rules.  */
#define YYNRULES  95
/* YYNRULES -- Number of states.  */
#define YYNSTATES  194

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   315

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      70,    72,    63,    61,    73,    62,    71,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    68,     2,
       2,    69,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    64,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    65,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    66,     2,    67,     2,     2,     2,     2,
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
      55,    56,    57,    58,    59,    60
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    11,    15,    25,    26,    30,
      31,    35,    39,    40,    43,    45,    47,    48,    51,    53,
      56,    58,    61,    65,    69,    73,    77,    79,    82,    87,
      92,    96,    97,   100,   102,   104,   106,   108,   110,   112,
     114,   118,   122,   124,   128,   133,   142,   149,   150,   160,
     161,   171,   172,   182,   186,   190,   194,   198,   202,   205,
     209,   213,   217,   221,   225,   229,   233,   237,   241,   245,
     249,   251,   253,   257,   259,   261,   263,   265,   270,   275,
     280,   285,   290,   295,   297,   299,   301,   305,   309,   313,
     317,   321,   323,   325,   327,   329
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      75,     0,    -1,    -1,    75,    76,    -1,    75,     1,    76,
      -1,    75,     1,    65,    -1,    80,     3,    10,    82,    66,
      77,    78,    79,    67,    -1,    -1,     6,    68,    84,    -1,
      -1,     7,    68,    86,    -1,     8,    68,    90,    -1,    -1,
      80,    81,    -1,     4,    -1,     5,    -1,    -1,    68,    83,
      -1,    10,    -1,    83,    10,    -1,    85,    -1,    84,    85,
      -1,    10,    69,    18,    -1,    10,    69,    16,    -1,    10,
      69,    49,    -1,    10,    69,    50,    -1,    87,    -1,    86,
      87,    -1,    11,    69,    18,    88,    -1,    11,    69,    20,
      88,    -1,    11,    69,    19,    -1,    -1,    88,    89,    -1,
      22,    -1,    21,    -1,    23,    -1,    24,    -1,    49,    -1,
      50,    -1,    10,    -1,    10,    44,    20,    -1,    10,    45,
      18,    -1,    11,    -1,    11,    25,    97,    -1,    11,    25,
      30,    97,    -1,    11,    33,    70,    97,    71,    71,    97,
      72,    -1,    11,    33,    37,    70,    18,    72,    -1,    -1,
      35,    97,    34,    94,    68,    91,    70,    90,    72,    -1,
      -1,    35,    28,    34,    94,    68,    92,    70,    90,    72,
      -1,    -1,    35,    29,    34,    94,    68,    93,    70,    90,
      72,    -1,    97,    34,    94,    -1,    28,    34,    94,    -1,
      29,    34,    94,    -1,    32,    54,    99,    -1,    70,    90,
      72,    -1,    53,    90,    -1,    90,    52,    90,    -1,    90,
      51,    90,    -1,    90,    54,    90,    -1,    97,    60,    97,
      -1,    97,    58,    97,    -1,    97,    59,    97,    -1,    97,
      57,    97,    -1,    97,    56,    97,    -1,    97,    54,    97,
      -1,    97,    55,    97,    -1,    70,    95,    72,    -1,    36,
      -1,    96,    -1,    95,    73,    96,    -1,    11,    -1,    14,
      -1,    26,    -1,    27,    -1,    38,    70,    97,    72,    -1,
      39,    70,    97,    72,    -1,    40,    70,    97,    72,    -1,
      41,    70,    97,    72,    -1,    42,    70,    97,    72,    -1,
      43,    70,    97,    72,    -1,    12,    -1,    13,    -1,    10,
      -1,    70,    97,    72,    -1,    97,    61,    97,    -1,    97,
      62,    97,    -1,    97,    63,    97,    -1,    97,    64,    97,
      -1,    98,    -1,    16,    -1,    46,    -1,    47,    -1,    48,
      -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   212,   212,   213,   214,   215,   218,   228,   229,   232,
     233,   236,   239,   240,   243,   244,   247,   248,   251,   260,
     270,   279,   290,   299,   308,   317,   328,   338,   350,   360,
     370,   382,   383,   386,   387,   388,   389,   392,   393,   394,
     404,   414,   424,   434,   444,   448,   458,   469,   468,   485,
     484,   501,   500,   516,   526,   536,   546,   547,   548,   549,
     550,   551,   552,   553,   554,   555,   556,   557,   558,   562,
     563,   566,   567,   573,   583,   596,   597,   598,   599,   600,
     601,   602,   603,   604,   614,   624,   634,   635,   636,   637,
     638,   639,   642,   645,   646,   647
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
  "_UINT16_", "_UINT32_", "_MATCH_", "_CONTAINS_", "_MZ_", "_PE_", "_DLL_",
  "_TRUE_", "_FALSE_", "_OR_", "_AND_", "_NOT_", "_IS_", "_NEQ_", "_EQ_",
  "_GE_", "_GT_", "_LE_", "_LT_", "'+'", "'-'", "'*'", "'\\\\'",
  "'include'", "'{'", "'}'", "':'", "'='", "'('", "'.'", "')'", "','",
  "$accept", "rules", "rule", "meta", "strings", "condition",
  "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "string_modifiers", "string_modifier",
  "boolean_expression", "@1", "@2", "@3", "string_set",
  "string_enumeration", "string_enumeration_item", "expression", "number",
  "type", 0
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
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,    43,    45,    42,    92,   105,   123,   125,    58,    61,
      40,    46,    41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    74,    75,    75,    75,    75,    76,    77,    77,    78,
      78,    79,    80,    80,    81,    81,    82,    82,    83,    83,
      84,    84,    85,    85,    85,    85,    86,    86,    87,    87,
      87,    88,    88,    89,    89,    89,    89,    90,    90,    90,
      90,    90,    90,    90,    90,    90,    90,    91,    90,    92,
      90,    93,    90,    90,    90,    90,    90,    90,    90,    90,
      90,    90,    90,    90,    90,    90,    90,    90,    90,    94,
      94,    95,    95,    96,    96,    97,    97,    97,    97,    97,
      97,    97,    97,    97,    97,    97,    97,    97,    97,    97,
      97,    97,    98,    99,    99,    99
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     3,     3,     9,     0,     3,     0,
       3,     3,     0,     2,     1,     1,     0,     2,     1,     2,
       1,     2,     3,     3,     3,     3,     1,     2,     4,     4,
       3,     0,     2,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     1,     3,     4,     8,     6,     0,     9,     0,
       9,     0,     9,     3,     3,     3,     3,     3,     2,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       1,     1,     3,     1,     1,     1,     1,     4,     4,     4,
       4,     4,     4,     1,     1,     1,     3,     3,     3,     3,
       3,     1,     1,     1,     1,     1
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
      25,     0,    27,    85,    42,    83,    84,    92,    75,    76,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      37,    38,     0,     0,    11,     0,    91,    31,    30,    31,
       0,     0,     0,     0,     0,     0,     0,    85,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    58,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    28,    29,    40,    41,
       0,    43,     0,     0,    70,     0,    54,    55,    93,    94,
      95,    56,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    57,    86,    60,    59,    61,    53,    67,    68,
      66,    65,    63,    64,    62,    87,    88,    89,    90,    34,
      33,    35,    36,    32,    44,     0,     0,    73,    74,     0,
      71,     0,     0,     0,    77,    78,    79,    80,    81,    82,
       0,     0,    69,     0,    49,    51,    47,    46,     0,    72,
       0,     0,     0,     0,     0,     0,     0,    45,     0,     0,
       0,    50,    52,    48
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     4,    20,    23,    29,     5,    11,    14,    16,
      25,    26,    33,    34,   106,   153,    64,   182,   180,   181,
     116,   159,   160,    65,    66,   121
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -57
static const yytype_int16 yypact[] =
{
     -57,   232,   -57,   -45,   -57,   155,   -57,   -57,    15,   -57,
     -57,   -57,   -40,    67,    -8,   -57,    69,    81,   -57,    21,
      88,    89,    42,   104,    45,    89,   -57,   111,    47,    60,
      48,   -57,    68,   111,   -57,    43,   -57,   -57,   -57,   -57,
     -57,   230,   -57,   150,   -24,   -57,   -57,   -57,   -57,   -57,
     107,   113,    84,    78,    75,    85,    97,   121,   126,   128,
     -57,   -57,    43,    43,    11,   151,   -57,   -57,   -57,   -57,
     131,   172,   123,   -29,   -32,   -32,   206,   -57,   165,   169,
     130,    39,   130,   130,   130,   130,   130,   130,   177,   -49,
     120,    43,    43,    43,   -32,   130,   130,   130,   130,   130,
     130,   130,   130,   130,   130,   130,   250,   250,   -57,   -57,
     130,   214,   146,   130,   -57,    10,   -57,   -57,   -57,   -57,
     -57,   -57,   -32,   -32,   -50,   -32,   -46,   125,   162,   166,
     179,   183,   -57,   -57,    22,   177,   -57,   -57,   214,   214,
     214,   214,   214,   214,   214,     4,     4,   -57,   -57,   -57,
     -57,   -57,   -57,   -57,   214,   202,   199,   -57,   -57,   -33,
     -57,   196,   197,   198,   -57,   -57,   -57,   -57,   -57,   -57,
     207,   209,   -57,    10,   -57,   -57,   -57,   -57,   130,   -57,
     211,   212,   213,   195,    43,    43,    43,   -57,    72,    80,
     167,   -57,   -57,   -57
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -57,   -57,   265,   -57,   -57,   -57,   -57,   -57,   -57,   -57,
     -57,   244,   -57,   251,   216,   -57,   -56,   -57,   -57,   -57,
     -14,   -57,   114,   -53,   -57,   -57
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -40
static const yytype_int16 yytable[] =
{
      81,    72,    91,    92,   114,    93,    88,    89,   112,    73,
      90,   102,   103,   104,   105,   102,   103,   104,   105,   111,
       6,   157,   133,   132,   158,    12,   164,   124,    13,   126,
     127,   128,   129,   130,   131,   134,   135,   136,   115,   172,
     173,   113,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,    43,    44,    45,    46,   154,    17,    47,
     156,   117,    91,    92,    37,    93,    38,   104,   105,    48,
      49,    50,    51,   125,    92,    52,    93,    15,    53,    18,
     137,    54,    55,    56,    57,    58,    59,    19,    77,    21,
      45,    46,    60,    61,    47,    22,    62,    39,    40,    24,
     102,   103,   104,   105,    48,    49,    78,    79,   161,   162,
      27,   163,    28,    63,    30,    35,    54,    55,    56,    57,
      58,    59,    32,    91,    92,   183,    93,    36,   188,   189,
     190,    91,    92,    77,    93,    45,    46,    41,    76,    47,
      77,    74,    45,    46,   191,    82,    47,    75,    80,    48,
      49,   108,   192,   110,    94,    83,    48,    49,     8,     9,
      10,    54,    55,    56,    57,    58,    59,    84,    54,    55,
      56,    57,    58,    59,    95,    96,    97,    98,    99,   100,
     101,   102,   103,   104,   105,    94,   102,   103,   104,   105,
     109,    85,   133,    80,    70,    71,    86,   165,    87,   122,
      80,   -39,   -39,   123,   -39,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,   155,   -39,    91,    92,
     170,    93,   -39,   102,   103,   104,   105,   102,   103,   104,
     105,    93,     2,     3,   166,   -12,   -12,   -12,   167,   193,
     102,   103,   104,   105,   102,   103,   104,   105,    67,    68,
      69,   168,   118,   119,   120,   169,   102,   103,   104,   105,
     102,   103,   104,   105,   174,   175,   176,   187,     7,    31,
     171,   149,   150,   151,   152,   102,   103,   104,   105,   177,
     178,   184,   185,   186,    42,   107,     0,   179
};

static const yytype_int16 yycheck[] =
{
      53,    25,    51,    52,    36,    54,    62,    63,    37,    33,
      63,    61,    62,    63,    64,    61,    62,    63,    64,    72,
      65,    11,    72,    72,    14,    10,    72,    80,    68,    82,
      83,    84,    85,    86,    87,    91,    92,    93,    70,    72,
      73,    70,    95,    96,    97,    98,    99,   100,   101,   102,
     103,   104,   105,    10,    11,    12,    13,   110,    66,    16,
     113,    75,    51,    52,    16,    54,    18,    63,    64,    26,
      27,    28,    29,    34,    52,    32,    54,    10,    35,    10,
      94,    38,    39,    40,    41,    42,    43,     6,    10,    68,
      12,    13,    49,    50,    16,     7,    53,    49,    50,    10,
      61,    62,    63,    64,    26,    27,    28,    29,   122,   123,
      68,   125,     8,    70,    69,    68,    38,    39,    40,    41,
      42,    43,    11,    51,    52,   178,    54,    67,   184,   185,
     186,    51,    52,    10,    54,    12,    13,    69,    54,    16,
      10,    34,    12,    13,    72,    70,    16,    34,    70,    26,
      27,    20,    72,    30,    34,    70,    26,    27,     3,     4,
       5,    38,    39,    40,    41,    42,    43,    70,    38,    39,
      40,    41,    42,    43,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    34,    61,    62,    63,    64,
      18,    70,    72,    70,    44,    45,    70,    72,    70,    34,
      70,    51,    52,    34,    54,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    70,    67,    51,    52,
      18,    54,    72,    61,    62,    63,    64,    61,    62,    63,
      64,    54,     0,     1,    72,     3,     4,     5,    72,    72,
      61,    62,    63,    64,    61,    62,    63,    64,    18,    19,
      20,    72,    46,    47,    48,    72,    61,    62,    63,    64,
      61,    62,    63,    64,    68,    68,    68,    72,     3,    25,
      71,    21,    22,    23,    24,    61,    62,    63,    64,    72,
      71,    70,    70,    70,    33,    69,    -1,   173
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    75,     0,     1,    76,    80,    65,    76,     3,     4,
       5,    81,    10,    68,    82,    10,    83,    66,    10,     6,
      77,    68,     7,    78,    10,    84,    85,    68,     8,    79,
      69,    85,    11,    86,    87,    68,    67,    16,    18,    49,
      50,    69,    87,    10,    11,    12,    13,    16,    26,    27,
      28,    29,    32,    35,    38,    39,    40,    41,    42,    43,
      49,    50,    53,    70,    90,    97,    98,    18,    19,    20,
      44,    45,    25,    33,    34,    34,    54,    10,    28,    29,
      70,    97,    70,    70,    70,    70,    70,    70,    90,    90,
      97,    51,    52,    54,    34,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    88,    88,    20,    18,
      30,    97,    37,    70,    36,    70,    94,    94,    46,    47,
      48,    99,    34,    34,    97,    34,    97,    97,    97,    97,
      97,    97,    72,    72,    90,    90,    90,    94,    97,    97,
      97,    97,    97,    97,    97,    97,    97,    97,    97,    21,
      22,    23,    24,    89,    97,    70,    97,    11,    14,    95,
      96,    94,    94,    94,    72,    72,    72,    72,    72,    72,
      18,    71,    72,    73,    68,    68,    68,    72,    71,    96,
      92,    93,    91,    97,    70,    70,    70,    72,    90,    90,
      90,    72,    72,    72
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
#line 219 "grammar.y"
    { 
                if (reduce_rule_declaration(yyscanner, (yyvsp[(3) - (9)].c_string),(yyvsp[(1) - (9)].integer),(yyvsp[(4) - (9)].tag),(yyvsp[(6) - (9)].meta),(yyvsp[(7) - (9)].string),(yyvsp[(8) - (9)].term)) != ERROR_SUCCESS)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR; 
                }  
            }
    break;

  case 7:
#line 228 "grammar.y"
    { (yyval.meta) = NULL; }
    break;

  case 8:
#line 229 "grammar.y"
    { (yyval.meta) = (yyvsp[(3) - (3)].meta); }
    break;

  case 9:
#line 232 "grammar.y"
    { (yyval.string) = NULL; }
    break;

  case 10:
#line 233 "grammar.y"
    { (yyval.string) = (yyvsp[(3) - (3)].string); }
    break;

  case 11:
#line 236 "grammar.y"
    { (yyval.term) = (yyvsp[(3) - (3)].term); }
    break;

  case 12:
#line 239 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 13:
#line 240 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 14:
#line 243 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 15:
#line 244 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 16:
#line 247 "grammar.y"
    { (yyval.tag) = NULL; }
    break;

  case 17:
#line 248 "grammar.y"
    { (yyval.tag) = (yyvsp[(2) - (2)].tag);   }
    break;

  case 18:
#line 251 "grammar.y"
    { 
                                                (yyval.tag) = reduce_tags(yyscanner,NULL,(yyvsp[(1) - (1)].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }
    break;

  case 19:
#line 260 "grammar.y"
    {   
                                                (yyval.tag) = reduce_tags(yyscanner,(yyvsp[(1) - (2)].tag),(yyvsp[(2) - (2)].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }
    break;

  case 20:
#line 270 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_metas(yyscanner, NULL, (yyvsp[(1) - (1)].meta)); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
    break;

  case 21:
#line 279 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_metas(yyscanner, (yyvsp[(1) - (2)].meta), (yyvsp[(2) - (2)].meta)); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
    break;

  case 22:
#line 290 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_STRING, (yyvsp[(1) - (3)].c_string), 0, (yyvsp[(3) - (3)].sized_string));
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 23:
#line 299 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_INTEGER, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].integer), NULL); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 24:
#line 308 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, (yyvsp[(1) - (3)].c_string), TRUE, NULL); 

                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 25:
#line 317 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, (yyvsp[(1) - (3)].c_string), FALSE, NULL); 

                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 26:
#line 329 "grammar.y"
    { 
                            (yyval.string) = reduce_strings(yyscanner,NULL,(yyvsp[(1) - (1)].string)); 
                            
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 27:
#line 339 "grammar.y"
    { 
                            (yyval.string) = reduce_strings(yyscanner,(yyvsp[(1) - (2)].string),(yyvsp[(2) - (2)].string));
                        
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }  
                        }
    break;

  case 28:
#line 351 "grammar.y"
    { 
                            (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[(1) - (4)].term), (yyvsp[(3) - (4)].sized_string), (yyvsp[(4) - (4)].integer)); 
                
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 29:
#line 361 "grammar.y"
    { 
                           (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[(1) - (4)].term), (yyvsp[(3) - (4)].sized_string), (yyvsp[(4) - (4)].integer) | STRING_FLAGS_REGEXP); 

                           if ((yyval.string) == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                       }
    break;

  case 30:
#line 371 "grammar.y"
    {
                            (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].sized_string), STRING_FLAGS_HEXADECIMAL);
            
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 31:
#line 382 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 32:
#line 383 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 33:
#line 386 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 34:
#line 387 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 35:
#line 388 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 36:
#line 389 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 37:
#line 392 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 1); }
    break;

  case 38:
#line 393 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 0); }
    break;

  case 39:
#line 395 "grammar.y"
    { 
                        (yyval.term) = reduce_identifier(yyscanner, (yyvsp[(1) - (1)].c_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 40:
#line 405 "grammar.y"
    { 
                        (yyval.term) = reduce_external_string_operation(yyscanner, TERM_TYPE_EXTERNAL_STRING_MATCH, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].sized_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 41:
#line 415 "grammar.y"
    { 
                        (yyval.term) = reduce_external_string_operation(yyscanner, TERM_TYPE_EXTERNAL_STRING_CONTAINS, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].sized_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 42:
#line 425 "grammar.y"
    {  
                        (yyval.term) = reduce_string(yyscanner, (yyvsp[(1) - (1)].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 43:
#line 435 "grammar.y"
    {          
                        (yyval.term) = reduce_string_at(yyscanner, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 44:
#line 445 "grammar.y"
    { 
                        (yyval.term) = NULL; 
                     }
    break;

  case 45:
#line 449 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_range(yyscanner, (yyvsp[(1) - (8)].term), (yyvsp[(4) - (8)].term), (yyvsp[(7) - (8)].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 46:
#line 459 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_section_by_name(yyscanner, (yyvsp[(1) - (6)].term), (yyvsp[(5) - (6)].sized_string));

                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 47:
#line 469 "grammar.y"
    { 
                           yyget_extra(yyscanner)->inside_for++; 
                      }
    break;

  case 48:
#line 473 "grammar.y"
    { 
                           yyget_extra(yyscanner)->inside_for--; 
                           
                           (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, (yyvsp[(2) - (9)].term), (yyvsp[(4) - (9)].term), (yyvsp[(8) - (9)].term)); 
                           
                           if ((yyval.term) == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                      }
    break;

  case 49:
#line 485 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }
    break;

  case 50:
#line 489 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for--; 
                          
                          (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, count_strings((yyvsp[(4) - (9)].term))), (yyvsp[(4) - (9)].term), (yyvsp[(8) - (9)].term)); 
                          
                          if ((yyval.term) == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
    break;

  case 51:
#line 501 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }
    break;

  case 52:
#line 505 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for--; 
                                                    
                          (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, 1), (yyvsp[(4) - (9)].term), (yyvsp[(8) - (9)].term)); 
                          
                          if ((yyval.term) == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
    break;

  case 53:
#line 517 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 54:
#line 527 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, count_strings((yyvsp[(3) - (3)].term))), (yyvsp[(3) - (3)].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 55:
#line 537 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, 1), (yyvsp[(3) - (3)].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 56:
#line 546 "grammar.y"
    { (yyval.term) = NULL; }
    break;

  case 57:
#line 547 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 58:
#line 548 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT, (yyvsp[(2) - (2)].term), NULL, NULL); }
    break;

  case 59:
#line 549 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_AND, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 60:
#line 550 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OR, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 61:
#line 551 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 62:
#line 552 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 63:
#line 553 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 64:
#line 554 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LE, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 65:
#line 555 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GE, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 66:
#line 556 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 67:
#line 557 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 68:
#line 558 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 69:
#line 562 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 70:
#line 563 "grammar.y"
    { (yyval.term) = reduce_string_with_wildcard(yyscanner, yr_strdup("$*")); }
    break;

  case 72:
#line 568 "grammar.y"
    {
                         (yyval.term) = reduce_string_enumeration(yyscanner, (yyvsp[(1) - (3)].term),(yyvsp[(3) - (3)].term));
                      }
    break;

  case 73:
#line 574 "grammar.y"
    {  
                              (yyval.term) = reduce_string(yyscanner, (yyvsp[(1) - (1)].term));

                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 74:
#line 584 "grammar.y"
    { 
                              (yyval.term) = reduce_string_with_wildcard(yyscanner, (yyvsp[(1) - (1)].term)); 
                              
                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 75:
#line 596 "grammar.y"
    { (yyval.term) = reduce_filesize(yyscanner); }
    break;

  case 76:
#line 597 "grammar.y"
    { (yyval.term) = reduce_entrypoint(yyscanner); }
    break;

  case 77:
#line 598 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT8_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 78:
#line 599 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT16_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 79:
#line 600 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT32_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 80:
#line 601 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT8_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 81:
#line 602 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT16_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 82:
#line 603 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT32_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 83:
#line 605 "grammar.y"
    { 
                (yyval.term) = reduce_string_count(yyscanner, (yyvsp[(1) - (1)].term)); 
                
                if ((yyval.term) == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
    break;

  case 84:
#line 615 "grammar.y"
    { 
                (yyval.term) = reduce_string_offset(yyscanner, (yyvsp[(1) - (1)].term)); 

                if ((yyval.term) == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
    break;

  case 85:
#line 625 "grammar.y"
    {
                 (yyval.term) = reduce_identifier(yyscanner, (yyvsp[(1) - (1)].c_string));
                    
                 if ((yyval.term) == NULL)
                 {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                 }
             }
    break;

  case 86:
#line 634 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 87:
#line 635 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_ADD, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 88:
#line 636 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_SUB, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 89:
#line 637 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_MUL, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 90:
#line 638 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_DIV, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 92:
#line 642 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, (yyvsp[(1) - (1)].integer)); }
    break;


/* Line 1267 of yacc.c.  */
#line 2442 "grammar.c"
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


#line 650 "grammar.y"



int count_strings(TERM_STRING* st)
{
    int count = 0;
    
    while(st != NULL)
    {
        count++;
        st = st->next;
    }
    
    return count;
}

int reduce_rule_declaration(    yyscan_t yyscanner,
                                char* identifier, 
                                int flags, 
                                TAG* tag_list_head,
                                META* meta_list_head,
                                STRING* string_list_head, 
                                TERM* condition
                            )
{
    STRING*         string;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);

    context->last_result = new_rule(&context->rule_list, 
                                    identifier, 
                                    context->current_namespace, 
                                    flags, 
                                    tag_list_head, 
                                    meta_list_head, 
                                    string_list_head, 
                                    condition);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        string = string_list_head;
        
        while (string != NULL)
        {
            if (! (string->flags & STRING_FLAGS_REFERENCED))
            {
                context->last_result = ERROR_UNREFERENCED_STRING;
                strncpy(context->last_error_extra_info, string->identifier, sizeof(context->last_error_extra_info));
                break;
            }
            
            string = string->next;
        }
    }
    
    return context->last_result;
}

STRING* reduce_string_declaration(  yyscan_t yyscanner,
                                    char* identifier, 
                                    SIZED_STRING* str, 
                                    int flags)
{
    char            tmp[200];
    STRING*         string = NULL;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);
    
    if (strcmp(identifier,"$") == 0)
    {
        flags |= STRING_FLAGS_ANONYMOUS;
    }
    
    context->last_result = new_string(context, identifier, str, flags, &string);
    
    if (context->last_result == ERROR_INVALID_REGULAR_EXPRESSION) 
    {
        sprintf(tmp, "invalid regular expression in string \"%s\": %s", identifier, context->last_error_extra_info);
        strncpy(context->last_error_extra_info, tmp, sizeof(context->last_error_extra_info));
    }
    else if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(str);
            
    return string;
}

STRING* reduce_strings( yyscan_t yyscanner,
                        STRING* string_list_head, 
                        STRING* string)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    /* no strings with the same identifier, except for anonymous strings */
    
    if (IS_ANONYMOUS(string) || lookup_string(string_list_head,string->identifier) == NULL) 
    {
        string->next = string_list_head;    
        context->current_rule_strings = string;
        context->last_result = ERROR_SUCCESS;
        return string;
    }
    else
    {
        strncpy(context->last_error_extra_info, string->identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_STRING_IDENTIFIER;
        return NULL;
    }   
}

META* reduce_meta_declaration(  yyscan_t yyscanner,
                                int type,
                                char* identifier,
                                unsigned int integer_value,
								SIZED_STRING* string_value)
{
    META*           meta = NULL;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);
    
    meta = yr_malloc(sizeof(META));
    
    if (meta != NULL)
    {
        meta->identifier = identifier;
        meta->type = type;
        
        if (type == META_TYPE_INTEGER)
        {
            meta->integer = integer_value;
        }
        else if (type == META_TYPE_BOOLEAN)
        {
            meta->boolean = integer_value;
        }
        else
        {
            meta->string = yr_strdup(string_value->c_string);
            yr_free(string_value);
        }    
    }
    else
    {
        context->last_result = ERROR_INSUFICIENT_MEMORY;
    }
    
    return meta;  
}

META* reduce_metas( yyscan_t yyscanner,
                    META* meta_list_head, 
                    META* meta)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    /* no metas with the same identifier */

    if (lookup_meta(meta_list_head, meta->identifier) == NULL) 
    {
        meta->next = meta_list_head;    
        context->last_result = ERROR_SUCCESS;
        return meta;
    }
    else
    {
        strncpy(context->last_error_extra_info, meta->identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_META_IDENTIFIER;
        return NULL;
    }   
}

TAG* reduce_tags(   yyscan_t yyscanner, 
                    TAG* tag_list_head,
                    char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TAG* tag;

    if (lookup_tag(tag_list_head, identifier) == NULL) /* no tags with the same identifier */
    {
        tag = yr_malloc(sizeof(TAG));
        
        if (tag != NULL)
        {
            tag->identifier = identifier;
            tag->next = tag_list_head;  
            context->last_result = ERROR_SUCCESS;
        }
        else
        {
            context->last_result = ERROR_INSUFICIENT_MEMORY;
        }
        
        return tag;
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
        return NULL;
    }
}

TERM* reduce_filesize(yyscan_t yyscanner)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    context->last_result = new_simple_term(TERM_TYPE_FILESIZE, &term); 
    return (TERM*) term;    
}

TERM* reduce_entrypoint(yyscan_t yyscanner)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    context->last_result = new_simple_term(TERM_TYPE_ENTRYPOINT, &term); 
    return (TERM*) term;    
}

TERM* reduce_term(yyscan_t yyscanner, int type, TERM* op1, TERM* op2, TERM* op3)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    if (op2 == NULL && op3 == NULL)
    {
        context->last_result = new_unary_operation(type, op1, (TERM_UNARY_OPERATION**) &term);
    }
    else if (op3 == NULL)
    {
        context->last_result = new_binary_operation(type, op1, op2, (TERM_BINARY_OPERATION**) &term);
    }
    else
    {
        context->last_result = new_ternary_operation(type, op1, op2, op3, (TERM_TERNARY_OPERATION**) &term);
    }
    
    return (TERM*) term;
}

TERM* reduce_constant(  yyscan_t yyscanner,
                        unsigned int constant)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_CONST* term = NULL;
    
    context->last_result = new_constant(constant, &term); 
    return (TERM*) term;
}

TERM* reduce_string(    yyscan_t yyscanner,
                        char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || context->inside_for > 0) 
    {  
        context->last_result = new_string_identifier(TERM_TYPE_STRING, context->current_rule_strings, identifier, &term);       
     
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
    }
    else
    {
        context->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_with_wildcard(  yyscan_t yyscanner,
                                    char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    TERM_STRING* next;
    STRING* string;
    
    int len = 0;

    string = context->current_rule_strings;
    next = NULL;
    
    while (identifier[len] != '\0' && identifier[len] != '*')
    {
        len++;
    }
    
    while (string != NULL)
    {
        if (strncmp(string->identifier, identifier, len) == 0)
        {
            context->last_result = new_string_identifier(TERM_TYPE_STRING, context->current_rule_strings, string->identifier, &term);
            
            if (context->last_result != ERROR_SUCCESS)
                break;
                
            string->flags |= STRING_FLAGS_REFERENCED;
            
            term->string = string;
            term->next = next;
            next = term;            
        }
        
        string = string->next;
    }
    
    yr_free(identifier);
    return (TERM*) term;  
}

TERM* reduce_string_at( yyscan_t yyscanner, 
                        char* identifier, 
                        TERM* offset)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || context->inside_for > 0) 
    {  
        context->last_result = new_string_identifier(TERM_TYPE_STRING_AT, context->current_rule_strings, identifier, &term);       
     
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
        else
        {
            term->offset = offset;
        }  
    }
    else
    {
        context->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(   yyscan_t yyscanner,    
                                char* identifier, 
                                TERM* lower_offset, 
                                TERM* upper_offset)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        term->lower_offset = lower_offset;
        term->upper_offset = upper_offset;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, SIZED_STRING* section_name)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        term->section_name = yr_strdup(section_name->c_string);
    }
    
    yr_free(section_name);
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_count(  yyscan_t yyscanner,
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;

    context->last_result = new_string_identifier(TERM_TYPE_STRING_COUNT, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_string_offset( yyscan_t yyscanner,
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;

    context->last_result = new_string_identifier(TERM_TYPE_STRING_OFFSET, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_identifier(    yyscan_t yyscanner, 
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    RULE* rule;
      
    rule = lookup_rule(&context->rule_list, identifier, context->current_namespace);
        
    if (rule != NULL)
    {
        context->last_result = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, (TERM_BINARY_OPERATION**) &term);        
    }
    else
    {
        context->last_result = new_external_variable(context, identifier, (TERM_EXTERNAL_VARIABLE**) &term);
    }
    
    yr_free(identifier);
    return (TERM*) term;
}

TERM* reduce_string_enumeration(    yyscan_t yyscanner,
                                    TERM* string_list_head, 
                                    TERM* string_identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = (TERM_STRING*) string_identifier;
    
    term->next = (TERM_STRING*) string_list_head;
    term->string->flags |= STRING_FLAGS_REFERENCED;

    return string_identifier;
}

TERM* reduce_external_string_operation( yyscan_t yyscanner,
                                        int type,
                                        char* identifier,
                                        SIZED_STRING* string)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    const char *error;
    int erroffset;
    
    EXTERNAL_VARIABLE* ext_var;  
    TERM_EXTERNAL_STRING_OPERATION* term = NULL;
    
    ext_var = lookup_external_variable(context->external_variables, identifier);
    
    if (ext_var != NULL)
    {
        if (ext_var->type == EXTERNAL_VARIABLE_TYPE_STRING)
        {    
            term = (TERM_EXTERNAL_STRING_OPERATION*) yr_malloc(sizeof(TERM_EXTERNAL_STRING_OPERATION));
            
            if (term != NULL)
            {
                term->type = type;
                term->ext_var = ext_var;
                
                if (type == TERM_TYPE_EXTERNAL_STRING_MATCH)
                {
                    term->re.regexp = pcre_compile(string->c_string, 0, &error, &erroffset, NULL); 
                    
                    if (term->re.regexp != NULL)  
                    {
                        term->re.extra = pcre_study(term->re.regexp, 0, &error);
                        context->last_result = ERROR_SUCCESS;
                    }
                    else /* compilation failed */
                    {
                        yr_free(term);
                        term = NULL;
                        strncpy(context->last_error_extra_info, error, sizeof(context->last_error_extra_info));
                        context->last_result = ERROR_INVALID_REGULAR_EXPRESSION;
                    }
                }
                else
                {
					term->string = yr_strdup(string->c_string);
                }
                                
                yr_free(string);             
            }
            else
            {
                context->last_result = ERROR_INSUFICIENT_MEMORY;
            }
         }
         else
         {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
            context->last_result = ERROR_INCORRECT_EXTERNAL_VARIABLE_TYPE;
         }
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_UNDEFINED_IDENTIFIER;
    }
    
    return (TERM*) term;

}

  







    
    
    
