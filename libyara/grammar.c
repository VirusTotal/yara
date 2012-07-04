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
#line 34 "grammar.y"
 
    
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ast.h"
#include "sizedstr.h"
#include "mem.h"
#include "lex.h"
#include "regex.h"

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
#line 148 "grammar.y"
{
    
    void*           sized_string;
    char*           c_string;
    size_t          integer;
    void*           string;
    void*           term;
    void*           tag;
    void*           meta;

}
/* Line 193 of yacc.c.  */
#line 251 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */
#line 163 "grammar.y"
 

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
                                TERM* range);
                                
TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, 
                                        SIZED_STRING* section_name);
                                        
TERM* reduce_string_count(  yyscan_t yyscanner, 
                            char* identifier);
                            
TERM* reduce_string_offset( yyscan_t yyscanner,  
                            char* identifier,
                            TERM* index); 

TERM* reduce_filesize(yyscan_t yyscanner);

TERM* reduce_entrypoint(yyscan_t yyscanner);

TERM* reduce_term(  yyscan_t yyscanner, 
                    int type, 
                    TERM* op1, 
                    TERM* op2, 
                    TERM* op3);
                    
TERM* reduce_constant(  yyscan_t yyscanner,
                        size_t constant);

TERM* reduce_identifier( yyscan_t yyscanner,
                         char* identifier);
                         
TERM* reduce_string_operation(  yyscan_t yyscanner,
                                int type,
                                char* identifier,
                                SIZED_STRING* string);
                                        
TERM* reduce_integer_enumeration(   yyscan_t yyscanner,
                                    TERM* vector,     
                                    TERM* expression);
                                    
TERM* reduce_integer_for(   yyscan_t yyscanner,
                            TERM* count,
                            char* identifier,
                            TERM* items,
                            TERM* expression);
                            
TERM* reduce_range( yyscan_t yyscanner,
                    TERM* min,
                    TERM* max);




/* Line 216 of yacc.c.  */
#line 366 "grammar.c"

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
#define YYLAST   500

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  84
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  29
/* YYNRULES -- Number of rules.  */
#define YYNRULES  105
/* YYNRULES -- Number of states.  */
#define YYNSTATES  207

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
       2,     2,     2,     2,     2,     2,     2,    82,    54,     2,
      76,    77,    67,    65,    78,    66,    79,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    74,     2,
       2,    75,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    80,    68,    81,    83,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    71,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    72,    55,    73,    70,     2,     2,     2,
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
      45,    46,    47,    48,    49,    50,    51,    52,    53,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    69
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
     114,   118,   122,   124,   128,   133,   137,   144,   145,   156,
     157,   167,   171,   175,   179,   182,   186,   190,   194,   198,
     202,   206,   210,   214,   218,   222,   224,   226,   230,   234,
     236,   238,   242,   244,   246,   253,   255,   257,   259,   261,
     263,   268,   273,   278,   283,   288,   293,   295,   300,   302,
     306,   310,   314,   318,   322,   326,   330,   334,   338,   341,
     345,   349,   351,   353,   355,   357
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      85,     0,    -1,    -1,    85,    86,    -1,    85,     1,    86,
      -1,    85,     1,    71,    -1,    90,     3,    10,    92,    72,
      87,    88,    89,    73,    -1,    -1,     6,    74,    94,    -1,
      -1,     7,    74,    96,    -1,     8,    74,   100,    -1,    -1,
      90,    91,    -1,     4,    -1,     5,    -1,    -1,    74,    93,
      -1,    10,    -1,    93,    10,    -1,    95,    -1,    94,    95,
      -1,    10,    75,    18,    -1,    10,    75,    16,    -1,    10,
      75,    50,    -1,    10,    75,    51,    -1,    97,    -1,    96,
      97,    -1,    11,    75,    18,    98,    -1,    11,    75,    20,
      98,    -1,    11,    75,    19,    -1,    -1,    98,    99,    -1,
      22,    -1,    21,    -1,    23,    -1,    24,    -1,    50,    -1,
      51,    -1,    10,    -1,    10,    44,    20,    -1,    10,    45,
      18,    -1,    11,    -1,    11,    25,   110,    -1,    11,    25,
      30,   110,    -1,    11,    33,   108,    -1,    11,    33,    37,
      76,    18,    77,    -1,    -1,    35,   109,    10,    33,   103,
      74,   101,    76,   100,    77,    -1,    -1,    35,   109,    34,
     105,    74,   102,    76,   100,    77,    -1,   109,    34,   105,
      -1,    32,    56,   112,    -1,    76,   100,    77,    -1,    69,
     100,    -1,   100,    53,   100,    -1,   100,    52,   100,    -1,
     110,    62,   110,    -1,   110,    60,   110,    -1,   110,    61,
     110,    -1,   110,    59,   110,    -1,   110,    58,   110,    -1,
     110,    56,   110,    -1,   110,    57,   110,    -1,    76,   104,
      77,    -1,   108,    -1,   110,    -1,   104,    78,   110,    -1,
      76,   106,    77,    -1,    36,    -1,   107,    -1,   106,    78,
     107,    -1,    11,    -1,    14,    -1,    76,   110,    79,    79,
     110,    77,    -1,   110,    -1,    28,    -1,    29,    -1,    26,
      -1,    27,    -1,    38,    76,   110,    77,    -1,    39,    76,
     110,    77,    -1,    40,    76,   110,    77,    -1,    41,    76,
     110,    77,    -1,    42,    76,   110,    77,    -1,    43,    76,
     110,    77,    -1,    12,    -1,    13,    80,   110,    81,    -1,
      10,    -1,    76,   110,    77,    -1,   110,    65,   110,    -1,
     110,    66,   110,    -1,   110,    67,   110,    -1,   110,    68,
     110,    -1,   110,    82,   110,    -1,   110,    83,   110,    -1,
     110,    54,   110,    -1,   110,    55,   110,    -1,    70,   110,
      -1,   110,    64,   110,    -1,   110,    63,   110,    -1,   111,
      -1,    16,    -1,    47,    -1,    48,    -1,    49,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   268,   268,   269,   270,   271,   274,   284,   285,   288,
     289,   292,   295,   296,   299,   300,   303,   304,   307,   316,
     326,   335,   346,   355,   364,   373,   384,   394,   406,   416,
     426,   438,   439,   442,   443,   444,   445,   448,   449,   450,
     460,   470,   480,   490,   500,   504,   514,   525,   524,   539,
     538,   554,   564,   565,   566,   567,   568,   570,   571,   572,
     573,   574,   575,   576,   581,   582,   585,   586,   591,   592,
     595,   596,   599,   609,   623,   627,   628,   629,   633,   634,
     635,   636,   637,   638,   639,   640,   641,   651,   661,   671,
     672,   673,   674,   675,   676,   677,   678,   679,   680,   681,
     682,   683,   686,   689,   690,   691
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
  "_IS_", "_NEQ_", "_EQ_", "_GE_", "_GT_", "_LE_", "_LT_", "_SHIFT_RIGHT_",
  "_SHIFT_LEFT_", "'+'", "'-'", "'*'", "'\\\\'", "_NOT_", "'~'",
  "'include'", "'{'", "'}'", "':'", "'='", "'('", "')'", "','", "'.'",
  "'['", "']'", "'%'", "'^'", "$accept", "rules", "rule", "meta",
  "strings", "condition", "rule_modifiers", "rule_modifier", "tags",
  "tag_list", "meta_declarations", "meta_declaration",
  "string_declarations", "string_declaration", "string_modifiers",
  "string_modifier", "boolean_expression", "@1", "@2", "integer_set",
  "integer_enumeration", "string_set", "string_enumeration",
  "string_enumeration_item", "range", "for_expression", "expression",
  "number", "type", 0
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
     305,   306,   307,   308,    38,   124,   309,   310,   311,   312,
     313,   314,   315,   316,   317,    43,    45,    42,    92,   318,
     126,   105,   123,   125,    58,    61,    40,    41,    44,    46,
      91,    93,    37,    94
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    84,    85,    85,    85,    85,    86,    87,    87,    88,
      88,    89,    90,    90,    91,    91,    92,    92,    93,    93,
      94,    94,    95,    95,    95,    95,    96,    96,    97,    97,
      97,    98,    98,    99,    99,    99,    99,   100,   100,   100,
     100,   100,   100,   100,   100,   100,   100,   101,   100,   102,
     100,   100,   100,   100,   100,   100,   100,   100,   100,   100,
     100,   100,   100,   100,   103,   103,   104,   104,   105,   105,
     106,   106,   107,   107,   108,   109,   109,   109,   110,   110,
     110,   110,   110,   110,   110,   110,   110,   110,   110,   110,
     110,   110,   110,   110,   110,   110,   110,   110,   110,   110,
     110,   110,   111,   112,   112,   112
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     3,     3,     9,     0,     3,     0,
       3,     3,     0,     2,     1,     1,     0,     2,     1,     2,
       1,     2,     3,     3,     3,     3,     1,     2,     4,     4,
       3,     0,     2,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     1,     3,     4,     3,     6,     0,    10,     0,
       9,     3,     3,     3,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     1,     3,     3,     1,
       1,     3,     1,     1,     6,     1,     1,     1,     1,     1,
       4,     4,     4,     4,     4,     4,     1,     4,     1,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     3,
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
      25,     0,    27,    88,    42,    86,     0,   102,    78,    79,
      76,    77,     0,     0,     0,     0,     0,     0,     0,     0,
      37,    38,     0,     0,     0,    11,     0,    75,   101,    31,
      30,    31,     0,     0,     0,     0,     0,     0,    88,     0,
       0,    75,     0,     0,     0,     0,     0,     0,    54,    98,
       0,    75,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    28,    29,    40,    41,     0,    43,     0,     0,
      45,     0,   103,   104,   105,    52,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    53,    89,    56,    55,    69,
       0,    51,    96,    97,    62,    63,    61,    60,    58,    59,
      57,   100,    99,    90,    91,    92,    93,    94,    95,    34,
      33,    35,    36,    32,    44,     0,     0,    87,     0,     0,
      80,    81,    82,    83,    84,    85,    72,    73,     0,    70,
       0,     0,     0,     0,    65,    49,    68,     0,    46,     0,
       0,    66,    47,     0,    71,     0,    64,     0,     0,     0,
      74,    67,     0,     0,     0,    50,    48
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     4,    20,    23,    29,     5,    11,    14,    16,
      25,    26,    33,    34,   112,   163,    65,   198,   193,   183,
     190,   141,   178,   179,   120,    66,    67,    68,   125
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -66
static const yytype_int16 yypact[] =
{
     -66,   112,   -66,   -65,   -66,   104,   -66,   -66,    -2,   -66,
     -66,   -66,   -62,    10,   -54,   -66,    14,    79,   -66,    12,
     107,   110,    48,   120,    66,   110,   -66,   132,    81,    83,
      21,   -66,    82,   132,   -66,    49,   -66,   -66,   -66,   -66,
     -66,   113,   -66,    53,   -16,   -66,    78,   -66,   -66,   -66,
     -66,   -66,   103,   111,    85,    88,    89,    92,    95,    96,
     -66,   -66,    49,   157,    49,    17,   140,   180,   -66,   -66,
     -66,   -66,   155,   160,   150,   -12,   157,    99,   -66,   157,
      -6,   411,   157,   157,   157,   157,   157,   157,   -66,    -9,
     -50,   147,    49,    49,   -35,   157,   157,   157,   157,   157,
     157,   157,   157,   157,   157,   157,   157,   157,   157,   157,
     157,   157,    80,    80,   -66,   -66,   157,   411,   106,   157,
     -66,   201,   -66,   -66,   -66,   -66,   222,   146,   -35,   243,
     264,   285,   306,   327,   348,   -66,   -66,   133,   -66,   -66,
       8,   -66,   417,   417,   411,   411,   411,   411,   411,   411,
     411,    28,    28,     0,     0,    -9,    -9,   411,   411,   -66,
     -66,   -66,   -66,   -66,   411,   167,   369,   -66,   118,   142,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,     2,   -66,
     141,   138,   157,   145,   -66,   -66,   -66,     8,   -66,   157,
      57,   369,   -66,   149,   -66,   390,   -66,   157,   152,    49,
     -66,   411,    49,   -39,   -37,   -66,   -66
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -66,   -66,   218,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   197,   -66,   190,   161,   -66,   -57,   -66,   -66,   -66,
     -66,   121,   -66,    44,    84,   198,   -53,   -66,   -66
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -40
static const yytype_int16 yytable[] =
{
      81,   139,    92,    93,   127,    88,     6,    90,    12,    74,
      89,    91,    13,    92,    93,    92,    93,    75,    17,   176,
      15,   117,   177,   121,    18,   118,   126,   135,   128,   129,
     130,   131,   132,   133,   134,   137,   138,    37,   205,    38,
     206,   140,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   154,   155,   156,   157,   158,    43,
      44,    45,    46,   164,   119,    47,   166,   108,   109,    92,
      93,    39,    40,   110,   111,    48,    49,    50,    51,   186,
     187,    52,   110,   111,    53,    19,    21,    54,    55,    56,
      57,    58,    59,   106,   107,   108,   109,    72,    73,    60,
      61,   159,   160,   161,   162,   -39,   -39,     8,     9,    10,
     110,   111,     2,     3,    22,   -12,   -12,   -12,    62,    63,
      24,    78,    27,    45,    46,    64,   -39,    47,    28,   191,
     -39,    69,    70,    71,   196,   197,   195,    48,    49,    50,
      51,    30,   203,    32,   201,   204,   122,   123,   124,    54,
      55,    56,    57,    58,    59,    35,    36,    41,    76,    77,
      78,    82,    45,    46,    83,    84,    47,    78,    85,    45,
      46,    86,    87,    47,    94,   114,    48,    49,   115,   168,
     116,    63,   165,    48,    49,   180,    93,    79,    54,    55,
      56,    57,    58,    59,   182,    54,    55,    56,    57,    58,
      59,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,   185,   189,   188,   192,
      63,     7,    31,    42,   136,   199,    79,    63,   202,   110,
     111,   194,   113,    79,    95,    96,    97,    98,    99,   100,
     101,   102,   103,   104,   105,   106,   107,   108,   109,   169,
       0,    80,   184,     0,     0,    95,    96,     0,     0,     0,
       0,     0,   110,   111,   104,   105,   106,   107,   108,   109,
       0,     0,     0,     0,     0,     0,    95,    96,     0,     0,
       0,     0,   167,   110,   111,   104,   105,   106,   107,   108,
     109,     0,     0,     0,     0,     0,     0,    95,    96,   136,
       0,     0,     0,     0,   110,   111,   104,   105,   106,   107,
     108,   109,     0,     0,     0,     0,     0,     0,    95,    96,
     170,     0,     0,     0,     0,   110,   111,   104,   105,   106,
     107,   108,   109,     0,     0,     0,     0,     0,     0,    95,
      96,   171,     0,     0,     0,     0,   110,   111,   104,   105,
     106,   107,   108,   109,     0,     0,     0,     0,     0,     0,
      95,    96,   172,     0,     0,     0,     0,   110,   111,   104,
     105,   106,   107,   108,   109,     0,     0,     0,     0,     0,
       0,    95,    96,   173,     0,     0,     0,     0,   110,   111,
     104,   105,   106,   107,   108,   109,     0,     0,     0,     0,
       0,     0,    95,    96,   174,     0,     0,     0,     0,   110,
     111,   104,   105,   106,   107,   108,   109,     0,     0,     0,
       0,     0,     0,    95,    96,   175,     0,     0,     0,     0,
     110,   111,   104,   105,   106,   107,   108,   109,     0,     0,
       0,     0,     0,     0,    95,    96,     0,     0,   181,     0,
       0,   110,   111,   104,   105,   106,   107,   108,   109,     0,
       0,     0,     0,     0,     0,    95,    96,   200,     0,     0,
       0,     0,   110,   111,   104,   105,   106,   107,   108,   109,
     104,   105,   106,   107,   108,   109,     0,     0,     0,     0,
       0,     0,     0,   110,   111,     0,     0,     0,     0,   110,
     111
};

static const yytype_int16 yycheck[] =
{
      53,    36,    52,    53,    10,    62,    71,    64,    10,    25,
      63,    64,    74,    52,    53,    52,    53,    33,    72,    11,
      10,    74,    14,    76,    10,    37,    79,    77,    34,    82,
      83,    84,    85,    86,    87,    92,    93,    16,    77,    18,
      77,    76,    95,    96,    97,    98,    99,   100,   101,   102,
     103,   104,   105,   106,   107,   108,   109,   110,   111,    10,
      11,    12,    13,   116,    76,    16,   119,    67,    68,    52,
      53,    50,    51,    82,    83,    26,    27,    28,    29,    77,
      78,    32,    82,    83,    35,     6,    74,    38,    39,    40,
      41,    42,    43,    65,    66,    67,    68,    44,    45,    50,
      51,    21,    22,    23,    24,    52,    53,     3,     4,     5,
      82,    83,     0,     1,     7,     3,     4,     5,    69,    70,
      10,    10,    74,    12,    13,    76,    73,    16,     8,   182,
      77,    18,    19,    20,    77,    78,   189,    26,    27,    28,
      29,    75,   199,    11,   197,   202,    47,    48,    49,    38,
      39,    40,    41,    42,    43,    74,    73,    75,    80,    56,
      10,    76,    12,    13,    76,    76,    16,    10,    76,    12,
      13,    76,    76,    16,    34,    20,    26,    27,    18,    33,
      30,    70,    76,    26,    27,    18,    53,    76,    38,    39,
      40,    41,    42,    43,    76,    38,    39,    40,    41,    42,
      43,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    74,    79,    77,    74,
      70,     3,    25,    33,    77,    76,    76,    70,    76,    82,
      83,   187,    71,    76,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,   128,
      -1,    53,   168,    -1,    -1,    54,    55,    -1,    -1,    -1,
      -1,    -1,    82,    83,    63,    64,    65,    66,    67,    68,
      -1,    -1,    -1,    -1,    -1,    -1,    54,    55,    -1,    -1,
      -1,    -1,    81,    82,    83,    63,    64,    65,    66,    67,
      68,    -1,    -1,    -1,    -1,    -1,    -1,    54,    55,    77,
      -1,    -1,    -1,    -1,    82,    83,    63,    64,    65,    66,
      67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    54,    55,
      77,    -1,    -1,    -1,    -1,    82,    83,    63,    64,    65,
      66,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    54,
      55,    77,    -1,    -1,    -1,    -1,    82,    83,    63,    64,
      65,    66,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,
      54,    55,    77,    -1,    -1,    -1,    -1,    82,    83,    63,
      64,    65,    66,    67,    68,    -1,    -1,    -1,    -1,    -1,
      -1,    54,    55,    77,    -1,    -1,    -1,    -1,    82,    83,
      63,    64,    65,    66,    67,    68,    -1,    -1,    -1,    -1,
      -1,    -1,    54,    55,    77,    -1,    -1,    -1,    -1,    82,
      83,    63,    64,    65,    66,    67,    68,    -1,    -1,    -1,
      -1,    -1,    -1,    54,    55,    77,    -1,    -1,    -1,    -1,
      82,    83,    63,    64,    65,    66,    67,    68,    -1,    -1,
      -1,    -1,    -1,    -1,    54,    55,    -1,    -1,    79,    -1,
      -1,    82,    83,    63,    64,    65,    66,    67,    68,    -1,
      -1,    -1,    -1,    -1,    -1,    54,    55,    77,    -1,    -1,
      -1,    -1,    82,    83,    63,    64,    65,    66,    67,    68,
      63,    64,    65,    66,    67,    68,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    82,    83,    -1,    -1,    -1,    -1,    82,
      83
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    85,     0,     1,    86,    90,    71,    86,     3,     4,
       5,    91,    10,    74,    92,    10,    93,    72,    10,     6,
      87,    74,     7,    88,    10,    94,    95,    74,     8,    89,
      75,    95,    11,    96,    97,    74,    73,    16,    18,    50,
      51,    75,    97,    10,    11,    12,    13,    16,    26,    27,
      28,    29,    32,    35,    38,    39,    40,    41,    42,    43,
      50,    51,    69,    70,    76,   100,   109,   110,   111,    18,
      19,    20,    44,    45,    25,    33,    80,    56,    10,    76,
     109,   110,    76,    76,    76,    76,    76,    76,   100,   110,
     100,   110,    52,    53,    34,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      82,    83,    98,    98,    20,    18,    30,   110,    37,    76,
     108,   110,    47,    48,    49,   112,   110,    10,    34,   110,
     110,   110,   110,   110,   110,    77,    77,   100,   100,    36,
      76,   105,   110,   110,   110,   110,   110,   110,   110,   110,
     110,   110,   110,   110,   110,   110,   110,   110,   110,    21,
      22,    23,    24,    99,   110,    76,   110,    81,    33,   105,
      77,    77,    77,    77,    77,    77,    11,    14,   106,   107,
      18,    79,    76,   103,   108,    74,    77,    78,    77,    79,
     104,   110,    74,   102,   107,   110,    77,    78,   101,    76,
      77,   110,    76,   100,   100,    77,    77
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
#line 275 "grammar.y"
    { 
                if (reduce_rule_declaration(yyscanner, (yyvsp[(3) - (9)].c_string),(yyvsp[(1) - (9)].integer),(yyvsp[(4) - (9)].tag),(yyvsp[(6) - (9)].meta),(yyvsp[(7) - (9)].string),(yyvsp[(8) - (9)].term)) != ERROR_SUCCESS)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR; 
                }  
            }
    break;

  case 7:
#line 284 "grammar.y"
    { (yyval.meta) = NULL; }
    break;

  case 8:
#line 285 "grammar.y"
    { (yyval.meta) = (yyvsp[(3) - (3)].meta); }
    break;

  case 9:
#line 288 "grammar.y"
    { (yyval.string) = NULL; }
    break;

  case 10:
#line 289 "grammar.y"
    { (yyval.string) = (yyvsp[(3) - (3)].string); }
    break;

  case 11:
#line 292 "grammar.y"
    { (yyval.term) = (yyvsp[(3) - (3)].term); }
    break;

  case 12:
#line 295 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 13:
#line 296 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 14:
#line 299 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 15:
#line 300 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 16:
#line 303 "grammar.y"
    { (yyval.tag) = NULL; }
    break;

  case 17:
#line 304 "grammar.y"
    { (yyval.tag) = (yyvsp[(2) - (2)].tag);   }
    break;

  case 18:
#line 307 "grammar.y"
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
#line 316 "grammar.y"
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
#line 326 "grammar.y"
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
#line 335 "grammar.y"
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
#line 346 "grammar.y"
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
#line 355 "grammar.y"
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
#line 364 "grammar.y"
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
#line 373 "grammar.y"
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
#line 385 "grammar.y"
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
#line 395 "grammar.y"
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
#line 407 "grammar.y"
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
#line 417 "grammar.y"
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
#line 427 "grammar.y"
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
#line 438 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 32:
#line 439 "grammar.y"
    { (yyval.integer) = (yyvsp[(1) - (2)].integer) | (yyvsp[(2) - (2)].integer); }
    break;

  case 33:
#line 442 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 34:
#line 443 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 35:
#line 444 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 36:
#line 445 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 37:
#line 448 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 1); }
    break;

  case 38:
#line 449 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 0); }
    break;

  case 39:
#line 451 "grammar.y"
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
#line 461 "grammar.y"
    { 
                        (yyval.term) = reduce_string_operation(yyscanner, TERM_TYPE_STRING_MATCH, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].sized_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 41:
#line 471 "grammar.y"
    { 
                        (yyval.term) = reduce_string_operation(yyscanner, TERM_TYPE_STRING_CONTAINS, (yyvsp[(1) - (3)].c_string), (yyvsp[(3) - (3)].sized_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 42:
#line 481 "grammar.y"
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
#line 491 "grammar.y"
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
#line 501 "grammar.y"
    { 
                        (yyval.term) = NULL; 
                     }
    break;

  case 45:
#line 505 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_range(yyscanner, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 46:
#line 515 "grammar.y"
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
#line 525 "grammar.y"
    {
                          yr_define_integer_variable(yyget_extra(yyscanner), (yyvsp[(3) - (6)].c_string), 0);
                     }
    break;

  case 48:
#line 529 "grammar.y"
    {                        
                         (yyval.term) = reduce_integer_for(yyscanner, (yyvsp[(2) - (10)].term), (yyvsp[(3) - (10)].c_string), (yyvsp[(5) - (10)].term), (yyvsp[(9) - (10)].term)); 
                           
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 49:
#line 539 "grammar.y"
    { 
                         yyget_extra(yyscanner)->inside_for++; 
                     }
    break;

  case 50:
#line 543 "grammar.y"
    { 
                         yyget_extra(yyscanner)->inside_for--; 
                           
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_STRING_FOR, (yyvsp[(2) - (9)].term), (yyvsp[(4) - (9)].term), (yyvsp[(8) - (9)].term)); 
                           
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 51:
#line 555 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 52:
#line 564 "grammar.y"
    { (yyval.term) = NULL; }
    break;

  case 53:
#line 565 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 54:
#line 566 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT, (yyvsp[(2) - (2)].term), NULL, NULL); }
    break;

  case 55:
#line 567 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_AND, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 56:
#line 568 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OR, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 57:
#line 570 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 58:
#line 571 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 59:
#line 572 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LE, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 60:
#line 573 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GE, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 61:
#line 574 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 62:
#line 575 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 63:
#line 576 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT_EQ, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 64:
#line 581 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 65:
#line 582 "grammar.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 67:
#line 586 "grammar.y"
    { (yyval.term) = reduce_integer_enumeration(yyscanner, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term)); }
    break;

  case 68:
#line 591 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 69:
#line 592 "grammar.y"
    { (yyval.term) = reduce_string_with_wildcard(yyscanner, yr_strdup("$*")); }
    break;

  case 71:
#line 596 "grammar.y"
    { (yyval.term) = reduce_string_enumeration(yyscanner, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term)); }
    break;

  case 72:
#line 600 "grammar.y"
    {  
                              (yyval.term) = reduce_string(yyscanner, (yyvsp[(1) - (1)].term));

                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 73:
#line 610 "grammar.y"
    { 
                              (yyval.term) = reduce_string_with_wildcard(yyscanner, (yyvsp[(1) - (1)].term)); 
                              
                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 74:
#line 623 "grammar.y"
    { (yyval.term) = reduce_range(yyscanner, (yyvsp[(2) - (6)].term), (yyvsp[(5) - (6)].term)); }
    break;

  case 76:
#line 628 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 0); }
    break;

  case 77:
#line 629 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 1); }
    break;

  case 78:
#line 633 "grammar.y"
    { (yyval.term) = reduce_filesize(yyscanner); }
    break;

  case 79:
#line 634 "grammar.y"
    { (yyval.term) = reduce_entrypoint(yyscanner); }
    break;

  case 80:
#line 635 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT8_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 81:
#line 636 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT16_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 82:
#line 637 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT32_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 83:
#line 638 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT8_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 84:
#line 639 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT16_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 85:
#line 640 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT32_AT_OFFSET, (yyvsp[(3) - (4)].term), NULL, NULL); }
    break;

  case 86:
#line 642 "grammar.y"
    { 
                (yyval.term) = reduce_string_count(yyscanner, (yyvsp[(1) - (1)].term)); 
                
                if ((yyval.term) == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
    break;

  case 87:
#line 652 "grammar.y"
    { 
                (yyval.term) = reduce_string_offset(yyscanner, (yyvsp[(1) - (4)].term), (yyvsp[(3) - (4)].term)); 

                if ((yyval.term) == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
    break;

  case 88:
#line 662 "grammar.y"
    {
                 (yyval.term) = reduce_identifier(yyscanner, (yyvsp[(1) - (1)].c_string));
                    
                 if ((yyval.term) == NULL)
                 {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                 }
             }
    break;

  case 89:
#line 671 "grammar.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 90:
#line 672 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_ADD, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 91:
#line 673 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_SUB, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 92:
#line 674 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_MUL, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 93:
#line 675 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_DIV, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 94:
#line 676 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_MOD, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 95:
#line 677 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_BITWISE_XOR, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 96:
#line 678 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_BITWISE_AND, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 97:
#line 679 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_BITWISE_OR, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 98:
#line 680 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_BITWISE_NOT, (yyvsp[(2) - (2)].term), NULL, NULL); }
    break;

  case 99:
#line 681 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_SHIFT_LEFT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 100:
#line 682 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_SHIFT_RIGHT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), NULL); }
    break;

  case 102:
#line 686 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, (yyvsp[(1) - (1)].integer)); }
    break;


/* Line 1267 of yacc.c.  */
#line 2526 "grammar.c"
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


#line 694 "grammar.y"



int valid_string_identifier(char* identifier, YARA_CONTEXT* context)
{
    if (strcmp(identifier, "$") != 0 || context->inside_for > 0) 
    {
        return TRUE;
    }
    else
    {
        context->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
        return FALSE;
    }
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
                                    flags | context->current_rule_flags, 
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
    
    context->current_rule_flags = 0;  
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

    if (context->fast_match)
    {
        string->flags |= STRING_FLAGS_FAST_MATCH;
    }
            
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
    context->current_rule_flags |= RULE_FLAGS_REQUIRE_FILE;
    return (TERM*) term;    
}

TERM* reduce_entrypoint(yyscan_t yyscanner)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    context->last_result = new_simple_term(TERM_TYPE_ENTRYPOINT, &term);
    context->current_rule_flags |= RULE_FLAGS_REQUIRE_EXECUTABLE;
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
                        size_t constant)
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
    
    if (valid_string_identifier(identifier, context)) 
    {  
        context->last_result = new_string_identifier(TERM_TYPE_STRING, context->current_rule_strings, identifier, &term);       
     
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
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
    
    if (valid_string_identifier(identifier, context))  
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
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(   yyscan_t yyscanner,    
                                char* identifier, 
                                TERM* range)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (valid_string_identifier(identifier, context)) 
    {
        context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, context->current_rule_strings, identifier, &term);
    
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
        else
        {
            term->range = range;
        }
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, SIZED_STRING* section_name)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (valid_string_identifier(identifier, context))
    {
        context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, context->current_rule_strings, identifier, &term);
    
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
        else
        {
            term->section_name = yr_strdup(section_name->c_string);
        }
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
    
    if (valid_string_identifier(identifier, context))
    {
        context->last_result = new_string_identifier(TERM_TYPE_STRING_COUNT, context->current_rule_strings, identifier, &term);
            
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_string_offset( yyscan_t yyscanner,
                            char* identifier,
                            TERM* index)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;

    if (valid_string_identifier(identifier, context))
    {
        context->last_result = new_string_identifier(TERM_TYPE_STRING_OFFSET, context->current_rule_strings, identifier, &term);
    
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
        else
        {
            term->index = index;
        }
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
        context->last_result = new_variable(context, identifier, (TERM_VARIABLE**) &term);
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

TERM* reduce_string_operation( yyscan_t yyscanner,
                                        int type,
                                        char* identifier,
                                        SIZED_STRING* string)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
   
    int erroffset;
    
    VARIABLE* variable;  
    TERM_STRING_OPERATION* term = NULL;
    
    variable = lookup_variable(context->variables, identifier);
    
    if ( variable != NULL)
    {
        if (variable->type == VARIABLE_TYPE_STRING)
        {    
            term = (TERM_STRING_OPERATION*) yr_malloc(sizeof(TERM_STRING_OPERATION));
            
            if (term != NULL)
            {
                term->type = type;
                term->variable = variable;
                
                if (type == TERM_TYPE_STRING_MATCH)
                {
                    if (regex_compile(&(term->re),
                                      string->c_string,
                                      FALSE,
                                      context->last_error_extra_info,
                                      sizeof(context->last_error_extra_info),
                                      &erroffset) <= 0)
                    {
                        yr_free(term);
                        term = NULL;
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
            context->last_result = ERROR_INCORRECT_VARIABLE_TYPE;
         }
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_UNDEFINED_IDENTIFIER;
    }
    
    yr_free(identifier);
    return (TERM*) term;

}

TERM* reduce_integer_enumeration(   yyscan_t yyscanner,
                                    TERM* term1,     
                                    TERM* term2)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_VECTOR* vector;
    
    if (term1->type == TERM_TYPE_VECTOR)
    {
        context->last_result = add_term_to_vector((TERM_VECTOR*) term1, term2);
        
        return term1;
    }
    else
    {
        context->last_result = new_vector(&vector);
        
        if (context->last_result == ERROR_SUCCESS)
            context->last_result = add_term_to_vector(vector, term1);
            
        if (context->last_result == ERROR_SUCCESS)
            context->last_result = add_term_to_vector(vector, term2);
            
        return (TERM*) vector;
    }
}

TERM* reduce_integer_for(   yyscan_t yyscanner,
                            TERM* count,
                            char* identifier,
                            TERM* items,
                            TERM* expression)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_INTEGER_FOR* term = NULL;
    VARIABLE* variable;  
    
    variable = lookup_variable(context->variables, identifier);
    
    term = (TERM_INTEGER_FOR*) yr_malloc(sizeof(TERM_INTEGER_FOR));
    
    if (term != NULL)
    {
        term->type = TERM_TYPE_INTEGER_FOR;
        term->count = count;
        term->items = (TERM_ITERABLE*) items;
        term->expression = expression;
        term->variable = variable;
    }
    else
    {
        context->last_result = ERROR_INSUFICIENT_MEMORY;
    }
    
    yr_free(identifier);           
    return (TERM*) term;    
}


TERM* reduce_range( yyscan_t yyscanner,
                    TERM* min,
                    TERM* max)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_RANGE* term = NULL;
    
    context->last_result = new_range(min, max, &term);
             
    return (TERM*) term;    
}

  







    
    
    

