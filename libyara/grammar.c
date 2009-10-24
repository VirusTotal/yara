/* A Bison parser, made by GNU Bison 2.0.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

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
     _MZ_ = 299,
     _PE_ = 300,
     _DLL_ = 301,
     _TRUE_ = 302,
     _FALSE_ = 303,
     _OR_ = 304,
     _AND_ = 305,
     _NOT_ = 306,
     _IS_ = 307,
     _NEQ_ = 308,
     _EQ_ = 309,
     _GE_ = 310,
     _GT_ = 311,
     _LE_ = 312,
     _LT_ = 313
   };
#endif
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
#define _MZ_ 299
#define _PE_ 300
#define _DLL_ 301
#define _TRUE_ 302
#define _FALSE_ 303
#define _OR_ 304
#define _AND_ 305
#define _NOT_ 306
#define _IS_ 307
#define _NEQ_ 308
#define _EQ_ 309
#define _GE_ 310
#define _GT_ 311
#define _LE_ 312
#define _LT_ 313




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

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 104 "grammar.y"
typedef union YYSTYPE {
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;
    void*           meta;

} YYSTYPE;
/* Line 190 of yacc.c.  */
#line 220 "grammar.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */
#line 119 "grammar.y"
 

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
                                unsigned int value);
                    
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

TERM* reduce_rule(  yyscan_t yyscanner,
                    char* identifier);

int count_strings(TERM_STRING* st);



/* Line 213 of yacc.c.  */
#line 315 "grammar.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   else
#    define YYSTACK_ALLOC alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short int yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short int) + sizeof (YYSTYPE))			\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
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
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short int yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   292

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  72
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  26
/* YYNRULES -- Number of rules. */
#define YYNRULES  92
/* YYNRULES -- Number of states. */
#define YYNSTATES  189

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   313

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      68,    70,    61,    59,    71,    60,    69,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    66,     2,
       2,    67,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    62,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    63,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    64,     2,    65,     2,     2,     2,     2,
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
      55,    56,    57,    58
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned short int yyprhs[] =
{
       0,     0,     3,     4,     7,    11,    15,    25,    26,    30,
      31,    35,    39,    40,    43,    45,    47,    48,    51,    53,
      56,    58,    61,    65,    69,    73,    77,    79,    82,    87,
      92,    96,    97,   100,   102,   104,   106,   108,   110,   112,
     114,   116,   120,   125,   134,   141,   142,   152,   153,   163,
     164,   174,   178,   182,   186,   190,   194,   197,   201,   205,
     209,   213,   217,   221,   225,   229,   233,   237,   241,   243,
     245,   249,   251,   253,   255,   257,   262,   267,   272,   277,
     282,   287,   289,   291,   295,   299,   303,   307,   311,   313,
     315,   317,   319
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      73,     0,    -1,    -1,    73,    74,    -1,    73,     1,    74,
      -1,    73,     1,    63,    -1,    78,     3,    10,    80,    64,
      75,    76,    77,    65,    -1,    -1,     6,    66,    82,    -1,
      -1,     7,    66,    84,    -1,     8,    66,    88,    -1,    -1,
      78,    79,    -1,     4,    -1,     5,    -1,    -1,    66,    81,
      -1,    10,    -1,    81,    10,    -1,    83,    -1,    82,    83,
      -1,    10,    67,    18,    -1,    10,    67,    16,    -1,    10,
      67,    47,    -1,    10,    67,    48,    -1,    85,    -1,    84,
      85,    -1,    11,    67,    18,    86,    -1,    11,    67,    20,
      86,    -1,    11,    67,    19,    -1,    -1,    86,    87,    -1,
      22,    -1,    21,    -1,    23,    -1,    24,    -1,    47,    -1,
      48,    -1,    10,    -1,    11,    -1,    11,    25,    95,    -1,
      11,    25,    30,    95,    -1,    11,    33,    68,    95,    69,
      69,    95,    70,    -1,    11,    33,    37,    68,    18,    70,
      -1,    -1,    35,    95,    34,    92,    66,    89,    68,    88,
      70,    -1,    -1,    35,    28,    34,    92,    66,    90,    68,
      88,    70,    -1,    -1,    35,    29,    34,    92,    66,    91,
      68,    88,    70,    -1,    95,    34,    92,    -1,    28,    34,
      92,    -1,    29,    34,    92,    -1,    32,    52,    97,    -1,
      68,    88,    70,    -1,    51,    88,    -1,    88,    50,    88,
      -1,    88,    49,    88,    -1,    88,    52,    88,    -1,    95,
      58,    95,    -1,    95,    56,    95,    -1,    95,    57,    95,
      -1,    95,    55,    95,    -1,    95,    54,    95,    -1,    95,
      52,    95,    -1,    95,    53,    95,    -1,    68,    93,    70,
      -1,    36,    -1,    94,    -1,    93,    71,    94,    -1,    11,
      -1,    14,    -1,    26,    -1,    27,    -1,    38,    68,    95,
      70,    -1,    39,    68,    95,    70,    -1,    40,    68,    95,
      70,    -1,    41,    68,    95,    70,    -1,    42,    68,    95,
      70,    -1,    43,    68,    95,    70,    -1,    12,    -1,    13,
      -1,    68,    95,    70,    -1,    95,    59,    95,    -1,    95,
      60,    95,    -1,    95,    61,    95,    -1,    95,    62,    95,
      -1,    96,    -1,    16,    -1,    44,    -1,    45,    -1,    46,
      -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short int yyrline[] =
{
       0,   205,   205,   206,   207,   208,   211,   221,   222,   225,
     226,   229,   232,   233,   236,   237,   240,   241,   244,   253,
     263,   272,   283,   292,   301,   310,   321,   331,   343,   353,
     363,   375,   376,   379,   380,   381,   382,   385,   386,   387,
     397,   407,   417,   421,   431,   442,   441,   458,   457,   474,
     473,   489,   499,   509,   519,   520,   521,   522,   523,   524,
     525,   526,   527,   528,   529,   530,   531,   535,   536,   539,
     540,   546,   556,   569,   570,   571,   572,   573,   574,   575,
     576,   577,   587,   597,   598,   599,   600,   601,   602,   605,
     608,   609,   610
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
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
  "_UINT16_", "_UINT32_", "_MZ_", "_PE_", "_DLL_", "_TRUE_", "_FALSE_",
  "_OR_", "_AND_", "_NOT_", "_IS_", "_NEQ_", "_EQ_", "_GE_", "_GT_",
  "_LE_", "_LT_", "'+'", "'-'", "'*'", "'\\\\'", "'include'", "'{'", "'}'",
  "':'", "'='", "'('", "'.'", "')'", "','", "$accept", "rules", "rule",
  "meta", "strings", "condition", "rule_modifiers", "rule_modifier",
  "tags", "tag_list", "meta_declarations", "meta_declaration",
  "string_declarations", "string_declaration", "string_modifiers",
  "string_modifier", "boolean_expression", "@1", "@2", "@3", "string_set",
  "string_enumeration", "string_enumeration_item", "expression", "number",
  "type", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short int yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,    43,
      45,    42,    92,   105,   123,   125,    58,    61,    40,    46,
      41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    72,    73,    73,    73,    73,    74,    75,    75,    76,
      76,    77,    78,    78,    79,    79,    80,    80,    81,    81,
      82,    82,    83,    83,    83,    83,    84,    84,    85,    85,
      85,    86,    86,    87,    87,    87,    87,    88,    88,    88,
      88,    88,    88,    88,    88,    89,    88,    90,    88,    91,
      88,    88,    88,    88,    88,    88,    88,    88,    88,    88,
      88,    88,    88,    88,    88,    88,    88,    92,    92,    93,
      93,    94,    94,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    95,    95,    95,    95,    95,    95,    96,
      97,    97,    97
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     2,     3,     3,     9,     0,     3,     0,
       3,     3,     0,     2,     1,     1,     0,     2,     1,     2,
       1,     2,     3,     3,     3,     3,     1,     2,     4,     4,
       3,     0,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     3,     4,     8,     6,     0,     9,     0,     9,     0,
       9,     3,     3,     3,     3,     3,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     1,     1,
       3,     1,     1,     1,     1,     4,     4,     4,     4,     4,
       4,     1,     1,     3,     3,     3,     3,     3,     1,     1,
       1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,    12,     3,     0,     5,     4,     0,    14,
      15,    13,    16,     0,     0,    18,    17,     7,    19,     0,
       9,     0,     0,     0,     0,     8,    20,     0,     0,     0,
       0,    21,     0,    10,    26,     0,     6,    23,    22,    24,
      25,     0,    27,    39,    40,    81,    82,    89,    73,    74,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      37,    38,     0,     0,    11,     0,    88,    31,    30,    31,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    56,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    28,    29,     0,    41,     0,     0,    68,
       0,    52,    53,    90,    91,    92,    54,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    55,    83,    58,
      57,    59,    51,    65,    66,    64,    63,    61,    62,    60,
      84,    85,    86,    87,    34,    33,    35,    36,    32,    42,
       0,     0,    71,    72,     0,    69,     0,     0,     0,    75,
      76,    77,    78,    79,    80,     0,     0,    67,     0,    47,
      49,    45,    44,     0,    70,     0,     0,     0,     0,     0,
       0,     0,    43,     0,     0,     0,    48,    50,    46
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     1,     4,    20,    23,    29,     5,    11,    14,    16,
      25,    26,    33,    34,   103,   148,    64,   177,   175,   176,
     111,   154,   155,    65,    66,   116
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -59
static const short int yypact[] =
{
     -59,    95,   -59,   -58,   -59,    66,   -59,   -59,     6,   -59,
     -59,   -59,   -16,    15,   -10,   -59,    50,    59,   -59,    10,
      73,    96,    17,   111,    68,    96,   -59,   115,    70,    76,
      20,   -59,    71,   115,   -59,    46,   -59,   -59,   -59,   -59,
     -59,    72,   -59,   -59,    28,   -59,   -59,   -59,   -59,   -59,
     108,   110,    93,    89,    78,    81,    82,    84,    87,    90,
     -59,   -59,    46,    46,   -41,   151,   -59,   -59,   -59,   -59,
     121,   -17,   -33,   -33,    67,   137,   138,   127,    48,   127,
     127,   127,   127,   127,   127,   134,   -48,   122,    46,    46,
      46,   -33,   127,   127,   127,   127,   127,   127,   127,   127,
     127,   127,   127,   264,   264,   127,   230,   105,   127,   -59,
       7,   -59,   -59,   -59,   -59,   -59,   -59,   -33,   -33,   -47,
     -33,   161,   165,   179,   183,   195,   199,   -59,   -59,    27,
     134,   -59,   -59,   230,   230,   230,   230,   230,   230,   230,
      42,    42,   -59,   -59,   -59,   -59,   -59,   -59,   -59,   230,
     169,   215,   -59,   -59,    51,   -59,   124,   125,   133,   -59,
     -59,   -59,   -59,   -59,   -59,   118,   132,   -59,     7,   -59,
     -59,   -59,   -59,   127,   -59,   147,   160,   162,   211,    46,
      46,    46,   -59,   144,   148,   167,   -59,   -59,   -59
};

/* YYPGOTO[NTERM-NUM].  */
static const short int yypgoto[] =
{
     -59,   -59,   226,   -59,   -59,   -59,   -59,   -59,   -59,   -59,
     -59,   177,   -59,   200,   163,   -59,   -56,   -59,   -59,   -59,
     -54,   -59,    79,   -53,   -59,   -59
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -13
static const short int yytable[] =
{
      78,    88,    89,   109,    90,     6,    85,    86,    88,    89,
      87,    90,    99,   100,   101,   102,    12,   106,   152,   112,
     107,   153,   127,   128,   119,    15,   121,   122,   123,   124,
     125,   126,   129,   130,   131,   110,    37,   132,    38,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
      13,   108,   149,    70,    17,   151,    43,    44,    45,    46,
      18,    71,    47,   156,   157,    19,   158,    39,    40,     8,
       9,    10,    48,    49,    50,    51,    21,    89,    52,    90,
      22,    53,   120,    27,    54,    55,    56,    57,    58,    59,
      67,    68,    69,    60,    61,     2,     3,    62,   -12,   -12,
     -12,    45,    46,   101,   102,    47,    24,    99,   100,   101,
     102,   113,   114,   115,    63,    48,    49,    75,    76,    28,
     178,   167,   168,   183,   184,   185,    32,    54,    55,    56,
      57,    58,    59,    45,    46,    30,    35,    47,    41,    45,
      46,    36,    72,    47,    73,    74,    79,    48,    49,    80,
      81,   105,    82,    48,    49,    83,    91,    77,    84,    54,
      55,    56,    57,    58,    59,    54,    55,    56,    57,    58,
      59,   117,   118,   150,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,    91,    90,   165,   172,    77,
     169,   170,   128,    88,    89,    77,    90,    88,    89,   171,
      90,   173,    31,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   186,   179,    88,    89,   187,    90,
      99,   100,   101,   102,    99,   100,   101,   102,   180,     7,
     181,   159,   104,    42,     0,   160,     0,   188,    99,   100,
     101,   102,    99,   100,   101,   102,     0,   174,     0,   161,
       0,     0,     0,   162,    99,   100,   101,   102,    99,   100,
     101,   102,     0,     0,     0,   163,     0,     0,     0,   164,
      99,   100,   101,   102,    99,   100,   101,   102,     0,     0,
       0,   182,     0,     0,   166,   144,   145,   146,   147,    99,
     100,   101,   102
};

static const short int yycheck[] =
{
      53,    49,    50,    36,    52,    63,    62,    63,    49,    50,
      63,    52,    59,    60,    61,    62,    10,    70,    11,    73,
      37,    14,    70,    70,    77,    10,    79,    80,    81,    82,
      83,    84,    88,    89,    90,    68,    16,    91,    18,    92,
      93,    94,    95,    96,    97,    98,    99,   100,   101,   102,
      66,    68,   105,    25,    64,   108,    10,    11,    12,    13,
      10,    33,    16,   117,   118,     6,   120,    47,    48,     3,
       4,     5,    26,    27,    28,    29,    66,    50,    32,    52,
       7,    35,    34,    66,    38,    39,    40,    41,    42,    43,
      18,    19,    20,    47,    48,     0,     1,    51,     3,     4,
       5,    12,    13,    61,    62,    16,    10,    59,    60,    61,
      62,    44,    45,    46,    68,    26,    27,    28,    29,     8,
     173,    70,    71,   179,   180,   181,    11,    38,    39,    40,
      41,    42,    43,    12,    13,    67,    66,    16,    67,    12,
      13,    65,    34,    16,    34,    52,    68,    26,    27,    68,
      68,    30,    68,    26,    27,    68,    34,    68,    68,    38,
      39,    40,    41,    42,    43,    38,    39,    40,    41,    42,
      43,    34,    34,    68,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    34,    52,    18,    70,    68,
      66,    66,    70,    49,    50,    68,    52,    49,    50,    66,
      52,    69,    25,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    70,    68,    49,    50,    70,    52,
      59,    60,    61,    62,    59,    60,    61,    62,    68,     3,
      68,    70,    69,    33,    -1,    70,    -1,    70,    59,    60,
      61,    62,    59,    60,    61,    62,    -1,   168,    -1,    70,
      -1,    -1,    -1,    70,    59,    60,    61,    62,    59,    60,
      61,    62,    -1,    -1,    -1,    70,    -1,    -1,    -1,    70,
      59,    60,    61,    62,    59,    60,    61,    62,    -1,    -1,
      -1,    70,    -1,    -1,    69,    21,    22,    23,    24,    59,
      60,    61,    62
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    73,     0,     1,    74,    78,    63,    74,     3,     4,
       5,    79,    10,    66,    80,    10,    81,    64,    10,     6,
      75,    66,     7,    76,    10,    82,    83,    66,     8,    77,
      67,    83,    11,    84,    85,    66,    65,    16,    18,    47,
      48,    67,    85,    10,    11,    12,    13,    16,    26,    27,
      28,    29,    32,    35,    38,    39,    40,    41,    42,    43,
      47,    48,    51,    68,    88,    95,    96,    18,    19,    20,
      25,    33,    34,    34,    52,    28,    29,    68,    95,    68,
      68,    68,    68,    68,    68,    88,    88,    95,    49,    50,
      52,    34,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    86,    86,    30,    95,    37,    68,    36,
      68,    92,    92,    44,    45,    46,    97,    34,    34,    95,
      34,    95,    95,    95,    95,    95,    95,    70,    70,    88,
      88,    88,    92,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    95,    21,    22,    23,    24,    87,    95,
      68,    95,    11,    14,    93,    94,    92,    92,    92,    70,
      70,    70,    70,    70,    70,    18,    69,    70,    71,    66,
      66,    66,    70,    69,    94,    90,    91,    89,    95,    68,
      68,    68,    70,    88,    88,    88,    70,    70,    70
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

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
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror (yyscanner, "syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (N)								\
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
    while (0)
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
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
} while (0)

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Type, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short int *bottom, short int *top)
#else
static void
yy_stack_print (bottom, top)
    short int *bottom;
    short int *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
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
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);


# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

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
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *yyscanner);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
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

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short int yyssa[YYINITDEPTH];
  short int *yyss = yyssa;
  register short int *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

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


  yyvsp[0] = yylval;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short int *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short int *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
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

/* Do appropriate processing given the current state.  */
/* Read a look-ahead token if we need one and don't already have one.  */
/* yyresume: */

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

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
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
#line 212 "grammar.y"
    { 
                if (reduce_rule_declaration(yyscanner, (yyvsp[-6].c_string),(yyvsp[-8].integer),(yyvsp[-5].tag),(yyvsp[-3].meta),(yyvsp[-2].string),(yyvsp[-1].term)) != ERROR_SUCCESS)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR; 
                }  
            }
    break;

  case 7:
#line 221 "grammar.y"
    { (yyval.meta) = NULL; }
    break;

  case 8:
#line 222 "grammar.y"
    { (yyval.meta) = (yyvsp[0].meta); }
    break;

  case 9:
#line 225 "grammar.y"
    { (yyval.string) = NULL; }
    break;

  case 10:
#line 226 "grammar.y"
    { (yyval.string) = (yyvsp[0].string); }
    break;

  case 11:
#line 229 "grammar.y"
    { (yyval.term) = (yyvsp[0].term); }
    break;

  case 12:
#line 232 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 13:
#line 233 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 14:
#line 236 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 15:
#line 237 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 16:
#line 240 "grammar.y"
    { (yyval.tag) = NULL; }
    break;

  case 17:
#line 241 "grammar.y"
    { (yyval.tag) = (yyvsp[0].tag);   }
    break;

  case 18:
#line 244 "grammar.y"
    { 
                                                (yyval.tag) = reduce_tags(yyscanner,NULL,(yyvsp[0].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }
    break;

  case 19:
#line 253 "grammar.y"
    {   
                                                (yyval.tag) = reduce_tags(yyscanner,(yyvsp[-1].tag),(yyvsp[0].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }
    break;

  case 20:
#line 263 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_metas(yyscanner, NULL, (yyvsp[0].meta)); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
    break;

  case 21:
#line 272 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_metas(yyscanner, (yyvsp[-1].meta), (yyvsp[0].meta)); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
    break;

  case 22:
#line 283 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_STRING, (yyvsp[-2].c_string), (unsigned int) (yyvsp[0].sized_string));
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 23:
#line 292 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_INTEGER, (yyvsp[-2].c_string), (yyvsp[0].integer)); 
                                                                
                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 24:
#line 301 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, (yyvsp[-2].c_string), TRUE); 

                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 25:
#line 310 "grammar.y"
    { 
                                                                (yyval.meta) = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, (yyvsp[-2].c_string), FALSE); 

                                                                if ((yyval.meta) == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
    break;

  case 26:
#line 322 "grammar.y"
    { 
                            (yyval.string) = reduce_strings(yyscanner,NULL,(yyvsp[0].string)); 
                            
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 27:
#line 332 "grammar.y"
    { 
                            (yyval.string) = reduce_strings(yyscanner,(yyvsp[-1].string),(yyvsp[0].string));
                        
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }  
                        }
    break;

  case 28:
#line 344 "grammar.y"
    { 
                            (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[-3].term), (yyvsp[-1].sized_string), (yyvsp[0].integer)); 
                
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 29:
#line 354 "grammar.y"
    { 
                           (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[-3].term), (yyvsp[-1].sized_string), (yyvsp[0].integer) | STRING_FLAGS_REGEXP); 

                           if ((yyval.string) == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                       }
    break;

  case 30:
#line 364 "grammar.y"
    {
                            (yyval.string) = reduce_string_declaration(yyscanner, (yyvsp[-2].term), (yyvsp[0].sized_string), STRING_FLAGS_HEXADECIMAL);
            
                            if ((yyval.string) == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
    break;

  case 31:
#line 375 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 32:
#line 376 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 33:
#line 379 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 34:
#line 380 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 35:
#line 381 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 36:
#line 382 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 37:
#line 385 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 1); }
    break;

  case 38:
#line 386 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, 0); }
    break;

  case 39:
#line 388 "grammar.y"
    { 
                        (yyval.term) = reduce_rule(yyscanner, (yyvsp[0].c_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 40:
#line 398 "grammar.y"
    {  
                        (yyval.term) = reduce_string(yyscanner, (yyvsp[0].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 41:
#line 408 "grammar.y"
    {          
                        (yyval.term) = reduce_string_at(yyscanner, (yyvsp[-2].term), (yyvsp[0].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 42:
#line 418 "grammar.y"
    { 
                        (yyval.term) = NULL; 
                     }
    break;

  case 43:
#line 422 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_range(yyscanner, (yyvsp[-7].term), (yyvsp[-4].term), (yyvsp[-1].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 44:
#line 432 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_section_by_name(yyscanner, (yyvsp[-5].term), (yyvsp[-1].sized_string));

                        if ((yyval.term) == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
    break;

  case 45:
#line 442 "grammar.y"
    { 
                           yyget_extra(yyscanner)->inside_for++; 
                      }
    break;

  case 46:
#line 446 "grammar.y"
    { 
                           yyget_extra(yyscanner)->inside_for--; 
                           
                           (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, (yyvsp[-7].term), (yyvsp[-5].term), (yyvsp[-1].term)); 
                           
                           if ((yyval.term) == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                      }
    break;

  case 47:
#line 458 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }
    break;

  case 48:
#line 462 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for--; 
                          
                          (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, count_strings((yyvsp[-5].term))), (yyvsp[-5].term), (yyvsp[-1].term)); 
                          
                          if ((yyval.term) == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
    break;

  case 49:
#line 474 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }
    break;

  case 50:
#line 478 "grammar.y"
    { 
                          yyget_extra(yyscanner)->inside_for--; 
                                                    
                          (yyval.term) = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, 1), (yyvsp[-5].term), (yyvsp[-1].term)); 
                          
                          if ((yyval.term) == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
    break;

  case 51:
#line 490 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, (yyvsp[-2].term), (yyvsp[0].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 52:
#line 500 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, count_strings((yyvsp[0].term))), (yyvsp[0].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 53:
#line 510 "grammar.y"
    { 
                         (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, 1), (yyvsp[0].term), NULL); 
                         
                         if ((yyval.term) == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
    break;

  case 54:
#line 519 "grammar.y"
    { (yyval.term) = NULL; }
    break;

  case 55:
#line 520 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 56:
#line 521 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT, (yyvsp[0].term), NULL, NULL); }
    break;

  case 57:
#line 522 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_AND, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 58:
#line 523 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_OR, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 59:
#line 524 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 60:
#line 525 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LT, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 61:
#line 526 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GT, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 62:
#line 527 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_LE, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 63:
#line 528 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_GE, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 64:
#line 529 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 65:
#line 530 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 66:
#line 531 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_NOT_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 67:
#line 535 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 68:
#line 536 "grammar.y"
    { (yyval.term) = reduce_string_with_wildcard(yyscanner, yr_strdup("$*")); }
    break;

  case 70:
#line 541 "grammar.y"
    {
                         (yyval.term) = reduce_string_enumeration(yyscanner, (yyvsp[-2].term),(yyvsp[0].term));
                      }
    break;

  case 71:
#line 547 "grammar.y"
    {  
                              (yyval.term) = reduce_string(yyscanner, (yyvsp[0].term));

                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 72:
#line 557 "grammar.y"
    { 
                              (yyval.term) = reduce_string_with_wildcard(yyscanner, (yyvsp[0].term)); 
                              
                              if ((yyval.term) == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
    break;

  case 73:
#line 569 "grammar.y"
    { (yyval.term) = reduce_filesize(yyscanner); }
    break;

  case 74:
#line 570 "grammar.y"
    { (yyval.term) = reduce_entrypoint(yyscanner); }
    break;

  case 75:
#line 571 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT8_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 76:
#line 572 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT16_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 77:
#line 573 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_INT32_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 78:
#line 574 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT8_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 79:
#line 575 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT16_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 80:
#line 576 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_UINT32_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 81:
#line 578 "grammar.y"
    { 
                    (yyval.term) = reduce_string_count(yyscanner, (yyvsp[0].term)); 
                    
                    if ((yyval.term) == NULL)
                    {
                        yyerror(yyscanner, NULL);
                        YYERROR;
                    }
             }
    break;

  case 82:
#line 588 "grammar.y"
    { 
                    (yyval.term) = reduce_string_offset(yyscanner, (yyvsp[0].term)); 

                    if ((yyval.term) == NULL)
                    {
                        yyerror(yyscanner, NULL);
                        YYERROR;
                    }
             }
    break;

  case 83:
#line 597 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 84:
#line 598 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_ADD, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 85:
#line 599 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_SUB, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 86:
#line 600 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_MUL, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 87:
#line 601 "grammar.y"
    { (yyval.term) = reduce_term(yyscanner, TERM_TYPE_DIV, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 89:
#line 605 "grammar.y"
    { (yyval.term) = reduce_constant(yyscanner, (yyvsp[0].integer)); }
    break;


    }

/* Line 1037 of yacc.c.  */
#line 2078 "grammar.c"

  yyvsp -= yylen;
  yyssp -= yylen;


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
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  const char* yyprefix;
	  char *yymsg;
	  int yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 0;

	  yyprefix = ", expecting ";
	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		yysize += yystrlen (yyprefix) + yystrlen (yytname [yyx]);
		yycount += 1;
		if (yycount == 5)
		  {
		    yysize = 0;
		    break;
		  }
	      }
	  yysize += (sizeof ("syntax error, unexpected ")
		     + yystrlen (yytname[yytype]));
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yyprefix = ", expecting ";
		  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			yyp = yystpcpy (yyp, yyprefix);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yyprefix = " or ";
		      }
		}
	      yyerror (yyscanner, yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror (yyscanner, "syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror (yyscanner, "syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (yychar == YYEOF)
	     for (;;)
	       {

		 YYPOPSTACK;
		 if (yyssp == yyss)
		   YYABORT;
		 yydestruct ("Error: popping",
                             yystos[*yyssp], yyvsp);
	       }
        }
      else
	{
	  yydestruct ("Error: discarding", yytoken, &yylval);
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

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     yyerrorlab therefore never appears in user code.  */
  if (0)
     goto yyerrorlab;
#endif

yyvsp -= yylen;
  yyssp -= yylen;
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


      yydestruct ("Error: popping", yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token. */
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
  yydestruct ("Error: discarding lookahead",
              yytoken, &yylval);
  yychar = YYEMPTY;
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror (yyscanner, "parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 613 "grammar.y"



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
                                unsigned int value)
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
            meta->integer = value;
        }
        else if (type == META_TYPE_BOOLEAN)
        {
            meta->boolean = value;
        }
        else
        {
            meta->string = yr_strdup(((SIZED_STRING*) value)->c_string);
            yr_free((SIZED_STRING*) value);
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

TERM* reduce_rule(  yyscan_t yyscanner, 
                    char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_BINARY_OPERATION*  term;
    RULE* rule;
    YARA_CONTEXT*   current_context = yyget_extra(yyscanner);
  
    rule = lookup_rule(&current_context->rule_list, identifier, context->current_namespace);
    
    if (rule != NULL)
    {
        context->last_result = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, &term);        
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_UNDEFINED_RULE;
        term = NULL;
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

  







    
    
    
