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
#define YYPURE 0

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
     _STRINGS_ = 261,
     _CONDITION_ = 262,
     _END_ = 263,
     _IDENTIFIER_ = 264,
     _STRING_IDENTIFIER_ = 265,
     _STRING_COUNT_ = 266,
     _STRING_IDENTIFIER_WITH_WILDCARD_ = 267,
     _ANONYMOUS_STRING_ = 268,
     _NUMBER_ = 269,
     _UNKNOWN_ = 270,
     _TEXTSTRING_ = 271,
     _HEXSTRING_ = 272,
     _REGEXP_ = 273,
     _ASCII_ = 274,
     _WIDE_ = 275,
     _NOCASE_ = 276,
     _FULLWORD_ = 277,
     _AT_ = 278,
     _SIZE_ = 279,
     _ENTRYPOINT_ = 280,
     _ALL_ = 281,
     _ANY_ = 282,
     _RVA_ = 283,
     _OFFSET_ = 284,
     _FILE_ = 285,
     _IN_ = 286,
     _OF_ = 287,
     _FOR_ = 288,
     _THEM_ = 289,
     _SECTION_ = 290,
     _INT8_ = 291,
     _INT16_ = 292,
     _INT32_ = 293,
     _UINT8_ = 294,
     _UINT16_ = 295,
     _UINT32_ = 296,
     _MZ_ = 297,
     _PE_ = 298,
     _DLL_ = 299,
     _TRUE_ = 300,
     _FALSE_ = 301,
     _OR_ = 302,
     _AND_ = 303,
     _NOT_ = 304,
     _IS_ = 305,
     _NEQ_ = 306,
     _EQ_ = 307,
     _GE_ = 308,
     _GT_ = 309,
     _LE_ = 310,
     _LT_ = 311
   };
#endif
#define _RULE_ 258
#define _PRIVATE_ 259
#define _GLOBAL_ 260
#define _STRINGS_ 261
#define _CONDITION_ 262
#define _END_ 263
#define _IDENTIFIER_ 264
#define _STRING_IDENTIFIER_ 265
#define _STRING_COUNT_ 266
#define _STRING_IDENTIFIER_WITH_WILDCARD_ 267
#define _ANONYMOUS_STRING_ 268
#define _NUMBER_ 269
#define _UNKNOWN_ 270
#define _TEXTSTRING_ 271
#define _HEXSTRING_ 272
#define _REGEXP_ 273
#define _ASCII_ 274
#define _WIDE_ 275
#define _NOCASE_ 276
#define _FULLWORD_ 277
#define _AT_ 278
#define _SIZE_ 279
#define _ENTRYPOINT_ 280
#define _ALL_ 281
#define _ANY_ 282
#define _RVA_ 283
#define _OFFSET_ 284
#define _FILE_ 285
#define _IN_ 286
#define _OF_ 287
#define _FOR_ 288
#define _THEM_ 289
#define _SECTION_ 290
#define _INT8_ 291
#define _INT16_ 292
#define _INT32_ 293
#define _UINT8_ 294
#define _UINT16_ 295
#define _UINT32_ 296
#define _MZ_ 297
#define _PE_ 298
#define _DLL_ 299
#define _TRUE_ 300
#define _FALSE_ 301
#define _OR_ 302
#define _AND_ 303
#define _NOT_ 304
#define _IS_ 305
#define _NEQ_ 306
#define _EQ_ 307
#define _GE_ 308
#define _GT_ 309
#define _LE_ 310
#define _LT_ 311




/* Copy the first part of user declarations.  */
#line 2 "grammar.y"
 
    
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ast.h"
#include "error.h"
#include "compile.h"
#include "sizedstr.h"

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
#line 92 "grammar.y"
typedef union YYSTYPE {
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;

} YYSTYPE;
/* Line 190 of yacc.c.  */
#line 215 "grammar.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */
#line 106 "grammar.y"
 
    
/* Global variables */

STRING* current_rule_strings;
int inside_for = 0;

/* Function declarations */

void reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition);
TAG* reduce_tags(TAG* tag_list_head, char* identifier);

STRING* reduce_string_declaration(char* identifier, SIZED_STRING* str, int flags);
STRING* reduce_strings(STRING* string_list_head, STRING* string);

TERM* reduce_string_enumeration(TERM* string_list_head, TERM* string_identifier);
TERM* reduce_string_with_wildcard(char* identifier);

TERM* reduce_string(char* identifier);
TERM* reduce_string_at(char* identifier, TERM* offset);
TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset);
TERM* reduce_string_in_section_by_name(char* identifier, SIZED_STRING* section_name);
TERM* reduce_string_count(char* identifier);

TERM* reduce_filesize();
TERM* reduce_entrypoint();

TERM* reduce_term(int type, TERM* op1, TERM* op2, TERM* op3);
TERM* reduce_constant(unsigned int constant);
TERM* reduce_rule(char* identifier);

int count_strings(TERM_STRING* st);



/* Line 213 of yacc.c.  */
#line 261 "grammar.c"

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
#define YYLAST   270

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  69
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  21
/* YYNRULES -- Number of rules. */
#define YYNRULES  80
/* YYNRULES -- Number of states. */
#define YYNSTATES  177

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   311

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      65,    67,    59,    57,    68,    58,    66,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    63,     2,
       2,    64,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    60,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    62,     2,    61,     2,     2,     2,     2,
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
      55,    56
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned short int yyprhs[] =
{
       0,     0,     3,     4,     7,    11,    21,    34,    35,    38,
      40,    42,    43,    46,    48,    51,    53,    56,    61,    66,
      70,    71,    74,    76,    78,    80,    82,    84,    86,    88,
      90,    94,    99,   108,   115,   116,   126,   127,   137,   138,
     148,   152,   156,   160,   164,   168,   171,   175,   179,   183,
     187,   191,   195,   199,   203,   207,   211,   215,   217,   219,
     223,   225,   227,   229,   231,   236,   241,   246,   251,   256,
     261,   263,   267,   271,   275,   279,   283,   285,   287,   289,
     291
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      70,     0,    -1,    -1,    70,    71,    -1,    70,     1,    61,
      -1,    72,     3,     9,    74,    62,     7,    63,    80,    61,
      -1,    72,     3,     9,    74,    62,     6,    63,    76,     7,
      63,    80,    61,    -1,    -1,    72,    73,    -1,     4,    -1,
       5,    -1,    -1,    63,    75,    -1,     9,    -1,    75,     9,
      -1,    77,    -1,    76,    77,    -1,    10,    64,    16,    78,
      -1,    10,    64,    18,    78,    -1,    10,    64,    17,    -1,
      -1,    78,    79,    -1,    20,    -1,    19,    -1,    21,    -1,
      22,    -1,    45,    -1,    46,    -1,     9,    -1,    10,    -1,
      10,    23,    87,    -1,    10,    23,    28,    87,    -1,    10,
      31,    65,    87,    66,    66,    87,    67,    -1,    10,    31,
      35,    65,    16,    67,    -1,    -1,    33,    87,    32,    84,
      63,    81,    65,    80,    67,    -1,    -1,    33,    26,    32,
      84,    63,    82,    65,    80,    67,    -1,    -1,    33,    27,
      32,    84,    63,    83,    65,    80,    67,    -1,    87,    32,
      84,    -1,    26,    32,    84,    -1,    27,    32,    84,    -1,
      30,    50,    89,    -1,    65,    80,    67,    -1,    49,    80,
      -1,    80,    48,    80,    -1,    80,    47,    80,    -1,    80,
      50,    80,    -1,    87,    56,    87,    -1,    87,    54,    87,
      -1,    87,    55,    87,    -1,    87,    53,    87,    -1,    87,
      52,    87,    -1,    87,    50,    87,    -1,    87,    51,    87,
      -1,    65,    85,    67,    -1,    34,    -1,    86,    -1,    85,
      68,    86,    -1,    10,    -1,    12,    -1,    24,    -1,    25,
      -1,    36,    65,    87,    67,    -1,    37,    65,    87,    67,
      -1,    38,    65,    87,    67,    -1,    39,    65,    87,    67,
      -1,    40,    65,    87,    67,    -1,    41,    65,    87,    67,
      -1,    11,    -1,    65,    87,    67,    -1,    87,    57,    87,
      -1,    87,    58,    87,    -1,    87,    59,    87,    -1,    87,
      60,    87,    -1,    88,    -1,    14,    -1,    42,    -1,    43,
      -1,    44,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short int yyrline[] =
{
       0,   143,   143,   144,   153,   162,   163,   166,   167,   170,
     171,   174,   175,   178,   188,   200,   210,   222,   233,   244,
     257,   258,   261,   262,   263,   264,   267,   268,   269,   280,
     291,   301,   305,   316,   328,   327,   337,   336,   346,   345,
     354,   358,   362,   366,   367,   368,   369,   370,   371,   372,
     373,   374,   375,   376,   377,   378,   382,   383,   386,   387,
     393,   404,   418,   419,   420,   421,   422,   423,   424,   425,
     426,   437,   438,   439,   440,   441,   442,   445,   448,   449,
     450
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_STRINGS_", "_CONDITION_", "_END_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_",
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_ANONYMOUS_STRING_", "_NUMBER_",
  "_UNKNOWN_", "_TEXTSTRING_", "_HEXSTRING_", "_REGEXP_", "_ASCII_",
  "_WIDE_", "_NOCASE_", "_FULLWORD_", "_AT_", "_SIZE_", "_ENTRYPOINT_",
  "_ALL_", "_ANY_", "_RVA_", "_OFFSET_", "_FILE_", "_IN_", "_OF_", "_FOR_",
  "_THEM_", "_SECTION_", "_INT8_", "_INT16_", "_INT32_", "_UINT8_",
  "_UINT16_", "_UINT32_", "_MZ_", "_PE_", "_DLL_", "_TRUE_", "_FALSE_",
  "_OR_", "_AND_", "_NOT_", "_IS_", "_NEQ_", "_EQ_", "_GE_", "_GT_",
  "_LE_", "_LT_", "'+'", "'-'", "'*'", "'\\\\'", "'}'", "'{'", "':'",
  "'='", "'('", "'.'", "')'", "','", "$accept", "rules", "rule",
  "rule_modifiers", "rule_modifier", "tags", "tag_list", "strings",
  "string_declaration", "string_modifiers", "string_modifier",
  "boolean_expression", "@1", "@2", "@3", "string_set",
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
     305,   306,   307,   308,   309,   310,   311,    43,    45,    42,
      92,   125,   123,    58,    61,    40,    46,    41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    69,    70,    70,    70,    71,    71,    72,    72,    73,
      73,    74,    74,    75,    75,    76,    76,    77,    77,    77,
      78,    78,    79,    79,    79,    79,    80,    80,    80,    80,
      80,    80,    80,    80,    81,    80,    82,    80,    83,    80,
      80,    80,    80,    80,    80,    80,    80,    80,    80,    80,
      80,    80,    80,    80,    80,    80,    84,    84,    85,    85,
      86,    86,    87,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    88,    89,    89,
      89
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     2,     3,     9,    12,     0,     2,     1,
       1,     0,     2,     1,     2,     1,     2,     4,     4,     3,
       0,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     4,     8,     6,     0,     9,     0,     9,     0,     9,
       3,     3,     3,     3,     3,     2,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     1,     1,     3,
       1,     1,     1,     1,     4,     4,     4,     4,     4,     4,
       1,     3,     3,     3,     3,     3,     1,     1,     1,     1,
       1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,     0,     3,     0,     4,     0,     9,    10,
       8,    11,     0,     0,    13,    12,     0,    14,     0,     0,
       0,     0,     0,     0,    15,    28,    29,    70,    77,    62,
      63,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    26,    27,     0,     0,     0,     0,    76,     0,     0,
      16,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    45,     0,     0,     0,
       0,     0,     5,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    20,    19,    20,     0,     0,
      30,     0,     0,    57,     0,    41,    42,    78,    79,    80,
      43,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    44,    71,    47,    46,    48,    40,    54,    55,    53,
      52,    50,    51,    49,    72,    73,    74,    75,    17,    18,
       0,    31,     0,     0,    60,    61,     0,    58,     0,     0,
       0,    64,    65,    66,    67,    68,    69,    23,    22,    24,
      25,    21,     6,     0,     0,    56,     0,    36,    38,    34,
      33,     0,    59,     0,     0,     0,     0,     0,     0,     0,
      32,     0,     0,     0,    37,    39,    35
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     1,     4,     5,    10,    13,    15,    23,    24,   128,
     151,    45,   165,   163,   164,    95,   136,   137,    46,    47,
     100
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -59
static const short int yypact[] =
{
     -59,    94,   -59,   -58,   -59,   173,   -59,     0,   -59,   -59,
     -59,   -50,     9,   -25,   -59,    47,    79,   -59,    14,    48,
      55,    43,    60,    68,   -59,   -59,    -8,   -59,   -59,   -59,
     -59,    97,   101,   107,    76,    61,   109,   117,   145,   164,
     175,   -59,   -59,    43,    43,   -36,   137,   -59,   168,   135,
     -59,    82,   -27,   -29,   -29,   170,   167,   192,   114,    77,
     114,   114,   114,   114,   114,   114,   194,   -46,   108,    43,
      43,    43,   -59,   -29,   114,   114,   114,   114,   114,   114,
     114,   114,   114,   114,   114,   -59,   -59,   -59,    43,   114,
       2,   190,   114,   -59,   134,   -59,   -59,   -59,   -59,   -59,
     -59,   -29,   -29,   144,   -29,   148,   159,   163,   174,   178,
     189,   -59,   -59,   177,   194,   -59,   -59,     2,     2,     2,
       2,     2,     2,     2,    45,    45,   -59,   -59,   151,   151,
      95,     2,   212,   204,   -59,   -59,    81,   -59,   146,   176,
     179,   -59,   -59,   -59,   -59,   -59,   -59,   -59,   -59,   -59,
     -59,   -59,   -59,   187,   191,   -59,   134,   -59,   -59,   -59,
     -59,   114,   -59,   200,   201,   202,   193,    43,    43,    43,
     -59,   -28,    24,   133,   -59,   -59,   -59
};

/* YYPGOTO[NTERM-NUM].  */
static const short int yypgoto[] =
{
     -59,   -59,   -59,   -59,   -59,   -59,   -59,   -59,   220,   171,
     -59,   -37,   -59,   -59,   -59,   -38,   -59,   103,   -34,   -59,
     -59
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -8
static const short int yytable[] =
{
      59,    69,    70,     6,    71,    93,    66,    67,    91,    11,
      68,    69,    70,    12,    71,    51,    96,    90,    14,    69,
      70,   111,    71,    52,   103,    72,   105,   106,   107,   108,
     109,   110,   113,   114,   115,   116,    94,    16,    92,   174,
     117,   118,   119,   120,   121,   122,   123,   124,   125,   126,
     127,   130,    25,    26,    27,   131,    17,    28,   133,    81,
      82,    83,    84,   138,   139,    22,   140,    29,    30,    31,
      32,    69,    70,    33,    71,    49,    34,    20,    22,    35,
      36,    37,    38,    39,    40,    18,    19,    27,    41,    42,
      28,   175,    43,    27,     2,     3,    28,    -7,    -7,    -7,
      29,    30,    56,    57,    83,    84,    29,    30,    44,   104,
      89,    21,    35,    36,    37,    38,    39,    40,    35,    36,
      37,    38,    39,    40,    48,    27,    60,   166,    28,    53,
     171,   172,   173,    54,    81,    82,    83,    84,    29,    30,
      73,    58,    69,    70,   134,    71,   135,    58,   155,   156,
      35,    36,    37,    38,    39,    40,   152,    55,    74,    75,
      76,    77,    78,    79,    80,    81,    82,    83,    84,    73,
     147,   148,   149,   150,    61,   112,     7,     8,     9,    58,
      69,    70,    62,    71,    85,    86,    87,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    88,   101,
     176,    81,    82,    83,    84,    81,    82,    83,    84,   157,
      63,   112,    97,    98,    99,   141,    81,    82,    83,    84,
      81,    82,    83,    84,   102,    70,   142,    71,   153,    64,
     143,    81,    82,    83,    84,    81,    82,    83,    84,   158,
      65,   144,   159,    50,    71,   145,    81,    82,    83,    84,
      81,    82,    83,    84,   160,   132,   146,   161,   129,   162,
     170,    81,    82,    83,    84,   167,   168,   169,     0,     0,
     154
};

static const short int yycheck[] =
{
      34,    47,    48,    61,    50,    34,    43,    44,    35,     9,
      44,    47,    48,    63,    50,    23,    54,    51,     9,    47,
      48,    67,    50,    31,    58,    61,    60,    61,    62,    63,
      64,    65,    69,    70,    71,    73,    65,    62,    65,    67,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    88,     9,    10,    11,    89,     9,    14,    92,    57,
      58,    59,    60,   101,   102,    10,   104,    24,    25,    26,
      27,    47,    48,    30,    50,     7,    33,    63,    10,    36,
      37,    38,    39,    40,    41,     6,     7,    11,    45,    46,
      14,    67,    49,    11,     0,     1,    14,     3,     4,     5,
      24,    25,    26,    27,    59,    60,    24,    25,    65,    32,
      28,    63,    36,    37,    38,    39,    40,    41,    36,    37,
      38,    39,    40,    41,    64,    11,    65,   161,    14,    32,
     167,   168,   169,    32,    57,    58,    59,    60,    24,    25,
      32,    65,    47,    48,    10,    50,    12,    65,    67,    68,
      36,    37,    38,    39,    40,    41,    61,    50,    50,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    32,
      19,    20,    21,    22,    65,    67,     3,     4,     5,    65,
      47,    48,    65,    50,    16,    17,    18,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    63,    32,
      67,    57,    58,    59,    60,    57,    58,    59,    60,    63,
      65,    67,    42,    43,    44,    67,    57,    58,    59,    60,
      57,    58,    59,    60,    32,    48,    67,    50,    16,    65,
      67,    57,    58,    59,    60,    57,    58,    59,    60,    63,
      65,    67,    63,    23,    50,    67,    57,    58,    59,    60,
      57,    58,    59,    60,    67,    65,    67,    66,    87,   156,
      67,    57,    58,    59,    60,    65,    65,    65,    -1,    -1,
      66
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    70,     0,     1,    71,    72,    61,     3,     4,     5,
      73,     9,    63,    74,     9,    75,    62,     9,     6,     7,
      63,    63,    10,    76,    77,     9,    10,    11,    14,    24,
      25,    26,    27,    30,    33,    36,    37,    38,    39,    40,
      41,    45,    46,    49,    65,    80,    87,    88,    64,     7,
      77,    23,    31,    32,    32,    50,    26,    27,    65,    87,
      65,    65,    65,    65,    65,    65,    80,    80,    87,    47,
      48,    50,    61,    32,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    16,    17,    18,    63,    28,
      87,    35,    65,    34,    65,    84,    84,    42,    43,    44,
      89,    32,    32,    87,    32,    87,    87,    87,    87,    87,
      87,    67,    67,    80,    80,    80,    84,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    87,    78,    78,
      80,    87,    65,    87,    10,    12,    85,    86,    84,    84,
      84,    67,    67,    67,    67,    67,    67,    19,    20,    21,
      22,    79,    61,    16,    66,    67,    68,    63,    63,    63,
      67,    66,    86,    82,    83,    81,    87,    65,    65,    65,
      67,    80,    80,    80,    67,    67,    67
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
      yyerror ("syntax error: cannot back up");\
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
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
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
      case 9: /* _IDENTIFIER_ */
#line 103 "grammar.y"
        { free ((yyvaluep->c_string)); };
#line 1048 "grammar.c"
        break;
      case 16: /* _TEXTSTRING_ */
#line 103 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 1053 "grammar.c"
        break;
      case 17: /* _HEXSTRING_ */
#line 103 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 1058 "grammar.c"
        break;
      case 18: /* _REGEXP_ */
#line 103 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 1063 "grammar.c"
        break;

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
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



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
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
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
        case 3:
#line 145 "grammar.y"
    {
            if (last_error != ERROR_SUCCESS)
            {
                show_last_error();
                yynerrs++;
                YYERROR;
            }
      }
    break;

  case 4:
#line 154 "grammar.y"
    {
           if (abort_on_first_error)
           {
               YYERROR;
           }
      }
    break;

  case 5:
#line 162 "grammar.y"
    { reduce_rule_declaration((yyvsp[-6].c_string),(yyvsp[-8].integer),(yyvsp[-5].tag),0,(yyvsp[-1].term));    }
    break;

  case 6:
#line 163 "grammar.y"
    { reduce_rule_declaration((yyvsp[-9].c_string),(yyvsp[-11].integer),(yyvsp[-8].tag),(yyvsp[-4].string),(yyvsp[-1].term));  }
    break;

  case 7:
#line 166 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 8:
#line 167 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 9:
#line 170 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 10:
#line 171 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 11:
#line 174 "grammar.y"
    { (yyval.tag) = NULL; }
    break;

  case 12:
#line 175 "grammar.y"
    { (yyval.tag) = (yyvsp[0].tag);   }
    break;

  case 13:
#line 178 "grammar.y"
    { 
                                                (yyval.tag) = reduce_tags(NULL,(yyvsp[0].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
    break;

  case 14:
#line 188 "grammar.y"
    {   
                                                (yyval.tag) = reduce_tags((yyvsp[-1].tag),(yyvsp[0].c_string)); 
                                                
                                                if ((yyval.tag) == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }  
                                            }
    break;

  case 15:
#line 200 "grammar.y"
    { 
                                                (yyval.string) = reduce_strings(NULL,(yyvsp[0].string)); 
                                                
                                                if ((yyval.string) == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
    break;

  case 16:
#line 210 "grammar.y"
    { 
                                                (yyval.string) = reduce_strings((yyvsp[-1].string),(yyvsp[0].string));
                                                
                                                if ((yyval.string) == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }   
                                            }
    break;

  case 17:
#line 223 "grammar.y"
    { 
                            (yyval.string) = reduce_string_declaration((yyvsp[-3].term), (yyvsp[-1].sized_string), (yyvsp[0].integer)); 
                
                            if ((yyval.string) == NULL)
                            {
                                show_last_error();
                                yynerrs++;
                                YYERROR;
                            } 
                        }
    break;

  case 18:
#line 234 "grammar.y"
    { 
                           (yyval.string) = reduce_string_declaration((yyvsp[-3].term), (yyvsp[-1].sized_string), (yyvsp[0].integer) | STRING_FLAGS_REGEXP); 

                           if ((yyval.string) == NULL)
                           {
                               show_last_error();
                               yynerrs++;
                               YYERROR;
                           } 
                       }
    break;

  case 19:
#line 245 "grammar.y"
    {
                            (yyval.string) = reduce_string_declaration((yyvsp[-2].term), (yyvsp[0].sized_string), STRING_FLAGS_HEXADECIMAL);
            
                            if ((yyval.string) == NULL)
                            {
                                show_last_error();
                                yynerrs++;
                                YYERROR;
                            }
                        }
    break;

  case 20:
#line 257 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 21:
#line 258 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 22:
#line 261 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 23:
#line 262 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 24:
#line 263 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 25:
#line 264 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 26:
#line 267 "grammar.y"
    { (yyval.term) = reduce_constant(1); }
    break;

  case 27:
#line 268 "grammar.y"
    { (yyval.term) = reduce_constant(0); }
    break;

  case 28:
#line 270 "grammar.y"
    { 
                        (yyval.term) = reduce_rule((yyvsp[0].c_string));
                        
                        if ((yyval.term) == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
    break;

  case 29:
#line 281 "grammar.y"
    {  
                        (yyval.term) = reduce_string((yyvsp[0].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
    break;

  case 30:
#line 292 "grammar.y"
    {          
                        (yyval.term) = reduce_string_at((yyvsp[-2].term), (yyvsp[0].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            show_last_error();
                            YYERROR;
                        }
                     }
    break;

  case 31:
#line 302 "grammar.y"
    { 
                        (yyval.term) = NULL; 
                     }
    break;

  case 32:
#line 306 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_range((yyvsp[-7].term), (yyvsp[-4].term), (yyvsp[-1].term));
                        
                        if ((yyval.term) == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
    break;

  case 33:
#line 317 "grammar.y"
    {          
                        (yyval.term) = reduce_string_in_section_by_name((yyvsp[-5].term), (yyvsp[-1].sized_string));

                        if ((yyval.term) == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
    break;

  case 34:
#line 328 "grammar.y"
    { 
                          inside_for++; 
                      }
    break;

  case 35:
#line 332 "grammar.y"
    { 
                           inside_for--; 
                           (yyval.term) = reduce_term(TERM_TYPE_FOR, (yyvsp[-7].term), (yyvsp[-5].term), (yyvsp[-1].term)); 
                      }
    break;

  case 36:
#line 337 "grammar.y"
    { 
                         inside_for++; 
                     }
    break;

  case 37:
#line 341 "grammar.y"
    { 
                          inside_for--; 
                          (yyval.term) = reduce_term(TERM_TYPE_FOR, reduce_constant(count_strings((yyvsp[-5].term))), (yyvsp[-5].term), (yyvsp[-1].term)); 
                     }
    break;

  case 38:
#line 346 "grammar.y"
    { 
                           inside_for++; 
                     }
    break;

  case 39:
#line 350 "grammar.y"
    { 
                          inside_for--; 
                          (yyval.term) = reduce_term(TERM_TYPE_FOR, reduce_constant(1), (yyvsp[-5].term), (yyvsp[-1].term)); 
                     }
    break;

  case 40:
#line 355 "grammar.y"
    { 
                         (yyval.term) = reduce_term(TERM_TYPE_OF, (yyvsp[-2].term), (yyvsp[0].term), NULL); 
                     }
    break;

  case 41:
#line 359 "grammar.y"
    { 
                         (yyval.term) = reduce_term(TERM_TYPE_OF, reduce_constant(count_strings((yyvsp[0].term))), (yyvsp[0].term), NULL); 
                     }
    break;

  case 42:
#line 363 "grammar.y"
    { 
                         (yyval.term) = reduce_term(TERM_TYPE_OF, reduce_constant(1), (yyvsp[0].term), NULL); 
                     }
    break;

  case 43:
#line 366 "grammar.y"
    { (yyval.term) = NULL; }
    break;

  case 44:
#line 367 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 45:
#line 368 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_NOT, (yyvsp[0].term), NULL, NULL); }
    break;

  case 46:
#line 369 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_AND, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 47:
#line 370 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_OR, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 48:
#line 371 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 49:
#line 372 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_LT, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 50:
#line 373 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_GT, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 51:
#line 374 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_LE, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 52:
#line 375 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_GE, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 53:
#line 376 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 54:
#line 377 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 55:
#line 378 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_NOT_EQ, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 56:
#line 382 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 57:
#line 383 "grammar.y"
    { (yyval.term) = reduce_string_with_wildcard(strdup("$*")); }
    break;

  case 59:
#line 388 "grammar.y"
    {
                         (yyval.term) = reduce_string_enumeration((yyvsp[-2].term),(yyvsp[0].term));
                      }
    break;

  case 60:
#line 394 "grammar.y"
    {  
                              (yyval.term) = reduce_string((yyvsp[0].term));

                              if ((yyval.term) == NULL)
                              {
                                  show_last_error();
                                  yynerrs++;
                                  YYERROR;
                              }
                          }
    break;

  case 61:
#line 405 "grammar.y"
    { 
                              (yyval.term) = reduce_string_with_wildcard((yyvsp[0].term)); 
                              
                              if ((yyval.term) == NULL)
                              {
                                  show_last_error();
                                  yynerrs++;
                                  YYERROR;
                              }
                          }
    break;

  case 62:
#line 418 "grammar.y"
    { (yyval.term) = reduce_filesize(); }
    break;

  case 63:
#line 419 "grammar.y"
    { (yyval.term) = reduce_entrypoint(); }
    break;

  case 64:
#line 420 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_INT8_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 65:
#line 421 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_INT16_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 66:
#line 422 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_INT32_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 67:
#line 423 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_UINT8_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 68:
#line 424 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_UINT16_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 69:
#line 425 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_UINT32_AT_OFFSET, (yyvsp[-1].term), NULL, NULL); }
    break;

  case 70:
#line 427 "grammar.y"
    { 
                    (yyval.term) = reduce_string_count((yyvsp[0].term)); 
                    
                    if ((yyval.term) == NULL)
                    {
                        show_last_error();
                        yynerrs++;
                        YYERROR;
                    }
             }
    break;

  case 71:
#line 437 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 72:
#line 438 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_ADD, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 73:
#line 439 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_SUB, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 74:
#line 440 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_MUL, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 75:
#line 441 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_DIV, (yyvsp[-2].term), (yyvsp[0].term), NULL); }
    break;

  case 77:
#line 445 "grammar.y"
    { (yyval.term) = reduce_constant((yyvsp[0].integer)); }
    break;


    }

/* Line 1037 of yacc.c.  */
#line 1908 "grammar.c"

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
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
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
  yyerror ("parser stack overflow");
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


#line 453 "grammar.y"



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


void reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition)
{
    STRING* string;
    
    last_error = new_rule(rule_list, identifier, flags, tag_list_head, string_list_head, condition);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        string = string_list_head;
        
        while (string != NULL)
        {
            if (! (string->flags & STRING_FLAGS_REFERENCED))
            {
                strcpy(last_error_extra_info, string->identifier);
                last_error = ERROR_UNREFERENCED_STRING;
                break;
            }
            
            string = string->next;
        }
    }
}

STRING* reduce_string_declaration(char* identifier, SIZED_STRING* str, int flags)
{
    char tmp[200];
    STRING* string = NULL;
    
    if (strcmp(identifier,"$") == 0)
    {
        flags |= STRING_FLAGS_ANONYMOUS;
    }
    
    last_error = new_string(identifier, str, flags, &string);
    
    if (last_error == ERROR_INVALID_REGULAR_EXPRESSION) 
    {
        sprintf(tmp, "invalid regular expression in string \"%s\": %s", identifier, last_error_extra_info);
        strcpy(last_error_extra_info, tmp);
    }
    else if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    free(str);
            
    return string;
}

STRING* reduce_strings(STRING* string_list_head, STRING* string)
{
    /* no strings with the same identifier, except for anonymous strings */
    
    if (IS_ANONYMOUS(string) || lookup_string(string_list_head,string->identifier) == NULL) 
    {
        string->next = string_list_head;    
        current_rule_strings = string;
        last_error = ERROR_SUCCESS;
        return string;
    }
    else
    {
        strcpy(last_error_extra_info, string->identifier);
        last_error = ERROR_DUPLICATE_STRING_IDENTIFIER;
        return NULL;
    }   
}

TAG* reduce_tags(TAG* tag_list_head, char* identifier)
{
    TAG* tag;

    if (lookup_tag(tag_list_head, identifier) == NULL) /* no tags with the same identifier */
    {
        tag = malloc(sizeof(TAG));
        
        if (tag != NULL)
        {
            tag->identifier = identifier;
            tag->next = tag_list_head;  
            last_error = ERROR_SUCCESS;
        }
        else
        {
            last_error = ERROR_INSUFICIENT_MEMORY;
        }
        
        return tag;
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_error = ERROR_DUPLICATE_TAG_IDENTIFIER;
        return NULL;
    }
}

TERM* reduce_filesize()
{
    TERM* term = NULL;
    
    last_error = new_simple_term(TERM_TYPE_FILESIZE, &term); 
    return (TERM*) term;    
}

TERM* reduce_entrypoint()
{
    TERM* term = NULL;
    
    last_error = new_simple_term(TERM_TYPE_ENTRYPOINT, &term); 
    return (TERM*) term;    
}

TERM* reduce_term(int type, TERM* op1, TERM* op2, TERM* op3)
{
    TERM* term = NULL;
    
    if (op2 == NULL && op3 == NULL)
    {
        last_error = new_unary_operation(type, op1, (TERM_UNARY_OPERATION**) &term);
    }
    else if (op3 == NULL)
    {
        last_error = new_binary_operation(type, op1, op2, (TERM_BINARY_OPERATION**) &term);
    }
    else
    {
        last_error = new_ternary_operation(type, op1, op2, op3, (TERM_TERNARY_OPERATION**) &term);
    }
    
    return (TERM*) term;
}

TERM* reduce_constant(unsigned int constant)
{
    TERM_CONST* term = NULL;
    
    last_error = new_constant(constant, &term); 
    return (TERM*) term;
}

TERM* reduce_string(char* identifier)
{
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || inside_for > 0) 
    {  
        last_error = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, identifier, &term);       
     
        if (last_error != ERROR_SUCCESS)
        {
            strcpy(last_error_extra_info, identifier);
        }
    }
    else
    {
        last_error = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_with_wildcard(char* identifier)
{
    TERM_STRING* term = NULL;
    TERM_STRING* next;
    STRING* string;
    
    int len = 0;

    string = current_rule_strings;
    next = NULL;
    
    while (identifier[len] != '\0' && identifier[len] != '*')
    {
        len++;
    }
    
    while (string != NULL)
    {
        if (strncmp(string->identifier, identifier, len) == 0)
        {
            last_error = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, string->identifier, &term);
            
            if (last_error != ERROR_SUCCESS)
                break;

            term->next = next;
            next = term;            
        }
        
        string = string->next;
    }
    
    free(identifier);
    return (TERM*) term;  
}

TERM* reduce_string_at(char* identifier, TERM* offset)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_AT, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->offset = offset;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->lower_offset = lower_offset;
        term->upper_offset = upper_offset;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name(char* identifier, SIZED_STRING* section_name)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->section_name = strdup(section_name->c_string);
    }
    
    free(section_name);
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_count(char* identifier)
{
    TERM_STRING* term = NULL;

    last_error = new_string_identifier(TERM_TYPE_STRING_COUNT, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    free(identifier);           
    return (TERM*) term;
}

TERM* reduce_rule(char* identifier)
{
    TERM_BINARY_OPERATION* term;
    RULE* rule;
    
    rule = lookup_rule(rule_list, identifier);
    
    if (rule != NULL)
    {
        last_error = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, &term);        
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_error = ERROR_UNDEFINED_RULE;
        term = NULL;
    }
    
    free(identifier);
    return (TERM*) term;
}

TERM* reduce_string_enumeration(TERM* string_list_head, TERM* string_identifier)
{
    TERM_STRING* term = (TERM_STRING*) string_identifier;
    
    term->next = (TERM_STRING*) string_list_head;
    term->string->flags |= STRING_FLAGS_REFERENCED;

    return string_identifier;
}

  







    
    
    
