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
     _NUMBER_ = 267,
     _UNKNOWN_ = 268,
     _TEXTSTRING_ = 269,
     _HEXSTRING_ = 270,
     _REGEXP_ = 271,
     _ASCII_ = 272,
     _WIDE_ = 273,
     _NOCASE_ = 274,
     _FULLWORD_ = 275,
     _AT_ = 276,
     _SIZE_ = 277,
     _ENTRYPOINT_ = 278,
     _RVA_ = 279,
     _OFFSET_ = 280,
     _FILE_ = 281,
     _IN_ = 282,
     _OF_ = 283,
     _THEM_ = 284,
     _SECTION_ = 285,
     _MZ_ = 286,
     _PE_ = 287,
     _DLL_ = 288,
     _TRUE_ = 289,
     _FALSE_ = 290,
     _OR_ = 291,
     _AND_ = 292,
     _NOT_ = 293,
     _IS_ = 294,
     _NEQ_ = 295,
     _EQ_ = 296,
     _GE_ = 297,
     _GT_ = 298,
     _LE_ = 299,
     _LT_ = 300
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
#define _NUMBER_ 267
#define _UNKNOWN_ 268
#define _TEXTSTRING_ 269
#define _HEXSTRING_ 270
#define _REGEXP_ 271
#define _ASCII_ 272
#define _WIDE_ 273
#define _NOCASE_ 274
#define _FULLWORD_ 275
#define _AT_ 276
#define _SIZE_ 277
#define _ENTRYPOINT_ 278
#define _RVA_ 279
#define _OFFSET_ 280
#define _FILE_ 281
#define _IN_ 282
#define _OF_ 283
#define _THEM_ 284
#define _SECTION_ 285
#define _MZ_ 286
#define _PE_ 287
#define _DLL_ 288
#define _TRUE_ 289
#define _FALSE_ 290
#define _OR_ 291
#define _AND_ 292
#define _NOT_ 293
#define _IS_ 294
#define _NEQ_ 295
#define _EQ_ 296
#define _GE_ 297
#define _GT_ 298
#define _LE_ 299
#define _LT_ 300




/* Copy the first part of user declarations.  */
#line 2 "grammar.y"
 
    
#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "error.h"
#include "compile.h"
#include "sizedstr.h"

#define YYERROR_VERBOSE



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
#line 77 "grammar.y"
typedef union YYSTYPE {
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;

} YYSTYPE;
/* Line 190 of yacc.c.  */
#line 191 "grammar.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */
#line 91 "grammar.y"
 
    
/* Global variables */

STRING* current_rule_strings;

/* Function declarations */

void reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition);
TAG* reduce_tags(TAG* tag_list_head, char* identifier);

STRING* reduce_string_declaration(char* identifier, SIZED_STRING* str, int flags);
STRING* reduce_strings(STRING* string_list_head, STRING* string);

TERM* reduce_string(char* identifier);
TERM* reduce_string_at(char* identifier, TERM* offset);
TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset);
TERM* reduce_string_in_section_by_name(char* identifier, SIZED_STRING* section_name);
TERM* reduce_string_count(char* identifier);

TERM* reduce_filesize();
TERM* reduce_entrypoint();
TERM* reduce_term(int type, TERM* op1, TERM* op2);
TERM* reduce_constant(unsigned int constant);
TERM* reduce_rule(char* identifier);
TERM* reduce_boolean_expression_list(TERM* boolean_expression_list_head, TERM* boolean_expression);
TERM* reduce_n_of_them(TERM* n);



/* Line 213 of yacc.c.  */
#line 232 "grammar.c"

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
#define YYLAST   164

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  60
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  17
/* YYNRULES -- Number of rules. */
#define YYNRULES  64
/* YYNRULES -- Number of states. */
#define YYNSTATES  121

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   300

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      57,    58,    48,    46,    59,    47,    55,    49,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    52,     2,
       2,    53,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    54,     2,    56,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    51,     2,    50,     2,     2,     2,     2,
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
      45
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     7,    11,    21,    34,    35,    38,
      40,    42,    43,    46,    48,    51,    53,    56,    61,    66,
      70,    71,    74,    76,    78,    80,    82,    84,    86,    88,
      90,    94,    99,   108,   115,   119,   123,   126,   130,   134,
     138,   142,   146,   150,   154,   158,   162,   166,   170,   174,
     178,   180,   184,   186,   188,   190,   194,   198,   202,   206,
     210,   212,   214,   216,   218
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      61,     0,    -1,    -1,    61,    62,    -1,    61,     1,    50,
      -1,    63,     3,     9,    65,    51,     7,    52,    71,    50,
      -1,    63,     3,     9,    65,    51,     6,    52,    67,     7,
      52,    71,    50,    -1,    -1,    63,    64,    -1,     4,    -1,
       5,    -1,    -1,    52,    66,    -1,     9,    -1,    66,     9,
      -1,    68,    -1,    67,    68,    -1,    10,    53,    14,    69,
      -1,    10,    53,    16,    69,    -1,    10,    53,    15,    -1,
      -1,    69,    70,    -1,    18,    -1,    17,    -1,    19,    -1,
      20,    -1,    34,    -1,    35,    -1,     9,    -1,    10,    -1,
      10,    21,    74,    -1,    10,    21,    24,    74,    -1,    10,
      27,    54,    74,    55,    55,    74,    56,    -1,    10,    27,
      30,    54,    14,    56,    -1,    26,    39,    76,    -1,    57,
      71,    58,    -1,    38,    71,    -1,    71,    37,    71,    -1,
      71,    36,    71,    -1,    71,    39,    71,    -1,    74,    45,
      74,    -1,    74,    43,    74,    -1,    74,    44,    74,    -1,
      74,    42,    74,    -1,    74,    41,    74,    -1,    74,    39,
      74,    -1,    74,    40,    74,    -1,    75,    28,    72,    -1,
      75,    28,    29,    -1,    57,    73,    58,    -1,    71,    -1,
      73,    59,    71,    -1,    22,    -1,    23,    -1,    11,    -1,
      57,    74,    58,    -1,    74,    46,    74,    -1,    74,    47,
      74,    -1,    74,    48,    74,    -1,    74,    49,    74,    -1,
      75,    -1,    12,    -1,    31,    -1,    32,    -1,    33,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short int yyrline[] =
{
       0,   123,   123,   124,   133,   136,   137,   140,   141,   144,
     145,   148,   149,   152,   162,   174,   184,   196,   207,   218,
     231,   232,   235,   236,   237,   238,   241,   242,   243,   254,
     265,   275,   279,   290,   301,   302,   303,   304,   305,   306,
     307,   308,   309,   310,   311,   312,   313,   314,   315,   318,
     321,   325,   331,   332,   333,   344,   345,   346,   347,   348,
     349,   352,   355,   356,   357
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_STRINGS_", "_CONDITION_", "_END_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_NUMBER_", "_UNKNOWN_",
  "_TEXTSTRING_", "_HEXSTRING_", "_REGEXP_", "_ASCII_", "_WIDE_",
  "_NOCASE_", "_FULLWORD_", "_AT_", "_SIZE_", "_ENTRYPOINT_", "_RVA_",
  "_OFFSET_", "_FILE_", "_IN_", "_OF_", "_THEM_", "_SECTION_", "_MZ_",
  "_PE_", "_DLL_", "_TRUE_", "_FALSE_", "_OR_", "_AND_", "_NOT_", "_IS_",
  "_NEQ_", "_EQ_", "_GE_", "_GT_", "_LE_", "_LT_", "'+'", "'-'", "'*'",
  "'/'", "'}'", "'{'", "':'", "'='", "'['", "'.'", "']'", "'('", "')'",
  "','", "$accept", "rules", "rule", "rule_modifiers", "rule_modifier",
  "tags", "tag_list", "strings", "string_declaration", "string_modifiers",
  "string_modifier", "boolean_expression", "boolean_expression_list",
  "boolean_expressions", "expression", "number", "type", 0
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
     295,   296,   297,   298,   299,   300,    43,    45,    42,    47,
     125,   123,    58,    61,    91,    46,    93,    40,    41,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    60,    61,    61,    61,    62,    62,    63,    63,    64,
      64,    65,    65,    66,    66,    67,    67,    68,    68,    68,
      69,    69,    70,    70,    70,    70,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    72,
      73,    73,    74,    74,    74,    74,    74,    74,    74,    74,
      74,    75,    76,    76,    76
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     2,     3,     9,    12,     0,     2,     1,
       1,     0,     2,     1,     2,     1,     2,     4,     4,     3,
       0,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     4,     8,     6,     3,     3,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       1,     3,     1,     1,     1,     3,     3,     3,     3,     3,
       1,     1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     0,     1,     0,     3,     0,     4,     0,     9,    10,
       8,    11,     0,     0,    13,    12,     0,    14,     0,     0,
       0,     0,     0,     0,    15,    28,    29,    54,    61,    52,
      53,     0,    26,    27,     0,     0,     0,     0,    60,     0,
       0,    16,     0,     0,     0,    36,     0,     0,     0,     0,
       0,     5,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    20,    19,    20,     0,     0,     0,
      30,    60,     0,     0,    62,    63,    64,    34,    35,    55,
      38,    37,    39,    45,    46,    44,    43,    41,    42,    40,
      56,    57,    58,    59,    48,     0,    47,    17,    18,     0,
      31,     0,     0,     0,    50,     0,    23,    22,    24,    25,
      21,     6,     0,     0,    49,     0,    33,     0,    51,     0,
      32
};

/* YYDEFGOTO[NTERM-NUM]. */
static const yysigned_char yydefgoto[] =
{
      -1,     1,     4,     5,    10,    13,    15,    23,    24,    97,
     110,    36,    96,   105,    37,    71,    77
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -50
static const short int yypact[] =
{
     -50,   115,   -50,   -49,   -50,   150,   -50,     3,   -50,   -50,
     -50,   -31,    14,    -1,   -50,    43,   137,   -50,     9,    11,
      67,    46,    22,    72,   -50,   -50,    49,   -50,   -50,   -50,
     -50,    44,   -50,   -50,    46,    46,    23,    85,    57,   142,
      38,   -50,    -6,   -23,   128,    78,     8,    65,    46,    46,
      46,   -50,    -3,    -3,    -3,    -3,    -3,    -3,    -3,    -3,
      -3,    -3,    -3,   -27,   -50,   -50,   -50,    46,    -3,    -3,
      53,   -50,    42,    -3,   -50,   -50,   -50,   -50,   -50,   -50,
      78,    78,   -50,    53,    53,    53,    53,    53,    53,    53,
     -45,   -45,   -50,   -50,   -50,    46,   -50,   132,   132,    28,
      53,    40,   133,    93,    56,    63,   -50,   -50,   -50,   -50,
     -50,   -50,    90,   107,   -50,    46,   -50,    -3,    56,    89,
     -50
};

/* YYPGOTO[NTERM-NUM].  */
static const short int yypgoto[] =
{
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   140,    98,
     -50,   -24,   -50,   -50,   -20,   -21,   -50
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -8
static const yysigned_char yytable[] =
{
      38,     6,    94,    61,    62,    27,    28,    72,    27,    28,
      45,    46,    11,    38,    38,    47,    29,    30,    68,    29,
      30,    12,    70,    14,    80,    81,    82,    38,    38,    38,
      95,    73,    83,    84,    85,    86,    87,    88,    89,    90,
      91,    92,    93,    99,    48,    49,    38,    50,   100,   101,
      16,    69,    17,   103,    69,    25,    26,    27,    28,    48,
      49,    20,    50,    21,    48,    49,    78,    50,    29,    30,
      42,   104,    31,    51,    38,    39,    43,    22,   111,    40,
      32,    33,    22,    44,    34,    63,    59,    60,    61,    62,
      67,   118,    48,    49,    38,    50,   102,   119,    79,    59,
      60,    61,    62,    35,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,     2,     3,    50,    -7,    -7,
      -7,   114,   115,    79,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    59,    60,    61,    62,    59,
      60,    61,    62,    18,    19,   120,   116,   112,   113,   106,
     107,   108,   109,     7,     8,     9,    64,    65,    66,    74,
      75,    76,   117,    41,    98
};

static const unsigned char yycheck[] =
{
      21,    50,    29,    48,    49,    11,    12,    30,    11,    12,
      34,    35,     9,    34,    35,    35,    22,    23,    24,    22,
      23,    52,    42,     9,    48,    49,    50,    48,    49,    50,
      57,    54,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    67,    36,    37,    67,    39,    68,    69,
      51,    57,     9,    73,    57,     9,    10,    11,    12,    36,
      37,    52,    39,    52,    36,    37,    58,    39,    22,    23,
      21,    95,    26,    50,    95,    53,    27,    10,    50,     7,
      34,    35,    10,    39,    38,    28,    46,    47,    48,    49,
      52,   115,    36,    37,   115,    39,    54,   117,    58,    46,
      47,    48,    49,    57,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,     0,     1,    39,     3,     4,
       5,    58,    59,    58,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    46,    47,    48,    49,    46,
      47,    48,    49,     6,     7,    56,    56,    14,    55,    17,
      18,    19,    20,     3,     4,     5,    14,    15,    16,    31,
      32,    33,    55,    23,    66
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    61,     0,     1,    62,    63,    50,     3,     4,     5,
      64,     9,    52,    65,     9,    66,    51,     9,     6,     7,
      52,    52,    10,    67,    68,     9,    10,    11,    12,    22,
      23,    26,    34,    35,    38,    57,    71,    74,    75,    53,
       7,    68,    21,    27,    39,    71,    71,    74,    36,    37,
      39,    50,    39,    40,    41,    42,    43,    44,    45,    46,
      47,    48,    49,    28,    14,    15,    16,    52,    24,    57,
      74,    75,    30,    54,    31,    32,    33,    76,    58,    58,
      71,    71,    71,    74,    74,    74,    74,    74,    74,    74,
      74,    74,    74,    74,    29,    57,    72,    69,    69,    71,
      74,    74,    54,    74,    71,    73,    17,    18,    19,    20,
      70,    50,    14,    55,    58,    59,    56,    55,    71,    74,
      56
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
#line 88 "grammar.y"
        { free ((yyvaluep->c_string)); };
#line 958 "grammar.c"
        break;
      case 14: /* _TEXTSTRING_ */
#line 88 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 963 "grammar.c"
        break;
      case 15: /* _HEXSTRING_ */
#line 88 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 968 "grammar.c"
        break;
      case 16: /* _REGEXP_ */
#line 88 "grammar.y"
        { free ((yyvaluep->sized_string)); };
#line 973 "grammar.c"
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
#line 125 "grammar.y"
    {
            if (last_error != ERROR_SUCCESS)
            {
                show_last_error();
                yynerrs++;
                YYERROR;
            }
      }
    break;

  case 5:
#line 136 "grammar.y"
    { reduce_rule_declaration((yyvsp[-6].c_string),(yyvsp[-8].integer),(yyvsp[-5].tag),0,(yyvsp[-1].term));    }
    break;

  case 6:
#line 137 "grammar.y"
    { reduce_rule_declaration((yyvsp[-9].c_string),(yyvsp[-11].integer),(yyvsp[-8].tag),(yyvsp[-4].string),(yyvsp[-1].term));  }
    break;

  case 7:
#line 140 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 8:
#line 141 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 9:
#line 144 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_PRIVATE; }
    break;

  case 10:
#line 145 "grammar.y"
    { (yyval.integer) = RULE_FLAGS_GLOBAL; }
    break;

  case 11:
#line 148 "grammar.y"
    { (yyval.tag) = NULL; }
    break;

  case 12:
#line 149 "grammar.y"
    { (yyval.tag) = (yyvsp[0].tag);   }
    break;

  case 13:
#line 152 "grammar.y"
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
#line 162 "grammar.y"
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
#line 174 "grammar.y"
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
#line 184 "grammar.y"
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
#line 197 "grammar.y"
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
#line 208 "grammar.y"
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
#line 219 "grammar.y"
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
#line 231 "grammar.y"
    { (yyval.integer) = 0;  }
    break;

  case 21:
#line 232 "grammar.y"
    { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
    break;

  case 22:
#line 235 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_WIDE; }
    break;

  case 23:
#line 236 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_ASCII; }
    break;

  case 24:
#line 237 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_NO_CASE; }
    break;

  case 25:
#line 238 "grammar.y"
    { (yyval.integer) = STRING_FLAGS_FULL_WORD; }
    break;

  case 26:
#line 241 "grammar.y"
    { (yyval.term) = reduce_constant(1); }
    break;

  case 27:
#line 242 "grammar.y"
    { (yyval.term) = reduce_constant(0); }
    break;

  case 28:
#line 244 "grammar.y"
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
#line 255 "grammar.y"
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
#line 266 "grammar.y"
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
#line 276 "grammar.y"
    { 
                        (yyval.term) = NULL; 
                     }
    break;

  case 32:
#line 280 "grammar.y"
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
#line 291 "grammar.y"
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
#line 301 "grammar.y"
    { (yyval.term) = NULL; }
    break;

  case 35:
#line 302 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 36:
#line 303 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_NOT, (yyvsp[0].term), NULL); }
    break;

  case 37:
#line 304 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_AND, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 38:
#line 305 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_OR, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 39:
#line 306 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 40:
#line 307 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_LT, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 41:
#line 308 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_GT, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 42:
#line 309 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_LE, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 43:
#line 310 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_GE, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 44:
#line 311 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 45:
#line 312 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_EQ, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 46:
#line 313 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_NOT_EQ, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 47:
#line 314 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_OF, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 48:
#line 315 "grammar.y"
    { (yyval.term) = reduce_n_of_them((yyvsp[-2].term)); }
    break;

  case 49:
#line 318 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 50:
#line 322 "grammar.y"
    {
                         (yyval.term) = reduce_boolean_expression_list(NULL,(yyvsp[0].term));
                      }
    break;

  case 51:
#line 326 "grammar.y"
    {
                         (yyval.term) = reduce_boolean_expression_list((yyvsp[-2].term),(yyvsp[0].term));
                      }
    break;

  case 52:
#line 331 "grammar.y"
    { (yyval.term) = reduce_filesize(); }
    break;

  case 53:
#line 332 "grammar.y"
    { (yyval.term) = reduce_entrypoint(); }
    break;

  case 54:
#line 334 "grammar.y"
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

  case 55:
#line 344 "grammar.y"
    { (yyval.term) = (yyvsp[-1].term); }
    break;

  case 56:
#line 345 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_ADD, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 57:
#line 346 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_SUB, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 58:
#line 347 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_MUL, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 59:
#line 348 "grammar.y"
    { (yyval.term) = reduce_term(TERM_TYPE_DIV, (yyvsp[-2].term), (yyvsp[0].term)); }
    break;

  case 61:
#line 352 "grammar.y"
    { (yyval.term) = reduce_constant((yyvsp[0].integer)); }
    break;


    }

/* Line 1037 of yacc.c.  */
#line 1696 "grammar.c"

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


#line 360 "grammar.y"



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
    if (lookup_string(string_list_head,string->identifier) == NULL) /* no strings with the same identifier */
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

TERM* reduce_term(int type, TERM* op1, TERM* op2)
{
    TERM_BINARY_OPERATION* term = NULL;
    
    last_error = new_binary_operation(type, op1, op2, &term);
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
    
    last_error = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
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

TERM* reduce_boolean_expression_list(TERM* boolean_expression_list_head, TERM* boolean_expression)
{
    boolean_expression->next = boolean_expression_list_head;
    return boolean_expression;
}

TERM* reduce_n_of_them(TERM* n)
{
    STRING* string;
    TERM_BINARY_OPERATION* term;
    
    last_error = new_binary_operation(TERM_TYPE_OF_THEM, n, NULL, &term);
    
    /* the keyword THEM implicitly references all the strings 
       on the rule, so let's flag them as referenced */
    
    string = current_rule_strings;
    
    while (string != NULL)
    {
        string->flags |= STRING_FLAGS_REFERENCED;
        string = string->next;
    }
    
    return (TERM*) term;  
}


    
    
    
