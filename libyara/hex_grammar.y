/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

%{

#include <string.h>
#include <limits.h>

#include <yara/integers.h>
#include <yara/utils.h>
#include <yara/hex_lexer.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/error.h>


#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define mark_as_not_fast_regexp() \
    ((RE_AST*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_REGEXP

#define fail_if_too_many_ast_levels(cleanup_code) \
    if (((RE_AST*) yyget_extra(yyscanner))->levels++ > RE_MAX_AST_LEVELS) \
    { \
      { cleanup_code } \
      yyerror(yyscanner, lex_env, "string too long"); \
      YYABORT; \
    }

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

%}

%name-prefix "hex_yy"
%pure-parser

%parse-param {void *yyscanner}
%parse-param {HEX_LEX_ENVIRONMENT *lex_env}

%lex-param {yyscan_t yyscanner}
%lex-param {HEX_LEX_ENVIRONMENT *lex_env}

%union {
  int64_t integer;
  RE_NODE *re_node;
}

%token <integer> _BYTE_
%token <integer> _MASKED_BYTE_
%token <integer> _NUMBER_

%type <re_node> tokens
%type <re_node> token_sequence
%type <re_node> token_or_range
%type <re_node> token byte
%type <re_node> alternatives
%type <re_node> range

%destructor { yr_re_node_destroy($$); $$ = NULL; } tokens
%destructor { yr_re_node_destroy($$); $$ = NULL; } token_sequence
%destructor { yr_re_node_destroy($$); $$ = NULL; } token_or_range
%destructor { yr_re_node_destroy($$); $$ = NULL; } token
%destructor { yr_re_node_destroy($$); $$ = NULL; } byte
%destructor { yr_re_node_destroy($$); $$ = NULL; } alternatives
%destructor { yr_re_node_destroy($$); $$ = NULL; } range

%%

hex_string
    : '{' tokens '}'
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->root_node = $2;
      }
    ;


tokens
    : token
      {
        $$ = $1;
      }
    | token token
      {
        fail_if_too_many_ast_levels({
          yr_re_node_destroy($1);
          yr_re_node_destroy($2);
        });

        $$ = yr_re_node_create(RE_NODE_CONCAT, $1, $2);

        destroy_node_if($$ == NULL, $1);
        destroy_node_if($$ == NULL, $2);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | token token_sequence token
      {
        RE_NODE* new_concat;
        RE_NODE* leftmost_concat = NULL;
        RE_NODE* leftmost_node = $2;

        fail_if_too_many_ast_levels({
          yr_re_node_destroy($1);
          yr_re_node_destroy($2);
          yr_re_node_destroy($3);
        });

        $$ = NULL;

        /*
        Some portions of the code (i.e: yr_re_split_at_chaining_point)
        expect a left-unbalanced tree where the right child of a concat node
        can't be another concat node. A concat node must be always the left
        child of its parent if the parent is also a concat. For this reason
        the can't simply create two new concat nodes arranged like this:

                concat
                 /   \
                /     \
            token's    \
            subtree  concat
                     /    \
                    /      \
                   /        \
           token_sequence's  token's
               subtree       subtree

        Instead we must insert the subtree for the first token as the
        leftmost node of the token_sequence subtree.
        */

        while (leftmost_node->type == RE_NODE_CONCAT)
        {
          leftmost_concat = leftmost_node;
          leftmost_node = leftmost_node->left;
        }

        new_concat = yr_re_node_create(
            RE_NODE_CONCAT, $1, leftmost_node);

        if (new_concat != NULL)
        {
          if (leftmost_concat != NULL)
          {
            leftmost_concat->left = new_concat;
            $$ = yr_re_node_create(RE_NODE_CONCAT, $2, $3);
          }
          else
          {
            $$ = yr_re_node_create(RE_NODE_CONCAT, new_concat, $3);
          }
        }

        destroy_node_if($$ == NULL, $1);
        destroy_node_if($$ == NULL, $2);
        destroy_node_if($$ == NULL, $3);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    ;


token_sequence
    : token_or_range
      {
        $$ = $1;
      }
    | token_sequence token_or_range
      {
        fail_if_too_many_ast_levels({
          yr_re_node_destroy($1);
          yr_re_node_destroy($2);
        });

        $$ = yr_re_node_create(RE_NODE_CONCAT, $1, $2);

        destroy_node_if($$ == NULL, $1);
        destroy_node_if($$ == NULL, $2);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    ;


token_or_range
    : token
      {
        $$ = $1;
      }
    |  range
      {
        $$ = $1;
        $$->greedy = false;
      }
    ;


token
    : byte
      {
        $$ = $1;
      }
    | '('
      {
        lex_env->inside_or++;
      }
      alternatives ')'
      {
        $$ = $3;
        lex_env->inside_or--;
      }
    ;


range
    : '[' _NUMBER_ ']'
      {
        if ($2 <= 0)
        {
          yyerror(yyscanner, lex_env, "invalid jump length");
          YYABORT;
        }

        if (lex_env->inside_or && $2 > YR_STRING_CHAINING_THRESHOLD)
        {
          yyerror(yyscanner, lex_env, "jumps over "
              STR(YR_STRING_CHAINING_THRESHOLD)
              " now allowed inside alternation (|)");
          YYABORT;
        }

        $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = (int) $2;
        $$->end = (int) $2;
      }
    | '[' _NUMBER_ '-' _NUMBER_ ']'
      {
        if (lex_env->inside_or &&
            ($2 > YR_STRING_CHAINING_THRESHOLD ||
             $4 > YR_STRING_CHAINING_THRESHOLD) )
        {
          yyerror(yyscanner, lex_env, "jumps over "
              STR(YR_STRING_CHAINING_THRESHOLD)
              " now allowed inside alternation (|)");

          YYABORT;
        }

        if ($2 < 0 || $4 < 0)
        {
          yyerror(yyscanner, lex_env, "invalid negative jump length");
          YYABORT;
        }

        if ($2 > $4)
        {
          yyerror(yyscanner, lex_env, "invalid jump range");
          YYABORT;
        }

        $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = (int) $2;
        $$->end = (int) $4;
      }
    | '[' _NUMBER_ '-' ']'
      {
        if (lex_env->inside_or)
        {
          yyerror(yyscanner, lex_env,
              "unbounded jumps not allowed inside alternation (|)");
          YYABORT;
        }

        if ($2 < 0)
        {
          yyerror(yyscanner, lex_env, "invalid negative jump length");
          YYABORT;
        }

        $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = (int) $2;
        $$->end = INT_MAX;
      }
    | '[' '-' ']'
      {
        if (lex_env->inside_or)
        {
          yyerror(yyscanner, lex_env,
              "unbounded jumps not allowed inside alternation (|)");
          YYABORT;
        }

        $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = 0;
        $$->end = INT_MAX;
      }
    ;


alternatives
    : tokens
      {
          $$ = $1;
      }
    | alternatives '|' tokens
      {
        mark_as_not_fast_regexp();

        fail_if_too_many_ast_levels({
          yr_re_node_destroy($1);
          yr_re_node_destroy($3);
        });

        $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);

        destroy_node_if($$ == NULL, $1);
        destroy_node_if($$ == NULL, $3);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    ;

byte
    : _BYTE_
      {
        $$ = yr_re_node_create(RE_NODE_LITERAL, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->value = (int) $1;
      }
    | _MASKED_BYTE_
      {
        uint8_t mask = (uint8_t) ($1 >> 8);

        if (mask == 0x00)
        {
          $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
        }
        else
        {
          $$ = yr_re_node_create(RE_NODE_MASKED_LITERAL, NULL, NULL);

          fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

          $$->value = $1 & 0xFF;
          $$->mask = mask;
        }
      }
    ;

%%