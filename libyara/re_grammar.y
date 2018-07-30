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

#define fail_if_too_many_ast_levels(cleanup_code) \
    if (((RE_AST*) yyget_extra(yyscanner))->levels++ > RE_MAX_AST_LEVELS) \
    { \
      { cleanup_code } \
      yyerror(yyscanner, lex_env, "regexp too long"); \
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

%name-prefix "re_yy"
%pure-parser

%parse-param {void *yyscanner}
%parse-param {RE_LEX_ENVIRONMENT *lex_env}

%lex-param {yyscan_t yyscanner}
%lex-param {RE_LEX_ENVIRONMENT *lex_env}

%union {
  int integer;
  uint32_t range;
  RE_NODE* re_node;
  RE_CLASS* re_class;
}


%token <integer> _CHAR_ _ANY_
%token <range> _RANGE_
%token <re_class> _CLASS_

%token _WORD_CHAR_
%token _NON_WORD_CHAR_
%token _SPACE_
%token _NON_SPACE_
%token _DIGIT_
%token _NON_DIGIT_
%token _WORD_BOUNDARY_
%token _NON_WORD_BOUNDARY_

%type <re_node>  alternative concatenation repeat single

%destructor { yr_free($$); $$ = NULL; } _CLASS_
%destructor { yr_re_node_destroy($$); $$ = NULL; } alternative
%destructor { yr_re_node_destroy($$); $$ = NULL; } concatenation
%destructor { yr_re_node_destroy($$); $$ = NULL; } repeat
%destructor { yr_re_node_destroy($$); $$ = NULL; } single

%%

re  : alternative
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->root_node = $1;
      }
    | error
    ;

alternative
    : concatenation
      {
        $$ = $1;
      }
    | alternative '|' concatenation
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
    | alternative '|'
      {
        RE_NODE* node;

        mark_as_not_fast_regexp();

        fail_if_too_many_ast_levels({
          yr_re_node_destroy($1);
        });

        node = yr_re_node_create(RE_NODE_EMPTY, NULL, NULL);

        destroy_node_if($$ == NULL, $1);
        fail_if(node == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$ = yr_re_node_create(RE_NODE_ALT, $1, node);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    ;

concatenation
    : repeat
      {
        $$ = $1;
      }
    | concatenation repeat
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

repeat
    : single '*'
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);

        destroy_node_if($$ == NULL, $1);
        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | single '*' '?'
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);

        destroy_node_if($$ == NULL, $1);
        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->greedy = false;
      }
    | single '+'
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);

        destroy_node_if($$ == NULL, $1);
        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | single '+' '?'
      {
        RE_AST* re_ast;

        mark_as_not_fast_regexp();

        re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);

        destroy_node_if($$ == NULL, $1);
        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->greedy = false;
      }
    | single '?'
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        if ($1->type == RE_NODE_ANY)
        {
          $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);
          destroy_node_if(true, $1);
        }
        else
        {
          mark_as_not_fast_regexp();
          $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
          destroy_node_if($$ == NULL, $1);
        }

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = 0;
        $$->end = 1;
      }
    | single '?' '?'
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        if ($1->type == RE_NODE_ANY)
        {
          $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);
          destroy_node_if(true, $1);
        }
        else
        {
          mark_as_not_fast_regexp();
          $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
          destroy_node_if($$ == NULL, $1);
        }

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = 0;
        $$->end = 1;
        $$->greedy = false;
      }
    | single _RANGE_
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_GREEDY;

        if ($1->type == RE_NODE_ANY)
        {
          $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);
          destroy_node_if(true, $1);
        }
        else
        {
          mark_as_not_fast_regexp();
          $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
          destroy_node_if($$ == NULL, $1);
        }

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = $2 & 0xFFFF;;
        $$->end = $2 >> 16;;
      }
    | single _RANGE_ '?'
      {
        RE_AST* re_ast = yyget_extra(yyscanner);
        re_ast->flags |= RE_FLAGS_UNGREEDY;

        if ($1->type == RE_NODE_ANY)
        {
          $$ = yr_re_node_create(RE_NODE_RANGE_ANY, NULL, NULL);
          destroy_node_if(true, $1);
        }
        else
        {
          mark_as_not_fast_regexp();
          $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
          destroy_node_if($$ == NULL, $1);
        }

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->start = $2 & 0xFFFF;;
        $$->end = $2 >> 16;;
        $$->greedy = false;
      }
    | single
      {
        $$ = $1;
      }
    | _WORD_BOUNDARY_
      {
        $$ = yr_re_node_create(RE_NODE_WORD_BOUNDARY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _NON_WORD_BOUNDARY_
      {
        $$ = yr_re_node_create(RE_NODE_NON_WORD_BOUNDARY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | '^'
      {
        $$ = yr_re_node_create(RE_NODE_ANCHOR_START, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | '$'
      {
        $$ = yr_re_node_create(RE_NODE_ANCHOR_END, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    ;

single
    : '(' alternative ')'
      {
        fail_if_too_many_ast_levels({
          yr_re_node_destroy($2);
        });

        $$ = $2;
      }
    | '.'
      {
        $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _CHAR_
      {
        $$ = yr_re_node_create(RE_NODE_LITERAL, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->value = $1;
      }
    | _WORD_CHAR_
      {
        $$ = yr_re_node_create(RE_NODE_WORD_CHAR, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _NON_WORD_CHAR_
      {
        $$ = yr_re_node_create(RE_NODE_NON_WORD_CHAR, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _SPACE_
      {
        $$ = yr_re_node_create(RE_NODE_SPACE, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _NON_SPACE_
      {
         $$ = yr_re_node_create(RE_NODE_NON_SPACE, NULL, NULL);

         fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _DIGIT_
      {
        $$ = yr_re_node_create(RE_NODE_DIGIT, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _NON_DIGIT_
      {
        $$ = yr_re_node_create(RE_NODE_NON_DIGIT, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);
      }
    | _CLASS_
      {
        $$ = yr_re_node_create(RE_NODE_CLASS, NULL, NULL);

        fail_if($$ == NULL, ERROR_INSUFFICIENT_MEMORY);

        $$->re_class = $1;
      }
    ;
%%
