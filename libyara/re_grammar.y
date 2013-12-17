/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

%{

#include <stdint.h>

#include "mem.h"
#include "re_lexer.h"
#include "re.h"

#include "config.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define YYERROR_VERBOSE


#define YYDEBUG 0

#if YYDEBUG
yydebug = 1;
#endif

#define ERROR_IF(x, error) \
    if (x) \
    { \
      RE* re = yyget_extra(yyscanner); \
      re->error_code = error; \
      YYABORT; \
    } \

#define DESTROY_NODE_IF(x, node) \
    if (x) \
    { \
      yr_re_node_destroy(node); \
    } \

%}

%debug

%name-prefix="re_yy"
%pure-parser

%parse-param {void *yyscanner}
%parse-param {LEX_ENVIRONMENT *lex_env}

%lex-param {yyscan_t yyscanner}
%lex-param {LEX_ENVIRONMENT *lex_env}

%union {
  int integer;
  uint32_t range;
  RE_NODE* re_node;
  uint8_t* class_vector;
}


%token <integer> _CHAR_ _ANY_
%token <range> _RANGE_
%token <class_vector> _CLASS_

%token _WORD_CHAR_
%token _NON_WORD_CHAR_
%token _SPACE_
%token _NON_SPACE_
%token _DIGIT_
%token _NON_DIGIT_

%type <re_node>  alternative concatenation repeat single

%destructor { yr_free($$); } _CLASS_
%destructor { yr_re_node_destroy($$); } alternative
%destructor { yr_re_node_destroy($$); } concatenation
%destructor { yr_re_node_destroy($$); } repeat
%destructor { yr_re_node_destroy($$); } single

%%

re : alternative
     {
        RE* re = yyget_extra(yyscanner);
        re->root_node = $1;
     }
   | error
   ;

alternative : concatenation
              {
                $$ = $1;
              }
            | alternative '|' concatenation
              {
                $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);

                DESTROY_NODE_IF($$ == NULL, $1);
                DESTROY_NODE_IF($$ == NULL, $3);

                ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
              }
            | alternative '|'
              {
                RE_NODE* node;

                node = yr_re_node_create(RE_NODE_EMPTY, NULL, NULL);

                DESTROY_NODE_IF($$ == NULL, $1);
                ERROR_IF(node == NULL, ERROR_INSUFICIENT_MEMORY);

                $$ = yr_re_node_create(RE_NODE_ALT, $1, node);

                ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
              }
            ;

concatenation : repeat
                {
                  $$ = $1;
                }
              | concatenation repeat
                {
                  $$ = yr_re_node_create(RE_NODE_CONCAT, $1, $2);

                  DESTROY_NODE_IF($$ == NULL, $1);
                  DESTROY_NODE_IF($$ == NULL, $2);
                  ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
                }
              ;

repeat : single '*'
         {
            $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | single '*' '?'
         {
            $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->greedy = FALSE;
         }
       | single '+'
         {
            $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | single '+' '?'
         {
            $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->greedy = FALSE;
         }
       | single '?'
         {
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->start = 0;
            $$->end = 1;
         }
       | single '?' '?'
         {
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->start = 0;
            $$->end = 1;
            $$->greedy = FALSE;
         }
       | single _RANGE_
         {
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);

            DESTROY_NODE_IF($$ == NULL, $1);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->start = $2 & 0xFFFF;;
            $$->end = $2 >> 16;;
         }
       | single
         {
            $$ = $1;
         }
       | '^'
         {
            $$ = yr_re_node_create(RE_NODE_ANCHOR_START, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | '$'
         {
            $$ = yr_re_node_create(RE_NODE_ANCHOR_END, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       ;

single : '(' alternative ')'
         {
            $$ = $2;
         }
       | '.'
         {
            $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _CHAR_
         {
            $$ = yr_re_node_create(RE_NODE_LITERAL, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->value = $1;
         }
       | _WORD_CHAR_
         {
            $$ = yr_re_node_create(RE_NODE_WORD_CHAR, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _NON_WORD_CHAR_
         {
            $$ = yr_re_node_create(RE_NODE_NON_WORD_CHAR, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _SPACE_
         {
            $$ = yr_re_node_create(RE_NODE_SPACE, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _NON_SPACE_
         {
            $$ = yr_re_node_create(RE_NODE_NON_SPACE, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _DIGIT_
         {
            $$ = yr_re_node_create(RE_NODE_DIGIT, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _NON_DIGIT_
         {
            $$ = yr_re_node_create(RE_NODE_NON_DIGIT, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       | _CLASS_
         {
            $$ = yr_re_node_create(RE_NODE_CLASS, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->class_vector = $1;
         }
       ;


%%
















