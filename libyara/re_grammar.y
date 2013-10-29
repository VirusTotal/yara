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

#define YYERROR_VERBOSE


#define YYDEBUG 0

#if YYDEBUG
yydebug = 1;
#endif


#define mark_as_not_literal() \
    ((RE*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_LITERAL_STRING
                
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

%destructor { yr_free($$); } _CLASS_


%type <re_node>  alternative concatenation repeat single

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
                mark_as_not_literal();
                $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);
              }
            ;

concatenation : repeat
                {
                  $$ = $1;
                }
              | concatenation repeat
                {
                  $$ = yr_re_node_create(RE_NODE_CONCAT, $1, $2);
                }
              ;

repeat : single '*'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);
         }
       | single '*' '?'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_STAR, $1, NULL);
            $$->greedy = FALSE;
         }
       | single '+'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);
         }
       | single '+' '?'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_PLUS, $1, NULL);
            $$->greedy = FALSE;
         }
       | single '?'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
            $$->start = 0;
            $$->end = 1;
         }  
       | single '?' '?'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
            $$->start = 0;
            $$->end = 1;
            $$->greedy = FALSE;
         } 
       | single _RANGE_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_RANGE, $1, NULL);
            $$->start = $2 & 0xFFFF;;
            $$->end = $2 >> 16;;
         }
       | single 
         {
            $$ = $1;
         }
       ;

single : '(' alternative ')'
         {
            $$ = $2;
         }
       | '.'
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);
         }
       | _CHAR_
         {
            RE* re = yyget_extra(yyscanner);

            $$ = yr_re_node_create(RE_NODE_LITERAL, NULL, NULL);
            $$->value = $1;

            if (re->literal_string_len == re->literal_string_max)
            {
              re->literal_string_max *= 2;
              re->literal_string = yr_realloc(
                  re->literal_string,
                  re->literal_string_max);

              if (re->literal_string == NULL)
              {
                //TODO
              }
            }

            re->literal_string[re->literal_string_len] = $1;
            re->literal_string_len++;
         }
       | _WORD_CHAR_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_WORD_CHAR, NULL, NULL);
         }
       | _NON_WORD_CHAR_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_NON_WORD_CHAR, NULL, NULL);
         }
       | _SPACE_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_SPACE, NULL, NULL);
         }
       | _NON_SPACE_
         {  
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_NON_SPACE, NULL, NULL);
         }
       | _DIGIT_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_DIGIT, NULL, NULL);
         }
       | _NON_DIGIT_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_NON_DIGIT, NULL, NULL);
         }
       | _CLASS_
         {
            mark_as_not_literal();
            $$ = yr_re_node_create(RE_NODE_CLASS, NULL, NULL);
            $$->class_vector = $1;
         }
       ;


%%
















