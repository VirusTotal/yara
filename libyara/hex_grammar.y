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

#include "hex_lexer.h"
#include "mem.h"
#include "re.h"

#define YYERROR_VERBOSE

#define YYDEBUG 0

#define mark_as_not_literal() \ 
    ((RE*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_LITERAL_STRING

#if YYDEBUG
yydebug = 1;
#endif

%}

%debug

%name-prefix="hex_yy"
%pure-parser
%parse-param {void *yyscanner}
%lex-param {yyscan_t yyscanner}

%union {
  int integer;
  RE_NODE *re_node;
}

%token <integer> _BYTE_ 
%token <integer> _MASKED_BYTE_
%token <integer> _NUMBER_

%type <re_node>  tokens token byte alternatives range

%%

hex_string : '{' tokens '}'
              {
                RE* re = yyget_extra(yyscanner);
                re->root_node = $2;
              }
           ;


tokens : token
         {
            $$ = $1;
         }
       | tokens token
         {
            $$ = yr_re_node_create(RE_NODE_CONCAT, $1, $2);
         }
       ;


token : byte
        {
          $$ = $1;
        }
      | '(' alternatives ')'
        {
          $$ = $2;
        }
      | '[' range ']'
        {
          mark_as_not_literal();
          $$ = $2;
        }
      ;


range : _NUMBER_
        {
          RE_NODE* re_any;

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);
          $$->start = $1;
          $$->end = $1;
        }
      | _NUMBER_ '-' _NUMBER_
        {
          RE_NODE* re_any;

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);
          $$->start = $1;
          $$->end = $3;
        }
      ;


alternatives : tokens
               {
                  $$ = $1;
               }
             | alternatives '|' tokens
               {
                  mark_as_not_literal();
                  $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);
               }
             ;

byte  : _BYTE_
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
      | _MASKED_BYTE_
        {
          uint8_t mask = $1 >> 8;

          mark_as_not_literal();

          if (mask == 0x00)
          {
            $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);
          }
          else 
          {
            $$ = yr_re_node_create(RE_NODE_MASKED_LITERAL, NULL, NULL);
            $$->value = $1 & 0xFF;
            $$->mask = mask;
          }
        }
      ;

%%














