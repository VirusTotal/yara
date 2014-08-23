/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <yara/utils.h>
#include <yara/hex_lexer.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/error.h>


#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define YYERROR_VERBOSE

#define mark_as_not_fast_hex_regexp() \
    ((RE*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_HEX_REGEXP

#define ERROR_IF(x, error) \
    if (x) \
    { \
      lex_env->last_error_code = error; \
      YYABORT; \
    } \

#define DESTROY_NODE_IF(x, node) \
    if (x) \
    { \
      yr_re_node_destroy(node); \
    } \

%}

%debug

%name-prefix="hex_yy"
%pure-parser

%parse-param {void *yyscanner}
%parse-param {HEX_LEX_ENVIRONMENT *lex_env}

%lex-param {yyscan_t yyscanner}
%lex-param {HEX_LEX_ENVIRONMENT *lex_env}

%union {
  int integer;
  RE_NODE *re_node;
}

%token <integer> _BYTE_
%token <integer> _MASKED_BYTE_
%token <integer> _NUMBER_

%type <re_node>  tokens token byte alternatives range

%destructor { yr_re_node_destroy($$); } tokens
%destructor { yr_re_node_destroy($$); } token
%destructor { yr_re_node_destroy($$); } byte
%destructor { yr_re_node_destroy($$); } alternatives
%destructor { yr_re_node_destroy($$); } range

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

            DESTROY_NODE_IF($$ == NULL, $1);
            DESTROY_NODE_IF($$ == NULL, $2);
            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
         }
       ;


token : byte
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
      | '[' range ']'
        {
          $$ = $2;
          $$->greedy = FALSE;
        }
      ;


range : _NUMBER_
        {
          RE_NODE* re_any;

          if ($1 < 0)
          {
            yyerror(yyscanner, lex_env, "invalid negative jump length");
            YYABORT;
          }

          if (lex_env->inside_or && $1 > STRING_CHAINING_THRESHOLD)
          {
            yyerror(yyscanner, lex_env, "jumps over "
                STR(STRING_CHAINING_THRESHOLD)
                " now allowed inside alternation (|)");
            YYABORT;
          }

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          ERROR_IF(re_any == NULL, ERROR_INSUFICIENT_MEMORY);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);

          ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

          $$->start = $1;
          $$->end = $1;
        }
      | _NUMBER_ '-' _NUMBER_
        {
          RE_NODE* re_any;

          if (lex_env->inside_or &&
              ($1 > STRING_CHAINING_THRESHOLD ||
               $3 > STRING_CHAINING_THRESHOLD) )
          {
            yyerror(yyscanner, lex_env, "jumps over "
                STR(STRING_CHAINING_THRESHOLD)
                " now allowed inside alternation (|)");

            YYABORT;
          }

          if ($1 < 0 || $3 < 0)
          {
            yyerror(yyscanner, lex_env, "invalid negative jump length");
            YYABORT;
          }

          if ($1 > $3)
          {
            yyerror(yyscanner, lex_env, "invalid jump range");
            YYABORT;
          }

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          ERROR_IF(re_any == NULL, ERROR_INSUFICIENT_MEMORY);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);

          ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

          $$->start = $1;
          $$->end = $3;
        }
      | _NUMBER_ '-'
        {
          RE_NODE* re_any;

          if (lex_env->inside_or)
          {
            yyerror(yyscanner, lex_env,
                "unbounded jumps not allowed inside alternation (|)");
            YYABORT;
          }

          if ($1 < 0)
          {
            yyerror(yyscanner, lex_env, "invalid negative jump length");
            YYABORT;
          }

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          ERROR_IF(re_any == NULL, ERROR_INSUFICIENT_MEMORY);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);

          ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

          $$->start = $1;
          $$->end = INT_MAX;
        }
      | '-'
        {
          RE_NODE* re_any;

          if (lex_env->inside_or)
          {
            yyerror(yyscanner, lex_env,
                "unbounded jumps not allowed inside alternation (|)");
            YYABORT;
          }

          re_any = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

          ERROR_IF(re_any == NULL, ERROR_INSUFICIENT_MEMORY);

          $$ = yr_re_node_create(RE_NODE_RANGE, re_any, NULL);

          ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

          $$->start = 0;
          $$->end = INT_MAX;
        }
      ;


alternatives : tokens
               {
                  $$ = $1;
               }
             | alternatives '|' tokens
               {
                  mark_as_not_fast_hex_regexp();

                  $$ = yr_re_node_create(RE_NODE_ALT, $1, $3);

                  DESTROY_NODE_IF($$ == NULL, $1);
                  DESTROY_NODE_IF($$ == NULL, $3);

                  ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
               }
             ;

byte  : _BYTE_
        {
          $$ = yr_re_node_create(RE_NODE_LITERAL, NULL, NULL);

          ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

          $$->value = $1;
        }
      | _MASKED_BYTE_
        {
          uint8_t mask = $1 >> 8;

          if (mask == 0x00)
          {
            $$ = yr_re_node_create(RE_NODE_ANY, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);
          }
          else
          {
            $$ = yr_re_node_create(RE_NODE_MASKED_LITERAL, NULL, NULL);

            ERROR_IF($$ == NULL, ERROR_INSUFICIENT_MEMORY);

            $$->value = $1 & 0xFF;
            $$->mask = mask;
          }
        }
      ;

%%














