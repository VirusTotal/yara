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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#include "exec.h"
#include "hash.h"
#include "sizedstr.h"
#include "mem.h"
#include "lexer.h"
#include "parser.h"
#include "re.h"
#include "utils.h"
#include "yara.h"

#define YYERROR_VERBOSE

#define INTEGER_SET_ENUMERATION 1
#define INTEGER_SET_RANGE 2

#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, NULL); \
      YYERROR; \
    } \

%}

%debug
%name-prefix="yara_yy"
%pure-parser
%parse-param {void *yyscanner}
%lex-param {yyscan_t yyscanner}

%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
%token <string> _STRINGS_
%token _CONDITION_
%token _END_
%token <c_string> _IDENTIFIER_
%token <c_string> _STRING_IDENTIFIER_
%token <c_string> _STRING_COUNT_
%token <c_string> _STRING_OFFSET_
%token <c_string> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <c_string> _ANONYMOUS_STRING_
%token <integer> _NUMBER_
%token _UNKNOWN_
%token <sized_string> _TEXTSTRING_
%token <sized_string> _HEXSTRING_
%token <sized_string> _REGEXP_
%token _ASCII_
%token _WIDE_
%token _NOCASE_
%token _FULLWORD_
%token _AT_
%token _SIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _RVA_
%token _OFFSET_
%token _FILE_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token <term> _SECTION_
%token _INT8_
%token _INT16_
%token _INT32_
%token _UINT8_
%token _UINT16_
%token _UINT32_
%token _MATCHES_
%token _CONTAINS_
%token _INDEX_

%token _MZ_
%token _PE_
%token _DLL_

%token _TRUE_
%token _FALSE_

%left _OR_
%left _AND_
%left '&' '|' '^'
%left _LT_ _LE_ _GT_ _GE_ _EQ_ _NEQ_ _IS_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right _NOT_
%right '~'

%type <string> strings
%type <string> string_declaration
%type <string> string_declarations


%type <meta> meta
%type <meta> meta_declaration
%type <meta> meta_declarations

%type <c_string> tags
%type <c_string> tag_list

%type <integer> string_modifier
%type <integer> string_modifiers

%type <integer> integer_set

%type <integer> rule_modifier
%type <integer> rule_modifiers


%destructor { yr_free($$); } _IDENTIFIER_
%destructor { yr_free($$); } _STRING_IDENTIFIER_
%destructor { yr_free($$); } _STRING_COUNT_
%destructor { yr_free($$); } _STRING_OFFSET_
%destructor { yr_free($$); } _STRING_IDENTIFIER_WITH_WILDCARD_
%destructor { yr_free($$); } _ANONYMOUS_STRING_
%destructor { yr_free($$); } _TEXTSTRING_
%destructor { yr_free($$); } _HEXSTRING_
%destructor { yr_free($$); } _REGEXP_

%union {
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
}


%%

rules : /* empty */
      | rules rule
      | rules error rule      /* on error skip until next rule..*/
      | rules error 'include' /* .. or include statement */
      ;


rule  : rule_modifiers _RULE_ _IDENTIFIER_ tags '{' meta strings condition '}'
        {
          int result = yr_parser_reduce_rule_declaration(
              yyscanner,
              $1,
              $3,
              $4,
              $7,
              $6);

          yr_free($3);

          ERROR_IF(result != ERROR_SUCCESS);
        }
      ;


meta  : /* empty */                      {  $$ = NULL; }
      | _META_ ':' meta_declarations
        {
          // Each rule have a list of meta-data info, consisting in a
          // sequence of YR_META structures. The last YR_META structure does
          // not represent a real meta-data, it's just a end-of-list marker
          // identified by a specific type (META_TYPE_NULL). Here we
          // write the end-of-list marker.

          YR_META null_meta;
          YR_COMPILER* compiler;

          compiler = yyget_extra(yyscanner);

          memset(&null_meta, 0xFF, sizeof(YR_META));
          null_meta.type = META_TYPE_NULL;

          yr_arena_write_data(
              compiler->metas_arena,
              &null_meta,
              sizeof(YR_META),
              NULL);

          $$ = $3;
        }
      ;


strings : /* empty */
        {
          $$ = NULL;
          yyget_extra(yyscanner)->current_rule_strings = $$;
        }
        | _STRINGS_ ':' string_declarations
        {
          // Each rule have a list of strings, consisting in a sequence
          // of YR_STRING structures. The last YR_STRING structure does not
          // represent a real string, it's just a end-of-list marker
          // identified by a specific flag (STRING_FLAGS_NULL). Here we
          // write the end-of-list marker.

          YR_STRING null_string;
          YR_COMPILER* compiler;

          compiler = yyget_extra(yyscanner);

          memset(&null_string, 0xFF, sizeof(YR_STRING));
          null_string.g_flags = STRING_GFLAGS_NULL;

          yr_arena_write_data(
              compiler->strings_arena,
              &null_string,
              sizeof(YR_STRING),
              NULL);

          $$ = $3;
          compiler->current_rule_strings = $$;
        }
        ;


condition : _CONDITION_ ':' boolean_expression
          ;


rule_modifiers : /* empty */                      { $$ = 0;  }
               | rule_modifiers rule_modifier     { $$ = $1 | $2; }
               ;


rule_modifier : _PRIVATE_       { $$ = RULE_GFLAGS_PRIVATE; }
              | _GLOBAL_        { $$ = RULE_GFLAGS_GLOBAL; }
              ;


tags  : /* empty */             { $$ = NULL; }
      | ':' tag_list
        {
          // Tags list is represented in the arena as a sequence
          // of null-terminated strings, the sequence ends with an
          // additional null character. Here we write the ending null
          //character. Example: tag1\0tag2\0tag3\0\0

          yr_arena_write_string(
              yyget_extra(yyscanner)->sz_arena, "", NULL);

          $$ = $2;
        }
      ;


tag_list  : _IDENTIFIER_
            {
              char* identifier;

              yr_arena_write_string(
                  yyget_extra(yyscanner)->sz_arena, $1, &identifier);

              yr_free($1);
              $$ = identifier;
            }
          | tag_list _IDENTIFIER_
            {
              YR_COMPILER* compiler = yyget_extra(yyscanner);
              char* tag_name = $1;
              size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

              while (tag_length > 0)
              {
                if (strcmp(tag_name, $2) == 0)
                {
                  yr_compiler_set_error_extra_info(compiler, tag_name);
                  compiler->last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
                  break;
                }

                tag_name = yr_arena_next_address(
                    yyget_extra(yyscanner)->sz_arena,
                    tag_name,
                    tag_length + 1);

                tag_length = tag_name != NULL ? strlen(tag_name) : 0;
              }

              if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_arena_write_string(
                    yyget_extra(yyscanner)->sz_arena, $2, NULL);

              yr_free($2);
              $$ = $1;

              ERROR_IF(compiler->last_result != ERROR_SUCCESS);
            }


meta_declarations : meta_declaration                    {  $$ = $1; }
                  | meta_declarations meta_declaration  {  $$ = $1; }
                  ;


meta_declaration  : _IDENTIFIER_ '=' _TEXTSTRING_
                    {
                      SIZED_STRING* sized_string = $3;

                      $$ = yr_parser_reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_STRING,
                          $1,
                          sized_string->c_string,
                          0);

                      yr_free($1);
                      yr_free($3);

                      ERROR_IF($$ == NULL);
                    }
                  | _IDENTIFIER_ '=' _NUMBER_
                    {
                      $$ = yr_parser_reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_INTEGER,
                          $1,
                          NULL,
                          $3);

                      yr_free($1);

                      ERROR_IF($$ == NULL);
                    }
                  | _IDENTIFIER_ '=' _TRUE_
                    {
                      $$ = yr_parser_reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_BOOLEAN,
                          $1,
                          NULL,
                          TRUE);

                      yr_free($1);

                      ERROR_IF($$ == NULL);
                    }
                  | _IDENTIFIER_ '=' _FALSE_
                    {
                      $$ = yr_parser_reduce_meta_declaration(
                          yyscanner,
                          META_TYPE_BOOLEAN,
                          $1,
                          NULL,
                          FALSE);

                      yr_free($1);

                      ERROR_IF($$ == NULL);
                    }
                  ;


string_declarations : string_declaration                      { $$ = $1; }
                    | string_declarations string_declaration  { $$ = $1; }
                    ;


string_declaration  : _STRING_IDENTIFIER_ '=' _TEXTSTRING_ string_modifiers
                      {
                        $$ = yr_parser_reduce_string_declaration(
                            yyscanner,
                            $4,
                            $1,
                            $3);

                        yr_free($1);
                        yr_free($3);

                        ERROR_IF($$ == NULL);
                      }
                    | _STRING_IDENTIFIER_ '='
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        compiler->error_line = yyget_lineno(yyscanner);
                      }
                      _REGEXP_ string_modifiers
                      {
                        $$ = yr_parser_reduce_string_declaration(
                            yyscanner,
                            $5 | STRING_GFLAGS_REGEXP,
                            $1,
                            $4);

                        yr_free($1);
                        yr_free($4);

                        ERROR_IF($$ == NULL);
                      }
                    | _STRING_IDENTIFIER_ '=' _HEXSTRING_
                      {
                        $$ = yr_parser_reduce_string_declaration(
                            yyscanner,
                            STRING_GFLAGS_HEXADECIMAL,
                            $1,
                            $3);

                        yr_free($1);
                        yr_free($3);

                        ERROR_IF($$ == NULL);
                      }
                    ;


string_modifiers : /* empty */                              { $$ = 0;  }
                 | string_modifiers string_modifier         { $$ = $1 | $2; }
                 ;


string_modifier : _WIDE_        { $$ = STRING_GFLAGS_WIDE; }
                | _ASCII_       { $$ = STRING_GFLAGS_ASCII; }
                | _NOCASE_      { $$ = STRING_GFLAGS_NO_CASE; }
                | _FULLWORD_    { $$ = STRING_GFLAGS_FULL_WORD; }
                ;


boolean_expression  : '(' boolean_expression ')'
                    | _TRUE_
                      {
                        yr_parser_emit_with_arg(yyscanner, PUSH, 1, NULL);
                      }
                    | _FALSE_
                      {
                        yr_parser_emit_with_arg(yyscanner, PUSH, 0, NULL);
                      }
                    | _IDENTIFIER_
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        YR_RULE* rule;

                        rule = (YR_RULE*) yr_hash_table_lookup(
                            compiler->rules_table,
                            $1,
                            compiler->current_namespace->name);

                        if (rule != NULL)
                        {
                          compiler->last_result = yr_parser_emit_with_arg_reloc(
                              yyscanner,
                              RULE_PUSH,
                              PTR_TO_UINT64(rule),
                              NULL);
                        }
                        else
                        {
                          compiler->last_result = yr_parser_reduce_external(
                              yyscanner,
                              $1,
                              EXT_BOOL);
                        }

                        yr_free($1);

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
                      }
                    | text _MATCHES_ _REGEXP_
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        SIZED_STRING* sized_string = $3;
                        RE* re;

                        compiler->last_result = yr_re_compile(
                            sized_string->c_string, &re);

                        if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
                          re->flags |= RE_FLAGS_NO_CASE;

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

                        compiler->last_result = yr_re_emit_code(
                            re, compiler->re_code_arena);

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

                        yr_parser_emit_with_arg_reloc(
                            yyscanner,
                            PUSH,
                            PTR_TO_UINT64(re->root_node->forward_code),
                            NULL);

                        yr_parser_emit_with_arg(
                            yyscanner,
                            PUSH,
                            re->flags,
                            NULL);

                        yr_parser_emit(yyscanner, MATCHES, NULL);

                        yr_re_destroy(re);
                        yr_free($3);

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
                      }
                    | text _CONTAINS_ text
                      {
                        yr_parser_emit(yyscanner, CONTAINS, NULL);
                      }
                    | _STRING_IDENTIFIER_
                      {
                        int result = yr_parser_reduce_string_identifier(
                            yyscanner,
                            $1,
                            SFOUND);

                        yr_free($1);

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
                    | _STRING_IDENTIFIER_ _AT_ expression
                      {
                        int result = yr_parser_reduce_string_identifier(
                            yyscanner,
                            $1,
                            SFOUND_AT);

                        yr_free($1);

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
                    | _STRING_IDENTIFIER_ _AT_ _RVA_ expression
                      {
                        yr_free($1);
                      }
                    | _STRING_IDENTIFIER_ _IN_ range
                      {
                        int result = yr_parser_reduce_string_identifier(
                            yyscanner,
                            $1,
                            SFOUND_IN);

                        yr_free($1);

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
                    | _STRING_IDENTIFIER_ _IN_ _SECTION_ '(' _TEXTSTRING_ ')'
                      {
                        yr_free($1);
                        yr_free($5);
                      }
                    | _FOR_ for_expression _IDENTIFIER_ _IN_
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        int result = ERROR_SUCCESS;
                        int var_index;

                        if (compiler->loop_depth == MAX_LOOP_NESTING)
                          compiler->last_result = \
                              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

                        var_index = yr_parser_lookup_loop_variable(
                            yyscanner,
                            $3);

                        if (var_index >= 0)
                        {
                          yr_compiler_set_error_extra_info(
                              compiler,
                              $3);

                          compiler->last_result = \
                              ERROR_DUPLICATE_LOOP_IDENTIFIER;
                        }

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

                        // Push end-of-list marker
                        result = yr_parser_emit_with_arg(
                            yyscanner,
                            PUSH,
                            UNDEFINED,
                            NULL);

                        ERROR_IF(result != ERROR_SUCCESS);
                      }
                      integer_set ':'
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
                        int8_t* addr;

                        // Clear counter for number of expressions evaluating
                        // to TRUE.
                        yr_parser_emit_with_arg(
                            yyscanner, CLEAR_M, mem_offset + 1, NULL);

                        // Clear iterations counter
                        yr_parser_emit_with_arg(
                            yyscanner, CLEAR_M, mem_offset + 2, NULL);

                        if ($6 == INTEGER_SET_ENUMERATION)
                        {
                          // Pop the first integer
                          yr_parser_emit_with_arg(
                              yyscanner, POP_M, mem_offset, &addr);
                        }
                        else // INTEGER_SET_RANGE
                        {
                          yr_parser_emit_with_arg(
                              yyscanner, POP_M, mem_offset + 3, &addr);

                          yr_parser_emit_with_arg(
                              yyscanner, POP_M, mem_offset, NULL);
                        }

                        compiler->loop_address[compiler->loop_depth] = addr;
                        compiler->loop_identifier[compiler->loop_depth] = $3;
                        compiler->loop_depth++;
                      }
                      '(' boolean_expression ')'
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        int mem_offset;

                        compiler->loop_depth--;
                        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

                        yr_parser_emit_with_arg(
                            yyscanner, ADD_M, mem_offset + 1, NULL);

                        yr_parser_emit_with_arg(
                            yyscanner, INCR_M, mem_offset + 2, NULL);

                        if ($6 == INTEGER_SET_ENUMERATION)
                        {
                          yr_parser_emit_with_arg_reloc(
                              yyscanner,
                              JNUNDEF,
                              PTR_TO_UINT64(
                                  compiler->loop_address[compiler->loop_depth]),
                              NULL);
                        }
                        else // INTEGER_SET_RANGE
                        {
                          yr_parser_emit_with_arg(
                              yyscanner, INCR_M, mem_offset, NULL);

                          yr_parser_emit_with_arg(
                              yyscanner, PUSH_M, mem_offset, NULL);

                          yr_parser_emit_with_arg(
                              yyscanner, PUSH_M, mem_offset + 3, NULL);

                          yr_parser_emit_with_arg_reloc(
                              yyscanner,
                              JLE,
                              PTR_TO_UINT64(
                                compiler->loop_address[compiler->loop_depth]),
                              NULL);

                          yr_parser_emit(yyscanner, POP, NULL);
                          yr_parser_emit(yyscanner, POP, NULL);
                        }

                        // Pop end-of-list marker.
                        yr_parser_emit(yyscanner, POP, NULL);

                        // At this point the loop quantifier (any, all, 1, 2,..)
                        // is at the top of the stack. Check if the quantifier
                        // is undefined (meaning "all") and replace it with the
                        // iterations counter in that case.
                        yr_parser_emit_with_arg(
                            yyscanner, SWAPUNDEF, mem_offset + 2, NULL);

                        // Compare the loop quantifier with the number of
                        // expressions evaluating to TRUE.
                        yr_parser_emit_with_arg(
                            yyscanner, PUSH_M, mem_offset + 1, NULL);

                        yr_parser_emit(yyscanner, LE, NULL);

                        compiler->loop_identifier[compiler->loop_depth] = NULL;
                        yr_free($3);
                      }
                    | _FOR_ for_expression _OF_ string_set ':'
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
                        int8_t* addr;

                        if (compiler->loop_depth == MAX_LOOP_NESTING)
                          compiler->last_result = \
                            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

                        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

                        yr_parser_emit_with_arg(
                            yyscanner, CLEAR_M, mem_offset + 1, NULL);

                        yr_parser_emit_with_arg(
                            yyscanner, CLEAR_M, mem_offset + 2, NULL);

                        // Pop the first string.
                        yr_parser_emit_with_arg(
                            yyscanner, POP_M, mem_offset, &addr);

                        compiler->loop_address[compiler->loop_depth] = addr;
                        compiler->loop_depth++;
                      }
                      '(' boolean_expression ')'
                      {
                        YR_COMPILER* compiler = yyget_extra(yyscanner);
                        int mem_offset;

                        compiler->loop_depth--;
                        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

                        // Increment counter by the value returned by the
                        // boolean expression (0 or 1).
                        yr_parser_emit_with_arg(
                            yyscanner, ADD_M, mem_offset + 1, NULL);

                        // Increment iterations counter.
                        yr_parser_emit_with_arg(
                            yyscanner, INCR_M, mem_offset + 2, NULL);

                        // If next string is not undefined, go back to the
                        // begining of the loop.
                        yr_parser_emit_with_arg_reloc(
                            yyscanner,
                            JNUNDEF,
                            PTR_TO_UINT64(
                                compiler->loop_address[compiler->loop_depth]),
                            NULL);

                        // Pop end-of-list marker.
                        yr_parser_emit(yyscanner, POP, NULL);

                        // At this point the loop quantifier (any, all, 1, 2,..)
                        // is at top of the stack. Check if the quantifier is
                        // undefined (meaning "all") and replace it with the
                        // iterations counter in that case.
                        yr_parser_emit_with_arg(
                            yyscanner, SWAPUNDEF, mem_offset + 2, NULL);

                        // Compare the loop quantifier with the number of
                        // expressions evaluating to TRUE.
                        yr_parser_emit_with_arg(
                            yyscanner, PUSH_M, mem_offset + 1, NULL);

                        yr_parser_emit(yyscanner, LE, NULL);

                      }
                    | for_expression _OF_ string_set
                      {
                        yr_parser_emit(yyscanner, OF, NULL);
                      }
                    | _FILE_ _IS_ type
                      {
                      }
                    | _NOT_ boolean_expression
                      {
                        yr_parser_emit(yyscanner, NOT, NULL);
                      }
                    | boolean_expression _AND_ boolean_expression
                      {
                        yr_parser_emit(yyscanner, AND, NULL);
                      }
                    | boolean_expression _OR_ boolean_expression
                      {
                        yr_parser_emit(yyscanner, OR, NULL);
                      }
                    | expression _LT_ expression
                      {
                        yr_parser_emit(yyscanner, LT, NULL);
                      }
                    | expression _GT_ expression
                      {
                        yr_parser_emit(yyscanner, GT, NULL);
                      }
                    | expression _LE_ expression
                      {
                        yr_parser_emit(yyscanner, LE, NULL);
                      }
                    | expression _GE_ expression
                      {
                        yr_parser_emit(yyscanner, GE, NULL);
                      }
                    | expression _EQ_ expression
                      {
                        yr_parser_emit(yyscanner, EQ, NULL);
                      }
                    | expression _IS_ expression
                      {
                        yr_parser_emit(yyscanner, EQ, NULL);
                      }
                    | expression _NEQ_ expression
                      {
                        yr_parser_emit(yyscanner, NEQ, NULL);
                      }
                    ;


text  : _TEXTSTRING_
        {
          YR_COMPILER* compiler = yyget_extra(yyscanner);
          SIZED_STRING* sized_string = $1;
          char* string;

          yr_arena_write_string(
            compiler->sz_arena,
            sized_string->c_string,
            &string);

          yr_parser_emit_with_arg_reloc(
              yyscanner,
              PUSH,
              PTR_TO_UINT64(string),
              NULL);

          yr_free($1);
        }
      | _IDENTIFIER_
        {
          int result = yr_parser_reduce_external(
              yyscanner,
              $1,
              EXT_STR);

          yr_free($1);

          ERROR_IF(result != ERROR_SUCCESS);
        }
      ;


integer_set : '(' integer_enumeration ')'  { $$ = INTEGER_SET_ENUMERATION; }
            | range                        { $$ = INTEGER_SET_RANGE; }
            ;


range : '(' expression '.' '.'  expression ')'
      ;


integer_enumeration : expression
                    | integer_enumeration ',' expression
                    ;

string_set  : '('
              {
                yr_parser_emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
              }
              string_enumeration ')'
            | _THEM_
              {
                yr_parser_emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
                yr_parser_emit_pushes_for_strings(yyscanner, "$*");
              }
            ;

string_enumeration  : string_enumeration_item
                    | string_enumeration ',' string_enumeration_item
                    ;

string_enumeration_item : _STRING_IDENTIFIER_
                          {
                            yr_parser_emit_pushes_for_strings(yyscanner, $1);
                            yr_free($1);
                          }
                        | _STRING_IDENTIFIER_WITH_WILDCARD_
                          {
                            yr_parser_emit_pushes_for_strings(yyscanner, $1);
                            yr_free($1);
                          }
                        ;

for_expression  : expression
                | _ALL_
                  {
                    yr_parser_emit_with_arg(yyscanner, PUSH, UNDEFINED, NULL);
                  }
                | _ANY_
                  {
                    yr_parser_emit_with_arg(yyscanner, PUSH, 1, NULL);
                  }
                ;


expression  : '(' expression ')'
            | _SIZE_
              {
                yr_parser_emit(yyscanner, SIZE, NULL);
              }
            | _ENTRYPOINT_
              {
                yr_parser_emit(yyscanner, ENTRYPOINT, NULL);
              }
            | _INT8_  '(' expression ')'
              {
                yr_parser_emit(yyscanner, INT8, NULL);
              }
            | _INT16_ '(' expression ')'
              {
                yr_parser_emit(yyscanner, INT16, NULL);
              }
            | _INT32_ '(' expression ')'
              {
                yr_parser_emit(yyscanner, INT32, NULL);
              }
            | _UINT8_  '(' expression ')'
              {
                yr_parser_emit(yyscanner, UINT8, NULL);
              }
            | _UINT16_ '(' expression ')'
              {
                yr_parser_emit(yyscanner, UINT16, NULL);
              }
            | _UINT32_ '(' expression ')'
              {
                yr_parser_emit(yyscanner, UINT32, NULL);
              }
            | _NUMBER_
              {
                yr_parser_emit_with_arg(yyscanner, PUSH, $1, NULL);
              }
            | _STRING_COUNT_
              {
                int result = yr_parser_reduce_string_identifier(
                    yyscanner,
                    $1,
                    SCOUNT);

                yr_free($1);

                ERROR_IF(result != ERROR_SUCCESS);
              }
            | _STRING_OFFSET_ '[' expression ']'
              {
                int result = yr_parser_reduce_string_identifier(
                    yyscanner,
                    $1,
                    SOFFSET);

                yr_free($1);

                ERROR_IF(result != ERROR_SUCCESS);
              }
            | _STRING_OFFSET_
              {
                int result = yr_parser_emit_with_arg(yyscanner, PUSH, 1, NULL);

                if (result == ERROR_SUCCESS)
                  result = yr_parser_reduce_string_identifier(
                      yyscanner,
                      $1,
                      SOFFSET);

                yr_free($1);

                ERROR_IF(result != ERROR_SUCCESS);
              }
            | _IDENTIFIER_
              {
                YR_COMPILER* compiler = yyget_extra(yyscanner);
                int var_index;

                var_index = yr_parser_lookup_loop_variable(yyscanner, $1);

                if (var_index >= 0)
                {
                  yr_parser_emit_with_arg(
                    yyscanner,
                    PUSH_M,
                    LOOP_LOCAL_VARS * var_index,
                    NULL);
                }
                else
                {
                  compiler->last_result = yr_parser_reduce_external(
                      yyscanner,
                      $1,
                      EXT_INT);
                }

                yr_free($1);

                ERROR_IF(compiler->last_result != ERROR_SUCCESS);
              }
            | expression '+' expression
              {
                yr_parser_emit(yyscanner, ADD, NULL);
              }
            | expression '-' expression
              {
                yr_parser_emit(yyscanner, SUB, NULL);
              }
            | expression '*' expression
              {
                yr_parser_emit(yyscanner, MUL, NULL);
              }
            | expression '\\' expression
              {
                yr_parser_emit(yyscanner, DIV, NULL);
              }
            | expression '%' expression
              {
                yr_parser_emit(yyscanner, MOD, NULL);
              }
            | expression '^' expression
              {
                yr_parser_emit(yyscanner, XOR, NULL);
              }
            | expression '&' expression
              {
                yr_parser_emit(yyscanner, AND, NULL);
              }
            | expression '|' expression
              {
                yr_parser_emit(yyscanner, OR, NULL);
              }
            | '~' expression
              {
                yr_parser_emit(yyscanner, NEG, NULL);
              }
            | expression _SHIFT_LEFT_ expression
              {
                yr_parser_emit(yyscanner, SHL, NULL);
              }
            | expression _SHIFT_RIGHT_ expression
              {
                yr_parser_emit(yyscanner, SHR, NULL);
              }
            ;

type : _MZ_
     | _PE_
     | _DLL_
     ;

%%














