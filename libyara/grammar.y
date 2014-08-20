/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>


#include <yara/utils.h>
#include <yara/compiler.h>
#include <yara/object.h>
#include <yara/sizedstr.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/lexer.h>
#include <yara/parser.h>


#define YYERROR_VERBOSE

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define EXPRESSION_TYPE_BOOLEAN   1
#define EXPRESSION_TYPE_INTEGER   2
#define EXPRESSION_TYPE_STRING    3
#define EXPRESSION_TYPE_REGEXP    4


#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \


#define CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, cleanup) \
    if (actual_type != expected_type) \
    { \
      switch(actual_type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_STRING: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"string\" for \"" op "\" operator"); \
          break; \
      } \
      compiler->last_result = ERROR_WRONG_TYPE; \
      cleanup; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }

#define CHECK_TYPE(actual_type, expected_type, op) \
    CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, ) \


#define MSG(op)  "wrong type \"string\" for \"" op "\" operator"

%}


%expect 2   // expect 2 shift/reduce conflicts

%debug
%name-prefix="yara_yy"
%pure-parser
%parse-param {void *yyscanner}
%parse-param {YR_COMPILER* compiler}
%lex-param {yyscan_t yyscanner}
%lex-param {YR_COMPILER* compiler}

%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
%token <string> _STRINGS_
%token _CONDITION_
%token <c_string> _IDENTIFIER_
%token <c_string> _STRING_IDENTIFIER_
%token <c_string> _STRING_COUNT_
%token <c_string> _STRING_OFFSET_
%token <c_string> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <integer> _NUMBER_
%token <sized_string> _TEXT_STRING_
%token <sized_string> _HEX_STRING_
%token <sized_string> _REGEXP_
%token _ASCII_
%token _WIDE_
%token _NOCASE_
%token _FULLWORD_
%token _AT_
%token _FILESIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token _INT8_
%token _INT16_
%token _INT32_
%token _UINT8_
%token _UINT16_
%token _UINT32_
%token _MATCHES_
%token _CONTAINS_
%token _IMPORT_

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

%type <object> identifier

%type <expression_type> primary_expression
%type <expression_type> boolean_expression
%type <expression_type> expression
%type <expression_type> regexp

%type <c_string> arguments_list


%destructor { yr_free($$); } _IDENTIFIER_
%destructor { yr_free($$); } _STRING_IDENTIFIER_
%destructor { yr_free($$); } _STRING_COUNT_
%destructor { yr_free($$); } _STRING_OFFSET_
%destructor { yr_free($$); } _STRING_IDENTIFIER_WITH_WILDCARD_
%destructor { yr_free($$); } _TEXT_STRING_
%destructor { yr_free($$); } _HEX_STRING_
%destructor { yr_free($$); } _REGEXP_

%union {
  SIZED_STRING*   sized_string;
  char*           c_string;
  int8_t          expression_type;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
  YR_OBJECT*      object;
}


%%

rules
    : /* empty */
    | rules rule
    | rules import
    | rules error rule      /* on error skip until next rule..*/
    | rules error 'include' /* .. or include statement */
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
        int result = yr_parser_reduce_import(yyscanner, $2);

        yr_free($2);

        ERROR_IF(result != ERROR_SUCCESS);
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_ tags '{' meta strings condition '}'
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


meta
    : /* empty */
      {
        $$ = NULL;
      }
    | _META_ ':' meta_declarations
      {
        // Each rule have a list of meta-data info, consisting in a
        // sequence of YR_META structures. The last YR_META structure does
        // not represent a real meta-data, it's just a end-of-list marker
        // identified by a specific type (META_TYPE_NULL). Here we
        // write the end-of-list marker.

        YR_META null_meta;

        memset(&null_meta, 0xFF, sizeof(YR_META));
        null_meta.type = META_TYPE_NULL;

        compiler->last_result = yr_arena_write_data(
            compiler->metas_arena,
            &null_meta,
            sizeof(YR_META),
            NULL);

        $$ = $3;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    ;


strings
    : /* empty */
      {
        $$ = NULL;
        compiler->current_rule_strings = $$;
      }
    | _STRINGS_ ':' string_declarations
      {
        // Each rule have a list of strings, consisting in a sequence
        // of YR_STRING structures. The last YR_STRING structure does not
        // represent a real string, it's just a end-of-list marker
        // identified by a specific flag (STRING_FLAGS_NULL). Here we
        // write the end-of-list marker.

        YR_STRING null_string;

        memset(&null_string, 0xFF, sizeof(YR_STRING));
        null_string.g_flags = STRING_GFLAGS_NULL;

        compiler->last_result = yr_arena_write_data(
            compiler->strings_arena,
            &null_string,
            sizeof(YR_STRING),
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        compiler->current_rule_strings = $3;
        $$ = $3;
      }
    ;


condition
    : _CONDITION_ ':' boolean_expression
    ;


rule_modifiers
    : /* empty */                      { $$ = 0;  }
    | rule_modifiers rule_modifier     { $$ = $1 | $2; }
    ;


rule_modifier
    : _PRIVATE_      { $$ = RULE_GFLAGS_PRIVATE; }
    | _GLOBAL_       { $$ = RULE_GFLAGS_GLOBAL; }
    ;


tags
    : /* empty */
      {
        $$ = NULL;
      }
    | ':' tag_list
      {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = $2;
      }
    ;


tag_list
    : _IDENTIFIER_
      {
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, $1, &identifier);

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = identifier;
      }
    | tag_list _IDENTIFIER_
      {
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

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = $1;
      }
    ;



meta_declarations
    : meta_declaration                    {  $$ = $1; }
    | meta_declarations meta_declaration  {  $$ = $1; }
    ;


meta_declaration
    : _IDENTIFIER_ '=' _TEXT_STRING_
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


string_declarations
    : string_declaration                      { $$ = $1; }
    | string_declarations string_declaration  { $$ = $1; }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '=' _TEXT_STRING_ string_modifiers
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
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
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


string_modifiers
    : /* empty */                         { $$ = 0; }
    | string_modifiers string_modifier    { $$ = $1 | $2; }
    ;


string_modifier
    : _WIDE_        { $$ = STRING_GFLAGS_WIDE; }
    | _ASCII_       { $$ = STRING_GFLAGS_ASCII; }
    | _NOCASE_      { $$ = STRING_GFLAGS_NO_CASE; }
    | _FULLWORD_    { $$ = STRING_GFLAGS_FULL_WORD; }
    ;


identifier
    : _IDENTIFIER_
      {
        YR_OBJECT* object = NULL;
        YR_RULE* rule;

        char* id;
        char* ns = NULL;

        int var_index;

        var_index = yr_parser_lookup_loop_variable(yyscanner, $1);

        if (var_index >= 0)
        {
          compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH_M,
            LOOP_LOCAL_VARS * var_index,
            NULL);

          $$ = (YR_OBJECT*) -1;
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                $1,
                NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.

            ns = compiler->current_namespace->name;
            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                $1,
                ns);
          }

          if (object != NULL)
          {
            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                $1,
                &id);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  PTR_TO_UINT64(id),
                  NULL);

            $$ = object;
          }
          else
          {
            rule = (YR_RULE*) yr_hash_table_lookup(
                compiler->rules_table,
                $1,
                compiler->current_namespace->name);

            if (rule != NULL)
            {
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_PUSH_RULE,
                  PTR_TO_UINT64(rule),
                  NULL);
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, $1);
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }

            $$ = (YR_OBJECT*) -2;
          }
        }

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    | identifier '.' _IDENTIFIER_
      {
        YR_OBJECT* object = $1;
        YR_OBJECT* field = NULL;

        char* ident;

        if (object != NULL &&
            object != (YR_OBJECT*) -1 &&    // not a loop variable identifier
            object != (YR_OBJECT*) -2 &&    // not a rule identifier
            object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field(object, $3);

          if (field != NULL)
          {
            compiler->last_result = yr_arena_write_string(
              compiler->sz_arena,
              $3,
              &ident);

            if (compiler->last_result == ERROR_SUCCESS)
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  PTR_TO_UINT64(ident),
                  NULL);
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, $3);
            compiler->last_result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              object->identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        $$ = field;

        yr_free($3);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    | identifier '[' primary_expression ']'
      {
        if ($1 != NULL && $1->type == OBJECT_TYPE_ARRAY)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_INDEX_ARRAY,
              NULL);

          $$ = ((YR_OBJECT_ARRAY*) $1)->items->objects[0];
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              $1->identifier);

          compiler->last_result = ERROR_NOT_AN_ARRAY;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }

    | identifier '(' arguments_list ')'
      {
        int args_count;

        if ($1 != NULL && $1->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) $1, $3);

          if (compiler->last_result == ERROR_SUCCESS)
          {
            args_count = strlen($3);

            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner,
                OP_CALL,
                args_count,
                NULL);
          }

          $$ = ((YR_OBJECT_FUNCTION*) $1)->return_obj;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              $1->identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free($3);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    ;


arguments_list
    : expression
      {
        $$ = yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch($1)
        {
          case EXPRESSION_TYPE_INTEGER:
            strcpy($$, "i");
            break;
          case EXPRESSION_TYPE_BOOLEAN:
            strcpy($$, "b");
            break;
          case EXPRESSION_TYPE_STRING:
            strcpy($$, "s");
            break;
          case EXPRESSION_TYPE_REGEXP:
            strcpy($$, "r");
            break;
        }

        ERROR_IF($$ == NULL);
      }
    | arguments_list ',' expression
      {
        if (strlen($1) == MAX_FUNCTION_ARGS)
        {
          compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch($3)
          {
            case EXPRESSION_TYPE_INTEGER:
              strcat($1, "i");
              break;
            case EXPRESSION_TYPE_BOOLEAN:
              strcat($1, "b");
              break;
            case EXPRESSION_TYPE_STRING:
              strcat($1, "s");
              break;
            case EXPRESSION_TYPE_REGEXP:
              strcat($1, "r");
              break;
          }
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = $1;
      }
    ;


regexp
    : _REGEXP_
      {
        SIZED_STRING* sized_string = $1;
        RE* re;
        RE_ERROR error;

        int re_flags = 0;

        if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if (sized_string->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        compiler->last_result = yr_re_compile(
            sized_string->c_string,
            re_flags,
            compiler->re_code_arena,
            &re,
            &error);

        yr_free($1);

        if (compiler->last_result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              PTR_TO_UINT64(re->root_node->forward_code),
              NULL);

        yr_re_destroy(re);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_REGEXP;
      }
    ;


boolean_expression
    : expression
      {
        if ($1 == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_TO_BOOL,
              NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }


        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    ;

expression
    : _TRUE_
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FALSE_
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _MATCHES_ regexp
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_STRING, "matches");
        CHECK_TYPE($3, EXPRESSION_TYPE_REGEXP, "matches");

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_MATCHES,
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_STRING, "contains");
        CHECK_TYPE($3, EXPRESSION_TYPE_STRING, "contains");

        compiler->last_result = yr_parser_emit(
            yyscanner,
            OP_CONTAINS,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_STR_FOUND);

        yr_free($1);

        ERROR_IF(result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "at");

        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_STR_FOUND_AT);

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_STR_FOUND_IN);

        yr_free($1);

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FOR_ for_expression _IDENTIFIER_ _IN_
      {
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
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            UNDEFINED,
            NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
      integer_set ':'
      {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        int8_t* addr;

        // Clear counter for number of expressions evaluating
        // to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

        // Clear iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

        if ($6 == INTEGER_SET_ENUMERATION)
        {
          // Pop the first integer
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, &addr);
        }
        else // INTEGER_SET_RANGE
        {
          // Pop higher bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset + 3, &addr);

          // Pop lower bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, NULL);
        }

        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = $3;
        compiler->loop_depth++;
      }
      '(' boolean_expression ')'
      {
        int mem_offset;

        compiler->loop_depth--;
        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // The value at the top of the stack is 1 if latest
        // expression was true or 0 otherwise. Add this value
        // to the counter for number of expressions evaluating
        // to true.
        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL);

        // Increment iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL);

        if ($6 == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              PTR_TO_UINT64(
                  compiler->loop_address[compiler->loop_depth]),
              NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Increment lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_INCR_M, mem_offset, NULL);

          // Push lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset, NULL);

          // Push higher bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset + 3, NULL);

          // Compare higher bound with lower bound, do loop again
          // if lower bound is still lower or equal than higher bound
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JLE,
              PTR_TO_UINT64(
                compiler->loop_address[compiler->loop_depth]),
              NULL);

          yr_parser_emit(yyscanner, OP_POP, NULL);
          yr_parser_emit(yyscanner, OP_POP, NULL);
        }

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at the top of the stack. Check if the quantifier
        // is undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

        yr_parser_emit(yyscanner, OP_LE, NULL);

        compiler->loop_identifier[compiler->loop_depth] = NULL;
        yr_free($3);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FOR_ for_expression _OF_ string_set ':'
      {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        int8_t* addr;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          compiler->last_result = \
            ERROR_NESTED_FOR_OF_LOOP;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, mem_offset, &addr);

        compiler->loop_for_of_mem_offset = mem_offset;
        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = NULL;
        compiler->loop_depth++;
      }
      '(' boolean_expression ')'
      {
        int mem_offset;

        compiler->loop_depth--;
        compiler->loop_for_of_mem_offset = -1;

        mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

        // Increment counter by the value returned by the
        // boolean expression (0 or 1).
        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL);

        // Increment iterations counter.
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL);

        // If next string is not undefined, go back to the
        // begining of the loop.
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JNUNDEF,
            PTR_TO_UINT64(
                compiler->loop_address[compiler->loop_depth]),
            NULL);

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at top of the stack. Check if the quantifier is
        // undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to TRUE.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

        yr_parser_emit(yyscanner, OP_LE, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;

      }
    | for_expression _OF_ string_set
      {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | _NOT_ boolean_expression
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | boolean_expression _AND_ boolean_expression
      {
        yr_parser_emit(yyscanner, OP_AND, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | boolean_expression _OR_ boolean_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_BOOLEAN, "or");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _LT_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "<");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "<");

        yr_parser_emit(yyscanner, OP_LT, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _GT_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, ">");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, ">");

        yr_parser_emit(yyscanner, OP_GT, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _LE_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "<=");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "<=");

        yr_parser_emit(yyscanner, OP_LE, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _GE_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, ">=");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, ">=");

        yr_parser_emit(yyscanner, OP_GE, NULL);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _EQ_ primary_expression
      {
        if ($1 != $3)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ($1 == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _IS_ primary_expression
      {
        if ($1 != $3)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ($1 == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _NEQ_ primary_expression
      {
        if ($1 != $3)
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for != operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ($1 == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_NEQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_NEQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression
      {
        $$ = $1;
      }
    |'(' expression ')'
      {
        $$ = $2;
      }
    ;


integer_set
    : '(' integer_enumeration ')'  { $$ = INTEGER_SET_ENUMERATION; }
    | range                        { $$ = INTEGER_SET_RANGE; }
    ;


range
    : '(' primary_expression '.' '.'  primary_expression ')'
      {
        if ($2 != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ($5 != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    ;


integer_enumeration
    : primary_expression
      {
        if ($1 != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;

        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    | integer_enumeration ',' primary_expression
      {
        if ($3 != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    ;


string_set
    : '('
      {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
      string_enumeration ')'
    | _THEM_
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");
      }
    ;


string_enumeration
    : string_enumeration_item
    | string_enumeration ',' string_enumeration_item
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
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


for_expression
    : primary_expression
    | _ALL_
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
    | _ANY_
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL);
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
        $$ = $2;
      }
    | _FILESIZE_
      {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    | _ENTRYPOINT_
      {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" " "function from PE module instead.");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _INT8_  '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "int8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _INT16_ '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "int16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _INT32_ '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "int32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _UINT8_ '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "uint8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _UINT16_ '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "uint16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _UINT32_ '(' primary_expression ')'
      {
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "uint32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _NUMBER_
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, $1, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _TEXT_STRING_
      {
        SIZED_STRING* sized_string = $1;
        char* string;

        compiler->last_result = yr_arena_write_string(
            compiler->sz_arena,
            sized_string->c_string,
            &string);

        yr_free($1);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              PTR_TO_UINT64(string),
              NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_STRING;
      }
    | _STRING_COUNT_
      {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_STR_COUNT);

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_STR_OFFSET);

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | _STRING_OFFSET_
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH,
            1,
            NULL);

        if (compiler->last_result == ERROR_SUCCESS)
          compiler->last_result = yr_parser_reduce_string_identifier(
              yyscanner,
              $1,
              OP_STR_OFFSET);

        yr_free($1);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | identifier
      {
        if ($1 == (YR_OBJECT*) -1)  // loop identifier
        {
          $$ = EXPRESSION_TYPE_INTEGER;
        }
        else if ($1 == (YR_OBJECT*) -2)  // rule identifier
        {
          $$ = EXPRESSION_TYPE_BOOLEAN;
        }
        else if ($1 != NULL)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch($1->type)
          {
            case OBJECT_TYPE_INTEGER:
              $$ = EXPRESSION_TYPE_INTEGER;
              break;
            case OBJECT_TYPE_STRING:
              $$ = EXPRESSION_TYPE_STRING;
              break;
            default:
              assert(FALSE);
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(compiler, $1->identifier);
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
    | primary_expression '+' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "+");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "+");

        yr_parser_emit(yyscanner, OP_ADD, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '-' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "-");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "-");

        yr_parser_emit(yyscanner, OP_SUB, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '*' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "*");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "*");

        yr_parser_emit(yyscanner, OP_MUL, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '\\' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "\\");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "\\");

        yr_parser_emit(yyscanner, OP_DIV, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '%' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '^' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_XOR, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '&' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_AND, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression '|' primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | '~' primary_expression
      {
        CHECK_TYPE($2, EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_NEG, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
        CHECK_TYPE($1, EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE($3, EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        $$ = EXPRESSION_TYPE_INTEGER;
      }
    | regexp
      {
        $$ = $1;
      }
    ;

%%














