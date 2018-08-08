/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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


#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>

#include <yara/integers.h>
#include <yara/utils.h>
#include <yara/strutils.h>
#include <yara/compiler.h>
#include <yara/object.h>
#include <yara/sizedstr.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/lexer.h>
#include <yara/parser.h>

#if defined(_MSC_VER)
#define llabs _abs64
#endif

#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define fail_if_error(e) \
    if (e != ERROR_SUCCESS) \
    { \
      compiler->last_error = e; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \


#define check_type_with_cleanup(expression, expected_type, op, cleanup) \
    if (((expression.type) & (expected_type)) == 0) \
    { \
      switch(expression.type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_FLOAT: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"float\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_STRING: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"string\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_BOOLEAN: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"boolean\" for " op " operator"); \
          break; \
      } \
      cleanup; \
      compiler->last_error = ERROR_WRONG_TYPE; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }


#define check_type(expression, expected_type, op) \
    check_type_with_cleanup(expression, expected_type, op, )

%}


%expect 1   // expect 1 shift/reduce conflicts

// Uncomment this line to print parsing information that can be useful to
// debug YARA's grammar.

// %debug

%name-prefix "yara_yy"
%pure-parser
%parse-param {void *yyscanner}
%parse-param {YR_COMPILER* compiler}
%lex-param {yyscan_t yyscanner}
%lex-param {YR_COMPILER* compiler}

// Token that marks the end of the original file.
%token _END_OF_FILE_  0                                "end of file"

// Token that marks the end of included files, we can't use  _END_OF_FILE_
// because bison stops parsing when it sees _END_OF_FILE_, we want to be
// be able to identify the point where an included file ends, but continuing
// parsing any content that follows.
%token _END_OF_INCLUDED_FILE_                          "end of included file"

%token _DOT_DOT_                                       ".."
%token _RULE_                                          "<rule>"
%token _PRIVATE_                                       "<private>"
%token _GLOBAL_                                        "<global>"
%token _META_                                          "<meta>"
%token <string> _STRINGS_                              "<strings>"
%token _CONDITION_                                     "<condition>"
%token <c_string> _IDENTIFIER_                         "identifier"
%token <c_string> _STRING_IDENTIFIER_                  "string identifier"
%token <c_string> _STRING_COUNT_                       "string count"
%token <c_string> _STRING_OFFSET_                      "string offset"
%token <c_string> _STRING_LENGTH_                      "string length"
%token <c_string> _STRING_IDENTIFIER_WITH_WILDCARD_
    "string identifier with wildcard"
%token <integer> _NUMBER_                              "integer number"
%token <double_> _DOUBLE_                              "floating point number"
%token <integer> _INTEGER_FUNCTION_                    "integer function"
%token <sized_string> _TEXT_STRING_                    "text string"
%token <sized_string> _HEX_STRING_                     "hex string"
%token <sized_string> _REGEXP_                         "regular expression"
%token _ASCII_                                         "<ascii>"
%token _WIDE_                                          "<wide>"
%token _XOR_                                           "<xor>"
%token _NOCASE_                                        "<nocase>"
%token _FULLWORD_                                      "<fullword>"
%token _AT_                                            "<at>"
%token _FILESIZE_                                      "<filesize>"
%token _ENTRYPOINT_                                    "<entrypoint>"
%token _ALL_                                           "<all>"
%token _ANY_                                           "<any>"
%token _IN_                                            "<in>"
%token _OF_                                            "<of>"
%token _FOR_                                           "<for>"
%token _THEM_                                          "<them>"
%token _MATCHES_                                       "<matches>"
%token _CONTAINS_                                      "<contains>"
%token _IMPORT_                                        "<import>"
%token _TRUE_                                          "<true>"
%token _FALSE_                                         "<false"
%token _OR_                                            "<or>"
%token _AND_                                           "<and>"
%token _NOT_                                           "<not>"
%token _EQ_                                            "=="
%token _NEQ_                                           "!="
%token _LT_                                            "<"
%token _LE_                                            "<="
%token _GT_                                            ">"
%token _GE_                                            ">="
%token _SHIFT_LEFT_                                    "<<"
%token _SHIFT_RIGHT_                                   ">>"

%left _OR_
%left _AND_
%left '|'
%left '^'
%left '&'
%left _EQ_ _NEQ_
%left _LT_ _LE_ _GT_ _GE_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right _NOT_ '~' UNARY_MINUS

%type <rule>   rule

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

%type <expression> primary_expression
%type <expression> boolean_expression
%type <expression> expression
%type <expression> identifier
%type <expression> regexp

%type <c_string> arguments
%type <c_string> arguments_list

%destructor { yr_free($$); $$ = NULL; } _IDENTIFIER_
%destructor { yr_free($$); $$ = NULL; } _STRING_COUNT_
%destructor { yr_free($$); $$ = NULL; } _STRING_OFFSET_
%destructor { yr_free($$); $$ = NULL; } _STRING_LENGTH_
%destructor { yr_free($$); $$ = NULL; } _STRING_IDENTIFIER_
%destructor { yr_free($$); $$ = NULL; } _STRING_IDENTIFIER_WITH_WILDCARD_
%destructor { yr_free($$); $$ = NULL; } _TEXT_STRING_
%destructor { yr_free($$); $$ = NULL; } _HEX_STRING_
%destructor { yr_free($$); $$ = NULL; } _REGEXP_

%destructor { yr_free($$); $$ = NULL; } arguments
%destructor { yr_free($$); $$ = NULL; } arguments_list

%union {
  EXPRESSION      expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_STRING*      string;
  YR_META*        meta;
  YR_RULE*        rule;
}


%%

rules
    : /* empty */
    | rules rule
    | rules import
    | rules error rule      /* on error skip until next rule..*/
    | rules error import    /* .. or import statement */
    | rules error "include" /* .. or include statement */
    | rules _END_OF_INCLUDED_FILE_
      {
        _yr_compiler_pop_file_name(compiler);
      }
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
        int result = yr_parser_reduce_import(yyscanner, $2);

        yr_free($2);

        fail_if_error(result);
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_
      {
        fail_if_error(yr_parser_reduce_rule_declaration_phase_1(
            yyscanner, (int32_t) $1, $3, &$<rule>$));
      }
      tags '{' meta strings
      {
        YR_RULE* rule = $<rule>4; // rule created in phase 1

        rule->tags = $5;
        rule->metas = $7;
        rule->strings = $8;
      }
      condition '}'
      {
        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, $<rule>4); // rule created in phase 1

        yr_free($3);

        fail_if_error(result);
      }
    ;


meta
    : /* empty */
      {
        $$ = NULL;
      }
    | _META_ ':' meta_declarations
      {
        int result;

        // Each rule have a list of meta-data info, consisting in a
        // sequence of YR_META structures. The last YR_META structure does
        // not represent a real meta-data, it's just a end-of-list marker
        // identified by a specific type (META_TYPE_NULL). Here we
        // write the end-of-list marker.

        YR_META null_meta;

        memset(&null_meta, 0xFF, sizeof(YR_META));
        null_meta.type = META_TYPE_NULL;

        result = yr_arena_write_data(
            compiler->metas_arena,
            &null_meta,
            sizeof(YR_META),
            NULL);

        $$ = $3;

        fail_if_error(result);
      }
    ;


strings
    : /* empty */
      {
        $$ = NULL;
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

        fail_if_error(yr_arena_write_data(
            compiler->strings_arena,
            &null_string,
            sizeof(YR_STRING),
            NULL));

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

        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        fail_if_error(result);

        $$ = $2;
      }
    ;


tag_list
    : _IDENTIFIER_
      {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, $1, &$$);

        yr_free($1);

        fail_if_error(result);
      }
    | tag_list _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;

        char* tag_name = $1;
        size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

        while (tag_length > 0)
        {
          if (strcmp(tag_name, $2) == 0)
          {
            yr_compiler_set_error_extra_info(compiler, tag_name);
            result = ERROR_DUPLICATED_TAG_IDENTIFIER;
            break;
          }

          tag_name = (char*) yr_arena_next_address(
              yyget_extra(yyscanner)->sz_arena,
              tag_name,
              tag_length + 1);

          tag_length = tag_name != NULL ? strlen(tag_name) : 0;
        }

        if (result == ERROR_SUCCESS)
          result = yr_arena_write_string(
              yyget_extra(yyscanner)->sz_arena, $2, NULL);

        yr_free($2);

        fail_if_error(result);

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

        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_STRING,
            $1,
            sized_string->c_string,
            0,
            &$$);

        yr_free($1);
        yr_free($3);

        fail_if_error(result);
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            $1,
            NULL,
            $3,
            &$$);

        yr_free($1);

        fail_if_error(result);
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_INTEGER,
            $1,
            NULL,
            -$4,
            &$$);

        yr_free($1);

        fail_if_error(result);
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            $1,
            NULL,
            true,
            &$$);

        yr_free($1);

        fail_if_error(result);
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
        int result = yr_parser_reduce_meta_declaration(
            yyscanner,
            META_TYPE_BOOLEAN,
            $1,
            NULL,
            false,
            &$$);

        yr_free($1);

        fail_if_error(result);
      }
    ;


string_declarations
    : string_declaration                      { $$ = $1; }
    | string_declarations string_declaration  { $$ = $1; }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
      _TEXT_STRING_ string_modifiers
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) $5, $1, $4, &$$);

        yr_free($1);
        yr_free($4);

        fail_if_error(result);
        compiler->current_line = 0;
      }
    | _STRING_IDENTIFIER_ '='
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
      _REGEXP_ string_modifiers
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, (int32_t) $5 | STRING_GFLAGS_REGEXP, $1, $4, &$$);

        yr_free($1);
        yr_free($4);

        fail_if_error(result);

        compiler->current_line = 0;
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
      {
        int result = yr_parser_reduce_string_declaration(
            yyscanner, STRING_GFLAGS_HEXADECIMAL, $1, $3, &$$);

        yr_free($1);
        yr_free($3);

        fail_if_error(result);
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
    | _XOR_         { $$ = STRING_GFLAGS_XOR; }
    ;


identifier
    : _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;
        int var_index = yr_parser_lookup_loop_variable(yyscanner, $1);

        if (var_index >= 0)
        {
          result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_M,
              LOOP_LOCAL_VARS * var_index,
              NULL,
              NULL);

          $$.type = EXPRESSION_TYPE_INTEGER;
          $$.value.integer = UNDEFINED;
          $$.identifier = compiler->loop_identifier[var_index];
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          YR_OBJECT* object = (YR_OBJECT*) yr_hash_table_lookup(
              compiler->objects_table, $1, NULL);

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            char* ns = compiler->current_namespace->name;

            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table, $1, ns);
          }

          if (object != NULL)
          {
            char* id;

            result = yr_arena_write_string(
                compiler->sz_arena, $1, &id);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  id,
                  NULL,
                  NULL);

            $$.type = EXPRESSION_TYPE_OBJECT;
            $$.value.object = object;
            $$.identifier = object->identifier;
          }
          else
          {
            YR_RULE* rule = (YR_RULE*) yr_hash_table_lookup(
                compiler->rules_table,
                $1,
                compiler->current_namespace->name);

            if (rule != NULL)
            {
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_PUSH_RULE,
                  rule,
                  NULL,
                  NULL);

              $$.type = EXPRESSION_TYPE_BOOLEAN;
              $$.value.integer = UNDEFINED;
              $$.identifier = rule->identifier;
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, $1);
              result = ERROR_UNDEFINED_IDENTIFIER;
            }
          }
        }

        yr_free($1);

        fail_if_error(result);
      }
    | identifier '.' _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;
        YR_OBJECT* field = NULL;

        if ($1.type == EXPRESSION_TYPE_OBJECT &&
            $1.value.object->type == OBJECT_TYPE_STRUCTURE)
        {
          field = yr_object_lookup_field($1.value.object, $3);

          if (field != NULL)
          {
            char* ident;

            result = yr_arena_write_string(
                compiler->sz_arena, $3, &ident);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  ident,
                  NULL,
                  NULL);

            $$.type = EXPRESSION_TYPE_OBJECT;
            $$.value.object = field;
            $$.identifier = field->identifier;
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, $3);
            result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, $1.identifier);

          result = ERROR_NOT_A_STRUCTURE;
        }

        yr_free($3);

        fail_if_error(result);
      }
    | identifier '[' primary_expression ']'
      {
        int result = ERROR_SUCCESS;
        YR_OBJECT_ARRAY* array;
        YR_OBJECT_DICTIONARY* dict;

        if ($1.type == EXPRESSION_TYPE_OBJECT &&
            $1.value.object->type == OBJECT_TYPE_ARRAY)
        {
          if ($3.type != EXPRESSION_TYPE_INTEGER)
          {
            yr_compiler_set_error_extra_info(
                compiler, "array indexes must be of integer type");
            result = ERROR_WRONG_TYPE;
          }

          fail_if_error(result);

          result = yr_parser_emit(
              yyscanner, OP_INDEX_ARRAY, NULL);

          array = object_as_array($1.value.object);

          $$.type = EXPRESSION_TYPE_OBJECT;
          $$.value.object = array->prototype_item;
          $$.identifier = array->identifier;
        }
        else if ($1.type == EXPRESSION_TYPE_OBJECT &&
                 $1.value.object->type == OBJECT_TYPE_DICTIONARY)
        {
          if ($3.type != EXPRESSION_TYPE_STRING)
          {
            yr_compiler_set_error_extra_info(
                compiler, "dictionary keys must be of string type");
            result = ERROR_WRONG_TYPE;
          }

          fail_if_error(result);

          result = yr_parser_emit(
              yyscanner, OP_LOOKUP_DICT, NULL);

          dict = object_as_dictionary($1.value.object);

          $$.type = EXPRESSION_TYPE_OBJECT;
          $$.value.object = dict->prototype_item;
          $$.identifier = dict->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, $1.identifier);

          result = ERROR_NOT_INDEXABLE;
        }

        fail_if_error(result);
      }

    | identifier '(' arguments ')'
      {
        int result = ERROR_SUCCESS;
        YR_OBJECT_FUNCTION* function;
        char* args_fmt;

        if ($1.type == EXPRESSION_TYPE_OBJECT &&
            $1.value.object->type == OBJECT_TYPE_FUNCTION)
        {
          result = yr_parser_check_types(
              compiler, object_as_function($1.value.object), $3);

          if (result == ERROR_SUCCESS)
            result = yr_arena_write_string(
                compiler->sz_arena, $3, &args_fmt);

          if (result == ERROR_SUCCESS)
            result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                args_fmt,
                NULL,
                NULL);

          function = object_as_function($1.value.object);

          $$.type = EXPRESSION_TYPE_OBJECT;
          $$.value.object = function->return_obj;
          $$.identifier = function->identifier;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, $1.identifier);

          result = ERROR_NOT_A_FUNCTION;
        }

        yr_free($3);

        fail_if_error(result);
      }
    ;


arguments
    : /* empty */     { $$ = yr_strdup(""); }
    | arguments_list  { $$ = $1; }


arguments_list
    : expression
      {
        $$ = (char*) yr_malloc(YR_MAX_FUNCTION_ARGS + 1);

        if ($$ == NULL)
          fail_if_error(ERROR_INSUFFICIENT_MEMORY);

        switch($1.type)
        {
          case EXPRESSION_TYPE_INTEGER:
            strlcpy($$, "i", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_FLOAT:
            strlcpy($$, "f", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_BOOLEAN:
            strlcpy($$, "b", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_STRING:
            strlcpy($$, "s", YR_MAX_FUNCTION_ARGS);
            break;
          case EXPRESSION_TYPE_REGEXP:
            strlcpy($$, "r", YR_MAX_FUNCTION_ARGS);
            break;
          default:
            assert(false);
        }
      }
    | arguments_list ',' expression
      {
        int result = ERROR_SUCCESS;

        if (strlen($1) == YR_MAX_FUNCTION_ARGS)
        {
          result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch($3.type)
          {
            case EXPRESSION_TYPE_INTEGER:
              strlcat($1, "i", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_FLOAT:
              strlcat($1, "f", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_BOOLEAN:
              strlcat($1, "b", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_STRING:
              strlcat($1, "s", YR_MAX_FUNCTION_ARGS);
              break;
            case EXPRESSION_TYPE_REGEXP:
              strlcat($1, "r", YR_MAX_FUNCTION_ARGS);
              break;
            default:
              assert(false);
          }
        }

        fail_if_error(result);

        $$ = $1;
      }
    ;


regexp
    : _REGEXP_
      {
        SIZED_STRING* sized_string = $1;
        RE* re;
        RE_ERROR error;

        int result = ERROR_SUCCESS;
        int re_flags = 0;

        if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if (sized_string->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        result = yr_re_compile(
            sized_string->c_string,
            re_flags,
            compiler->re_code_arena,
            &re,
            &error);

        yr_free($1);

        if (result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        if (result == ERROR_SUCCESS)
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              re,
              NULL,
              NULL);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_REGEXP;
      }
    ;


boolean_expression
    : expression
      {
        if ($1.type == EXPRESSION_TYPE_STRING)
        {
          if ($1.value.sized_string != NULL)
          {
            yywarning(yyscanner,
              "Using literal string \"%s\" in a boolean operation.",
              $1.value.sized_string->c_string);
          }

          fail_if_error(yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL));
        }

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    ;

expression
    : _TRUE_
      {
        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FALSE_
      {
        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _MATCHES_ regexp
      {
        check_type($1, EXPRESSION_TYPE_STRING, "matches");
        check_type($3, EXPRESSION_TYPE_REGEXP, "matches");

        fail_if_error(yr_parser_emit(
            yyscanner,
            OP_MATCHES,
            NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "contains");
        check_type($3, EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_FOUND,
            UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        int result;

        check_type_with_cleanup($3, EXPRESSION_TYPE_INTEGER, "at", yr_free($1));

        result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_FOUND_AT, $3.value.integer);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_FOUND_IN, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FOR_ for_expression error
      {
        if (compiler->loop_depth > 0)
        {
          compiler->loop_depth--;
          compiler->loop_identifier[compiler->loop_depth] = NULL;
        }

        YYERROR;
      }
    | _FOR_ for_expression _IDENTIFIER_ _IN_
      {
        int result = ERROR_SUCCESS;
        int var_index;

        if (compiler->loop_depth == YR_MAX_LOOP_NESTING)
          result = ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        fail_if_error(result);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner, $3);

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler, $3);

          result = ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if_error(result);

        // Push end-of-list marker
        result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);

        fail_if_error(result);
      }
      integer_set ':'
      {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        uint8_t* addr;

        // Clear counter for number of expressions evaluating
        // to true.
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL, NULL);

        // Clear iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL, NULL);

        if ($6 == INTEGER_SET_ENUMERATION)
        {
          // Pop the first integer
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, &addr, NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Pop higher bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset + 3, &addr, NULL);

          // Pop lower bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, NULL, NULL);
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

        // The value at the top of the stack is the result of
        // evaluating the boolean expression, so it could be
        // 0, 1 or UNDEFINED. Add this value to a counter
        // keeping the number of expressions evaluating to true.
        // If the value is UNDEFINED instruction OP_ADD_M
        // does nothing.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL, NULL);

        // Increment iterations counter
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL, NULL);

        if ($6 == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              compiler->loop_address[compiler->loop_depth],
              NULL,
              NULL);
        }
        else // INTEGER_SET_RANGE
        {
          // Increment lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_INCR_M, mem_offset, NULL, NULL);

          // Push lower bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset, NULL, NULL);

          // Push higher bound of integer set
          yr_parser_emit_with_arg(
              yyscanner, OP_PUSH_M, mem_offset + 3, NULL, NULL);

          // Compare higher bound with lower bound, do loop again
          // if lower bound is still lower or equal than higher bound
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JLE,
              compiler->loop_address[compiler->loop_depth],
              NULL,
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
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to true.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit(yyscanner, OP_INT_LE, NULL);

        compiler->loop_identifier[compiler->loop_depth] = NULL;
        yr_free($3);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FOR_ for_expression _OF_ string_set ':'
      {
        int result = ERROR_SUCCESS;
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        uint8_t* addr;

        if (compiler->loop_depth == YR_MAX_LOOP_NESTING)
          result = ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          result = ERROR_NESTED_FOR_OF_LOOP;

        fail_if_error(result);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, mem_offset, &addr, NULL);

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
        // boolean expression (0 or 1). If the boolean expression
        // returned UNDEFINED the OP_ADD_M won't do anything.

        yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, mem_offset + 1, NULL, NULL);

        // Increment iterations counter.
        yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, mem_offset + 2, NULL, NULL);

        // If next string is not undefined, go back to the
        // beginning of the loop.
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JNUNDEF,
            compiler->loop_address[compiler->loop_depth],
            NULL,
            NULL);

        // Pop end-of-list marker.
        yr_parser_emit(yyscanner, OP_POP, NULL);

        // At this point the loop quantifier (any, all, 1, 2,..)
        // is at top of the stack. Check if the quantifier is
        // undefined (meaning "all") and replace it with the
        // iterations counter in that case.
        yr_parser_emit_with_arg(
            yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL, NULL);

        // Compare the loop quantifier with the number of
        // expressions evaluating to true.
        yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, mem_offset + 1, NULL, NULL);

        yr_parser_emit(yyscanner, OP_INT_LE, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;

      }
    | for_expression _OF_ string_set
      {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _NOT_ boolean_expression
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | boolean_expression _AND_
      {
        YR_FIXUP* fixup;
        void* jmp_destination_addr;

        fail_if_error(yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump destination
            NULL,
            &jmp_destination_addr));

        // create a fixup entry for the jump and push it in the stack
        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_if_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
      boolean_expression
      {
        YR_FIXUP* fixup;
        uint8_t* nop_addr;

        fail_if_error(yr_parser_emit(yyscanner, OP_AND, NULL));

        // Generate a do-nothing instruction (NOP) in order to get its address
        // and use it as the destination for the OP_JFALSE. We can not simply
        // use the address of the OP_AND instruction +1 because we can't be
        // sure that the instruction following the OP_AND is going to be in
        // the same arena page. As we don't have a reliable way of getting the
        // address of the next instruction we generate the OP_NOP.

        fail_if_error(yr_parser_emit(yyscanner, OP_NOP, &nop_addr));

        fixup = compiler->fixup_stack_head;
        *(void**)(fixup->address) = (void*) nop_addr;
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | boolean_expression _OR_
      {
        YR_FIXUP* fixup;
        void* jmp_destination_addr;

        fail_if_error(yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination
            NULL,
            &jmp_destination_addr));

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_if_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->address = jmp_destination_addr;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
      boolean_expression
      {
        YR_FIXUP* fixup;
        uint8_t* nop_addr;

        fail_if_error(yr_parser_emit(yyscanner, OP_OR, NULL));

        // Generate a do-nothing instruction (NOP) in order to get its address
        // and use it as the destination for the OP_JFALSE. We can not simply
        // use the address of the OP_OR instruction +1 because we can't be
        // sure that the instruction following the OP_AND is going to be in
        // the same arena page. As we don't have a reliable way of getting the
        // address of the next instruction we generate the OP_NOP.

        fail_if_error(yr_parser_emit(yyscanner, OP_NOP, &nop_addr));

        fixup = compiler->fixup_stack_head;
        *(void**)(fixup->address) = (void*)(nop_addr);
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _LT_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _GT_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _LE_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _GE_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _EQ_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | primary_expression _NEQ_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
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
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {
        int result = ERROR_SUCCESS;

        if ($2.type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          result = ERROR_WRONG_TYPE;
        }

        if ($4.type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);
      }
    ;


integer_enumeration
    : primary_expression
      {
        int result = ERROR_SUCCESS;

        if ($1.type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);
      }
    | integer_enumeration ',' primary_expression
      {
        int result = ERROR_SUCCESS;

        if ($3.type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);
      }
    ;


string_set
    : '('
      {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
      string_enumeration ')'
    | _THEM_
      {
        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, UNDEFINED, NULL, NULL));

        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*"));
      }
    ;


string_enumeration
    : string_enumeration_item
    | string_enumeration ',' string_enumeration_item
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, $1);
        yr_free($1);

        fail_if_error(result);
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        int result = yr_parser_emit_pushes_for_strings(yyscanner, $1);
        yr_free($1);

        fail_if_error(result);
      }
    ;


for_expression
    : primary_expression
    | _ALL_
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL, NULL);
      }
    | _ANY_
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL, NULL);
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
        $$ = $2;
      }
    | _FILESIZE_
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _ENTRYPOINT_
      {
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
      {
        check_type($3, EXPRESSION_TYPE_INTEGER, "intXXXX or uintXXXX");

        // _INTEGER_FUNCTION_ could be any of int8, int16, int32, uint8,
        // uint32, etc. $1 contains an index that added to OP_READ_INT results
        // in the proper OP_INTXX opcode.

        fail_if_error(yr_parser_emit(
            yyscanner, (uint8_t) (OP_READ_INT + $1), NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _NUMBER_
      {
        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, $1, NULL, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = $1;
      }
    | _DOUBLE_
      {
        fail_if_error(yr_parser_emit_with_arg_double(
            yyscanner, OP_PUSH, $1, NULL, NULL));

        $$.type = EXPRESSION_TYPE_FLOAT;
      }
    | _TEXT_STRING_
      {
        SIZED_STRING* sized_string;

        int result = yr_arena_write_data(
            compiler->sz_arena,
            $1,
            $1->length + sizeof(SIZED_STRING),
            (void**) &sized_string);

        yr_free($1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              sized_string,
              NULL,
              NULL);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_STRING;
        $$.value.sized_string = sized_string;
      }
    | _STRING_COUNT_
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_COUNT, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_OFFSET, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _STRING_OFFSET_
      {
        int result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, $1, OP_OFFSET, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_LENGTH, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | _STRING_LENGTH_
      {
        int result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL, NULL);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, $1, OP_LENGTH, UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = UNDEFINED;
      }
    | identifier
      {
        int result = ERROR_SUCCESS;

        if ($1.type == EXPRESSION_TYPE_INTEGER)  // loop identifier
        {
          $$.type = EXPRESSION_TYPE_INTEGER;
          $$.value.integer = UNDEFINED;
        }
        else if ($1.type == EXPRESSION_TYPE_BOOLEAN)  // rule identifier
        {
          $$.type = EXPRESSION_TYPE_BOOLEAN;
          $$.value.integer = UNDEFINED;
        }
        else if ($1.type == EXPRESSION_TYPE_OBJECT)
        {
          result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch($1.value.object->type)
          {
            case OBJECT_TYPE_INTEGER:
              $$.type = EXPRESSION_TYPE_INTEGER;
              $$.value.integer = UNDEFINED;
              break;
            case OBJECT_TYPE_FLOAT:
              $$.type = EXPRESSION_TYPE_FLOAT;
              break;
            case OBJECT_TYPE_STRING:
              $$.type = EXPRESSION_TYPE_STRING;
              $$.value.sized_string = NULL;
              break;
            default:
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  $1.identifier);
              result = ERROR_WRONG_TYPE;
          }
        }
        else
        {
          assert(false);
        }

        fail_if_error(result);
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
        int result = ERROR_SUCCESS;

        check_type($2, EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT, "-");

        if ($2.type == EXPRESSION_TYPE_INTEGER)
        {
          $$.type = EXPRESSION_TYPE_INTEGER;
          $$.value.integer = ($2.value.integer == UNDEFINED) ?
              UNDEFINED : -($2.value.integer);
          result = yr_parser_emit(yyscanner, OP_INT_MINUS, NULL);
        }
        else if ($2.type == EXPRESSION_TYPE_FLOAT)
        {
          $$.type = EXPRESSION_TYPE_FLOAT;
          result = yr_parser_emit(yyscanner, OP_DBL_MINUS, NULL);
        }

        fail_if_error(result);
      }
    | primary_expression '+' primary_expression
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "+", $1, $3);

        if ($1.type == EXPRESSION_TYPE_INTEGER &&
            $3.type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = $1.value.integer;
          int64_t i2 = $3.value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                (i2 > 0 && i1 > INT64_MAX - i2) ||
                (i2 < 0 && i1 < INT64_MIN - i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " + %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            $$.value.integer = OPERATION(+, i1, i2);
            $$.type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          $$.type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
    | primary_expression '-' primary_expression
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "-", $1, $3);

        if ($1.type == EXPRESSION_TYPE_INTEGER &&
            $3.type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = $1.value.integer;
          int64_t i2 = $3.value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                (i2 < 0 && i1 > INT64_MAX + i2) ||
                (i2 > 0 && i1 < INT64_MIN + i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " - %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            $$.value.integer = OPERATION(-, i1, i2);
            $$.type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          $$.type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
    | primary_expression '*' primary_expression
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "*", $1, $3);

        if ($1.type == EXPRESSION_TYPE_INTEGER &&
            $3.type == EXPRESSION_TYPE_INTEGER)
        {
          int64_t i1 = $1.value.integer;
          int64_t i2 = $3.value.integer;

          if (!IS_UNDEFINED(i1) && !IS_UNDEFINED(i2) &&
              (
                i2 != 0 && llabs(i1) > INT64_MAX / llabs(i2)
              ))
          {
            yr_compiler_set_error_extra_info_fmt(
                compiler, "%" PRId64 " * %" PRId64, i1, i2);

            result = ERROR_INTEGER_OVERFLOW;
          }
          else
          {
            $$.value.integer = OPERATION(*, i1, i2);
            $$.type = EXPRESSION_TYPE_INTEGER;
          }
        }
        else
        {
          $$.type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
    | primary_expression '\\' primary_expression
      {
        int result = yr_parser_reduce_operation(
            yyscanner, "\\", $1, $3);

        if ($1.type == EXPRESSION_TYPE_INTEGER &&
            $3.type == EXPRESSION_TYPE_INTEGER)
        {
          if ($3.value.integer != 0)
          {
            $$.value.integer = OPERATION(/, $1.value.integer, $3.value.integer);
            $$.type = EXPRESSION_TYPE_INTEGER;
          }
          else
          {
            result = ERROR_DIVISION_BY_ZERO;
          }
        }
        else
        {
          $$.type = EXPRESSION_TYPE_FLOAT;
        }

        fail_if_error(result);
      }
    | primary_expression '%' primary_expression
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "%");
        check_type($3, EXPRESSION_TYPE_INTEGER, "%");

        fail_if_error(yr_parser_emit(yyscanner, OP_MOD, NULL));

        if ($3.value.integer != 0)
        {
          $$.value.integer = OPERATION(%, $1.value.integer, $3.value.integer);
          $$.type = EXPRESSION_TYPE_INTEGER;
        }
        else
        {
          fail_if_error(ERROR_DIVISION_BY_ZERO);
        }
      }
    | primary_expression '^' primary_expression
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "^");
        check_type($3, EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_XOR, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = OPERATION(^, $1.value.integer, $3.value.integer);
      }
    | primary_expression '&' primary_expression
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "^");
        check_type($3, EXPRESSION_TYPE_INTEGER, "^");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_AND, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = OPERATION(&, $1.value.integer, $3.value.integer);
      }
    | primary_expression '|' primary_expression
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "|");
        check_type($3, EXPRESSION_TYPE_INTEGER, "|");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_OR, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = OPERATION(|, $1.value.integer, $3.value.integer);
      }
    | '~' primary_expression
      {
        check_type($2, EXPRESSION_TYPE_INTEGER, "~");

        fail_if_error(yr_parser_emit(yyscanner, OP_BITWISE_NOT, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = ($2.value.integer == UNDEFINED) ?
            UNDEFINED : ~($2.value.integer);
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
        int result;

        check_type($1, EXPRESSION_TYPE_INTEGER, "<<");
        check_type($3, EXPRESSION_TYPE_INTEGER, "<<");

        result = yr_parser_emit(yyscanner, OP_SHL, NULL);

        if (!IS_UNDEFINED($3.value.integer) && $3.value.integer < 0)
          result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED($3.value.integer) && $3.value.integer >= 64)
          $$.value.integer = 0;
        else
          $$.value.integer = OPERATION(<<, $1.value.integer, $3.value.integer);

        $$.type = EXPRESSION_TYPE_INTEGER;

        fail_if_error(result);
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
        int result;

        check_type($1, EXPRESSION_TYPE_INTEGER, ">>");
        check_type($3, EXPRESSION_TYPE_INTEGER, ">>");

        result = yr_parser_emit(yyscanner, OP_SHR, NULL);

        if (!IS_UNDEFINED($3.value.integer) && $3.value.integer < 0)
          result = ERROR_INVALID_OPERAND;
        else if (!IS_UNDEFINED($3.value.integer) && $3.value.integer >= 64)
          $$.value.integer = 0;
        else
          $$.value.integer = OPERATION(<<, $1.value.integer, $3.value.integer);

        $$.type = EXPRESSION_TYPE_INTEGER;

        fail_if_error(result);
      }
    | regexp
      {
        $$ = $1;
      }
    ;

%%
