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

// clang-format off

%{

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>

#include <yara/arena.h>
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

#define FOR_EXPRESSION_ALL  1
#define FOR_EXPRESSION_ANY  2
#define FOR_EXPRESSION_NONE 3

#define FOR_ITERATION_ITERATOR   1
#define FOR_ITERATION_STRING_SET 2

// fail_with_error() is used in parser actions for aborting the parsing with
// an error. If the error is recoverable (like syntax errors), the parser will
// report the error and continue parsing the next rule. If the error is a
// fatal, non-recoverable error, the parser will be completely aborted.
#define fail_with_error(e) \
    { \
      compiler->last_error = e; \
      yyerror(yyscanner, compiler, NULL); \
      switch (e) \
      { \
      case ERROR_INSUFFICIENT_MEMORY: \
        YYABORT; \
      default: \
        YYERROR; \
      } \
    }

// fail_if_error() is used in parser actions for aborting the parsing if an
// error has occurred. See fail_with_error for details.
#define fail_if_error(e) \
    if (e != ERROR_SUCCESS && e != ERROR_UNKNOWN_ESCAPE_SEQUENCE) \
    { \
      fail_with_error(e); \
    }


// check_type(expression, EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT) is
// used to ensure that the type of "expression" is either integer or float,
// the cleanup statements are executed if the condition is not met.
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

// check_type(expression, EXPRESSION_TYPE_INTEGER | EXPRESSION_TYPE_FLOAT) is
// used to ensure that the type of "expression" is either integer or float.
#define check_type(expression, expected_type, op) \
    check_type_with_cleanup(expression, expected_type, op, )


#define loop_vars_cleanup(loop_index) \
    {  \
      YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[loop_index]; \
      for (int i = 0; i < loop_ctx->vars_count; i++) \
      { \
        yr_free((void*) loop_ctx->vars[i].identifier.ptr); \
        loop_ctx->vars[i].identifier.ptr = NULL; \
        loop_ctx->vars[i].identifier.ref = YR_ARENA_NULL_REF; \
      } \
      loop_ctx->vars_count = 0; \
    } \


// Given a YR_EXPRESSION returns its identifier. It returns identifier.ptr if
// not NULL and relies on identifier.ref if otherwise.
#define expression_identifier(expr) \
    ((expr).identifier.ptr != NULL ? \
     (expr).identifier.ptr : \
     (const char*) yr_arena_ref_to_ptr(compiler->arena, &(expr).identifier.ref))


#define DEFAULT_BASE64_ALPHABET \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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

// The parser produces more detailed syntax errors. Accepted values are
// "simple", "verbose", "detailed" and "custom". Introduced in Bison 3.0
// with support for "simple" and "verbose". Values "custom" and "detailed"
// were introduced in Bison 3.6. See:
// https://www.gnu.org/software/bison/manual/html_node/_0025define-Summary.html
%define parse.error verbose

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
%token _BASE64_                                        "<base64>"
%token _BASE64_WIDE_                                   "<base64wide>"
%token _NOCASE_                                        "<nocase>"
%token _FULLWORD_                                      "<fullword>"
%token _AT_                                            "<at>"
%token _FILESIZE_                                      "<filesize>"
%token _ENTRYPOINT_                                    "<entrypoint>"
%token _ALL_                                           "<all>"
%token _ANY_                                           "<any>"
%token _NONE_                                          "<none>"
%token _IN_                                            "<in>"
%token _OF_                                            "<of>"
%token _FOR_                                           "<for>"
%token _THEM_                                          "<them>"
%token _MATCHES_                                       "<matches>"
%token _CONTAINS_                                      "<contains>"
%token _STARTSWITH_                                    "<startswith>"
%token _ENDSWITH_                                      "<endswith>"
%token _ICONTAINS_                                     "<icontains>"
%token _ISTARTSWITH_                                   "<istartswith>"
%token _IENDSWITH_                                     "<iendswith>"
%token _IEQUALS_                                       "<iequals>"
%token _IMPORT_                                        "<import>"
%token _TRUE_                                          "<true>"
%token _FALSE_                                         "<false>"
%token _OR_                                            "<or>"
%token _AND_                                           "<and>"
%token _NOT_                                           "<not>"
%token _DEFINED_                                       "<defined>"
%token _EQ_                                            "=="
%token _NEQ_                                           "!="
%token _LT_                                            "<"
%token _LE_                                            "<="
%token _GT_                                            ">"
%token _GE_                                            ">="
%token _SHIFT_LEFT_                                    "<<"
%token _SHIFT_RIGHT_                                   ">>"

// Operator precedence and associativity. Higher precedence operators are lower
// in the list. Operators that appear in the same line have the same precedence.
%left _OR_
%left _AND_
%right _NOT_ _DEFINED_
%left _EQ_ _NEQ_ _CONTAINS_ _ICONTAINS_ _STARTSWITH_ _ENDSWITH_ _ISTARTSWITH_ _IENDSWITH_ _IEQUALS_ _MATCHES_
%left _LT_ _LE_ _GT_ _GE_
%left '|'
%left '^'
%left '&'
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right '~' UNARY_MINUS

%type <rule>   rule

%type <string> strings
%type <string> string_declaration
%type <string> string_declarations

%type <meta> meta
%type <meta> meta_declaration
%type <meta> meta_declarations

%type <tag> tags
%type <tag> tag_list

%type <modifier> string_modifier
%type <modifier> string_modifiers

%type <modifier> regexp_modifier
%type <modifier> regexp_modifiers

%type <modifier> hex_modifier
%type <modifier> hex_modifiers

%type <enumeration> set
%type <enumeration> enumeration
%type <integer> rule_modifier
%type <integer> rule_modifiers
%type <integer> string_enumeration
%type <integer> string_enumeration_item
%type <integer> string_set
%type <integer> for_iteration
%type <integer> rule_enumeration
%type <integer> rule_enumeration_item
%type <integer> rule_set

%type <expression> primary_expression
%type <expression> boolean_expression
%type <expression> expression
%type <expression> identifier
%type <expression> regexp
%type <expression> for_expression
%type <expression> for_quantifier
%type <expression> condition


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

%destructor {
  if ($$.alphabet != NULL)
  {
    yr_free($$.alphabet);
    $$.alphabet = NULL;
  }
} string_modifier

%destructor {
  if ($$.alphabet != NULL)
  {
    yr_free($$.alphabet);
    $$.alphabet = NULL;
  }
} string_modifiers


%union {
  YR_EXPRESSION   expression;
  SIZED_STRING*   sized_string;
  char*           c_string;
  int64_t         integer;
  double          double_;
  YR_MODIFIER     modifier;
  YR_ENUMERATION  enumeration;

  YR_ARENA_REF tag;
  YR_ARENA_REF rule;
  YR_ARENA_REF meta;
  YR_ARENA_REF string;
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
    | rules error _END_OF_INCLUDED_FILE_
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
        YR_RULE* rule = (YR_RULE*) yr_arena_ref_to_ptr(
            compiler->arena, &$<rule>4);

        rule->tags = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &$5);

        rule->metas = (YR_META*) yr_arena_ref_to_ptr(
            compiler->arena, &$7);

        rule->strings = (YR_STRING*) yr_arena_ref_to_ptr(
            compiler->arena, &$8);
      }
      condition '}'
      {
        YR_RULE* rule = (YR_RULE*) yr_arena_ref_to_ptr(
            compiler->arena, &$<rule>4);
        rule->required_strings = $10.required_strings.count;

        int result = yr_parser_reduce_rule_declaration_phase_2(
            yyscanner, &$<rule>4); // rule created in phase 1

        yr_free($3);

        fail_if_error(result);
      }
    ;


meta
    : /* empty */
      {
        $$ = YR_ARENA_NULL_REF;
      }
    | _META_ ':' meta_declarations
      {
        YR_META* meta = yr_arena_get_ptr(
            compiler->arena,
            YR_METAS_TABLE,
            (compiler->current_meta_idx - 1) * sizeof(YR_META));

        meta->flags |= META_FLAGS_LAST_IN_RULE;

        $$ = $3;
      }
    ;


strings
    : /* empty */
      {
        $$ = YR_ARENA_NULL_REF;
      }
    | _STRINGS_ ':' string_declarations
      {
        YR_STRING* string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            (compiler->current_string_idx - 1) * sizeof(YR_STRING));

        string->flags |= STRING_FLAGS_LAST_IN_RULE;

        $$ = $3;
      }
    ;


condition
    : _CONDITION_ ':' boolean_expression
      {
        $$ = $3;
      }
    ;


rule_modifiers
    : /* empty */                      { $$ = 0;  }
    | rule_modifiers rule_modifier     { $$ = $1 | $2; }
    ;


rule_modifier
    : _PRIVATE_      { $$ = RULE_FLAGS_PRIVATE; }
    | _GLOBAL_       { $$ = RULE_FLAGS_GLOBAL; }
    ;


tags
    : /* empty */
      {
        $$ = YR_ARENA_NULL_REF;
      }
    | ':' tag_list
      {
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        fail_if_error(yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, "", NULL));

        $$ = $2;
      }
    ;


tag_list
    : _IDENTIFIER_
      {
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, $1, &$<tag>$);

        yr_free($1);

        fail_if_error(result);
      }
    | tag_list _IDENTIFIER_
      {
        YR_ARENA_REF ref;

        // Write the new tag identifier.
        int result = yr_arena_write_string(
            yyget_extra(yyscanner)->arena, YR_SZ_POOL, $2, &ref);

        yr_free($2);

        fail_if_error(result);

        // Get the address for the tag identifier just written.
        char* new_tag = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &ref);

        // Take the address of first tag's identifier in the list.
        char* tag = (char*) yr_arena_ref_to_ptr(
            compiler->arena, &$<tag>$);

        // Search for duplicated tags. Tags are written one after
        // the other, with zeroes in between (i.e: tag1/0tag2/0tag3)
        // that's why can use tag < new_tag as the condition for the
        // loop.
        while (tag < new_tag)
        {
          if (strcmp(tag, new_tag) == 0)
          {
            yr_compiler_set_error_extra_info(compiler, tag);
            fail_with_error(ERROR_DUPLICATED_TAG_IDENTIFIER);
          }

          tag += strlen(tag) + 1;
        }

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
            &$<meta>$);

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
            &$<meta>$);

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
            &$<meta>$);

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
            &$<meta>$);

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
            &$<meta>$);

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
            yyscanner, $5, $1, $4, &$<string>$);

        yr_free($1);
        yr_free($4);
        yr_free($5.alphabet);

        fail_if_error(result);
        compiler->current_line = 0;
      }
    | _STRING_IDENTIFIER_ '='
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
      _REGEXP_ regexp_modifiers
      {
        int result;

        $5.flags |= STRING_FLAGS_REGEXP;

        result = yr_parser_reduce_string_declaration(
            yyscanner, $5, $1, $4, &$<string>$);

        yr_free($1);
        yr_free($4);

        fail_if_error(result);

        compiler->current_line = 0;
      }
    | _STRING_IDENTIFIER_ '='
      {
        compiler->current_line = yyget_lineno(yyscanner);
      }
      _HEX_STRING_ hex_modifiers
      {
        int result;

        $5.flags |= STRING_FLAGS_HEXADECIMAL;

        result = yr_parser_reduce_string_declaration(
            yyscanner, $5, $1, $4, &$<string>$);

        yr_free($1);
        yr_free($4);

        fail_if_error(result);

        compiler->current_line = 0;
      }
    ;


string_modifiers
    : /* empty */
      {
        $$.flags = 0;
        $$.xor_min = 0;
        $$.xor_max = 0;
        $$.alphabet = NULL;
      }
    | string_modifiers string_modifier
      {
        $$ = $1;

        // Only set the xor minimum and maximum if we are dealing with the
        // xor modifier. If we don't check for this then we can end up with
        // "xor wide" resulting in whatever is on the stack for "wide"
        // overwriting the values for xor.
        if ($2.flags & STRING_FLAGS_XOR)
        {
          $$.xor_min = $2.xor_min;
          $$.xor_max = $2.xor_max;
        }

        // Only set the base64 alphabet if we are dealing with the base64
        // modifier. If we don't check for this then we can end up with
        // "base64 ascii" resulting in whatever is on the stack for "ascii"
        // overwriting the values for base64.
        if (($2.flags & STRING_FLAGS_BASE64) ||
            ($2.flags & STRING_FLAGS_BASE64_WIDE))
        {
          if ($$.alphabet != NULL)
          {
            if (ss_compare($$.alphabet, $2.alphabet) != 0)
            {
              yr_compiler_set_error_extra_info(
                  compiler, "can not specify multiple alphabets");

              yr_free($2.alphabet);
              yr_free($$.alphabet);

              fail_with_error(ERROR_INVALID_MODIFIER);
            }
            else
            {
              yr_free($2.alphabet);
            }
          }
          else
          {
            $$.alphabet = $2.alphabet;
          }
        }

        if ($$.flags & $2.flags)
        {
          if ($$.alphabet != NULL)
            yr_free($$.alphabet);

          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          $$.flags = $$.flags | $2.flags;
        }
      }
    ;


string_modifier
    : _WIDE_        { $$.flags = STRING_FLAGS_WIDE; }
    | _ASCII_       { $$.flags = STRING_FLAGS_ASCII; }
    | _NOCASE_      { $$.flags = STRING_FLAGS_NO_CASE; }
    | _FULLWORD_    { $$.flags = STRING_FLAGS_FULL_WORD; }
    | _PRIVATE_     { $$.flags = STRING_FLAGS_PRIVATE; }
    | _XOR_
      {
        $$.flags = STRING_FLAGS_XOR;
        $$.xor_min = 0;
        $$.xor_max = 255;
      }
    | _XOR_ '(' _NUMBER_ ')'
      {
        int result = ERROR_SUCCESS;

        if ($3 < 0 || $3 > 255)
        {
          yr_compiler_set_error_extra_info(compiler, "invalid xor range");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        $$.flags = STRING_FLAGS_XOR;
        $$.xor_min = (uint8_t) $3;
        $$.xor_max = (uint8_t) $3;
      }
    /*
     * Would love to use range here for consistency in the language but that
     * uses a primary expression which pushes a value on the VM stack we don't
     * account for.
     */
    | _XOR_ '(' _NUMBER_ '-' _NUMBER_ ')'
      {
        int result = ERROR_SUCCESS;

        if ($3 < 0)
        {
          yr_compiler_set_error_extra_info(
              compiler, "lower bound for xor range exceeded (min: 0)");
          result = ERROR_INVALID_MODIFIER;
        }

        if ($5 > 255)
        {
          yr_compiler_set_error_extra_info(
              compiler, "upper bound for xor range exceeded (max: 255)");
          result = ERROR_INVALID_MODIFIER;
        }

        if ($3 > $5)
        {
          yr_compiler_set_error_extra_info(
              compiler, "xor lower bound exceeds upper bound");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        $$.flags = STRING_FLAGS_XOR;
        $$.xor_min = (uint8_t) $3;
        $$.xor_max = (uint8_t) $5;
      }
    | _BASE64_
      {
        $$.flags = STRING_FLAGS_BASE64;
        $$.alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
    | _BASE64_ '(' _TEXT_STRING_ ')'
      {
        int result = ERROR_SUCCESS;

        if ($3->length != 64)
        {
          yr_free($3);
          yr_compiler_set_error_extra_info(
              compiler, "length of base64 alphabet must be 64");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        $$.flags = STRING_FLAGS_BASE64;
        $$.alphabet = $3;
      }
    | _BASE64_WIDE_
      {
        $$.flags = STRING_FLAGS_BASE64_WIDE;
        $$.alphabet = ss_new(DEFAULT_BASE64_ALPHABET);
      }
    | _BASE64_WIDE_ '(' _TEXT_STRING_ ')'
      {
        int result = ERROR_SUCCESS;

        if ($3->length != 64)
        {
          yr_free($3);
          yr_compiler_set_error_extra_info(
              compiler, "length of base64 alphabet must be 64");
          result = ERROR_INVALID_MODIFIER;
        }

        fail_if_error(result);

        $$.flags = STRING_FLAGS_BASE64_WIDE;
        $$.alphabet = $3;
      }
    ;

regexp_modifiers
    : /* empty */                         { $$.flags = 0; }
    | regexp_modifiers regexp_modifier
      {
        if ($1.flags & $2.flags)
        {
          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          $$.flags = $1.flags | $2.flags;
        }
      }
    ;

regexp_modifier
    : _WIDE_        { $$.flags = STRING_FLAGS_WIDE; }
    | _ASCII_       { $$.flags = STRING_FLAGS_ASCII; }
    | _NOCASE_      { $$.flags = STRING_FLAGS_NO_CASE; }
    | _FULLWORD_    { $$.flags = STRING_FLAGS_FULL_WORD; }
    | _PRIVATE_     { $$.flags = STRING_FLAGS_PRIVATE; }
    ;

hex_modifiers
    : /* empty */                         { $$.flags = 0; }
    | hex_modifiers hex_modifier
      {
        if ($1.flags & $2.flags)
        {
          fail_with_error(ERROR_DUPLICATED_MODIFIER);
        }
        else
        {
          $$.flags = $1.flags | $2.flags;
        }
      }
    ;

hex_modifier
    : _PRIVATE_     { $$.flags = STRING_FLAGS_PRIVATE; }
    ;

identifier
    : _IDENTIFIER_
      {
        YR_EXPRESSION expr;

        int result = ERROR_SUCCESS;
        int var_index = yr_parser_lookup_loop_variable(yyscanner, $1, &expr);

        if (var_index >= 0)
        {
          // The identifier corresponds to a loop variable.
          result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_M,
              var_index,
              NULL,
              NULL);

          // The expression associated to this identifier is the same one
          // associated to the loop variable.
          $$ = expr;
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.

          YR_OBJECT* object = (YR_OBJECT*) yr_hash_table_lookup(
              compiler->objects_table, $1, NULL);

          YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
              compiler->arena,
              YR_NAMESPACES_TABLE,
              compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

          if (object == NULL)
          {
            // If not found, search within the current namespace.
            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table, $1, ns->name);
          }

          if (object != NULL)
          {
            YR_ARENA_REF ref;

            result = _yr_compiler_store_string(
                compiler, $1, &ref);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_LOAD,
                  yr_arena_ref_to_ptr(compiler->arena, &ref),
                  NULL,
                  NULL);

            $$.type = EXPRESSION_TYPE_OBJECT;
            $$.value.object = object;
            $$.identifier.ptr = NULL;
            $$.identifier.ref = ref;
          }
          else
          {
            uint32_t rule_idx = yr_hash_table_lookup_uint32(
                compiler->rules_table, $1, ns->name);

            if (rule_idx != UINT32_MAX)
            {
              result = yr_parser_emit_with_arg(
                  yyscanner,
                  OP_PUSH_RULE,
                  rule_idx,
                  NULL,
                  NULL);

              YR_RULE* rule = _yr_compiler_get_rule_by_idx(compiler, rule_idx);

              yr_arena_ptr_to_ref(compiler->arena, rule->identifier, &$$.identifier.ref);

              $$.type = EXPRESSION_TYPE_BOOLEAN;
              $$.value.integer = YR_UNDEFINED;
              $$.identifier.ptr = NULL;
              $$.required_strings.count = 0;
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
            YR_ARENA_REF ref;

            result = _yr_compiler_store_string(
                compiler, $3, &ref);

            if (result == ERROR_SUCCESS)
              result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_OBJ_FIELD,
                  yr_arena_ref_to_ptr(compiler->arena, &ref),
                  NULL,
                  NULL);

            $$.type = EXPRESSION_TYPE_OBJECT;
            $$.value.object = field;
            $$.identifier.ref = ref;
            $$.identifier.ptr = NULL;
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
             compiler, expression_identifier($1));

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
          $$.identifier.ptr = array->identifier;
          $$.identifier.ref = YR_ARENA_NULL_REF;
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
          $$.identifier.ptr = dict->identifier;
          $$.identifier.ref = YR_ARENA_NULL_REF;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, expression_identifier($1));

          result = ERROR_NOT_INDEXABLE;
        }

        fail_if_error(result);
      }

    | identifier '(' arguments ')'
      {
        YR_ARENA_REF ref = YR_ARENA_NULL_REF;
        int result = ERROR_SUCCESS;

        if ($1.type == EXPRESSION_TYPE_OBJECT &&
            $1.value.object->type == OBJECT_TYPE_FUNCTION)
        {
          YR_OBJECT_FUNCTION* function = object_as_function($1.value.object);

          result = yr_parser_check_types(compiler, function, $3);

          if (result == ERROR_SUCCESS)
            result = _yr_compiler_store_string(
                compiler, $3, &ref);

          if (result == ERROR_SUCCESS)
            result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_CALL,
                yr_arena_ref_to_ptr(compiler->arena, &ref),
                NULL,
                NULL);

          $$.type = EXPRESSION_TYPE_OBJECT;
          $$.value.object = function->return_obj;
          $$.identifier.ref = ref;
          $$.identifier.ptr = NULL;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler, expression_identifier($1));

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
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

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
          case EXPRESSION_TYPE_UNKNOWN:
            yr_free($$);
            yr_compiler_set_error_extra_info(
                compiler, "unknown type for argument 1 in function call");
            fail_with_error(ERROR_WRONG_TYPE);
            break;
          default:
            // An unknown expression type is OK iff an error ocurred.
            assert(compiler->last_error != ERROR_SUCCESS);
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
            case EXPRESSION_TYPE_UNKNOWN:
              result = ERROR_WRONG_TYPE;
              yr_compiler_set_error_extra_info_fmt(
                  compiler, "unknown type for argument %zu in function call",
                  // As we add one character per argument, the length of $1 is
                  // the number of arguments parsed so far, and the argument
                  // represented by <expression> is length of $1 plus one.
                  strlen($1) + 1);
              break;
            default:
              // An unknown expression type is OK iff an error ocurred.
              assert(compiler->last_error != ERROR_SUCCESS);
          }
        }

        if (result != ERROR_SUCCESS)
          yr_free($1);

        fail_if_error(result);

        $$ = $1;
      }
    ;


regexp
    : _REGEXP_
      {
        YR_ARENA_REF re_ref;
        RE_ERROR error;

        int result = ERROR_SUCCESS;
        int re_flags = 0;
        int parser_flags = RE_PARSER_FLAG_NONE;

        if ($1->flags & SIZED_STRING_FLAGS_NO_CASE)
          re_flags |= RE_FLAGS_NO_CASE;

        if ($1->flags & SIZED_STRING_FLAGS_DOT_ALL)
          re_flags |= RE_FLAGS_DOT_ALL;

        if (compiler->strict_escape)
          parser_flags |= RE_PARSER_FLAG_ENABLE_STRICT_ESCAPE_SEQUENCES;

        result = yr_re_compile(
            $1->c_string,
            re_flags,
            parser_flags,
            compiler->arena,
            &re_ref,
            &error);

        yr_free($1);

        if (result == ERROR_INVALID_REGULAR_EXPRESSION)
          yr_compiler_set_error_extra_info(compiler, error.message);

        if (result == ERROR_SUCCESS || result == ERROR_UNKNOWN_ESCAPE_SEQUENCE)
        {
          if (result == ERROR_UNKNOWN_ESCAPE_SEQUENCE)
          {
              yywarning(
                yyscanner,
                "unknown escape sequence");
          }
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              yr_arena_ref_to_ptr(compiler->arena, &re_ref),
              NULL,
              NULL);
        }

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_REGEXP;
      }
    ;


boolean_expression
    : expression
      {
        if ($1.type == EXPRESSION_TYPE_STRING)
        {
          if (!YR_ARENA_IS_NULL_REF($1.value.sized_string_ref))
          {
            SIZED_STRING* sized_string = yr_arena_ref_to_ptr(
                compiler->arena, &$1.value.sized_string_ref);

            yywarning(yyscanner,
                "using literal string \"%s\" in a boolean operation.",
                sized_string->c_string);
          }

          fail_if_error(yr_parser_emit(
              yyscanner, OP_STR_TO_BOOL, NULL));
        }
        if ($1.type != EXPRESSION_TYPE_BOOLEAN)
        {
          $$.required_strings.count = 0;
        }
        else
        {
          $$.required_strings.count = $1.required_strings.count;
        }

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    ;

expression
    : _TRUE_
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 1));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | _FALSE_
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, 0));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
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
        $$.required_strings.count = 0;
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "contains");
        check_type($3, EXPRESSION_TYPE_STRING, "contains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_CONTAINS, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _ICONTAINS_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "icontains");
        check_type($3, EXPRESSION_TYPE_STRING, "icontains");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ICONTAINS, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _STARTSWITH_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "startswith");
        check_type($3, EXPRESSION_TYPE_STRING, "startswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_STARTSWITH, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _ISTARTSWITH_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "istartswith");
        check_type($3, EXPRESSION_TYPE_STRING, "istartswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ISTARTSWITH, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _ENDSWITH_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "endswith");
        check_type($3, EXPRESSION_TYPE_STRING, "endswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENDSWITH, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _IENDSWITH_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "iendswith");
        check_type($3, EXPRESSION_TYPE_STRING, "iendswith");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IENDSWITH, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _IEQUALS_ primary_expression
      {
        check_type($1, EXPRESSION_TYPE_STRING, "iequals");
        check_type($3, EXPRESSION_TYPE_STRING, "iequals");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_IEQUALS, NULL));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | _STRING_IDENTIFIER_
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            $1,
            OP_FOUND,
            YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 1;
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        int result;

        check_type_with_cleanup($3, EXPRESSION_TYPE_INTEGER, "at", yr_free($1));

        result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_FOUND_AT, $3.value.integer);

        yr_free($1);

        fail_if_error(result);

        $$.required_strings.count = 1;
        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_FOUND_IN, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.required_strings.count = 1;
        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _FOR_ for_expression error
      {
        // Free all the loop variable identifiers, including the variables for
        // the current loop (represented by loop_index), and set loop_index to
        // -1. This is OK even if we have nested loops. If an error occurs while
        // parsing the inner loop, it will be propagated to the outer loop
        // anyways, so it's safe to do this cleanup while processing the error
        // for the inner loop.

        for (int i = 0; i <= compiler->loop_index; i++)
        {
          loop_vars_cleanup(i);
        }

        compiler->loop_index = -1;
        YYERROR;
      }
    | _FOR_ for_expression
      //
      //  for <min_expression> <identifier> in <iterator> : (<expression>)
      //
      //  CLEAR_M 0       ; clear number of true results returned by <expression>
      //  CLEAR_M 1       ; clear loop iteration counter
      //  POP_M 2         ; takes the result of <min_expression> from the stack
      //                  ; and puts it in M[2], once M[0] reaches M[2] the whole
      //                  ; for expression is satisfied
      //  <iterator>      ; the instructions generated by the <iterator> depend
      //                  ; on the type of iterator, but they will initialize the
      //                  ; iterator and get it ready for the ITER_NEXT instruction.
      // repeat:
      //  ITER_NEXT       ; reads the iterator object from the stack but leaves it there,
      //                  ; puts next item in the sequence in the stack, and also a TRUE
      //                  ; or a FALSE value indicating whether or not there are more items
      //
      //  POP_M 3         ; pops the next item from the stack and puts it in M[3], it
      //                  ; can be even more POPs depending on the type of the loop.
      //                  ; loops usually have just a single variable but loops over
      //                  ; dictionaries will have more POPs here.
      //
      //  JTRUE_P epilog  ; pops the boolean that tells if we already reached
      //                  ; the end of the iterator
      //  <expression>    ; here goes the code for <expression> the value of the
      //                  ; expressions ends up being at the top of the stack
      //
      //  INCR_M 1        ; increments iteration counter
      //  PUSH_M 0        ; push M[0] - number of true expressions
      //  PUSH_M 2        ; push M[2] - <min_expression> of this loop
      //  ITER_CONDITION  ; reads the top 3 values from the stack which are
      //                  ; (in this order from the top)
      //                  ; 1. <min_expression> of this loop
      //                  ; 2. number of true expressions
      //                  ; 3. result of the body <expression>
      //                  ; and determines whether the loop should continue
      //                  ; according to the short-circuit evaluation.
      //                  ; leaves 2 values on the stack (in this order from the top)
      //                  ; 1. result of the body <expression>
      //                  ; 2. indicator whether the loop should continue or not
      //
      //  ADD_M 0         ; if <expression> was true M[0] is incremented by one,
      //                  ; this consumes the <expression>'s result from the stack
      //
      //  JTRUE_P repeat  ; repeat the loop if ITER_CONDITION left true on the stack
      //
      // epilog:
      //  POP             ; remove the iterator object from the stack
      //
      //  PUSH_M 1        ; push iteration counter
      //  PUSH_M 0        ; pushes number of true results for <expression>
      //  PUSH_M 2        ; pushes value of <min_expression>
      //
      //  ITER_END        ; final evaluation of the loop according to it's
      //                  ; iteration counter, number of true expressions
      //                  ; and value of <min_expression>
      // end:
      //
      {
        // var_frame is used for accessing local variables used in this loop.
        // All local variables are accessed using var_frame as a reference,
        // like var_frame + 0, var_frame + 1, etc. Here we initialize var_frame
        // with the correct value, which depends on the number of variables
        // defined by any outer loops.

        int var_frame;
        int result = ERROR_SUCCESS;

        if (compiler->loop_index + 1 == YR_MAX_LOOP_NESTING)
          result = ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        fail_if_error(result);

        compiler->loop_index++;

        // This loop uses internal variables besides the ones explicitly
        // defined by the user.
        compiler->loop[compiler->loop_index].vars_internal_count = \
            YR_INTERNAL_LOOP_VARS;

        // Initialize the number of variables, this number will be incremented
        // as variable declaration are processed by for_variables.
        compiler->loop[compiler->loop_index].vars_count = 0;

        var_frame = _yr_compiler_get_var_frame(compiler);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, var_frame + 2, NULL, NULL));
      }
      for_iteration ':'
      {
        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];
        YR_FIXUP* fixup;

        YR_ARENA_REF loop_start_ref;
        YR_ARENA_REF jmp_offset_ref;

        int var_frame = _yr_compiler_get_var_frame(compiler);

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_NEXT, &loop_start_ref));

        // For each variable generate an instruction that pops the value from
        // the stack and store it into one memory slot starting at var_frame +
        // YR_INTERNAL_LOOP_VARS because the first YR_INTERNAL_LOOP_VARS slots
        // in the frame are for the internal variables.

        for (int i = 0; i < loop_ctx->vars_count; i++)
        {
          fail_if_error(yr_parser_emit_with_arg(
              yyscanner,
              OP_POP_M,
              var_frame + YR_INTERNAL_LOOP_VARS + i,
              NULL,
              NULL));
        }

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE_P,
            0,              // still don't know the jump offset, use 0 for now.
            NULL,
            &jmp_offset_ref));

        // We still don't know the jump's target, so we push a fixup entry
        // in the stack, so that the jump's offset can be set once we know it.

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;

        loop_ctx->start_ref = loop_start_ref;
      }
      '(' boolean_expression ')'
      {
        int32_t jmp_offset;
        YR_FIXUP* fixup;
        YR_ARENA_REF pop_ref;

        int var_frame = _yr_compiler_get_var_frame(compiler);

        if ($4 == FOR_ITERATION_STRING_SET)
        {
          compiler->loop_for_of_var_index = -1;
        }

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_INCR_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        fail_if_error(yr_parser_emit(yyscanner, OP_ITER_CONDITION, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_ADD_M, var_frame + 0, NULL, NULL));

        jmp_offset = \
            compiler->loop[compiler->loop_index].start_ref.offset -
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION);

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE_P,
            jmp_offset,
            NULL,
            NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_POP, &pop_ref));

        // Pop from the stack the fixup entry containing the reference to
        // the jump offset that needs to be fixed.

        fixup = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup->next;

        // The fixup entry has a reference to the jump offset that need
        // to be fixed, convert the address into a pointer.
        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        // The reference in the fixup entry points to the jump's offset
        // but the jump instruction is one byte before, that's why we add
        // one to the offset.
        jmp_offset = pop_ref.offset - fixup->ref.offset + 1;

        // Fix the jump's offset.
        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        yr_free(fixup);

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 1, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 0, NULL, NULL));

        fail_if_error(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_M, var_frame + 2, NULL, NULL));

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_END, NULL));

        loop_vars_cleanup(compiler->loop_index);

        compiler->loop_index--;

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | for_expression _OF_ string_set
      {
        if ($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > $3)
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", $1.value.integer, $3);
        }

        if (($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > 0) ||
              ($1.type == EXPRESSION_TYPE_QUANTIFIER &&
                  ($1.value.integer == FOR_EXPRESSION_ALL || $1.value.integer == FOR_EXPRESSION_ANY)))
        {
          $$.required_strings.count = 1;
        }
        else
        {
          $$.required_strings.count = 0;
        }

        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_STRING_SET, NULL, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | for_expression _OF_ rule_set
      {
        if ($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > $3)
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", $1.value.integer, $3);
        }
        yr_parser_emit_with_arg(yyscanner, OP_OF, OF_RULE_SET, NULL, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression '%' _OF_ string_set
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "%");

        // The value of primary_expression can be undefined because
        // it could be a variable for which don't know the value during
        // compiling time. However, if the value is defined it should be
        // in the range [1,100].
        if (!IS_UNDEFINED($1.value.integer) &&
            ($1.value.integer < 1 || $1.value.integer > 100))
        {
          yr_compiler_set_error_extra_info(
              compiler, "percentage must be between 1 and 100 (inclusive)");

          fail_with_error(ERROR_INVALID_PERCENTAGE);
        }

        if (!IS_UNDEFINED($1.value.integer))
        {
          $$.required_strings.count = 1;
        }
        else
        {
          $$.required_strings.count = 0;
        }

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_STRING_SET, NULL, NULL);
      }
    | primary_expression '%' _OF_ rule_set
      {
        check_type($1, EXPRESSION_TYPE_INTEGER, "%");

        // The value of primary_expression can be undefined because
        // it could be a variable for which don't know the value during
        // compiling time. However, if the value is defined it should be
        // in the range [1,100].
        if (!IS_UNDEFINED($1.value.integer) &&
            ($1.value.integer < 1 || $1.value.integer > 100))
        {
          yr_compiler_set_error_extra_info(
              compiler, "percentage must be between 1 and 100 (inclusive)");

          fail_with_error(ERROR_INVALID_PERCENTAGE);
        }

        yr_parser_emit_with_arg(yyscanner, OP_OF_PERCENT, OF_RULE_SET, NULL, NULL);
      }
    | for_expression _OF_ string_set _IN_ range
      {
        if ($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > $3)
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", $1.value.integer, $3);
        }

        if (($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > 0) ||
              ($1.type == EXPRESSION_TYPE_QUANTIFIER &&
                  ($1.value.integer == FOR_EXPRESSION_ALL || $1.value.integer == FOR_EXPRESSION_ANY)))
        {
          $$.required_strings.count = 1;
        }
        else
        {
          $$.required_strings.count = 0;
        }

        yr_parser_emit(yyscanner, OP_OF_FOUND_IN, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | for_expression _OF_ string_set _AT_ primary_expression
      {
        if ($5.type != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(compiler,
              "at expression must be an integer");

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > $3)
        {
          yywarning(yyscanner,
            "expression always false - requesting %" PRId64 " of %" PRId64 ".", $1.value.integer, $3);
        }

        // Both of these are warnings:
        //
        // "N of them at 0" where N > 1
        //
        //"all of them at 0" where there is more than 1 in "them".
        //
        // This means you can do "all of them at 0" if you only have one string
        // defined in the set.
        if (($1.type == EXPRESSION_TYPE_INTEGER &&
              !IS_UNDEFINED($1.value.integer) && $1.value.integer > 1) ||
              ($1.type == EXPRESSION_TYPE_QUANTIFIER &&
              $1.value.integer == FOR_EXPRESSION_ALL && $3 > 1))
        {
          yywarning(yyscanner,
            "multiple strings at an offset is usually false.");
        }

        if (($1.type == EXPRESSION_TYPE_INTEGER && $1.value.integer > 0) ||
              ($1.type == EXPRESSION_TYPE_QUANTIFIER &&
                  ($1.value.integer == FOR_EXPRESSION_ALL || $1.value.integer == FOR_EXPRESSION_ANY)))
        {
          $$.required_strings.count = 1;
        }
        else
        {
          $$.required_strings.count = 0;
        }

        yr_parser_emit(yyscanner, OP_OF_FOUND_AT, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
      }
    | _NOT_ boolean_expression
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | _DEFINED_ boolean_expression
      {
        yr_parser_emit(yyscanner, OP_DEFINED, NULL);
        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | boolean_expression _AND_
      {
        YR_FIXUP* fixup;
        YR_ARENA_REF jmp_offset_ref;

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JFALSE,
            0,          // still don't know the jump offset, use 0 for now.
            NULL,
            &jmp_offset_ref));

        // Create a fixup entry for the jump and push it in the stack.
        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
      boolean_expression
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_AND, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = $4.required_strings.count + $1.required_strings.count;
      }
    | boolean_expression _OR_
      {
        YR_FIXUP* fixup;
        YR_ARENA_REF jmp_offset_ref;

        fail_if_error(yr_parser_emit_with_arg_int32(
            yyscanner,
            OP_JTRUE,
            0,         // still don't know the jump destination, use 0 for now.
            NULL,
            &jmp_offset_ref));

        fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

        if (fixup == NULL)
          fail_with_error(ERROR_INSUFFICIENT_MEMORY);

        fixup->ref = jmp_offset_ref;
        fixup->next = compiler->fixup_stack_head;
        compiler->fixup_stack_head = fixup;
      }
      boolean_expression
      {
        YR_FIXUP* fixup;

        fail_if_error(yr_parser_emit(yyscanner, OP_OR, NULL));

        fixup = compiler->fixup_stack_head;

        int32_t jmp_offset = \
            yr_arena_get_current_offset(compiler->arena, YR_CODE_SECTION) -
            fixup->ref.offset + 1;

        int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
            compiler->arena, &fixup->ref);

        memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

        // Remove fixup from the stack.
        compiler->fixup_stack_head = fixup->next;
        yr_free(fixup);

        $$.type = EXPRESSION_TYPE_BOOLEAN;

        // Set required string count to minimum from both parts
        if ($1.required_strings.count > $4.required_strings.count) {
          $$.required_strings.count = $4.required_strings.count;
        } else {
          $$.required_strings.count = $1.required_strings.count;
        }
      }
    | primary_expression _LT_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _GT_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _LE_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "<=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _GE_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, ">=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _EQ_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "==", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
      }
    | primary_expression _NEQ_ primary_expression
      {
        fail_if_error(yr_parser_reduce_operation(
            yyscanner, "!=", $1, $3));

        $$.type = EXPRESSION_TYPE_BOOLEAN;
        $$.required_strings.count = 0;
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


for_iteration
    : for_variables _IN_ iterator { $$ = FOR_ITERATION_ITERATOR; }
    | _OF_ string_iterator
      {
        int var_frame;
        int result = ERROR_SUCCESS;

        if (compiler->loop_for_of_var_index != -1)
          result = ERROR_NESTED_FOR_OF_LOOP;

        fail_if_error(result);

        // Simulate that we have 1 variable with string loops
        compiler->loop[compiler->loop_index].vars_count = 1;

        // Set where we can find our string in case $ is in
        // the body of the loop
        var_frame = _yr_compiler_get_var_frame(compiler);
        compiler->loop_for_of_var_index = var_frame +
            compiler->loop[compiler->loop_index].vars_internal_count;

        $$ = FOR_ITERATION_STRING_SET;
      }
    ;


for_variables
    : _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (yr_parser_lookup_loop_variable(yyscanner, $1, NULL) >= 0)
        {
          yr_compiler_set_error_extra_info(compiler, $1);
          yr_free($1);

          result = ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if_error(result);

        loop_ctx->vars[loop_ctx->vars_count++].identifier.ptr = $1;

        assert(loop_ctx->vars_count <= YR_MAX_LOOP_VARS);
      }
    | for_variables ',' _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (loop_ctx->vars_count == YR_MAX_LOOP_VARS)
        {
          yr_compiler_set_error_extra_info(compiler, "too many loop variables");
          yr_free($3);

          result = ERROR_SYNTAX_ERROR;
        }
        else if (yr_parser_lookup_loop_variable(yyscanner, $3, NULL) >= 0)
        {
          yr_compiler_set_error_extra_info(compiler, $3);
          yr_free($3);

          result = ERROR_DUPLICATED_LOOP_IDENTIFIER;
        }

        fail_if_error(result);

        loop_ctx->vars[loop_ctx->vars_count++].identifier.ptr = $3;
      }
    ;

iterator
    : identifier
      {
        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        // Initially we assume that the identifier is from a non-iterable type,
        // this will change later if it's iterable.
        int result = ERROR_WRONG_TYPE;

        if ($1.type == EXPRESSION_TYPE_OBJECT)
        {
          switch($1.value.object->type)
          {
            case OBJECT_TYPE_ARRAY:
              // If iterating an array the loop must define a single variable
              // that will hold the current item. If a different number of
              // variables were defined that's an error.
              if (loop_ctx->vars_count == 1)
              {
                loop_ctx->vars[0].type = EXPRESSION_TYPE_OBJECT;
                loop_ctx->vars[0].value.object = \
                    object_as_array($1.value.object)->prototype_item;

                result = yr_parser_emit(yyscanner, OP_ITER_START_ARRAY, NULL);
              }
              else
              {
                yr_compiler_set_error_extra_info_fmt(
                    compiler,
                    "iterator for \"%s\" yields a single item on each iteration"
                    ", but the loop expects %d",
                    expression_identifier($1),
                    loop_ctx->vars_count);

                result = ERROR_SYNTAX_ERROR;
              }
              break;

            case OBJECT_TYPE_DICTIONARY:
              // If iterating a dictionary the loop must define exactly two
              // variables, one for the key and another for the value . If a
              // different number of variables were defined that's an error.
              if (loop_ctx->vars_count == 2)
              {
                loop_ctx->vars[0].type = EXPRESSION_TYPE_STRING;
                loop_ctx->vars[0].value.sized_string_ref = YR_ARENA_NULL_REF;
                loop_ctx->vars[1].type = EXPRESSION_TYPE_OBJECT;
                loop_ctx->vars[1].value.object = \
                    object_as_array($1.value.object)->prototype_item;

                result = yr_parser_emit(yyscanner, OP_ITER_START_DICT, NULL);
              }
              else
              {
                yr_compiler_set_error_extra_info_fmt(
                    compiler,
                    "iterator for \"%s\" yields a key,value pair item on each iteration",
                    expression_identifier($1));

                result = ERROR_SYNTAX_ERROR;
              }
              break;
          }
        }

        if (result == ERROR_WRONG_TYPE)
        {
          yr_compiler_set_error_extra_info_fmt(
              compiler,
              "identifier \"%s\" is not iterable",
              expression_identifier($1));
        }

        fail_if_error(result);
      }
    | set
      {
        int result = ERROR_SUCCESS;

        YR_LOOP_CONTEXT* loop_ctx = &compiler->loop[compiler->loop_index];

        if (loop_ctx->vars_count == 1)
        {
          loop_ctx->vars[0].type = $1.type;

          if ($1.type == EXPRESSION_TYPE_STRING)
            loop_ctx->vars[0].value.sized_string_ref = YR_ARENA_NULL_REF;
          else
            loop_ctx->vars[0].value.integer = YR_UNDEFINED;
        }
        else
        {
          yr_compiler_set_error_extra_info_fmt(
              compiler,
              "iterator yields one value on each iteration "
              ", but the loop expects %d",
              loop_ctx->vars_count);

          result = ERROR_SYNTAX_ERROR;
        }

        fail_if_error(result);
      }
    ;


set
    : '(' enumeration ')'
      {
        // $2.count contains the number of items in the enumeration
        fail_if_error(yr_parser_emit_push_const(yyscanner, $2.count));

        if ($2.type == EXPRESSION_TYPE_INTEGER)
        {
          fail_if_error(yr_parser_emit(
              yyscanner, OP_ITER_START_INT_ENUM, NULL));
        }
        else
        {
          fail_if_error(yr_parser_emit(
              yyscanner, OP_ITER_START_TEXT_STRING_SET, NULL));
        }

        $$.type = $2.type;
      }
    | range
      {
        fail_if_error(yr_parser_emit(
            yyscanner, OP_ITER_START_INT_RANGE, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
      }
    ;


range
    : '(' primary_expression _DOT_DOT_ primary_expression ')'
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

        // If we can statically determine lower and upper bounds, ensure
        // lower < upper. Check for upper bound here because some things (like
        // string count) are EXPRESSION_TYPE_INTEGER.
        if ($2.value.integer != YR_UNDEFINED && $4.value.integer != YR_UNDEFINED)
        {
          if ($2.value.integer > $4.value.integer)
          {
            yr_compiler_set_error_extra_info(
                compiler, "range lower bound must be less than upper bound");
            result = ERROR_INVALID_VALUE;
          }
          else if ($2.value.integer < 0)
          {
            yr_compiler_set_error_extra_info(
                compiler, "range lower bound can not be negative");
            result = ERROR_INVALID_VALUE;
          }
        }

        fail_if_error(result);
      }
    ;


enumeration
    : primary_expression
      {
        int result = ERROR_SUCCESS;

        if ($1.type != EXPRESSION_TYPE_INTEGER && $1.type != EXPRESSION_TYPE_STRING)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        $$.type = $1.type;
        $$.count = 1;
      }
    | enumeration ',' primary_expression
      {
        int result = ERROR_SUCCESS;

        if ($3.type != $1.type)
        {
          yr_compiler_set_error_extra_info(
              compiler, "enumerations must be all the same type");
          result = ERROR_WRONG_TYPE;
        }

        fail_if_error(result);

        $$.type = $1.type;
        $$.count = $1.count + 1;
      }
    ;


string_iterator
    : string_set
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, $1));
        fail_if_error(yr_parser_emit(yyscanner, OP_ITER_START_STRING_SET,
            NULL));
      }
    ;

string_set
    : '('
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
      string_enumeration ')'
      {
        $$ = $3;
      }
    | _THEM_
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, YR_UNDEFINED));

        int count = 0;
        fail_if_error(yr_parser_emit_pushes_for_strings(
            yyscanner, "$*", &count));

        $$ = count;
      }
    ;


string_enumeration
    : string_enumeration_item { $$ = $1; }
    | string_enumeration ',' string_enumeration_item { $$ = $1 + $3; }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
        int count = 0;
        int result = yr_parser_emit_pushes_for_strings(yyscanner, $1, &count);
        yr_free($1);

        fail_if_error(result);

        $$ = count;
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        int count = 0;
        int result = yr_parser_emit_pushes_for_strings(yyscanner, $1, &count);
        yr_free($1);

        fail_if_error(result);

        $$ = count;
      }
    ;


rule_set
    : '('
      {
        // Push end-of-list marker
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
      }
      rule_enumeration ')'
      {
        $$ = $3;
      }
    ;


rule_enumeration
    : rule_enumeration_item { $$ = $1; }
    | rule_enumeration ',' rule_enumeration_item { $$ = $1 + $3; }
    ;


rule_enumeration_item
    : _IDENTIFIER_
      {
        int result = ERROR_SUCCESS;

        YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
            compiler->arena,
            YR_NAMESPACES_TABLE,
            compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

        uint32_t rule_idx = yr_hash_table_lookup_uint32(
            compiler->rules_table, $1, ns->name);

        if (rule_idx != UINT32_MAX)
        {
          result = yr_parser_emit_with_arg(
              yyscanner,
              OP_PUSH_RULE,
              rule_idx,
              NULL,
              NULL);
        }
        else
        {
          yr_compiler_set_error_extra_info(compiler, $1);
          result = ERROR_UNDEFINED_IDENTIFIER;
        }

        yr_free($1);

        fail_if_error(result);

        $$ = 1;
      }
    | _IDENTIFIER_ '*'
      {
        int count = 0;
        YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
            compiler->arena,
            YR_NAMESPACES_TABLE,
            compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

        yr_hash_table_add_uint32(
            compiler->wildcard_identifiers_table,
            $1,
            ns->name,
            1);

        int result = yr_parser_emit_pushes_for_rules(yyscanner, $1, &count);
        yr_free($1);

        fail_if_error(result);

        $$ = count;
      }
    ;


for_expression
    : primary_expression
      {
        if ($1.type == EXPRESSION_TYPE_INTEGER && !IS_UNDEFINED($1.value.integer))
        {
          if ($1.value.integer == 0)
          {
            yywarning(yyscanner,
                "consider using \"none\" keyword, it is less ambiguous.");
          }

          if ($1.value.integer < 0)
          {
            yr_compiler_set_error_extra_info_fmt(compiler,
                "%" PRId64, $1.value.integer);

            fail_with_error(ERROR_INVALID_VALUE);
          }
        }

        if ($1.type == EXPRESSION_TYPE_FLOAT)
        {
          yr_compiler_set_error_extra_info_fmt(compiler,
              "%a", $1.value.double_);

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ($1.type == EXPRESSION_TYPE_STRING)
        {
          SIZED_STRING* ss = yr_arena_ref_to_ptr(compiler->arena,
              &$1.value.sized_string_ref);
          // If the expression is an external string variable we need to get
          // it some other way.
          if (ss != NULL)
          {
            yr_compiler_set_error_extra_info_fmt(compiler, "%s", ss->c_string);
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler,
                "string in for_expression is invalid");
          }

          fail_with_error(ERROR_INVALID_VALUE);
        }

        if ($1.type == EXPRESSION_TYPE_REGEXP)
        {
          yr_compiler_set_error_extra_info(compiler,
              "regexp in for_expression is invalid");

          fail_with_error(ERROR_INVALID_VALUE);
        }

        $$.value.integer = $1.value.integer;
      }
    | for_quantifier
      {
        $$.value.integer = $1.value.integer;
      }
    ;

for_quantifier
    : _ALL_
      {
        yr_parser_emit_push_const(yyscanner, YR_UNDEFINED);
        $$.type = EXPRESSION_TYPE_QUANTIFIER;
        $$.value.integer = FOR_EXPRESSION_ALL;
     }
    | _ANY_
      {
        yr_parser_emit_push_const(yyscanner, 1);
        $$.type = EXPRESSION_TYPE_QUANTIFIER;
        $$.value.integer = FOR_EXPRESSION_ANY;
      }
    | _NONE_
      {
        yr_parser_emit_push_const(yyscanner, 0);
        $$.type = EXPRESSION_TYPE_QUANTIFIER;
        $$.value.integer = FOR_EXPRESSION_NONE;
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
        $$.value.integer = YR_UNDEFINED;
      }
    | _ENTRYPOINT_
      {
        yywarning(yyscanner,
            "using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
            "function from PE module instead.");

        fail_if_error(yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL));

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
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
        $$.value.integer = YR_UNDEFINED;
      }
    | _NUMBER_
      {
        fail_if_error(yr_parser_emit_push_const(yyscanner, $1));

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
        YR_ARENA_REF ref;

        int result = _yr_compiler_store_data(
            compiler,
            $1,
            $1->length + sizeof(SIZED_STRING),
            &ref);

        yr_free($1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_PUSH,
              yr_arena_ref_to_ptr(compiler->arena, &ref),
              NULL,
              NULL);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_STRING;
        $$.value.sized_string_ref = ref;
      }
    | _STRING_COUNT_ _IN_ range
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_COUNT_IN, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | _STRING_COUNT_
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_COUNT, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_OFFSET, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | _STRING_OFFSET_
      {
        int result = yr_parser_emit_push_const(yyscanner, 1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, $1, OP_OFFSET, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner, $1, OP_LENGTH, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | _STRING_LENGTH_
      {
        int result = yr_parser_emit_push_const(yyscanner, 1);

        if (result == ERROR_SUCCESS)
          result = yr_parser_reduce_string_identifier(
              yyscanner, $1, OP_LENGTH, YR_UNDEFINED);

        yr_free($1);

        fail_if_error(result);

        $$.type = EXPRESSION_TYPE_INTEGER;
        $$.value.integer = YR_UNDEFINED;
      }
    | identifier
      {
        int result = ERROR_SUCCESS;

        if ($1.type == EXPRESSION_TYPE_OBJECT)
        {
          result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch($1.value.object->type)
          {
            case OBJECT_TYPE_INTEGER:
              $$.type = EXPRESSION_TYPE_INTEGER;
              $$.value.integer = $1.value.object->value.i;
              break;
            case OBJECT_TYPE_FLOAT:
              $$.type = EXPRESSION_TYPE_FLOAT;
              break;
            case OBJECT_TYPE_STRING:
              $$.type = EXPRESSION_TYPE_STRING;
              $$.value.sized_string_ref = YR_ARENA_NULL_REF;
              break;
            default:
              // In a primary expression any identifier that corresponds to an
              // object must be of type integer, float or string. If "foobar" is
              // either a function, structure, dictionary or array you can not
              // use it as:
              //   condition: foobar
              yr_compiler_set_error_extra_info_fmt(
                  compiler,
                  "wrong usage of identifier \"%s\"",
                  expression_identifier($1));

              result = ERROR_WRONG_TYPE;
          }
        }
        else
        {
          $$ = $1;
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
          $$.value.integer = ($2.value.integer == YR_UNDEFINED) ?
              YR_UNDEFINED : -($2.value.integer);
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
        $$.value.integer = ($2.value.integer == YR_UNDEFINED) ?
            YR_UNDEFINED : ~($2.value.integer);
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
