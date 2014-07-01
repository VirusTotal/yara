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

#include <yara/compiler.h>
#include <grammar.h>

#undef yyparse
#undef yylex
#undef yyerror
#undef yyfatal
#undef yychar
#undef yydebug
#undef yynerrs
#undef yyget_extra
#undef yyget_lineno

#undef YY_DECL
#undef YY_FATAL_ERROR
#undef YY_EXTRA_TYPE

#define yyparse       yara_yyparse
#define yylex         yara_yylex
#define yyerror       yara_yyerror
#define yyfatal       yara_yyfatal
#define yychar        yara_yychar
#define yydebug       yara_yydebug
#define yynerrs       yara_yynerrs
#define yyget_extra   yara_yyget_extra
#define yyget_lineno  yara_yyget_lineno


#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif


#define YY_DECL int yylex( \
    YYSTYPE* yylval_param, yyscan_t yyscanner, YR_COMPILER* compiler)


#define YY_FATAL_ERROR(msg) yara_yyfatal(yyscanner, msg)


#define YY_EXTRA_TYPE YR_COMPILER*
#define YY_USE_CONST


int yyget_lineno(yyscan_t yyscanner);

int yylex(
    YYSTYPE* yylval_param,
    yyscan_t yyscanner,
    YR_COMPILER* compiler);

int yyparse(
    void *yyscanner,
    YR_COMPILER* compiler);

void yyerror(
    yyscan_t yyscanner,
    YR_COMPILER* compiler,
    const char *error_message);

void yyfatal(
    yyscan_t yyscanner,
    const char *error_message);

YY_EXTRA_TYPE yyget_extra(
    yyscan_t yyscanner);

int yr_lex_parse_rules_string(
    const char* rules_string,
    YR_COMPILER* compiler);

int yr_lex_parse_rules_file(
    FILE* rules_file,
    YR_COMPILER* compiler);



