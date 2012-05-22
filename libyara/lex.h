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

#include "yara.h"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

#define YY_EXTRA_TYPE YARA_CONTEXT*
#define YY_USE_CONST

void yyerror(yyscan_t yyscanner, const char *error_message);

YY_EXTRA_TYPE yyget_extra (yyscan_t yyscanner);

int parse_rules_string(const char* rules_string, YARA_CONTEXT* context);
int parse_rules_file(FILE* rules_file, YARA_CONTEXT* context);

