/*

Copyright(c) 2007. Victor M. Alvarez [plusvic@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

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

