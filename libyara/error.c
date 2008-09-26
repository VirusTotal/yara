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

#include <stdio.h>
#include <string.h>

#include "error.h"
#include "compile.h"

int last_error;
char last_error_extra_info[100];


void yyerror(const char *str)
{
	fprintf(stderr,"%s:%d: %s\n", file_name, line_number, str);
}

void show_last_error()
{
	char errmsg[1000];
	
	switch(last_error)
	{
		case ERROR_INSUFICIENT_MEMORY:
		    yyerror("not enough memory");
			break;
		case ERROR_DUPLICATERULEIDENTIFIER:
			sprintf(errmsg, "duplicate rule identifier \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_DUPLICATE_STRING_IDENTIFIER:
			sprintf(errmsg, "duplicate string identifier \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_DUPLICATE_TAG_IDENTIFIER:
			sprintf(errmsg, "duplicate tag identifier \"%s\"", last_error_extra_info);
			yyerror(errmsg);			
			break;			
		case ERROR_INVALID_CHAR_IN_HEX_STRING:
		   	sprintf(errmsg, "invalid char in hex string \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_MISMATCHED_BRACKET:
			sprintf(errmsg, "mismatched bracket in string \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_SKIP_AT_END:		
			sprintf(errmsg, "skip at the end of string \"%s\"", last_error_extra_info);
			yyerror(errmsg);	
		    break;
		case ERROR_INVALID_SKIP_VALUE:
			sprintf(errmsg, "invalid skip in string \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_UNPAIRED_NIBBLE:
			sprintf(errmsg, "unpaired nibble in string \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_CONSECUTIVE_SKIPS:
			sprintf(errmsg, "two consecutive skips in string \"%s\"", last_error_extra_info);
			yyerror(errmsg);			
			break;
		case ERROR_MISPLACED_WILDCARD_OR_SKIP:
			sprintf(errmsg, "misplaced wildcard or skip at string \"%s\", wildcards and skips are only allowed after the first two bytes of the string", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_UNDEFINED_STRING:
			sprintf(errmsg, "undefined string %s", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_UNDEFINED_RULE:
		    sprintf(errmsg, "undefined rule \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_UNREFERENCED_STRING:
		    sprintf(errmsg, "unreferenced string \"%s\"", last_error_extra_info);
			yyerror(errmsg);
			break;
		case ERROR_INVALID_REGULAR_EXPRESSION:
			yyerror(last_error_extra_info);
			break;
		case ERROR_INVALID_BEGINING_FOR_REGEXP:
		    sprintf(errmsg, "invalid regular expression in string \"%s\": first two characters of regular expressions must be strictly defined", last_error_extra_info);
			yyerror(errmsg);
			break;
	}
	
}
