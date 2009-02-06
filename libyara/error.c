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

#ifdef WIN32
#define snprintf _snprintf
#endif

int last_error = ERROR_SUCCESS;
int abort_on_first_error = FALSE;

char last_error_extra_info[100];

YARAREPORT report_function = NULL;

void yyerror(const char *err_msg)
{
    if (report_function != NULL)
    {
        report_function(file_name, line_number, err_msg);
    }	
}

int get_last_error()
{
    return last_error;
}

void set_abort_on_first_error(int new_value)
{
    abort_on_first_error = new_value;
}

void set_report_function(YARAREPORT fn)
{
    report_function = fn;
}

void get_error_message(int error_code, char* error_message, int size)
{
    switch(error_code)
	{
		case ERROR_INSUFICIENT_MEMORY:
		    snprintf(error_message, size, "not enough memory");
			break;
		case ERROR_DUPLICATE_RULE_IDENTIFIER:
			snprintf(error_message, size, "duplicate rule identifier \"%s\"", last_error_extra_info);
			break;
		case ERROR_DUPLICATE_STRING_IDENTIFIER:
			snprintf(error_message, size, "duplicate string identifier \"%s\"", last_error_extra_info);
			break;
		case ERROR_DUPLICATE_TAG_IDENTIFIER:
			snprintf(error_message, size, "duplicate tag identifier \"%s\"", last_error_extra_info);			
			break;			
		case ERROR_INVALID_CHAR_IN_HEX_STRING:
		   	snprintf(error_message, size, "invalid char in hex string \"%s\"", last_error_extra_info);
			break;
		case ERROR_MISMATCHED_BRACKET:
			snprintf(error_message, size, "mismatched bracket in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_SKIP_AT_END:		
			snprintf(error_message, size, "skip at the end of string \"%s\"", last_error_extra_info);	
		    break;
		case ERROR_INVALID_SKIP_VALUE:
			snprintf(error_message, size, "invalid skip in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNPAIRED_NIBBLE:
			snprintf(error_message, size, "unpaired nibble in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_CONSECUTIVE_SKIPS:
			snprintf(error_message, size, "two consecutive skips in string \"%s\"", last_error_extra_info);			
			break;
		case ERROR_MISPLACED_WILDCARD_OR_SKIP:
			snprintf(error_message, size, "misplaced wildcard or skip at string \"%s\", wildcards and skips are only allowed after the first byte of the string", last_error_extra_info);
		    break;
		case ERROR_MISPLACED_OR_OPERATOR:
		    snprintf(error_message, size, "misplaced OR (|) operator at string \"%s\"", last_error_extra_info);
			break;
		case ERROR_NESTED_OR_OPERATION:
	        snprintf(error_message, size, "nested OR (|) operator at string \"%s\"", last_error_extra_info);
		    break;		
		case ERROR_INVALID_OR_OPERATION_SYNTAX:
		    snprintf(error_message, size, "invalid syntax at hex string \"%s\"", last_error_extra_info);
			break;
		case ERROR_SKIP_INSIDE_OR_OPERATION:
    		snprintf(error_message, size, "skip inside an OR (|) operation at string \"%s\"", last_error_extra_info);
    		break;
		case ERROR_UNDEFINED_STRING:
            snprintf(error_message, size, "undefined string \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNDEFINED_RULE:
		    snprintf(error_message, size, "undefined rule \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNREFERENCED_STRING:
		    snprintf(error_message, size, "unreferenced string \"%s\"", last_error_extra_info);
			break;
		case ERROR_MISPLACED_ANONYMOUS_STRING:
	        snprintf(error_message, size, "wrong use of anonymous string");
		    break;		
		case ERROR_INVALID_REGULAR_EXPRESSION:
		    snprintf(error_message, size, "%s", last_error_extra_info);
			break;
	}
}

void show_last_error()
{
	char error_message[1000];
	
    get_error_message(last_error, error_message, sizeof(error_message));
    
    yyerror(error_message);	
}
