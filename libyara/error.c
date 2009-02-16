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

int last_result = ERROR_SUCCESS;
int last_error = ERROR_SUCCESS;
int last_error_line = 0;
char last_error_extra_info[100];
char last_error_message[500];
char error_message[500];

YARAREPORT report_function = NULL;

//TODO: Arreglar los mensajes de error en yara-python. No sale nada cuando se trata de un error de sintaxis de yyparse

void yyerror(const char *error_message)
{    
    if (last_result != ERROR_SUCCESS) 
    {
        last_error = last_result;
    }
    else /* when yyerror is invoked and last_result == 0 is because a syntax error found by yyparse itself */
    {
        last_error = ERROR_SYNTAX_ERROR;
    }
    
    last_error_line = line_number;
    
    strcpy(last_error_message, error_message);
        
    if (report_function != NULL)
    {
        report_function(file_name, line_number, error_message);
    }	
}

int get_last_error()
{
    return last_error;
}

int get_error_line_number()
{
    return last_error_line;
}

char* get_last_error_message()
{
    return last_error_message;
}


void set_report_function(YARAREPORT fn)
{
    report_function = fn;
}

char* get_error_message(int error_code)
{
    switch(error_code)
	{
		case ERROR_INSUFICIENT_MEMORY:
		    snprintf(error_message, sizeof(error_message), "not enough memory");
			break;
		case ERROR_DUPLICATE_RULE_IDENTIFIER:
			snprintf(error_message, sizeof(error_message), "duplicate rule identifier \"%s\"", last_error_extra_info);
			break;
		case ERROR_DUPLICATE_STRING_IDENTIFIER:
			snprintf(error_message, sizeof(error_message), "duplicate string identifier \"%s\"", last_error_extra_info);
			break;
		case ERROR_DUPLICATE_TAG_IDENTIFIER:
			snprintf(error_message, sizeof(error_message), "duplicate tag identifier \"%s\"", last_error_extra_info);			
			break;			
		case ERROR_INVALID_CHAR_IN_HEX_STRING:
		   	snprintf(error_message, sizeof(error_message), "invalid char in hex string \"%s\"", last_error_extra_info);
			break;
		case ERROR_MISMATCHED_BRACKET:
			snprintf(error_message, sizeof(error_message), "mismatched bracket in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_SKIP_AT_END:		
			snprintf(error_message, sizeof(error_message), "skip at the end of string \"%s\"", last_error_extra_info);	
		    break;
		case ERROR_INVALID_SKIP_VALUE:
			snprintf(error_message, sizeof(error_message), "invalid skip in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNPAIRED_NIBBLE:
			snprintf(error_message, sizeof(error_message), "unpaired nibble in string \"%s\"", last_error_extra_info);
			break;
		case ERROR_CONSECUTIVE_SKIPS:
			snprintf(error_message, sizeof(error_message), "two consecutive skips in string \"%s\"", last_error_extra_info);			
			break;
		case ERROR_MISPLACED_WILDCARD_OR_SKIP:
			snprintf(error_message, sizeof(error_message), "misplaced wildcard or skip at string \"%s\", wildcards and skips are only allowed after the first byte of the string", last_error_extra_info);
		    break;
		case ERROR_MISPLACED_OR_OPERATOR:
		    snprintf(error_message, sizeof(error_message), "misplaced OR (|) operator at string \"%s\"", last_error_extra_info);
			break;
		case ERROR_NESTED_OR_OPERATION:
	        snprintf(error_message, sizeof(error_message), "nested OR (|) operator at string \"%s\"", last_error_extra_info);
		    break;		
		case ERROR_INVALID_OR_OPERATION_SYNTAX:
		    snprintf(error_message, sizeof(error_message), "invalid syntax at hex string \"%s\"", last_error_extra_info);
			break;
		case ERROR_SKIP_INSIDE_OR_OPERATION:
    		snprintf(error_message, sizeof(error_message), "skip inside an OR (|) operation at string \"%s\"", last_error_extra_info);
    		break;
		case ERROR_UNDEFINED_STRING:
            snprintf(error_message, sizeof(error_message), "undefined string \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNDEFINED_RULE:
		    snprintf(error_message, sizeof(error_message), "undefined rule \"%s\"", last_error_extra_info);
			break;
		case ERROR_UNREFERENCED_STRING:
		    snprintf(error_message, sizeof(error_message), "unreferenced string \"%s\"", last_error_extra_info);
			break;
		case ERROR_MISPLACED_ANONYMOUS_STRING:
	        snprintf(error_message, sizeof(error_message), "wrong use of anonymous string");
		    break;		
		case ERROR_INVALID_REGULAR_EXPRESSION:
		    snprintf(error_message, sizeof(error_message), "%s", last_error_extra_info);
			break;
	}
	
    return error_message;
}

