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
#include "compile.h"
#include "error.h"


int line_number;
const char* file_name;

RULE_LIST* rule_list;

void set_file_name(const char* rules_file_name)
{
	file_name = rules_file_name;
}

int compile_rules(FILE* rules_file, RULE_LIST* rules)
{	
	rule_list = rules;	
	yyin = rules_file;

	if (yyin != NULL)
	{
		//yydebug = 1;	
		line_number = 1;		
		yyparse();	
	}
		
	return yynerrs;
}


/*int yywrap()
{
	// line_number = 1;
	return 1;
*/

