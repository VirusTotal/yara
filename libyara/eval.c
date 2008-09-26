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
#include "ast.h"
#include "eval.h"

unsigned int evaluate(TERM* term, EVALUATION_CONTEXT* context)
{
	unsigned int i;
	unsigned int offs, hi_bound, lo_bound;
	
	TERM_CONST* term_const = ((TERM_CONST*) term);
	TERM_BINARY_OPERATION* term_binary = ((TERM_BINARY_OPERATION*) term);
	TERM_STRING* term_string = ((TERM_STRING*) term);
	
	
	MATCH* match;
	TERM* t;
	
	switch(term->type)
	{
	case TERM_TYPE_CONST:
		return term_const->value;
		
	case TERM_TYPE_FILESIZE:
		return context->file_size;
		
	case TERM_TYPE_ENTRYPOINT:
		return context->entry_point;
		
	case TERM_TYPE_RULE:
		return evaluate(term_binary->op1, context);
		
	case TERM_TYPE_STRING:
		return term_string->string->flags & STRING_FLAGS_FOUND;
		
	case TERM_TYPE_STRING_AT:
		if (term_string->string->flags & STRING_FLAGS_FOUND)
		{	
			offs = evaluate(term_string->offset, context);
					
			match = term_string->string->matches;
			
			while (match != NULL)
			{
				if (match->offset == offs)
					return 1;
					
				match = match->next;
			}
			
			return 0;				
		}
		else return 0;
		
	case TERM_TYPE_STRING_IN_RANGE:
		if (term_string->string->flags & STRING_FLAGS_FOUND)
		{	
			lo_bound = evaluate(term_string->lower_offset, context);
			hi_bound = evaluate(term_string->upper_offset, context);
				
			match = term_string->string->matches;

			while (match != NULL)
			{
				if (match->offset >= lo_bound && match->offset <= hi_bound)
					return 1;

				match = match->next;
			}

			return 0;				
		}
		else return 0;
		
	case TERM_TYPE_STRING_IN_SECTION_BY_NAME:
		return 0; /*TODO: Implementar section by name*/
		
	case TERM_TYPE_STRING_COUNT:
		i = 0;
		match = term_string->string->matches;
		
		while (match != NULL)
		{
			i++;
			match = match->next;
		}
		return i;
			
	case TERM_TYPE_AND:
		if (evaluate(term_binary->op1, context))  
			return evaluate(term_binary->op2, context);	
		else
			return	0;
			
	case TERM_TYPE_OR:
		if (evaluate(term_binary->op1, context))
			return 1;
		else
			return evaluate(term_binary->op2, context);
			
	case TERM_TYPE_NOT:
		return !evaluate(term_binary->op1, context);
		
	case TERM_TYPE_ADD:
		return evaluate(term_binary->op1, context) + evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_SUB:            
		return evaluate(term_binary->op1, context) - evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_MUL:            
		return evaluate(term_binary->op1, context) * evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_DIV:            
		return evaluate(term_binary->op1, context) / evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_GT:             
		return evaluate(term_binary->op1, context) > evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_LT:             
		return evaluate(term_binary->op1, context) < evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_GE:             
		return evaluate(term_binary->op1, context) >= evaluate(term_binary->op2, context);
		                      
	case TERM_TYPE_LE:             
		return evaluate(term_binary->op1, context) <= evaluate(term_binary->op2, context);	
		                      
	case TERM_TYPE_EQ:    
		return evaluate(term_binary->op1, context) == evaluate(term_binary->op2, context);
	
	case TERM_TYPE_NOT_EQ:             
			return evaluate(term_binary->op1, context) != evaluate(term_binary->op2, context);
		
	case TERM_TYPE_OF:
		t = term_binary->op2;
		i = evaluate(term_binary->op1, context);
		
		while (t != NULL && i > 0)
		{
			if (evaluate(t, context)) 
			{
				i--;
			}				
			t = t->next;
		} 
		
		return (i == 0);
		
	default:
		return 0;
	}
}
