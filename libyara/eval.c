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
#include "regex.h"

#include <string.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef char int8;
typedef short int16;
typedef int int32;

#define function_read(type, tsize) int read_##type##tsize(MEMORY_BLOCK* block, size_t offset) \
{ \
    while (block != NULL) \
    { \
        if (offset >= block->base && offset < block->base + block->size - (tsize - 1)) \
        { \
            return *((type##tsize *) (block->data + offset - block->base)); \
        } \
        block = block->next; \
    } \
    return 0xE0FE0F; \
};


function_read(uint, 8)
function_read(uint, 16)
function_read(uint, 32)
function_read(int, 8)
function_read(int, 16)
function_read(int, 32)



long long evaluate(TERM* term, EVALUATION_CONTEXT* context)
{
	size_t offs, hi_bound, lo_bound;

	unsigned int i;
	int ovector[3];
	int rc;
	
    STRING* string;
    STRING* saved_anonymous_string;
	
	TERM_CONST* term_const = ((TERM_CONST*) term);
	TERM_UNARY_OPERATION* term_unary = ((TERM_UNARY_OPERATION*) term);
	TERM_BINARY_OPERATION* term_binary = ((TERM_BINARY_OPERATION*) term);
	TERM_TERNARY_OPERATION* term_ternary = ((TERM_TERNARY_OPERATION*) term);
	TERM_STRING* term_string = ((TERM_STRING*) term);
	TERM_EXTERNAL_VARIABLE* term_external_variable = ((TERM_EXTERNAL_VARIABLE*) term);
	TERM_EXTERNAL_STRING_OPERATION* term_external_string_operation = ((TERM_EXTERNAL_STRING_OPERATION*) term);
	
	MATCH* match;
	TERM_STRING* t;
	
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
	
	    if (term_string->string == NULL) /* it's an anonymous string */
	    {
            string = context->current_string;
	    }
	    else
	    {
            string = term_string->string;
	    }
	    	
		return string->flags & STRING_FLAGS_FOUND;
		
	case TERM_TYPE_STRING_AT:
	
    	if (term_string->string == NULL) /* it's an anonymous string */
        {
            string = context->current_string;
        }
        else
        {
            string = term_string->string;
        }
	
		if (string->flags & STRING_FLAGS_FOUND)
		{	
			offs = evaluate(term_string->offset, context);
								
			match = string->matches;
			
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
	
        if (term_string->string == NULL) /* it's an anonymous string */
        {
            string = context->current_string;
        }
        else
        {
            string = term_string->string;
        }
	
		if (string->flags & STRING_FLAGS_FOUND)
		{	
			lo_bound = evaluate(term_string->lower_offset, context);
			hi_bound = evaluate(term_string->upper_offset, context);
				
			match = string->matches;

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
		
		if (term_string->string == NULL) /* it's an anonymous string */
        {
            string = context->current_string;
        }
        else
        {
            string = term_string->string;
        }
        
		match = string->matches;
		
		while (match != NULL)
		{
			i++;
			match = match->next;
		}
		return i;
		
	case TERM_TYPE_STRING_OFFSET:
	
    	if (term_string->string == NULL) /* it's an anonymous string */
        {
            string = context->current_string;
        }
        else
        {
            string = term_string->string;
        }
	
	    if (string->matches != NULL)
	    {
            match = string->matches;
	        
    		while (match->next != NULL)
    		{
    			match = match->next;
    		}	  
    		
            return match->offset;      
	    }
	    else
	    {
            return -1;
	    }

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
		return !evaluate(term_unary->op, context);
		
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
			
		i = evaluate(term_binary->op1, context);
		t = (TERM_STRING*) term_binary->op2;
						
		while (t != NULL && i > 0)
		{
			if (evaluate((TERM*) t, context)) 
			{
				i--;
			}				
			t = t->next;
		} 
		
		return (i == 0);
		
	case TERM_TYPE_FOR:

		i = evaluate(term_ternary->op1, context);		
		t = (TERM_STRING*) term_ternary->op2;	

		while (t != NULL && i > 0)
		{
            saved_anonymous_string = context->current_string;
            context->current_string = t->string;
		    
			if (evaluate(term_ternary->op3, context)) 
			{
				i--;
			}	
			
            context->current_string = saved_anonymous_string;
						
			t = t->next;
		} 
		
		return (i == 0);
	
	case TERM_TYPE_FOR_OCCURRENCES:
	    
        i = evaluate(term_ternary->op1, context);
        t = (TERM_STRING*) term_ternary->op2;
        
        saved_anonymous_string = context->current_string;
        context->current_string = t->string;
        
        match = t->string->matches;
        
        while (match != NULL && i > 0)
        {            
            if (evaluate(term_ternary->op3, context)) 
			{
				i--;
			}
			
            match = match->next;	
        }
        
        context->current_string = saved_anonymous_string;
        
        return (i == 0);
    
    case TERM_TYPE_UINT8_AT_OFFSET:

        return read_uint8(context->mem_block, evaluate(term_unary->op, context));

    case TERM_TYPE_UINT16_AT_OFFSET:
        
        return read_uint16(context->mem_block, evaluate(term_unary->op, context));
        
    case TERM_TYPE_UINT32_AT_OFFSET:

        return read_uint32(context->mem_block, evaluate(term_unary->op, context));
        
    case TERM_TYPE_INT8_AT_OFFSET:

        return read_int8(context->mem_block, evaluate(term_unary->op, context));

    case TERM_TYPE_INT16_AT_OFFSET:

        return read_int16(context->mem_block, evaluate(term_unary->op, context));

    case TERM_TYPE_INT32_AT_OFFSET:

        return read_int32(context->mem_block, evaluate(term_unary->op, context));  
        
    case TERM_TYPE_EXTERNAL_VARIABLE:
    
        if (term_external_variable->variable->type == EXTERNAL_VARIABLE_TYPE_STRING)
        {
            return ( term_external_variable->variable->string != NULL && *term_external_variable->variable->string != '\0');
        }
        else
        {
            return term_external_variable->variable->integer;
        }
        
    case TERM_TYPE_EXTERNAL_STRING_MATCH:
        rc = regex_exec(&(term_external_string_operation->re),
                        term_external_string_operation->ext_var->string,
                        strlen(term_external_string_operation->ext_var->string));
        return (rc >= 0);

	case TERM_TYPE_EXTERNAL_STRING_CONTAINS:
		
		return (strstr(term_external_string_operation->ext_var->string, term_external_string_operation->string) != NULL);
     	
	default:
		return 0;
	}
}
