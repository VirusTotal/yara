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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "yara.h"
#include "ast.h"
#include "mem.h"
#include "regex.h"

#define todigit(x)  ((x) >='A'&& (x) <='F')? ((unsigned char) (x - 'A' + 10)) : ((unsigned char) (x - '0'))

RULE* lookup_rule(RULE_LIST* rules, const char* identifier, NAMESPACE* ns)
{
    RULE* rule = rules->head;
    
    while (rule != NULL)
    {
        if (strcmp(rule->identifier, identifier) == 0 &&
			strcmp(rule->ns->name, ns->name) == 0)
        {
            return rule;
        }
        
        rule = rule->next;
    }
    
    return NULL;
}

META* lookup_meta(META* meta_list_head, const char* identifier)
{
    META* meta = meta_list_head;
    
    while (meta != NULL)
    {
        if (strcmp(meta->identifier, identifier) == 0)
        {
            return meta;
        }
            
        meta = meta->next;
    }
    
    return NULL;
}


STRING* lookup_string(STRING* string_list_head, const char* identifier)
{
    STRING* string = string_list_head;
    
    while (string != NULL)
    {
        if (strcmp(string->identifier, identifier) == 0)
        {
            return string;
        }
            
        string = string->next;
    }
    
    return NULL;
}

TAG* lookup_tag(TAG* tag_list_head, const char* identifier)
{
    TAG* tag = tag_list_head;
    
    while (tag != NULL)
    {
        if (strcmp(tag->identifier, identifier) == 0)
        {
            return tag;
        }
            
        tag = tag->next;
    }
    
    return NULL;
}

VARIABLE* lookup_variable(VARIABLE* variable_list_head, const char* identifier)
{
    VARIABLE*  variable = variable_list_head;
    
    while ( variable != NULL)
    {
        if (strcmp(variable->identifier, identifier) == 0)
        {
            return variable;
        }
            
        variable = variable->next;
    }
    
    return NULL;
}


int new_rule(RULE_LIST* rules, char* identifier, NAMESPACE* ns, int flags, TAG* tag_list_head, META* meta_list_head, STRING* string_list_head, TERM* condition)
{
    RULE* new_rule;
    
    int result = ERROR_SUCCESS;
    
    if (lookup_rule(rules, identifier, ns) == NULL)  /* do not allow rules with the same identifier */
    {
        new_rule = (RULE*) yr_malloc(sizeof(RULE));
    
        if (new_rule != NULL)
        {
            new_rule->identifier = identifier;
			new_rule->ns = ns;
            new_rule->flags = flags;
			new_rule->tag_list_head = tag_list_head;
            new_rule->meta_list_head = meta_list_head;
            new_rule->string_list_head = string_list_head;
            new_rule->condition = condition;
            new_rule->next = NULL;
            
            if (rules->head == NULL && rules->tail == NULL)  /* list is empty */
            {
                rules->head = new_rule;
                rules->tail = new_rule;
            }
            else
            {
                rules->tail->next = new_rule;
                rules->tail = new_rule;
            }			
        }
        else
        {
            result = ERROR_INSUFICIENT_MEMORY;
        }
    }
    else
    {
        result = ERROR_DUPLICATE_RULE_IDENTIFIER;
    }

    return result;
}

int new_hex_string( YARA_CONTEXT* context, 
                    SIZED_STRING* charstr, 
                    unsigned char** hexstr, 
                    unsigned char** maskstr, 
                    unsigned int* length)
{
    int i;
    int skip_lo;
    int skip_hi;
    int skip_exact;
    char c,d;
    char* s;
    char* closing_bracket;
    int inside_or;
    int or_count;
    int len;  
    int result = ERROR_SUCCESS;
    
    unsigned char high_nibble = 0;
    unsigned char low_nibble = 0;
    unsigned char mask_high_nibble = 0;
    unsigned char mask_low_nibble = 0;
    unsigned char* hex;
    unsigned char* mask;
    
    //assert(charstr && hexstr && maskstr && length);
    
    len = (int) charstr->length;
    
    //assert(charstr[0] == '{' && charstr[len - 1] == '}');
    
    *hexstr = hex = (unsigned char*) yr_malloc(len / 2);
    *maskstr = mask = (unsigned char*) yr_malloc(len);
    
    if (hex == NULL || mask == NULL)
    {
        if (hex) yr_free(hex);
        if (mask) yr_free(mask);
        
        return ERROR_INSUFICIENT_MEMORY;
    }
    
    i = 1;  
    *length = 0;
    inside_or = FALSE;
    
    while (i < len - 1)
    {
        c = toupper(charstr->c_string[i]);    
        
        if (isalnum(c) || (c == '?'))
        {   
            d = toupper(charstr->c_string[i + 1]);
            
            if (!isalnum(d) && (d != '?'))
            {
                result = ERROR_UNPAIRED_NIBBLE;
                break;
            }
            
            if (c != '?')
            {  
                high_nibble = todigit(c);
                mask_high_nibble = 0x0F;
            }
            else
            {
                high_nibble = 0;
                mask_high_nibble = 0;
            }
            
            if (d != '?')
            {  
                low_nibble = todigit(d);
                mask_low_nibble = 0x0F;
            }
            else
            {
                low_nibble = 0;
                mask_low_nibble = 0;
            }
                      
            *hex++ = (high_nibble << 4) | (low_nibble); 
            *mask++ = (mask_high_nibble << 4) | (mask_low_nibble);
            
            (*length)++; 
            
            i+=2;
        }      
        else if (c == '(')
        {            
            if (inside_or)
            {
                result = ERROR_NESTED_OR_OPERATION;
                break;                
            }
            
            inside_or = TRUE;
            *mask++ = MASK_OR;
            i++;
        }
        else if (c == ')')
        {
            inside_or = FALSE;
            *mask++ = MASK_OR_END;
            i++;
        }
        else if (c == '|')
        {   
            if (!inside_or)
            {
                result = ERROR_MISPLACED_OR_OPERATOR;
                break;
            }
            
            *mask++ = MASK_OR;
            i++;
        }
        else if (c == '[')
        {   
            if (inside_or)
            {
                result = ERROR_SKIP_INSIDE_OR_OPERATION;
                break;
            }
                        
            closing_bracket = strchr(charstr->c_string + i + 1, ']');

            if (closing_bracket == NULL)
            {
                result = ERROR_MISMATCHED_BRACKET;
                break;
            } 
            else  
            {
                s = closing_bracket + 1; 
                
                while (*s == ' ') s++;  /* skip spaces */
                
                if (*s == '}')          /* no skip instruction should exists at the end of the string */
                {
                    result = ERROR_SKIP_AT_END;
                    break;          
                } 
                else if (*s == '[')     /* consecutive skip intructions are not allowed */
                {
                    result = ERROR_CONSECUTIVE_SKIPS;
                    break;          
                }   
            }
            
            /* only decimal digits and '-' are allowed between brackets */
            
            for (s = charstr->c_string + i + 1; s < closing_bracket; s++)
            {
                if ((*s != '-') && (*s < '0' || *s > '9'))
                {
                    result = ERROR_INVALID_SKIP_VALUE;
                    break;
                }
            }
            
            skip_lo = atoi(charstr->c_string + i + 1);
            
            if (skip_lo < 0 || skip_lo > MASK_MAX_SKIP)
            { 
                result = ERROR_INVALID_SKIP_VALUE;
                break;  
            }

            skip_exact = 1;

            s = strchr(charstr->c_string + i + 1, '-');

            if (s != NULL && s < closing_bracket)
            {
                skip_hi = atoi(s + 1);

                if (skip_hi <= skip_lo || skip_hi > MASK_MAX_SKIP)
                {
                    result = ERROR_INVALID_SKIP_VALUE;
                    break;  
                }
                
                skip_exact = 0;
            }
            
            if (skip_exact)
            {
                *mask++ = MASK_EXACT_SKIP;
                *mask++ = (unsigned char) skip_lo;
            }
            else
            {
                *mask++ = MASK_RANGE_SKIP;
                *mask++ = (unsigned char) skip_lo;
                *mask++ = (unsigned char) skip_hi;
            }
            
            i = (int) (closing_bracket - charstr->c_string + 1); 
            
        }
        else if (c == ']')
        {
            result = ERROR_MISMATCHED_BRACKET;
            break;          
        }
        else if (c == ' ' || c == '\n' || c == '\t')
		{
			i++;
		}
        else 
        {
            result = ERROR_INVALID_CHAR_IN_HEX_STRING;
            break;
        }   
    
    }
        
    *mask++ = MASK_END;
    
    /* wildcards or skip instructions are not allowed at the first position the string */
    
    if ((*maskstr)[0] != 0xFF) 
    {
        result = ERROR_MISPLACED_WILDCARD_OR_SKIP;
    }
        
    /* check if byte or syntax is correct */
    
    i = 0;
    or_count = 0;
    
    while ((*maskstr)[i] != MASK_END)
    {
        if ((*maskstr)[i] == MASK_OR)
        {
            or_count++;
            
            if ( (*maskstr)[i+1] == MASK_OR || (*maskstr)[i+1] == MASK_OR_END )
            {
                result = ERROR_INVALID_OR_OPERATION_SYNTAX;
                break;
            }
        }
        else if ((*maskstr)[i] == MASK_OR_END)
        {
            if (or_count <  2)
            {
                result = ERROR_INVALID_OR_OPERATION_SYNTAX;
                break;              
            }
            
            or_count = 0;
        }
        
        i++;
    }
    
    if (result != ERROR_SUCCESS)
    {
        yr_free(*hexstr);
        yr_free(*maskstr); 
        *hexstr = NULL;
        *maskstr = NULL;
    }
    
    return result;
}


int new_text_string(    YARA_CONTEXT* context, 
                        SIZED_STRING* charstr, 
                        int flags, 
                        unsigned char** hexstr, 
                        REGEXP* re,
                        unsigned int* length)
{
    char *error;
    int erroffset;
    int options;
    int result = ERROR_SUCCESS;
    
    //assert(charstr && hexstr && regexp && length);
    
    *length = charstr->length;
    *hexstr = yr_malloc(charstr->length);
    
    if (*hexstr == NULL)
    {
        return ERROR_INSUFICIENT_MEMORY;
    }

    memcpy(*hexstr, charstr->c_string, charstr->length);
         
    if (flags & STRING_FLAGS_REGEXP)
    {
        if (regex_compile(re,  // REGEXP *
                          charstr->c_string,  // Regex pattern
                          TRUE,  // Anchor the pattern to the first character when evaluating
                          flags & STRING_FLAGS_NO_CASE,  // If TRUE then case insensitive search
                          context->last_error_extra_info,  // Error message
                          sizeof(context->last_error_extra_info), // Size of error buffer
                          &erroffset) <= 0) // Offset into regex pattern if error detected
        {
             result = ERROR_INVALID_REGULAR_EXPRESSION;
        }
    }
    else
    {
        // re contains multiple pointers now, if we're
        // not doing a regex, make sure all are NULL.
        memset(re, '\0', sizeof(REGEXP));
    }
    
    return result;
}

int new_string( YARA_CONTEXT* context, 
                char* identifier, 
                SIZED_STRING* charstr, 
                int flags, 
                STRING** string)
{
    STRING* new_string;
    int result = ERROR_SUCCESS;
        
    new_string = (STRING*) yr_malloc(sizeof(STRING));
    
    if(new_string != NULL)
    {
        if (!(flags & STRING_FLAGS_WIDE))
            flags |= STRING_FLAGS_ASCII;
        
        new_string->identifier = identifier;
        new_string->flags = flags;
        new_string->next = NULL;
        new_string->matches_head = NULL;
        new_string->matches_tail = NULL;
        
        if (flags & STRING_FLAGS_HEXADECIMAL)
        {
            result = new_hex_string(context, charstr, &new_string->string, &new_string->mask, &new_string->length);  
        }
        else
        {
            result = new_text_string(context, charstr, flags, &new_string->string, &new_string->re, &new_string->length);
        }
        
        if (result != ERROR_SUCCESS)
        {
            yr_free(new_string);
            new_string = NULL;
        }   
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;   
    }

    *string = new_string;
    return result;
}

int new_simple_term(int type, TERM** term)
{
    TERM* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM*) yr_malloc(sizeof(TERM));
    
    if (new_term != NULL)
    {
        new_term->type = type;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;   
    return result;	
}

int new_unary_operation(int type, TERM* op, TERM_UNARY_OPERATION** term)
{
    TERM_UNARY_OPERATION* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_UNARY_OPERATION*) yr_malloc(sizeof(TERM_UNARY_OPERATION));
    
    if (new_term != NULL)
    {
        new_term->type = type;
        new_term->op = op;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;   
    return result;
}

int new_binary_operation(int type, TERM* op1, TERM* op2, TERM_BINARY_OPERATION** term)
{
    TERM_BINARY_OPERATION* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_BINARY_OPERATION*) yr_malloc(sizeof(TERM_BINARY_OPERATION));
    
    if (new_term != NULL)
    {
        new_term->type = type;
        new_term->op1 = op1;
        new_term->op2 = op2;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;   
    return result;
}

int new_ternary_operation(int type, TERM* op1, TERM* op2, TERM* op3, TERM_TERNARY_OPERATION** term)
{
    TERM_TERNARY_OPERATION* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_TERNARY_OPERATION*) yr_malloc(sizeof(TERM_TERNARY_OPERATION));
    
    if (new_term != NULL)
    {
        new_term->type = type;
        new_term->op1 = op1;
        new_term->op2 = op2;
        new_term->op3 = op3;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;   
    return result;
}

int new_constant(size_t constant, TERM_CONST** term)
{
    TERM_CONST* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_CONST*) yr_malloc(sizeof(TERM_CONST));

    if (new_term != NULL)
    {
        new_term->type = TERM_TYPE_CONST;
        new_term->value = constant;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;
    return result;
}


int new_string_identifier(int type, STRING* defined_strings, char* identifier, TERM_STRING** term)
{
    TERM_STRING* new_term = NULL;
    STRING* string;
    int result = ERROR_SUCCESS;
        
    if (strcmp(identifier, "$") != 0) /* non-anonymous strings */
    {
        string = lookup_string(defined_strings, identifier);
      
        if (string != NULL)
        {
    		/* the string has been used in an expression, mark it as referenced */
    		string->flags |= STRING_FLAGS_REFERENCED;  

			/* in these cases we can't not use the fast-matching mode */
			if (type == TERM_TYPE_STRING_COUNT ||
			    type == TERM_TYPE_STRING_AT ||
			    type == TERM_TYPE_STRING_IN_RANGE ||
			    type == TERM_TYPE_STRING_OFFSET)
			{
				string->flags &= ~STRING_FLAGS_FAST_MATCH;
			}
	
            new_term = (TERM_STRING*) yr_malloc(sizeof(TERM_STRING));

            if (new_term != NULL)
            {
                new_term->type = type;
                new_term->string = string;
                new_term->next = NULL;
            }
        }
        else
        {
            result = ERROR_UNDEFINED_STRING;
        }
    }
    else  /* anonymous strings */
    {
        new_term = (TERM_STRING*) yr_malloc(sizeof(TERM_STRING));

        if (new_term != NULL)
        {
            new_term->type = type;
            new_term->string = NULL;
            new_term->next = NULL;
        }      
    }
    
    *term = new_term;   
    return result;
}


int new_variable(YARA_CONTEXT* context, char* identifier, TERM_VARIABLE** term)
{
    TERM_VARIABLE* new_term = NULL;
    VARIABLE* variable;
    int result = ERROR_SUCCESS;
    
    variable = lookup_variable(context->variables, identifier);
    
    if (variable != NULL) /* external variable should be defined */
    {    
        new_term = (TERM_VARIABLE*) yr_malloc(sizeof(TERM_VARIABLE));

        if (new_term != NULL)
        {
            new_term->type = TERM_TYPE_VARIABLE;
            new_term->variable = variable;
        }
        else
        {
            result = ERROR_INSUFICIENT_MEMORY;
        }
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        result = ERROR_UNDEFINED_IDENTIFIER;
    }
    
    *term = new_term;
    return result;    
}

TERM* vector_first(TERM_ITERABLE* self, EVALUATION_FUNCTION evaluate, EVALUATION_CONTEXT* context)
{
    TERM_VECTOR* vector = (TERM_VECTOR*) self;
    vector->current = 0;
    return vector->items[0];
}

TERM* vector_next(TERM_ITERABLE* self, EVALUATION_FUNCTION evaluate, EVALUATION_CONTEXT* context)
{
    TERM_VECTOR* vector = (TERM_VECTOR*) self;
    TERM* result = NULL;
    
    if (vector->current < vector->count - 1)
    {
        vector->current++;
        result = vector->items[vector->current];
    }
    
    return result;
}


int new_vector(TERM_VECTOR** term)
{
    TERM_VECTOR* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_VECTOR*) yr_malloc(sizeof(TERM_VECTOR));
    
    if (new_term != NULL)
    {
        new_term->type = TERM_TYPE_VECTOR;
        new_term->first = vector_first;
        new_term->next = vector_next;
        new_term->count = 0;
        new_term->current = 0;
        new_term->items[0] = NULL;
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }
    
    *term = new_term;   
    return result;	
}


int add_term_to_vector(TERM_VECTOR* vector, TERM* term)
{
    int result = ERROR_SUCCESS;
    
    if (vector->count < MAX_VECTOR_SIZE)
    {
        vector->items[vector->count] = term;
        vector->count++;
    }
    else
    {
        result = ERROR_VECTOR_TOO_LONG;
    }
    
    return result;
    
}


TERM* range_first(TERM_ITERABLE* self, EVALUATION_FUNCTION evaluate, EVALUATION_CONTEXT* context)
{
    TERM_RANGE* range = (TERM_RANGE*) self;
    range->current->value = evaluate(range->min, context);
    return (TERM*) range->current;
}


TERM* range_next(TERM_ITERABLE* self, EVALUATION_FUNCTION evaluate, EVALUATION_CONTEXT* context)
{
    TERM_RANGE* range = (TERM_RANGE*) self;

    if (range->current->value < evaluate(range->max, context))
    {
        range->current->value++;
        return (TERM*) range->current;
    }
    else
    {
        return NULL;
    }
}


int new_range(TERM* min, TERM* max, TERM_RANGE** term)
{
    TERM_RANGE* new_term = NULL;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_RANGE*) yr_malloc(sizeof(TERM_RANGE));
    
    if (new_term != NULL)
    {
        new_term->type = TERM_TYPE_RANGE;
        new_term->first = range_first;
        new_term->next = range_next;
        new_term->min = min;
        new_term->max = max;
        
        result = new_constant(0, &new_term->current);
    }
    else
    {
        result = ERROR_INSUFICIENT_MEMORY;
    }    
    
    *term = new_term;
    return result;
}


/* 
	free_term(TERM* term)

	Frees a term. If the term depends on other terms they are also freed. Notice that
	some terms hold references to STRING or VARIABLE structures, but these 
	structures are freed by yr_destroy_context not by this function.
	
*/

void free_term(TERM* term)
{
    TERM_STRING* next;
    TERM_STRING* tmp;
    int i, count;

    switch(term->type)
    {
    case TERM_TYPE_STRING:
    
        next = ((TERM_STRING*) term)->next;
    
        while (next != NULL)
        {
            tmp = next->next;
            yr_free(next);
            next = tmp;     
        }
    
        break;
    
	case TERM_TYPE_STRING_AT:
	
		free_term(((TERM_STRING*)term)->offset);
		break;
		
	case TERM_TYPE_STRING_OFFSET:

    	free_term(((TERM_STRING*)term)->index);
    	break;
	
	case TERM_TYPE_STRING_IN_RANGE:
	
        free_term(((TERM_STRING*)term)->range);
        break;
        
	case TERM_TYPE_STRING_IN_SECTION_BY_NAME:
	    
	    yr_free(((TERM_STRING*)term)->section_name);
		break;
		
    case TERM_TYPE_STRING_MATCH:

        regex_free(&(((TERM_STRING_OPERATION*)term)->re));
        break;

	case TERM_TYPE_STRING_CONTAINS:
		yr_free(((TERM_STRING_OPERATION*)term)->string);
		break;
                    
    case TERM_TYPE_AND:          
    case TERM_TYPE_OR:
    case TERM_TYPE_ADD:
    case TERM_TYPE_SUB:      
    case TERM_TYPE_MUL:
    case TERM_TYPE_DIV:  
    case TERM_TYPE_GT:       
    case TERM_TYPE_LT:
    case TERM_TYPE_GE:       
    case TERM_TYPE_LE:
    case TERM_TYPE_EQ:
    case TERM_TYPE_OF:
    case TERM_TYPE_NOT_EQ:
    case TERM_TYPE_SHIFT_LEFT:
    case TERM_TYPE_SHIFT_RIGHT:
    case TERM_TYPE_BITWISE_OR:
    case TERM_TYPE_BITWISE_AND:
    
        free_term(((TERM_BINARY_OPERATION*)term)->op1);
        free_term(((TERM_BINARY_OPERATION*)term)->op2);
        break;        
                  
    case TERM_TYPE_NOT:
    case TERM_TYPE_BITWISE_NOT:
    case TERM_TYPE_INT8_AT_OFFSET:
    case TERM_TYPE_INT16_AT_OFFSET:
    case TERM_TYPE_INT32_AT_OFFSET:  
    case TERM_TYPE_UINT8_AT_OFFSET:
    case TERM_TYPE_UINT16_AT_OFFSET:
    case TERM_TYPE_UINT32_AT_OFFSET:
    
        free_term(((TERM_UNARY_OPERATION*)term)->op);
        break;
        
    case TERM_TYPE_RANGE:
    
        free_term(((TERM_RANGE*)term)->min);
        free_term(((TERM_RANGE*)term)->max);
        free_term((TERM*) ((TERM_RANGE*)term)->current);
        break;
        
    case TERM_TYPE_VECTOR:
    
        count = ((TERM_VECTOR*)term)->count;
        
        for (i = 0; i < count; i++)
        {
            free_term(((TERM_VECTOR*)term)->items[i]);
        }
        
        break;
        
    case TERM_TYPE_INTEGER_FOR:
    
        free_term(((TERM_INTEGER_FOR*)term)->count);
        free_term(((TERM_INTEGER_FOR*)term)->expression);
        free_term((TERM*) ((TERM_INTEGER_FOR*)term)->items);
        break;
        
    case TERM_TYPE_STRING_FOR:

        free_term(((TERM_TERNARY_OPERATION*)term)->op1);
        free_term(((TERM_TERNARY_OPERATION*)term)->op2);
        free_term(((TERM_TERNARY_OPERATION*)term)->op3);          
        break;
    }
    
    yr_free(term);
}



