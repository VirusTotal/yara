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
#include "error.h"

#define todigit(x)  ((x) >='A'&& (x) <='F')? ((unsigned char) (x - 'A' + 10)) : ((unsigned char) (x - '0'))

#ifdef WIN32
#define strdup _strdup
#endif

RULE* lookup_rule(RULE_LIST* rules, char* identifier)
{
    RULE* rule = rules->head;
    
    while (rule != NULL)
    {
        if (strcmp(rule->identifier, identifier) == 0)
        {
            return rule;
        }
        
        rule = rule->next;
    }
    
    return NULL;
}

STRING* lookup_string(STRING* string_list_head, char* identifier)
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

TAG* lookup_tag(TAG* tag_list_head, char* identifier)
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


int require_exe_file(TERM* term)
{
    switch(term->type)
    {
	case TERM_TYPE_ENTRYPOINT:
	case TERM_TYPE_STRING_IN_SECTION_BY_NAME:
		return TRUE;
	
	case TERM_TYPE_STRING_IN_RANGE:
        return require_exe_file(((TERM_STRING*)term)->lower_offset) || require_exe_file(((TERM_STRING*)term)->upper_offset);
                    
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
        return require_exe_file(((TERM_BINARY_OPERATION*)term)->op1) || require_exe_file(((TERM_BINARY_OPERATION*)term)->op2);    
                      
    case TERM_TYPE_NOT:    
        return require_exe_file(((TERM_BINARY_OPERATION*)term)->op1);

	default:
		return FALSE;
    }
}

int new_rule(RULE_LIST* rules, char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition)
{
    RULE* new_rule;
    
    int result = ERROR_SUCCESS;
    
    if (lookup_rule(rules, identifier) == NULL)  /* do not allow rules with the same identifier */
    {
        new_rule = (RULE*) malloc(sizeof(RULE));
    
        if (new_rule != NULL)
        {
            new_rule->identifier = identifier;
            new_rule->flags = flags;
			new_rule->tag_list_head = tag_list_head;
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
			
			if (require_exe_file(condition))
			{
				new_rule->flags |= RULE_FLAGS_REQUIRE_PE_FILE;
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

int new_hex_string(SIZED_STRING* charstr, unsigned char** hexstr, unsigned char** maskstr, unsigned int* length)
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
    
    *hexstr = hex = (unsigned char*) malloc(len / 2);
    *maskstr = mask = (unsigned char*) malloc(len);
    
    if (hex == NULL || mask == NULL)
    {
        if (hex) free(hex);
        if (mask) free(mask);
        
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
        else if (c == ' ')
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
        free(*hexstr);
        free(*maskstr); 
        *hexstr = NULL;
        *maskstr = NULL;
    }
    
    return result;
}


int new_text_string(SIZED_STRING* charstr, int flags, unsigned char** hexstr, REGEXP* re, unsigned int* length)
{
    const char *error;
    int erroffset;
    int options;
    int result = ERROR_SUCCESS;
    
    //assert(charstr && hexstr && regexp && length);
    
    *length = charstr->length;
    *hexstr = malloc(charstr->length);
    
    if (*hexstr == NULL)
    {
        return ERROR_INSUFICIENT_MEMORY;
    }
    
    memcpy(*hexstr, charstr->c_string, charstr->length);
    
     
     if (flags & STRING_FLAGS_REGEXP)
     {           
		options = PCRE_ANCHORED;
         
         if (flags & STRING_FLAGS_NO_CASE)
         {
             options |= PCRE_CASELESS;
         }
         
         re->regexp = pcre_compile((char*) *hexstr, options, &error, &erroffset, NULL); 

         if (re->regexp != NULL)  
         {
             re->extra = pcre_study(re->regexp, 0, &error);
             result = ERROR_SUCCESS;
         }
         else /* compilation failed */
         {
             strcpy(last_error_extra_info, error);
             result = ERROR_INVALID_REGULAR_EXPRESSION;
         }
     }
     else
     {
         re->regexp = NULL;
     }

    
    return result;
}

int new_string(char* identifier, SIZED_STRING* charstr, int flags, STRING** string)
{
    STRING* new_string;
    int result = ERROR_SUCCESS;
        
    new_string = (STRING*) malloc(sizeof(STRING));
    
    if(new_string != NULL)
    {
        if (!(flags & STRING_FLAGS_WIDE))
            flags |= STRING_FLAGS_ASCII;
        
        new_string->identifier = identifier;
        new_string->flags = flags;
        new_string->next = NULL;
        new_string->matches = NULL;
        
        if (flags & STRING_FLAGS_HEXADECIMAL)
        {
            result = new_hex_string(charstr, &new_string->string, &new_string->mask, &new_string->length);  
        }
        else
        {
            result = new_text_string(charstr, flags, &new_string->string, &new_string->re, &new_string->length);
        }
        
        if (result != ERROR_SUCCESS)
        {
            free(new_string);
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
    
    new_term = (TERM*) malloc(sizeof(TERM));
    
    if (new_term != NULL)
    {
        new_term->type = type;
        new_term->next = NULL;
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
    
    new_term = (TERM_UNARY_OPERATION*) malloc(sizeof(TERM_UNARY_OPERATION));
    
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
    
    new_term = (TERM_BINARY_OPERATION*) malloc(sizeof(TERM_BINARY_OPERATION));
    
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
    
    new_term = (TERM_TERNARY_OPERATION*) malloc(sizeof(TERM_TERNARY_OPERATION));
    
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

int new_constant(unsigned int constant, TERM_CONST** term)
{
    TERM_CONST* new_term;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_CONST*) malloc(sizeof(TERM_CONST));

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
	
            new_term = (TERM_STRING*) malloc(sizeof(TERM_STRING));

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
        new_term = (TERM_STRING*) malloc(sizeof(TERM_STRING));

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

int new_anonymous_string_identifier(int type, STRING* defined_strings, TERM_STRING** term)
{
    TERM_STRING* new_term = NULL;
    STRING* string;
    int result = ERROR_SUCCESS;
    
    new_term = (TERM_STRING*) malloc(sizeof(TERM_STRING));

    if (new_term != NULL)
    {
        new_term->type = type;
        new_term->string = NULL;
        new_term->next = NULL;
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
	some terms hold references to STRING structures, but these structures are freed
	by free_rule_list, not by this function.
	
*/

void free_term(TERM* term)
{
    switch(term->type)
    {
    case TERM_TYPE_STRING:
        break;//TODO: free next
    
	case TERM_TYPE_STRING_AT:
		free_term(((TERM_STRING*)term)->offset);
		break;
	
	case TERM_TYPE_STRING_IN_RANGE:
        free_term(((TERM_STRING*)term)->lower_offset);
		free_term(((TERM_STRING*)term)->upper_offset);
        break;

	case TERM_TYPE_STRING_IN_SECTION_BY_NAME:
	    free(((TERM_STRING*)term)->section_name);
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
        free_term(((TERM_BINARY_OPERATION*)term)->op1);
        free_term(((TERM_BINARY_OPERATION*)term)->op2);
        break;        
                  
    case TERM_TYPE_NOT:
    case TERM_TYPE_INT8_AT_OFFSET:
    case TERM_TYPE_INT16_AT_OFFSET:
    case TERM_TYPE_INT32_AT_OFFSET:  
    case TERM_TYPE_UINT8_AT_OFFSET:
    case TERM_TYPE_UINT16_AT_OFFSET:
    case TERM_TYPE_UINT32_AT_OFFSET:
        free_term(((TERM_UNARY_OPERATION*)term)->op);
        break;
    }
    
    free(term);
}

RULE_LIST* alloc_rule_list()
{
	RULE_LIST* rule_list = (RULE_LIST*) malloc(sizeof(RULE_LIST));

	rule_list->head = NULL;
	rule_list->tail = NULL;
    rule_list->non_hashed_strings = NULL;

	memset(rule_list->hash_table, 0, sizeof(rule_list->hash_table));

	return rule_list;
}


/* 
	void free_rule_list(RULE_LIST* rule_list)

	Frees a list of rules, its strings and conditions.
	
*/

void free_rule_list(RULE_LIST* rule_list)
{
    RULE* rule;
    RULE* next_rule;
    STRING* string;
    STRING* next_string;
    MATCH* match;
    MATCH* next_match;
	TAG* tag;
	TAG* next_tag;
    
    rule = rule_list->head;
    
    while (rule != NULL)
    {
        next_rule = rule->next;
        
        string = rule->string_list_head;
        
        while (string != NULL)
        {
            next_string = string->next;
            
			free(string->identifier);
            free(string->string);
            
            if (IS_HEX(string))
            {   
                free(string->mask);
            }
            else if (IS_REGEXP(string))
            {
                pcre_free(string->re.regexp);
                pcre_free(string->re.extra);
            }
            
            match = string->matches;
            
            while (match != NULL)
            {
                next_match = match->next;
                free(match);
                match = next_match;
            }
            
            free(string);
            string = next_string;
        }

		tag = rule->tag_list_head;

		while (tag != NULL)
		{
			next_tag = tag->next;
			
			free(tag->identifier);
			free(tag);
			
			tag = next_tag;
		}
        
        free_term(rule->condition);
        
        free(rule);
        rule = next_rule;
    }

	free(rule_list);
}

