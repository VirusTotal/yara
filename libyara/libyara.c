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
#include <stdio.h>

#include "filemap.h"
#include "mem.h"
#include "eval.h"
#include "lex.h"
#include "yara.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

void yr_init()
{
    yr_heap_alloc();
}


YARA_CONTEXT* yr_create_context()
{
    YARA_CONTEXT* context = (YARA_CONTEXT*) yr_malloc(sizeof(YARA_CONTEXT));
    
    context->rule_list.head = NULL;
    context->rule_list.tail = NULL;
    context->hash_table.non_hashed_strings = NULL;
    context->hash_table.populated = FALSE;
    context->errors = 0;
    context->error_report_function = NULL;
    context->last_error = ERROR_SUCCESS;
    context->last_error_line = 0;
    context->last_result = ERROR_SUCCESS;
    context->file_name_stack_ptr = 0;
    context->current_rule_strings = NULL;
    context->inside_for = 0;
    
    memset(context->hash_table.hashed_strings, 0, sizeof(context->hash_table.hashed_strings));
    
    return context;
    
}

void yr_destroy_context(YARA_CONTEXT* context)
{
    RULE* rule;
    RULE* next_rule;
    STRING* string;
    STRING* next_string;
    MATCH* match;
    MATCH* next_match;
	TAG* tag;
	TAG* next_tag;
    
    rule = context->rule_list.head;
    
    while (rule != NULL)
    {        
        next_rule = rule->next;
        
        string = rule->string_list_head;
        
        while (string != NULL)
        {
            next_string = string->next;
            
			yr_free(string->identifier);
            yr_free(string->string);
            
            if (IS_HEX(string))
            {   
                yr_free(string->mask);
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
                yr_free(match);
                match = next_match;
            }
            
            yr_free(string);
            string = next_string;
        }

		tag = rule->tag_list_head;

		while (tag != NULL)
		{
			next_tag = tag->next;
			
			yr_free(tag->identifier);
			yr_free(tag);
			
			tag = next_tag;
		}
        
        free_term(rule->condition);
        yr_free(rule->identifier);     
        yr_free(rule);
        rule = next_rule;
    }
    
    clear_hash_table(&context->hash_table);
	yr_free(context);
}

char* yr_get_current_file_name(YARA_CONTEXT* context)
{   
    if (context->file_name_stack_ptr > 0)
    {
        return context->file_name_stack[context->file_name_stack_ptr - 1];
    }
    else
    {
        return NULL;
    }
}

void yr_push_file_name(YARA_CONTEXT* context, const char* file_name)
{  
    context->file_name_stack[context->file_name_stack_ptr] = yr_strdup(file_name);
    context->file_name_stack_ptr++;
}


void yr_pop_file_name(YARA_CONTEXT* context)
{  
    context->file_name_stack_ptr--;
    if (context->file_name_stack_ptr > 0)
    {
        yr_free(context->file_name_stack[context->file_name_stack_ptr]);
        context->file_name_stack[context->file_name_stack_ptr] = NULL;  
    }
}

int yr_compile_file(FILE* rules_file, YARA_CONTEXT* context)
{	
    return parse_file(rules_file, context);
}

int yr_compile_string(const char* rules_string, YARA_CONTEXT* context)
{	
    return parse_string(rules_string, context);
}

int yr_scan_mem(unsigned char* buffer, unsigned int buffer_size, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
    int error;
    int global_rules_satisfied;
	unsigned int i;	
	int file_is_pe;
	
	RULE* rule;
	EVALUATION_CONTEXT eval_context;
	
	if (buffer_size < 2)
        return ERROR_SUCCESS;
	
	if (!context->hash_table.populated)
	{
        populate_hash_table(&context->hash_table, &context->rule_list);
	}
	
	eval_context.file_size = buffer_size;
    eval_context.data = buffer;
	
	file_is_pe = is_pe(buffer, buffer_size);
	
	if (file_is_pe)
	{
		eval_context.entry_point = get_entry_point_offset(buffer, buffer_size);
	}
	
	clear_marks(&context->rule_list);
	
	for (i = 0; i < buffer_size - 1; i++)
	{		    
		/* search for normal strings */	
        error = find_matches(   buffer[i], 
                                buffer[i + 1], 
                                buffer + i, 
                                buffer_size - i, 
                                i, 
                                STRING_FLAGS_HEXADECIMAL | STRING_FLAGS_ASCII, 
                                i, 
                                context);
		
		if (error != ERROR_SUCCESS)
		    return error;
		
		/* search for wide strings */
		if ((buffer[i + 1] == 0) && (buffer_size > 3) && (i < buffer_size - 3) && (buffer[i + 3] == 0))
		{
			error = find_matches(   buffer[i], 
			                        buffer[i + 2], 
			                        buffer + i, 
			                        buffer_size - i, 
			                        i, 
			                        STRING_FLAGS_WIDE, 
			                        i, 
			                        context);
			
			if (error != ERROR_SUCCESS)
    		    return error;
		}	
	}
	
	rule = context->rule_list.head;
	
	/* evaluate global rules */
	
    global_rules_satisfied = TRUE;
	
	while (rule != NULL)
	{	
		if (rule->flags & RULE_FLAGS_GLOBAL)
		{
            eval_context.rule = rule;
            
            if (evaluate(rule->condition, &eval_context))
    		{
                rule->flags |= RULE_FLAGS_MATCH;
    		}
    		else
    		{
                global_rules_satisfied = FALSE;
    		}
    		
    		if (!(rule->flags & RULE_FLAGS_PRIVATE))
    		{
        		if (callback(rule, buffer, buffer_size, user_data) != 0)
        		{
                    return ERROR_CALLBACK_ERROR;
        		}
		    }
		}
			
		rule = rule->next;
	}
	
	if (!global_rules_satisfied)
	{
        return ERROR_SUCCESS;
	}

	rule = context->rule_list.head;
	
	while (rule != NULL)
	{
		/* skip global rules and privates rules */
		
		if (rule->flags & RULE_FLAGS_GLOBAL || rule->flags & RULE_FLAGS_PRIVATE)  
		{
			rule = rule->next;
			continue;
		}
		
		/* evaluate only if file is PE or the rule does not requires PE files*/
	  
		if (file_is_pe || !(rule->flags & RULE_FLAGS_REQUIRE_PE_FILE))
		{
		    eval_context.rule = rule;
		    
		    if (evaluate(rule->condition, &eval_context))
    		{
                rule->flags |= RULE_FLAGS_MATCH;
    		}
		}
		
		if (callback(rule, buffer, buffer_size, user_data) != 0)
		{
            return ERROR_CALLBACK_ERROR;
		}
		
		rule = rule->next;
	}
	
	return ERROR_SUCCESS;
}


int yr_scan_file(const char* file_path, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
	MAPPED_FILE mfile;
	int result;

    result = map_file(file_path, &mfile);
	
	if (result == ERROR_SUCCESS)
	{
		result = yr_scan_mem(mfile.data, (unsigned int) mfile.size, context, callback, user_data);		
		unmap_file(&mfile);
	}
		
	return result;
}

char* yr_get_error_message(YARA_CONTEXT* context, char* buffer, int buffer_size)
{
    switch(context->last_error)
	{
		case ERROR_INSUFICIENT_MEMORY:
		    snprintf(buffer, buffer_size, "not enough memory");
			break;
		case ERROR_DUPLICATE_RULE_IDENTIFIER:
			snprintf(buffer, buffer_size, "duplicate rule identifier \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_DUPLICATE_STRING_IDENTIFIER:
			snprintf(buffer, buffer_size, "duplicate string identifier \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_DUPLICATE_TAG_IDENTIFIER:
			snprintf(buffer, buffer_size, "duplicate tag identifier \"%s\"", context->last_error_extra_info);			
			break;			
		case ERROR_INVALID_CHAR_IN_HEX_STRING:
		   	snprintf(buffer, buffer_size, "invalid char in hex string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_MISMATCHED_BRACKET:
			snprintf(buffer, buffer_size, "mismatched bracket in string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_SKIP_AT_END:		
			snprintf(buffer, buffer_size, "skip at the end of string \"%s\"", context->last_error_extra_info);	
		    break;
		case ERROR_INVALID_SKIP_VALUE:
			snprintf(buffer, buffer_size, "invalid skip in string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_UNPAIRED_NIBBLE:
			snprintf(buffer, buffer_size, "unpaired nibble in string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_CONSECUTIVE_SKIPS:
			snprintf(buffer, buffer_size, "two consecutive skips in string \"%s\"", context->last_error_extra_info);			
			break;
		case ERROR_MISPLACED_WILDCARD_OR_SKIP:
			snprintf(buffer, buffer_size, "misplaced wildcard or skip at string \"%s\", wildcards and skips are only allowed after the first byte of the string", context->last_error_extra_info);
		    break;
		case ERROR_MISPLACED_OR_OPERATOR:
		    snprintf(buffer, buffer_size, "misplaced OR (|) operator at string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_NESTED_OR_OPERATION:
	        snprintf(buffer, buffer_size, "nested OR (|) operator at string \"%s\"", context->last_error_extra_info);
		    break;		
		case ERROR_INVALID_OR_OPERATION_SYNTAX:
		    snprintf(buffer, buffer_size, "invalid syntax at hex string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_SKIP_INSIDE_OR_OPERATION:
    		snprintf(buffer, buffer_size, "skip inside an OR (|) operation at string \"%s\"", context->last_error_extra_info);
    		break;
		case ERROR_UNDEFINED_STRING:
            snprintf(buffer, buffer_size, "undefined string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_UNDEFINED_RULE:
		    snprintf(buffer, buffer_size, "undefined rule \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_UNREFERENCED_STRING:
		    snprintf(buffer, buffer_size, "unreferenced string \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_MISPLACED_ANONYMOUS_STRING:
	        snprintf(buffer, buffer_size, "wrong use of anonymous string");
		    break;		
		case ERROR_INVALID_REGULAR_EXPRESSION:
		case ERROR_SYNTAX_ERROR:
		    snprintf(buffer, buffer_size, "%s", context->last_error_extra_info);
			break;
	}
	
    return buffer;
}

