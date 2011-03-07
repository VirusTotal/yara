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
#include "weight.h"
#include "proc.h"
#include "exe.h"
#include "regex.h"
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
	context->namespaces = NULL;
	context->external_variables = NULL;
    context->allow_includes = TRUE;
	context->current_namespace = yr_create_namespace(context, "default");
	context->fast_match = FALSE;
    context->scanning_process_memory = FALSE;
    
    memset(context->hash_table.hashed_strings_2b, 0, sizeof(context->hash_table.hashed_strings_2b));
    memset(context->hash_table.hashed_strings_1b, 0, sizeof(context->hash_table.hashed_strings_1b));
    
    return context;
    
}

void yr_destroy_context(YARA_CONTEXT* context)
{
    RULE* rule;
    RULE* next_rule;
    STRING* string;
    STRING* next_string;
    META* meta;
    META* next_meta;
    MATCH* match;
    MATCH* next_match;
	TAG* tag;
	TAG* next_tag;
	NAMESPACE* ns;
	NAMESPACE* next_ns;
    EXTERNAL_VARIABLE* ext_var;
	EXTERNAL_VARIABLE* next_ext_var;
    
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
                regex_free(&(string->re));
            }
            
            match = string->matches;
            
            while (match != NULL)
            {
                next_match = match->next;
                yr_free(match->data);
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
		
		meta = rule->meta_list_head;

		while (meta != NULL)
		{
			next_meta = meta->next;
			
			if (meta->type == META_TYPE_STRING)
			{
                yr_free(meta->string);
			}
			
			yr_free(meta->identifier);
			yr_free(meta);
			
			meta = next_meta;
		}
        
        free_term(rule->condition);
        yr_free(rule->identifier);    
        yr_free(rule);
        rule = next_rule;
    }
	
	ns = context->namespaces;

	while(ns != NULL)
	{
		next_ns = ns->next;
		
		yr_free(ns->name);
		yr_free(ns);
		
		ns = next_ns;
	}
	
	ext_var = context->external_variables;

	while(ext_var != NULL)
	{
		next_ext_var = ext_var->next;
/*		
		if (ext_var->type == EXTERNAL_VARIABLE_TYPE_STRING)
		{
		    yr_free(ext_var->string);
		}
	*/	
		yr_free(ext_var->identifier);
		yr_free(ext_var);
		
		ext_var = next_ext_var;
	}
	
	while (context->file_name_stack_ptr > 0)
    {
        yr_pop_file_name(context);
    }
    
    clear_hash_table(&context->hash_table);
	yr_free(context);
}


NAMESPACE* yr_create_namespace(YARA_CONTEXT* context, const char* name)
{
	NAMESPACE* ns = yr_malloc(sizeof(NAMESPACE));
	
	if (ns != NULL)
	{
		ns->name = yr_strdup(name);
		ns->global_rules_satisfied = FALSE;
		ns->next = context->namespaces;
		context->namespaces = ns;
	}
	
	return ns;
}


int yr_set_external_integer(YARA_CONTEXT* context, const char* identifier, size_t value)
{
    EXTERNAL_VARIABLE* ext_var;

    ext_var = lookup_external_variable(context->external_variables, identifier);
    
    if (ext_var == NULL) /* variable doesn't exists, create it */
    {
        ext_var = (EXTERNAL_VARIABLE*) yr_malloc(sizeof(EXTERNAL_VARIABLE));
        
        if (ext_var != NULL)
        {
            ext_var->identifier = yr_strdup(identifier);      
            ext_var->next = context->external_variables;
            context->external_variables = ext_var;
        }
        else
        {
            return ERROR_INSUFICIENT_MEMORY;
        }
    }

    ext_var->type = EXTERNAL_VARIABLE_TYPE_INTEGER;
    ext_var->integer = value;
    
    return ERROR_SUCCESS;
}


int yr_set_external_boolean(YARA_CONTEXT* context, const char* identifier, int value)
{
    EXTERNAL_VARIABLE* ext_var;

    ext_var = lookup_external_variable(context->external_variables, identifier);
    
    if (ext_var == NULL) /* variable doesn't exists, create it */
    {
        ext_var = (EXTERNAL_VARIABLE*) yr_malloc(sizeof(EXTERNAL_VARIABLE));
        
        if (ext_var != NULL)
        {      
            ext_var->identifier = yr_strdup(identifier);      
            ext_var->next = context->external_variables;
            context->external_variables = ext_var;
        }
        else
        {
            return ERROR_INSUFICIENT_MEMORY;
        }
    }

	ext_var->type = EXTERNAL_VARIABLE_TYPE_BOOLEAN;
    ext_var->boolean = value;
    
    return ERROR_SUCCESS;
}


int yr_set_external_string(YARA_CONTEXT* context, const char* identifier, const char* value)
{
    EXTERNAL_VARIABLE* ext_var;

    ext_var = lookup_external_variable(context->external_variables, identifier);
    
    if (ext_var == NULL) /* variable doesn't exists, create it */
    {
        ext_var = (EXTERNAL_VARIABLE*) yr_malloc(sizeof(EXTERNAL_VARIABLE));
        
        if (ext_var != NULL)
        {
            ext_var->identifier = yr_strdup(identifier);    
            ext_var->next = context->external_variables;
            context->external_variables = ext_var;
        }
        else
        {
            return ERROR_INSUFICIENT_MEMORY;
        }
    }

	ext_var->type = EXTERNAL_VARIABLE_TYPE_STRING;
    ext_var->string = (char*) value;
    
    return ERROR_SUCCESS;
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

int yr_push_file_name(YARA_CONTEXT* context, const char* file_name)
{  
    int i;
    
    for (i = 0; i < context->file_name_stack_ptr; i++)
    {
        if (strcmp(file_name, context->file_name_stack[i]) == 0)
        {
            context->last_result = ERROR_INCLUDES_CIRCULAR_REFERENCE;
            return ERROR_INCLUDES_CIRCULAR_REFERENCE;
        }
    }
    
    context->file_name_stack[context->file_name_stack_ptr] = yr_strdup(file_name);
    context->file_name_stack_ptr++;
    
    return ERROR_SUCCESS;
}


void yr_pop_file_name(YARA_CONTEXT* context)
{  
    if (context->file_name_stack_ptr > 0)
    {
        context->file_name_stack_ptr--;
        yr_free(context->file_name_stack[context->file_name_stack_ptr]);
        context->file_name_stack[context->file_name_stack_ptr] = NULL;  
    }
}

int yr_compile_file(FILE* rules_file, YARA_CONTEXT* context)
{	
    return parse_rules_file(rules_file, context);
}

int yr_compile_string(const char* rules_string, YARA_CONTEXT* context)
{	
    return parse_rules_string(rules_string, context);
}


int yr_scan_mem_blocks(MEMORY_BLOCK* block, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
    int error;
    int global_rules_satisfied;
	unsigned int i;	
	int is_executable;
    int is_file;
	
	RULE* rule;
	NAMESPACE* ns;
	EVALUATION_CONTEXT eval_context;
	
	if (block->size < 2)
        return ERROR_SUCCESS;
	
	if (!context->hash_table.populated)
	{
        populate_hash_table(&context->hash_table, &context->rule_list);
	}
	
	eval_context.file_size = block->size;
    eval_context.mem_block = block;
    eval_context.entry_point = 0;
	
    is_executable = is_pe(block->data, block->size) || is_elf(block->data, block->size) || context->scanning_process_memory;
    is_file = !context->scanning_process_memory;

	clear_marks(&context->rule_list);
	
	while (block != NULL)
	{
	    if (eval_context.entry_point == 0)
	    {
	        if (context->scanning_process_memory)
	        {
	            eval_context.entry_point = get_entry_point_address(block->data, block->size, block->base);
	        }
	        else
	        {
	            eval_context.entry_point = get_entry_point_offset(block->data, block->size);
            }
        }
	    
    	for (i = 0; i < block->size - 1; i++)
    	{		    
    		/* search for normal strings */	
            error = find_matches(   block->data[i], 
                                    block->data[i + 1], 
                                    block->data + i, 
                                    block->size - i, 
                                    block->base + i, 
                                    STRING_FLAGS_HEXADECIMAL | STRING_FLAGS_ASCII, 
                                    i, 
                                    context);
		
    		if (error != ERROR_SUCCESS)
    		    return error;
		
    		/* search for wide strings */
    		if ((block->data[i + 1] == 0) && (block->size > 3) && (i < block->size - 3) && (block->data[i + 3] == 0))
    		{
    			error = find_matches(   block->data[i], 
    			                        block->data[i + 2], 
    			                        block->data + i, 
    			                        block->size - i, 
    			                        block->base + i, 
    			                        STRING_FLAGS_WIDE, 
    			                        i, 
    			                        context);
			
    			if (error != ERROR_SUCCESS)
        		    return error;
    		}	
    	}
    	
        block = block->next;
    }
	
	rule = context->rule_list.head;
	
	/* initialize global rules flag for all namespaces */
	
	ns = context->namespaces;
	
	while(ns != NULL)
	{
		ns->global_rules_satisfied = TRUE;
		ns = ns->next;
	}
	
	/* evaluate global rules */
	
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
                rule->ns->global_rules_satisfied = FALSE;
    		}
    		
    		if (!(rule->flags & RULE_FLAGS_PRIVATE))
    		{
        		if (callback(rule, user_data) != 0)
        		{
                    return ERROR_CALLBACK_ERROR;
        		}
		    }
		}
			
		rule = rule->next;
	}
	
	/* evaluate the rest of the rules rules */

	rule = context->rule_list.head;
	
	while (rule != NULL)
	{
		/* 
		   skip global rules, privates rules, and rules that don't need to be
		   evaluated due to some global rule unsatisfied in it's namespace
		*/
		
		if (rule->flags & RULE_FLAGS_GLOBAL || rule->flags & RULE_FLAGS_PRIVATE || !rule->ns->global_rules_satisfied)  
		{
			rule = rule->next;
			continue;
		}

	  
		if ((is_executable  || !(rule->flags & RULE_FLAGS_REQUIRE_EXECUTABLE)) &&
		    (is_file        || !(rule->flags & RULE_FLAGS_REQUIRE_FILE)))
		{
		    eval_context.rule = rule;
		    
		    if (evaluate(rule->condition, &eval_context))
    		{
                rule->flags |= RULE_FLAGS_MATCH;
    		}
		}
		
		switch (callback(rule, user_data))
		{
		    case CALLBACK_ABORT:
                return ERROR_SUCCESS;
                
            case CALLBACK_ERROR:
                return ERROR_CALLBACK_ERROR;
		}
		
		rule = rule->next;
	}
	
	return ERROR_SUCCESS;
}


int yr_scan_mem(unsigned char* buffer, size_t buffer_size, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
    MEMORY_BLOCK block;
    
    block.data = buffer;
    block.size = buffer_size;
    block.base = 0;
    block.next = NULL;
    
    return yr_scan_mem_blocks(&block, context, callback, user_data);
}


int yr_scan_file(const char* file_path, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
	MAPPED_FILE mfile;
	int result;

    result = map_file(file_path, &mfile);
	
	if (result == ERROR_SUCCESS)
	{
		result = yr_scan_mem(mfile.data, mfile.size, context, callback, user_data);		
		unmap_file(&mfile);
	}
		
	return result;
}


int yr_scan_proc(int pid, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data)
{
    
    MEMORY_BLOCK* first_block;
    MEMORY_BLOCK* next_block;
    MEMORY_BLOCK* block;
        
    int result = get_process_memory(pid, &first_block);

    if (result == ERROR_SUCCESS)
    {
        context->scanning_process_memory = TRUE;
        result = yr_scan_mem_blocks(first_block, context, callback, user_data);
    }
    
    if (result == ERROR_SUCCESS)
    {  
        block = first_block;
    
        while (block != NULL)
        {
            next_block = block->next;
        
            yr_free(block->data);
            yr_free(block);   
        
            block = next_block;   
        }
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
		case ERROR_DUPLICATE_META_IDENTIFIER:
			snprintf(buffer, buffer_size, "duplicate metadata identifier \"%s\"", context->last_error_extra_info);			
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
		case ERROR_UNDEFINED_IDENTIFIER:
		    snprintf(buffer, buffer_size, "undefined identifier \"%s\"", context->last_error_extra_info);
			break;
		case ERROR_UNREFERENCED_STRING:
		    snprintf(buffer, buffer_size, "unreferenced string \"%s\"", context->last_error_extra_info);
			break;
	    case ERROR_INCORRECT_EXTERNAL_VARIABLE_TYPE:
		    snprintf(buffer, buffer_size, "external variable \"%s\" has an incorrect type for this operation", context->last_error_extra_info);
			break;
		case ERROR_MISPLACED_ANONYMOUS_STRING:
	        snprintf(buffer, buffer_size, "wrong use of anonymous string");
		    break;		
		case ERROR_INVALID_REGULAR_EXPRESSION:
		case ERROR_SYNTAX_ERROR:
		    snprintf(buffer, buffer_size, "%s", context->last_error_extra_info);
			break;
		case ERROR_INCLUDES_CIRCULAR_REFERENCE:
		    snprintf(buffer, buffer_size, "include circular reference");
            break;		    
	}
	
    return buffer;
}


int yr_calculate_rules_weight(YARA_CONTEXT* context)
{
    STRING_LIST_ENTRY* entry;

    int i,j, count, weight = 0;

    if (!context->hash_table.populated)
    {        
        populate_hash_table(&context->hash_table, &context->rule_list);
    }
    
    for (i = 0; i < 256; i++)
    {   
        for (j = 0; j < 256; j++)
        {
            entry = context->hash_table.hashed_strings_2b[i][j];
        
            count = 0;
        
            while (entry != NULL)
            {         
                weight += string_weight(entry->string, 1);               
                entry = entry->next;
                count++;
            }
            
            weight += count;
        }
        
        entry = context->hash_table.hashed_strings_1b[i];
    
        count = 0;
    
        while (entry != NULL)
        {         
            weight += string_weight(entry->string, 2);               
            entry = entry->next;
            count++;
        }
    }
    
    entry = context->hash_table.non_hashed_strings;
    
    while (entry != NULL)
    {
        weight += string_weight(entry->string, 4);
    }
    
    return weight;
}

