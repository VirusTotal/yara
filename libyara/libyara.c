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

#include "yara.h"
#include "scan.h"
#include "filemap.h"
#include "mem.h"
#include "error.h"
#include "eval.h"

extern FILE *yyin;
extern int yydebug;

int yylex (void); 
int yyparse (void);

int             line_number;
const char*     file_name;
RULE_LIST*      rule_list;


void yr_set_file_name(const char* rules_file_name)
{
	file_name = rules_file_name;
}

void yr_init()
{
    yr_heap_alloc();
}

RULE_LIST* yr_alloc_rule_list()
{    
	RULE_LIST* rule_list = (RULE_LIST*) yr_malloc(sizeof(RULE_LIST));

	rule_list->head = NULL;
	rule_list->tail = NULL;
    rule_list->non_hashed_strings = NULL;

	memset(rule_list->hash_table, 0, sizeof(rule_list->hash_table));

	return rule_list;
}


void yr_free_rule_list(RULE_LIST* rule_list)
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
    
    free_hash_table(rule_list);
	yr_free(rule_list);
}


int yr_compile_file(FILE* rules_file, RULE_LIST* rules)
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


int yr_prepare_rules(RULE_LIST* rule_list)
{
	RULE* rule;
	STRING* string;
	STRING_LIST_ENTRY* entry;
	unsigned char x,y;
	int next;
    char hashable;
		
	rule = rule_list->head;
	
	while (rule != NULL)
	{
		string = rule->string_list_head;

		while (string != NULL)
		{	        
			if (string->flags & STRING_FLAGS_REGEXP)
			{	
				/* take into account anchors (^) at beginning of regular expressions */
							
				if (string->string[0] == '^')
				{
				    if (string->length > 2)
				    {
					    x = string->string[1];
					    y = string->string[2];
					}
					else
					{
                        x = 0;
                        y = 0; 
					}
				}
				else
				{
					x = string->string[0];
					y = string->string[1];
				}
			
                hashable = isalnum(x) && isalnum(y);
			}
			else
			{
			    x = string->string[0];
				y = string->string[1];
				
				hashable = TRUE;
				
			} /* if (string->flags & STRING_FLAGS_REGEXP) */
			
			if (string->flags & STRING_FLAGS_HEXADECIMAL)
			{
			    hashable = (string->mask[0] == 0xFF) && (string->mask[1] == 0xFF);
			}
			
			if (hashable && string->flags & STRING_FLAGS_NO_CASE)
			{	
			    /* 
			       if string is case-insensitive add an entry in the hash table
			       for each posible combination 
			    */
			    
				x = tolower(x);
				y = tolower(y);
				
				/* both lowercases */
				
				entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
    			    return ERROR_INSUFICIENT_MEMORY;
    			    
    			entry->next = rule_list->hash_table[x][y];
    			entry->string = string;
    			rule_list->hash_table[x][y] = entry;
    			
    			/* X uppercase Y lowercase */
    			
                x = toupper(x);
				
				entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = rule_list->hash_table[x][y];  
        		entry->string = string;
        		rule_list->hash_table[x][y] = entry; 
        		
        		/* both uppercases */			    
    			
    			y = toupper(y);  
    			    
    			entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = rule_list->hash_table[x][y];
        		entry->string = string;
        		rule_list->hash_table[x][y] = entry;
        		
        		/* X lowercase Y uppercase */
    			    
                x = tolower(x);
 
    			entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = rule_list->hash_table[x][y]; 
        		entry->string = string; 
        		rule_list->hash_table[x][y] = entry;               
    							
			}
			else if (hashable)
			{
				entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = rule_list->hash_table[x][y]; 
        		entry->string = string; 
        		rule_list->hash_table[x][y] = entry;    
			}
			else /* non hashable */
			{
			    entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
			    
			    entry->next = rule_list->non_hashed_strings;
			    entry->string = string; 
                rule_list->non_hashed_strings = entry;
			}
		
			string = string->next;
		}
		
		rule = rule->next;
	}
	
	return ERROR_SUCCESS;
}



int yr_scan_mem(unsigned char* buffer, unsigned int buffer_size, RULE_LIST* rule_list, YARACALLBACK callback, void* user_data)
{
    int error;
    int global_rules_satisfied;
	unsigned int i;	
	int file_is_pe;
	
	RULE* rule;
	EVALUATION_CONTEXT context;
	
	context.file_size = buffer_size;
    context.data = buffer;
	
	file_is_pe = is_pe(buffer, buffer_size);
	
	if (file_is_pe)
	{
		context.entry_point = get_entry_point_offset(buffer, buffer_size);
	}
	
	clear_marks(rule_list);
	
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
                                rule_list);
		
		if (error != ERROR_SUCCESS)
		    return error;
		
		/* search for wide strings */
		if (i < buffer_size - 3 && buffer[i + 1] == 0 && buffer[i + 3] == 0)
		{
			error = find_matches(   buffer[i], 
			                        buffer[i + 2], 
			                        buffer + i, 
			                        buffer_size - i, 
			                        i, 
			                        STRING_FLAGS_WIDE, 
			                        i, 
			                        rule_list);
			
			if (error != ERROR_SUCCESS)
    		    return error;
		}	
	}
	
	rule = rule_list->head;
	
	/* evaluate global rules */
	
    global_rules_satisfied = TRUE;
	
	while (rule != NULL)
	{	
		if (rule->flags & RULE_FLAGS_GLOBAL)
		{
            context.rule = rule;
            
            if (evaluate(rule->condition, &context))
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

	rule = rule_list->head;
	
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
		    context.rule = rule;
		    
		    if (evaluate(rule->condition, &context))
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


int yr_scan_file(const char* file_path, RULE_LIST* rule_list, YARACALLBACK callback, void* user_data)
{
	MAPPED_FILE mfile;
	int result;

    result = map_file(file_path, &mfile);
	
	if (result == ERROR_SUCCESS)
	{
		result = yr_scan_mem(mfile.data, (unsigned int) mfile.size, rule_list, callback, user_data);		
		unmap_file(&mfile);
	}
		
	return result;
}