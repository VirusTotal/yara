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
#include <ctype.h>
#include <pcre.h>

#include "filemap.h"
#include "yara.h"
#include "eval.h"
#include "ast.h"
#include "pefile.h"
#include "mem.h"
#include "eval.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifdef WIN32
#define inline __inline
#endif


/* Function implementations */

inline int compare(char* str1, char* str2, int len)
{
	char* s1 = str1;
	char* s2 = str2;
	int i = 0;
	
	while (i < len && *s1++ == *s2++) 
	{
	    i++;
    }

	return ((i==len) ? i : 0);
}

inline int icompare(char* str1, char* str2, int len)
{
	char* s1 = str1;
	char* s2 = str2;
	int i = 0;
	
	while (i < len && tolower(*s1++) == tolower(*s2++)) 
	{
	    i++;
    }
	
	return ((i==len) ? i : 0);
}


inline int wcompare(char* str1, char* str2, int len)
{
	char* s1 = str1;
	char* s2 = str2;
	int i = 0;

	while (i < len && *s1 == *s2) 
	{
		s1++;
		s2+=2;
		i++;
	}
	
	return ((i==len) ? i * 2 : 0);
}

inline int wicompare(char* str1, char* str2, int len)
{
	char* s1 = str1;
	char* s2 = str2;
	int i = 0;

	while (i < len && tolower(*s1) == tolower(*s2)) 
	{
		s1++;
		s2+=2;
		i++;
	}
	
	return ((i==len) ? i * 2 : 0);
}

 
int hex_match(unsigned char* buffer, unsigned int buffer_size, unsigned char* pattern, int pattern_length, unsigned char* mask)
{
	size_t b,p,m;
	unsigned char i;
	unsigned char distance;
	unsigned char delta;
    int match;
    int match_length;
    int longest_match;
	int matches;
    int tmp, tmp_b;
	
	b = 0;
	p = 0;
	m = 0;
	
	matches = 0;	
	
	while (b < (size_t) buffer_size && p < (size_t) pattern_length)
	{
		if (mask[m] == MASK_EXACT_SKIP)
		{
			m++;
			distance = mask[m++];
			b += distance;
			matches += distance;
		}
		else if (mask[m] == MASK_RANGE_SKIP)
		{
			m++;
			distance = mask[m++];
			delta = mask[m++] - distance;
			b += distance;
			matches += distance;
			
            i = 0;
                        
            while (i <= delta && b + i < buffer_size)
            {
                if ((buffer[b + i] & mask[m]) == pattern[p])
                {
       			    tmp = hex_match(buffer + b + i, buffer_size - b - i,  pattern + p, pattern_length - p, mask + m);
       			}
       			else
       			{
                    tmp = 0;
       			}
				
			    if (tmp > 0) 
					return b + i + tmp;
				
                i++;      
            }
			
			break;	
		}
		else if (mask[m] == MASK_OR)
		{		    
            longest_match = 0;
            		    
		    while (mask[m] != MASK_OR_END)
		    {
                tmp_b = b;
                match = TRUE;
                match_length = 0;
                m++;
		        
		        while (mask[m] != MASK_OR && mask[m] != MASK_OR_END)
                {
                    if ((buffer[tmp_b] & mask[m]) != pattern[p])
                    {
                        match = FALSE;
                    }
                    
                    if (match)
                    {
                        match_length++;
                    }
                
                    tmp_b++;
                    m++;
                    p++;                    
                }
		        
		        if (match && match_length > longest_match)
		        {
                    longest_match = match_length;
		        }	     
		    }
		    
            m++;
		    
		    if (longest_match > 0)
		    {
                b += longest_match;
                matches += longest_match;
            }
            else
            {
                matches = 0;
                break;
            }
    
		}
		else if ((buffer[b] & mask[m]) == pattern[p])  // TODO: This is the most common case, maybe could be checked first for speed optimization
		{
			b++;
			m++;
			p++;
			matches++;
		}
		else  /* do not match */
		{
			matches = 0;
			break;
		}
	}
	
	if (p < (size_t) pattern_length)  /* did not reach the end of pattern because buffer was too small */
	{
		matches = 0;
	}
	
	return matches;
}

int regexp_match(unsigned char* buffer, unsigned int buffer_size, unsigned char* pattern, int pattern_length, REGEXP re, int file_beginning)
{
	int ovector[3];
	unsigned int len;
	int rc;
	int result;
	char* s;
	
	result = 0;
	
	/* 
		if we are not at the beginning of the file, and the pattern 
		begins with ^, the string doesn't match
	*/
	
	if (file_beginning && pattern[0] == '^')
	{
		return 0;
	}

	rc = pcre_exec(
	  				re.regexp,            /* the compiled pattern */
	  				re.extra,             /* extra data */
	  				(char*) buffer,  	  /* the subject string */
	  				buffer_size,          /* the length of the subject */
	  				0,                    /* start at offset 0 in the subject */
	  				0,                    /* default options */
	  				ovector,              /* output vector for substring information */
	  				3);                   /* number of elements in the output vector */
		
	if (rc >= 0)
	{	
		result = pcre_get_substring(	(char*) buffer, 
										ovector,
		            					1, 	
										0,
		            					(const char**) &s);
		            							
		if (result != PCRE_ERROR_NOMEMORY &&
		    result != PCRE_ERROR_NOSUBSTRING)	
		
		{
			pcre_free_substring(s);
			return result;
		}
	
	}
	
	return 0;
}

int populate_hash_table(HASH_TABLE* hash_table, RULE_LIST* rule_list)
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
    			    
    			entry->next = hash_table->hashed_strings[x][y];
    			entry->string = string;
    			hash_table->hashed_strings[x][y] = entry;
    			
    			/* X uppercase Y lowercase */
    			
                x = toupper(x);
				
				entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = hash_table->hashed_strings[x][y];  
        		entry->string = string;
        		hash_table->hashed_strings[x][y] = entry; 
        		
        		/* both uppercases */			    
    			
    			y = toupper(y);  
    			    
    			entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = hash_table->hashed_strings[x][y];
        		entry->string = string;
        		hash_table->hashed_strings[x][y] = entry;
        		
        		/* X lowercase Y uppercase */
    			    
                x = tolower(x);
 
    			entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = hash_table->hashed_strings[x][y]; 
        		entry->string = string; 
        		hash_table->hashed_strings[x][y] = entry;               
    							
			}
			else if (hashable)
			{
				entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
    			    
        		entry->next = hash_table->hashed_strings[x][y]; 
        		entry->string = string; 
        		hash_table->hashed_strings[x][y] = entry;    
			}
			else /* non hashable */
			{
			    entry = (STRING_LIST_ENTRY*) yr_malloc(sizeof(STRING_LIST_ENTRY));
				
				if (entry == NULL)
                    return ERROR_INSUFICIENT_MEMORY;
			    
			    entry->next = hash_table->non_hashed_strings;
			    entry->string = string; 
                hash_table->non_hashed_strings = entry;
			}
		
			string = string->next;
		}
		
		rule = rule->next;
	}
	
    hash_table->populated = TRUE;
	
	return ERROR_SUCCESS;
}


void clear_hash_table(HASH_TABLE* hash_table)
{
	int i,j;
	
	STRING_LIST_ENTRY* next_entry;
	STRING_LIST_ENTRY* entry;

	for (i = 0; i < 256; i++)
	{
		for (j = 0; j < 256; j++)
		{
			entry = hash_table->hashed_strings[i][j];
				
			while (entry != NULL)
			{
				next_entry = entry->next;
				yr_free(entry);
				entry = next_entry;
			}
			
			hash_table->hashed_strings[i][j] = NULL;
		}
	}
	
    entry = hash_table->non_hashed_strings;
    
    while (entry != NULL)
	{
		next_entry = entry->next;
		yr_free(entry);
		entry = next_entry;
	}
	
    hash_table->non_hashed_strings = NULL;
}

void clear_marks(RULE_LIST* rule_list)
{
	RULE* rule;
	STRING* string;
	MATCH* match;
	MATCH* next_match;
	
	rule = rule_list->head;
	
	while (rule != NULL)
	{	 
	    rule->flags &= ~RULE_FLAGS_MATCH;
	    string = rule->string_list_head;
		
		while (string != NULL)
		{
			string->flags &= ~STRING_FLAGS_FOUND;  /* clear found mark */
			
			match = string->matches;
			
			while (match != NULL)
			{
				next_match = match->next;
				yr_free(match);
				match = next_match;
			}
			
			string->matches = NULL;
			string = string->next;
		}
		
		rule = rule->next;
	}
}

int string_match(unsigned char* buffer, unsigned int buffer_size, STRING* string, int flags, int negative_size)
{
	int match;
	int i, len;
	int is_wide_char;
	
	unsigned char* tmp;
	
	if (IS_HEX(string))
	{
		return hex_match(buffer, buffer_size, string->string, string->length, string->mask);
	}
	else if (IS_REGEXP(string)) 
	{
		if (IS_WIDE(string))
		{
			i = 0;
			
			while(i < buffer_size - 1 && isalnum(buffer[i]) && buffer[i + 1] == 0)
			{
				i += 2;
			}
						
			len = i/2;
			tmp = yr_malloc(len);
            i = 0;
			
			if (tmp != NULL)
			{						
				while(i < len)
				{
					tmp[i] = buffer[i*2];
					i++;
				}
								
				match = regexp_match(tmp, len, string->string, string->length, string->re, (negative_size > 2));
			
				yr_free(tmp);			
				return match * 2;
			}
			
		}
		else
		{
			return regexp_match(buffer, buffer_size, string->string, string->length, string->re, negative_size);
		}
	}
	
	if ((flags & STRING_FLAGS_WIDE) && IS_WIDE(string) && string->length * 2 <= buffer_size)
	{	
		if(IS_NO_CASE(string))
		{
			match = wicompare((char*) string->string, (char*) buffer, string->length);			
		}
		else
		{
			match = wcompare((char*) string->string, (char*) buffer, string->length);		
		}
		
		if (match > 0 && IS_FULL_WORD(string))
		{
			if (negative_size >= 2)
			{
				is_wide_char = (buffer[-1] == 0 && isalnum((char) (buffer[-2])));
				
				if (is_wide_char)
				{
					match = 0;
				}
			}
			
			if (string->length * 2 < buffer_size - 1)
			{
				is_wide_char = (isalnum((char) (buffer[string->length * 2])) && buffer[string->length * 2 + 1] == 0);
				
				if (is_wide_char)
				{
					match = 0;
				}
			}
		}	
		
		if (match > 0)
            return match;
	}
	
	if ((flags & STRING_FLAGS_ASCII) && IS_ASCII(string) && string->length <= buffer_size)
	{		
		if(IS_NO_CASE(string))
		{
			match = icompare((char*) string->string, (char*) buffer, string->length);			
		}
		else
		{
			match = compare((char*) string->string, (char*) buffer, string->length);		
		}
				
		if (match > 0 && IS_FULL_WORD(string))
		{
			if (negative_size >= 1 && isalnum((char) (buffer[-1])))
			{
				match = 0;
			}
			else if (string->length < buffer_size && isalnum((char) (buffer[string->length])))
			{
				match = 0;
			}
		}
		
		return match;
	}
	
	return 0;
}


int find_matches_for_strings(   STRING_LIST_ENTRY* first_string, 
                                unsigned char* buffer, 
                                unsigned int buffer_size,
                                unsigned int current_file_offset,
                                int flags, 
                                int negative_size)
{
	int len;
    int overlap;
	
	STRING* string;
	MATCH* match;
    STRING_LIST_ENTRY* entry = first_string;
    
   	while (entry != NULL)
	{	
		string = entry->string;

		if ( (string->flags & flags) && (len = string_match(buffer, buffer_size, string, flags, negative_size)))
		{
		    /*  
		        If this string already matched we must check that this match is not 
		        overlapping a previous one. This can occur for example if we search 
		        for the string 'aa' and the file contains 'aaaaaa'. 
		     */
		     
            overlap = FALSE;
		     
		    if (string->flags && STRING_FLAGS_FOUND)
		    {
                match = string->matches;
                
                while(match != NULL) // TODO: Possible optimization: is enough to check the only last match instead of all the previous ones?
                {
                    if (match->offset + match->length > current_file_offset)
                    {
                        overlap = TRUE;
                        break;
                    }
                    
                    match = match->next;
                }
		    }
		    
		    if (!overlap)
		    {		    
    			string->flags |= STRING_FLAGS_FOUND;
    			match = (MATCH*) yr_malloc(sizeof(MATCH));

    			if (match != NULL)
    			{
    				match->offset = current_file_offset;
    				match->length = len;
    				match->next = string->matches;
    				string->matches = match;
    			}
    			else
    			{
    				return ERROR_INSUFICIENT_MEMORY;
    			}
		    }
		}
		
		entry = entry->next;
	}
	
    return ERROR_SUCCESS;
}


int find_matches(	unsigned char first_char, 
					unsigned char second_char, 
					unsigned char* buffer, 
					unsigned int buffer_size, 
					unsigned int current_file_offset,
					int flags,
					int negative_size, 
					YARA_CONTEXT* context)
{
	
    int result = ERROR_SUCCESS;
    	
    if (context->hash_table.hashed_strings[first_char][second_char] != NULL)
    {
        result =  find_matches_for_strings( context->hash_table.hashed_strings[first_char][second_char], 
                                            buffer, 
                                            buffer_size, 
                                            current_file_offset, 
                                            flags, 
                                            negative_size);
    }
    
    if (result == ERROR_SUCCESS && context->hash_table.non_hashed_strings != NULL)
    {
         result = find_matches_for_strings(    context->hash_table.non_hashed_strings, 
                                               buffer, 
                                               buffer_size, 
                                               current_file_offset, 
                                               flags, 
                                               negative_size);
    }
            	
	return result;
}




