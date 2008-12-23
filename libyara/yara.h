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

#ifndef _YARA_H 
#define _YARA_H

#include <stdio.h>
#include <pcre.h>


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#define STRING_FLAGS_FOUND                      0x01
#define STRING_FLAGS_REFERENCED					0x02
#define STRING_FLAGS_HEXADECIMAL                0x04
#define STRING_FLAGS_NO_CASE                    0x08
#define STRING_FLAGS_WIDE                       0x10
#define STRING_FLAGS_REGEXP                     0x20
#define STRING_FLAGS_FULL_WORD                  0x40

#define RULE_FLAGS_MATCH                        0x01
#define RULE_FLAGS_PRIVATE                      0x02
#define RULE_FLAGS_GLOBAL						0x04
#define RULE_FLAGS_REQUIRE_PE_FILE 	            0x08

#define IS_HEX(x)       (((x)->flags) & STRING_FLAGS_HEXADECIMAL)
#define IS_NO_CASE(x)   (((x)->flags) & STRING_FLAGS_NO_CASE)
#define IS_WIDE(x)      (((x)->flags) & STRING_FLAGS_WIDE)
#define IS_REGEXP(x)    (((x)->flags) & STRING_FLAGS_REGEXP)
#define IS_FULL_WORD(x) (((x)->flags) & STRING_FLAGS_FULL_WORD)



#ifndef ERROR_SUCCESS 
#define ERROR_SUCCESS                           0
#endif

#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_DUPLICATERULEIDENTIFIER           2
#define ERROR_INVALID_CHAR_IN_HEX_STRING        3
#define ERROR_MISMATCHED_BRACKET                4
#define ERROR_SKIP_AT_END                       5
#define ERROR_INVALID_SKIP_VALUE                6
#define ERROR_UNPAIRED_NIBBLE                   7
#define ERROR_CONSECUTIVE_SKIPS                 8
#define ERROR_MISPLACED_WILDCARD_OR_SKIP        9
#define ERROR_UNDEFINED_STRING                  10
#define ERROR_UNDEFINED_RULE                    11
#define ERROR_COULD_NOT_OPEN_FILE               12
#define ERROR_INVALID_REGULAR_EXPRESSION        13
#define ERROR_SYNTAX_ERROR                      14
#define ERROR_DUPLICATE_TAG_IDENTIFIER			15
#define ERROR_UNREFERENCED_STRING				16
#define ERROR_DUPLICATE_STRING_IDENTIFIER		17
#define ERROR_CALLBACK_ERROR            		18
      
typedef struct _MATCH
{   
    unsigned int    offset;   
	unsigned int	length;
    struct _MATCH* next;
    
} MATCH;


typedef struct _STRING
{
    int             flags;
    char*           identifier;
    unsigned int    length;
    unsigned char*  string;
    
    union {
        unsigned char*  mask;
        pcre*           regexp;
    };  
    
    MATCH*         	matches;        
    struct _STRING* next;
    
} STRING;


typedef struct _TAG
{
	char*			identifier;
	struct _TAG*	next;
	
} TAG;


typedef struct _TERM
{
    int				type;
    struct _TERM*   next;           

} TERM;


typedef struct _RULE
{
    char*           identifier;
    int             flags;
    STRING*         string_list_head;
	TAG*			tag_list_head;
    TERM*           condition;
    struct _RULE*   next;
    
} RULE;


typedef struct _STRING_LIST_ENTRY
{
	STRING* string;
	struct _STRING_LIST_ENTRY* next;
	
} STRING_LIST_ENTRY;


typedef struct _RULE_LIST
{
    RULE* head; 
    RULE* tail;
    STRING_LIST_ENTRY* hash_table[256][256];
    STRING_LIST_ENTRY* non_hashed_strings;
        
} RULE_LIST;


RULE* lookup_rule(RULE_LIST* rules, char* identifier);

STRING* lookup_string(STRING* string_list_head, char* identifier);

TAG* lookup_tag(TAG* tag_list_head, char* identifier);


RULE_LIST* alloc_rule_list();
void free_rule_list(RULE_LIST* rule_list);

void set_file_name(const char* rules_file_name);
int compile_rules(FILE* rules_file, RULE_LIST* rules);

int init_hash_table(RULE_LIST* rule_list);
void free_hash_table(RULE_LIST* rule_list);

typedef int (*YARACALLBACK)(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data);

int scan_mem(unsigned char* buffer, unsigned int buffer_size, RULE_LIST* rule_list, YARACALLBACK callback, void* user_data);

int scan_file(const char* file_path, RULE_LIST* rule_list, YARACALLBACK callback, void* user_data);

#endif

