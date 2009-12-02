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

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#define MAX_INCLUDE_DEPTH                       16

#define STRING_FLAGS_FOUND                      0x01
#define STRING_FLAGS_REFERENCED					0x02
#define STRING_FLAGS_HEXADECIMAL                0x04
#define STRING_FLAGS_NO_CASE                    0x08
#define STRING_FLAGS_ASCII                      0x10
#define STRING_FLAGS_WIDE                       0x20
#define STRING_FLAGS_REGEXP                     0x40
#define STRING_FLAGS_FULL_WORD                  0x80
#define STRING_FLAGS_ANONYMOUS                  0x100

#define IS_HEX(x)       (((x)->flags) & STRING_FLAGS_HEXADECIMAL)
#define IS_NO_CASE(x)   (((x)->flags) & STRING_FLAGS_NO_CASE)
#define IS_ASCII(x)     (((x)->flags) & STRING_FLAGS_ASCII)
#define IS_WIDE(x)      (((x)->flags) & STRING_FLAGS_WIDE)
#define IS_REGEXP(x)    (((x)->flags) & STRING_FLAGS_REGEXP)
#define IS_FULL_WORD(x) (((x)->flags) & STRING_FLAGS_FULL_WORD)
#define IS_ANONYMOUS(x) (((x)->flags) & STRING_FLAGS_ANONYMOUS)

#define RULE_FLAGS_MATCH                        0x01
#define RULE_FLAGS_PRIVATE                      0x02
#define RULE_FLAGS_GLOBAL						0x04
#define RULE_FLAGS_REQUIRE_PE_FILE 	            0x08

#ifndef ERROR_SUCCESS 
#define ERROR_SUCCESS                           0
#endif

#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_DUPLICATE_RULE_IDENTIFIER         2
#define ERROR_INVALID_CHAR_IN_HEX_STRING        3
#define ERROR_MISMATCHED_BRACKET                4
#define ERROR_SKIP_AT_END                       5
#define ERROR_INVALID_SKIP_VALUE                6
#define ERROR_UNPAIRED_NIBBLE                   7
#define ERROR_CONSECUTIVE_SKIPS                 8
#define ERROR_MISPLACED_WILDCARD_OR_SKIP        9
#define ERROR_UNDEFINED_STRING                  10
#define ERROR_UNDEFINED_IDENTIFIER              11
#define ERROR_COULD_NOT_OPEN_FILE               12
#define ERROR_INVALID_REGULAR_EXPRESSION        13
#define ERROR_SYNTAX_ERROR                      14
#define ERROR_DUPLICATE_TAG_IDENTIFIER			15
#define ERROR_UNREFERENCED_STRING				16
#define ERROR_DUPLICATE_STRING_IDENTIFIER		17
#define ERROR_CALLBACK_ERROR            		18
#define ERROR_MISPLACED_OR_OPERATOR             19
#define ERROR_INVALID_OR_OPERATION_SYNTAX       20
#define ERROR_SKIP_INSIDE_OR_OPERATION          21  
#define ERROR_NESTED_OR_OPERATION               22 
#define ERROR_MISPLACED_ANONYMOUS_STRING        23
#define ERROR_COULD_NOT_MAP_FILE                24
#define ERROR_ZERO_LENGTH_FILE                  25
#define ERROR_INVALID_ARGUMENT                  26
#define ERROR_DUPLICATE_META_IDENTIFIER         27
#define ERROR_INCLUDES_CIRCULAR_REFERENCE       28
#define ERROR_INCORRECT_EXTERNAL_VARIABLE_TYPE  29

#define META_TYPE_INTEGER                       1
#define META_TYPE_STRING                        2
#define META_TYPE_BOOLEAN                       3

#define EXTERNAL_VARIABLE_TYPE_INTEGER          1
#define EXTERNAL_VARIABLE_TYPE_STRING           2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN          3

      

typedef struct _MATCH
{   
    unsigned int    offset;   
	unsigned int	length;
    struct _MATCH* next;
    
} MATCH;


typedef struct _REGEXP
{
    pcre* regexp;
    pcre_extra* extra;
    
} REGEXP;


typedef struct _STRING
{
    int             flags;
    char*           identifier;
    unsigned int    length;
    unsigned char*  string;
    
    union {
        unsigned char*  mask;
        REGEXP re;
    };  
    
    MATCH*         	matches;        
    struct _STRING* next;
    
} STRING;


typedef struct _EXTERNAL_VARIABLE
{
    int     type;
    char*   identifier;
    
    union {      
        char*   string;
        int     integer;
        int     boolean;
    };
    
    struct _EXTERNAL_VARIABLE* next;
    
} EXTERNAL_VARIABLE;


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


typedef struct _NAMESPACE
{
    char*				name;
	int					global_rules_satisfied;
    struct _NAMESPACE*  next;           

} NAMESPACE;


typedef struct _META
{
    int                 type;
    char*				identifier;
    
    union {
        char*   string;
        int     integer;
        int     boolean;
    };
    
    struct _META*       next;           

} META;


typedef struct _RULE
{
    char*           identifier;
    int             flags;
	NAMESPACE*		namespace;
    STRING*         string_list_head;
	TAG*			tag_list_head;
    META*           meta_list_head;
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
        
} RULE_LIST;


typedef struct _HASH_TABLE
{
    STRING_LIST_ENTRY*  hashed_strings[256][256];
    STRING_LIST_ENTRY*  non_hashed_strings;
    int                 populated;
        
} HASH_TABLE;


typedef int (*YARACALLBACK)(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data);
typedef void (*YARAREPORT)(const char* file_name, int line_number, const char* error_message);


typedef struct _YARA_CONTEXT
{  
    int                     last_result;
    YARAREPORT              error_report_function;
    int                     errors;
    int                     last_error;
    int                     last_error_line;
    
    RULE_LIST               rule_list;
    HASH_TABLE              hash_table;
    
	NAMESPACE*		        namespaces;
	NAMESPACE*		        current_namespace;
	
	EXTERNAL_VARIABLE*      external_variables;

	STRING*                 current_rule_strings;  
    int                     inside_for;
    
    char*                   file_name_stack[MAX_INCLUDE_DEPTH];
    int                     file_name_stack_ptr;
           
    char                    last_error_extra_info[256];

    char 		            lex_buf[256];
    char*		            lex_buf_ptr;
    unsigned short          lex_buf_len;
    
    int                     allow_includes;
    char                    include_base_dir[MAX_PATH];

} YARA_CONTEXT;


RULE*                   lookup_rule(RULE_LIST* rules, const char* identifier, NAMESPACE* namespace);
STRING*                 lookup_string(STRING* string_list_head, const char* identifier);
TAG*                    lookup_tag(TAG* tag_list_head, const char* identifier);
META*                   lookup_meta(META* meta_list_head, const char* identifier);
EXTERNAL_VARIABLE*      lookup_external_variable(EXTERNAL_VARIABLE* ext_var_list_head, const char* identifier);

void                yr_init();

YARA_CONTEXT*       yr_create_context();
void                yr_destroy_context(YARA_CONTEXT* context);

int                 yr_calculate_rules_weight(YARA_CONTEXT* context);

NAMESPACE*			yr_create_namespace(YARA_CONTEXT* context, const char* namespace);

int                 yr_set_external_integer(YARA_CONTEXT* context, const char* identifier, int value);
int                 yr_set_external_boolean(YARA_CONTEXT* context, const char* identifier, int value);
int                 yr_set_external_string(YARA_CONTEXT* context, const char* identifier, const char* value);

char*               yr_get_current_file_name(YARA_CONTEXT* context);

int 		yr_push_file_name(YARA_CONTEXT* context, const char* file_name);
void 		yr_pop_file_name(YARA_CONTEXT* context);

int         yr_compile_file(FILE* rules_file, YARA_CONTEXT* context);
int         yr_compile_string(const char* rules_string, YARA_CONTEXT* context);

int         yr_scan_mem(unsigned char* buffer, unsigned int buffer_size, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
int         yr_scan_file(const char* file_path, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);

char*       yr_get_error_message(YARA_CONTEXT* context, char* buffer, int buffer_size);

#endif

