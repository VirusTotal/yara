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
#define STRING_FLAGS_REFERENCED                 0x02
#define STRING_FLAGS_HEXADECIMAL                0x04
#define STRING_FLAGS_NO_CASE                    0x08
#define STRING_FLAGS_ASCII                      0x10
#define STRING_FLAGS_WIDE                       0x20
#define STRING_FLAGS_REGEXP                     0x40
#define STRING_FLAGS_FULL_WORD                  0x80
#define STRING_FLAGS_ANONYMOUS                  0x100
#define STRING_FLAGS_FAST_MATCH                 0x200

#define IS_HEX(x)       (((x)->flags) & STRING_FLAGS_HEXADECIMAL)
#define IS_NO_CASE(x)   (((x)->flags) & STRING_FLAGS_NO_CASE)
#define IS_ASCII(x)     (((x)->flags) & STRING_FLAGS_ASCII)
#define IS_WIDE(x)      (((x)->flags) & STRING_FLAGS_WIDE)
#define IS_REGEXP(x)    (((x)->flags) & STRING_FLAGS_REGEXP)
#define IS_FULL_WORD(x) (((x)->flags) & STRING_FLAGS_FULL_WORD)
#define IS_ANONYMOUS(x) (((x)->flags) & STRING_FLAGS_ANONYMOUS)

#define RULE_FLAGS_MATCH                        0x01
#define RULE_FLAGS_PRIVATE                      0x02
#define RULE_FLAGS_GLOBAL                       0x04
#define RULE_FLAGS_REQUIRE_EXECUTABLE           0x08
#define RULE_FLAGS_REQUIRE_FILE                 0x10

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
#define ERROR_DUPLICATE_TAG_IDENTIFIER          15
#define ERROR_UNREFERENCED_STRING               16
#define ERROR_DUPLICATE_STRING_IDENTIFIER       17
#define ERROR_CALLBACK_ERROR                    18
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
#define ERROR_INCORRECT_VARIABLE_TYPE           29
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS       30
#define ERROR_VECTOR_TOO_LONG                   31

#define META_TYPE_INTEGER                       1
#define META_TYPE_STRING                        2
#define META_TYPE_BOOLEAN                       3

#define VARIABLE_TYPE_INTEGER          1
#define VARIABLE_TYPE_STRING           2
#define VARIABLE_TYPE_BOOLEAN          3

#define CALLBACK_CONTINUE                       0
#define CALLBACK_ABORT                          1
#define CALLBACK_ERROR                          2 

typedef struct _MATCH
{   
    size_t          offset;
    unsigned char*  data;
    unsigned int    length;
    struct _MATCH*  next;
    
} MATCH;


typedef struct _REGEXP 
{
    void    *regexp;
    void    *extra;
    int     re2_anchored;
    
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
    
    MATCH*          matches_head;
    MATCH*          matches_tail;      
    struct _STRING* next;
    
} STRING;


typedef struct _VARIABLE
{
    int     type;
    char*   identifier;
    
    union {      
        char*   string;
        size_t  integer;
        int     boolean;
    };
    
    struct _VARIABLE* next;
    
} VARIABLE;


typedef struct _TAG
{
    char*           identifier;
    struct _TAG*    next;
    
} TAG;


typedef struct _TERM
{
    int             type;

} TERM;


typedef struct _NAMESPACE
{
    char*               name;
    int                 global_rules_satisfied;
    struct _NAMESPACE*  next;           

} NAMESPACE;


typedef struct _META
{
    int                 type;
    char*               identifier;
    
    union {
        char*   string;
        size_t  integer;
        int     boolean;
    };
    
    struct _META*       next;           

} META;


typedef struct _RULE
{
    char*           identifier;
    int             flags;
    NAMESPACE*      ns;
    STRING*         string_list_head;
    TAG*            tag_list_head;
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
    STRING_LIST_ENTRY*  hashed_strings_2b[256][256];
    STRING_LIST_ENTRY*  hashed_strings_1b[256];
    STRING_LIST_ENTRY*  non_hashed_strings;
    int                 populated;
        
} HASH_TABLE;


typedef struct _MEMORY_BLOCK
{
    unsigned char*          data;
    size_t                  size;
    size_t                  base;
    struct _MEMORY_BLOCK*   next;
        
} MEMORY_BLOCK;



typedef int (*YARACALLBACK)(RULE* rule, void* data);
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
    
    NAMESPACE*              namespaces;
    NAMESPACE*              current_namespace;
    
    VARIABLE*               variables;
    
    STRING*                 current_rule_strings;  
    int                     current_rule_flags;
    int                     inside_for;
    
    char*                   file_name_stack[MAX_INCLUDE_DEPTH];
    int                     file_name_stack_ptr;
    
    char                    last_error_extra_info[256];
    
    char                    lex_buf[256];
    char*                   lex_buf_ptr;
    unsigned short          lex_buf_len;
    
    int                     fast_match;
    int                     allow_includes;
    int                     scanning_process_memory;
        
    char                    include_base_dir[MAX_PATH];

} YARA_CONTEXT;


RULE*             lookup_rule(RULE_LIST* rules, const char* identifier, NAMESPACE* ns);
STRING*           lookup_string(STRING* string_list_head, const char* identifier);
TAG*              lookup_tag(TAG* tag_list_head, const char* identifier);
META*             lookup_meta(META* meta_list_head, const char* identifier);
VARIABLE*         lookup_variable(VARIABLE* _list_head, const char* identifier);

void              yr_init();

YARA_CONTEXT*     yr_create_context();
void              yr_destroy_context(YARA_CONTEXT* context);

int               yr_calculate_rules_weight(YARA_CONTEXT* context);

NAMESPACE*        yr_create_namespace(YARA_CONTEXT* context, const char* name);

int               yr_define_integer_variable(YARA_CONTEXT* context, const char* identifier, size_t value);
int               yr_define_boolean_variable(YARA_CONTEXT* context, const char* identifier, int value);
int               yr_define_string_variable(YARA_CONTEXT* context, const char* identifier, const char* value);
int               yr_undefine_variable(YARA_CONTEXT* context, const char* identifier);

char*             yr_get_current_file_name(YARA_CONTEXT* context);

int               yr_push_file_name(YARA_CONTEXT* context, const char* file_name);
void              yr_pop_file_name(YARA_CONTEXT* context);

int               yr_compile_file(FILE* rules_file, YARA_CONTEXT* context);
int               yr_compile_string(const char* rules_string, YARA_CONTEXT* context);

int               yr_scan_mem(unsigned char* buffer, size_t buffer_size, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
int               yr_scan_file(const char* file_path, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
int               yr_scan_proc(int pid, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);

char*             yr_get_error_message(YARA_CONTEXT* context, char* buffer, int buffer_size);

#endif

