
%{ 
    
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ast.h"
#include "error.h"
#include "compile.h"
#include "sizedstr.h"
#include "mem.h"

#define YYERROR_VERBOSE
//#define YYDEBUG 1

%} 

%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token <string> _STRINGS_
%token _CONDITION_
%token _END_
%token <c_string> _IDENTIFIER_
%token <term> _STRING_IDENTIFIER_
%token <term> _STRING_COUNT_
%token <term> _STRING_OFFSET_
%token <term> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <term> _ANONYMOUS_STRING_
%token <integer> _NUMBER_
%token _UNKNOWN_
%token <sized_string> _TEXTSTRING_
%token <sized_string> _HEXSTRING_
%token <sized_string> _REGEXP_
%token _ASCII_
%token _WIDE_
%token _NOCASE_
%token _REGEXP_
%token _FULLWORD_
%token _AT_
%token _SIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _RVA_
%token _OFFSET_
%token _FILE_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token <term> _SECTION_
%token _INT8_
%token _INT16_
%token _INT32_
%token _UINT8_
%token _UINT16_
%token _UINT32_

%token _MZ_
%token _PE_
%token _DLL_

%token _TRUE_
%token _FALSE_

%left _OR_
%left _AND_
%left _NOT_
%left _LT_ _LE_ _GT_ _GE_ _EQ_ _NEQ_ _IS_
%left '+' '-' 
%left '*' '\\'

%type <string> strings
%type <string> string_declaration

%type <integer> string_modifier
%type <integer> string_modifiers

%type <integer> rule_modifier
%type <integer> rule_modifiers

%type <tag>  tags
%type <tag>  tag_list

%type <term> boolean_expression
%type <term> expression
%type <term> number
%type <term> string_set
%type <term> string_enumeration
%type <term> string_enumeration_item

%union {
    
    void*           sized_string;
    char*           c_string;
    unsigned int    integer;
    void*           string;
    void*           term;
    void*           tag;

}

//%destructor { free ($$); } _TEXTSTRING_ _HEXSTRING_ _REGEXP_ _IDENTIFIER_


%{ 
    
/* Global variables */

STRING* current_rule_strings;
int inside_for = 0;

/* Function declarations */

int reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition);
TAG* reduce_tags(TAG* tag_list_head, char* identifier);

STRING* reduce_string_declaration(char* identifier, SIZED_STRING* str, int flags);
STRING* reduce_strings(STRING* string_list_head, STRING* string);

TERM* reduce_string_enumeration(TERM* string_list_head, TERM* string_identifier);
TERM* reduce_string_with_wildcard(char* identifier);

TERM* reduce_string(char* identifier);
TERM* reduce_string_at(char* identifier, TERM* offset);
TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset);
TERM* reduce_string_in_section_by_name(char* identifier, SIZED_STRING* section_name);
TERM* reduce_string_count(char* identifier);
TERM* reduce_string_offset(char* identifier); 

TERM* reduce_filesize();
TERM* reduce_entrypoint();

TERM* reduce_term(int type, TERM* op1, TERM* op2, TERM* op3);
TERM* reduce_constant(unsigned int constant);
TERM* reduce_rule(char* identifier);

int count_strings(TERM_STRING* st);

%} 

%%

rules :  /* empty */
      | rules rule
      | rules error '}' /* on error skip until end of rule*/
      ;

rule    :   rule_modifiers _RULE_ _IDENTIFIER_ tags '{' _CONDITION_ ':' boolean_expression '}'                          
            { 
                if (reduce_rule_declaration($3,$1,$4,0,$8) != ERROR_SUCCESS)
                {
                    yyerror(get_error_message(last_result));
                    yynerrs++;
                    YYERROR;
                }
            }
        |   rule_modifiers _RULE_ _IDENTIFIER_ tags '{' _STRINGS_ ':' strings _CONDITION_ ':' boolean_expression '}'    
            { 
                if (reduce_rule_declaration($3,$1,$4,$8,$11) != ERROR_SUCCESS)
                {
                    yyerror(get_error_message(last_result));
                    yynerrs++;
                    YYERROR; 
                }  
            }
        ;
        
rule_modifiers : /* empty */                          { $$ = 0;  }
               | rule_modifiers rule_modifier         { $$ = $1 | $2; }
               ;
        
rule_modifier : _PRIVATE_       { $$ = RULE_FLAGS_PRIVATE; }
		      | _GLOBAL_	    { $$ = RULE_FLAGS_GLOBAL; }
              ;

tags    : /* empty */                       { $$ = NULL; }
        | ':' tag_list                      { $$ = $2;   }
        ;
        
tag_list : _IDENTIFIER_                     { 
                                                $$ = reduce_tags(NULL,$1); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(get_error_message(last_result));
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
         | tag_list _IDENTIFIER_            {   
                                                $$ = reduce_tags($1,$2); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(get_error_message(last_result));
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }

        
strings :   string_declaration              { 
                                                $$ = reduce_strings(NULL,$1); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(get_error_message(last_result));
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
        |   strings string_declaration      { 
                                                $$ = reduce_strings($1,$2);
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(get_error_message(last_result));
                                                    yynerrs++;
                                                    YYERROR;
                                                }  
                                            }
        ;
        
string_declaration  :   _STRING_IDENTIFIER_ '=' _TEXTSTRING_ string_modifiers   
                        { 
                            $$ = reduce_string_declaration($1, $3, $4); 
                
                            if ($$ == NULL)
                            {
                                yyerror(get_error_message(last_result));
                                yynerrs++;
                                YYERROR;
                            }
                        }
                    |   _STRING_IDENTIFIER_ '=' _REGEXP_ string_modifiers   
                       { 
                           $$ = reduce_string_declaration($1, $3, $4 | STRING_FLAGS_REGEXP); 

                           if ($$ == NULL)
                           {
                               yyerror(get_error_message(last_result));
                               yynerrs++;
                               YYERROR;
                           }
                       }
                    |   _STRING_IDENTIFIER_ '=' _HEXSTRING_         
                        {
                            $$ = reduce_string_declaration($1, $3, STRING_FLAGS_HEXADECIMAL);
            
                            if ($$ == NULL)
                            {
                                yyerror(get_error_message(last_result));
                                yynerrs++;
                                YYERROR;
                            }
                        }
                    ;
    
string_modifiers : /* empty */                              { $$ = 0;  }
                 | string_modifiers string_modifier         { $$ = $1 | $2; }
                 ;

string_modifier : _WIDE_        { $$ = STRING_FLAGS_WIDE; }
                | _ASCII_       { $$ = STRING_FLAGS_ASCII; }
                | _NOCASE_      { $$ = STRING_FLAGS_NO_CASE; }
                | _FULLWORD_    { $$ = STRING_FLAGS_FULL_WORD; }
                ;

boolean_expression : _TRUE_                                 { $$ = reduce_constant(1); }
                   | _FALSE_                                { $$ = reduce_constant(0); } 
                   | _IDENTIFIER_                                   
                     { 
                        $$ = reduce_rule($1);
                        
                        if ($$ == NULL)
                        {
                            yyerror(get_error_message(last_result));
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_                                
                     {  
                        $$ = reduce_string($1);
                        
                        if ($$ == NULL)
                        {
                            yyerror(get_error_message(last_result));
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ expression    
                     {          
                        $$ = reduce_string_at($1, $3);
                        
                        if ($$ == NULL)
                        {
                            yyerror(get_error_message(last_result));
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ _RVA_ expression          
                     { 
                        $$ = NULL; 
                     }
                   | _STRING_IDENTIFIER_ _IN_ '(' expression '.' '.' expression ')'                     
                     {          
                        $$ = reduce_string_in_range($1, $4, $7);
                        
                        if ($$ == NULL)
                        {
                            yyerror(get_error_message(last_result));
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _IN_ _SECTION_ '(' _TEXTSTRING_ ')'                    
                     {          
                        $$ = reduce_string_in_section_by_name($1, $5);

                        if ($$ == NULL)
                        {
                            yyerror(get_error_message(last_result));
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _FOR_ expression _OF_ string_set ':'
                      { 
                          inside_for++; 
                      }           
                      '(' boolean_expression ')'                     
                      { 
                           inside_for--; 
                           
                           $$ = reduce_term(TERM_TYPE_FOR, $2, $4, $8); 
                           
                           if ($$ == NULL)
                           {
                               yyerror(get_error_message(last_result));
                               yynerrs++;
                               YYERROR;
                           }
                      }
                   | _FOR_ _ALL_ _OF_ string_set ':'
                     { 
                         inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                          inside_for--; 
                          
                          $$ = reduce_term(TERM_TYPE_FOR, reduce_constant(count_strings($4)), $4, $8); 
                          
                          if ($$ == NULL)
                          {
                              yyerror(get_error_message(last_result));
                              yynerrs++;
                              YYERROR;
                          }
                     }
                   | _FOR_ _ANY_ _OF_ string_set ':'
                     { 
                           inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                          inside_for--; 
                                                    
                          $$ = reduce_term(TERM_TYPE_FOR, reduce_constant(1), $4, $8); 
                          
                          if ($$ == NULL)
                          {
                              yyerror(get_error_message(last_result));
                              yynerrs++;
                              YYERROR;
                          }
                     }
                   | expression _OF_ string_set                         
                     { 
                         $$ = reduce_term(TERM_TYPE_OF, $1, $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(get_error_message(last_result));
                             yynerrs++;
                             YYERROR;
                         }
                     }
                   | _ALL_ _OF_ string_set                              
                     { 
                         $$ = reduce_term(TERM_TYPE_OF, reduce_constant(count_strings($3)), $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(get_error_message(last_result));
                             yynerrs++;
                             YYERROR;
                         }
                     }
                   | _ANY_ _OF_ string_set                              
                     { 
                         $$ = reduce_term(TERM_TYPE_OF, reduce_constant(1), $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(get_error_message(last_result));
                             yynerrs++;
                             YYERROR;
                         }
                     }
                   | _FILE_ _IS_ type                                   { $$ = NULL; }
                   | '(' boolean_expression ')'                         { $$ = $2; }
                   | _NOT_ boolean_expression                           { $$ = reduce_term(TERM_TYPE_NOT, $2, NULL, NULL); }
                   | boolean_expression _AND_ boolean_expression        { $$ = reduce_term(TERM_TYPE_AND, $1, $3, NULL); }
                   | boolean_expression _OR_ boolean_expression         { $$ = reduce_term(TERM_TYPE_OR, $1, $3, NULL); }
                   | boolean_expression _IS_ boolean_expression         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _LT_ expression                         { $$ = reduce_term(TERM_TYPE_LT, $1, $3, NULL); }
                   | expression _GT_ expression                         { $$ = reduce_term(TERM_TYPE_GT, $1, $3, NULL); }
                   | expression _LE_ expression                         { $$ = reduce_term(TERM_TYPE_LE, $1, $3, NULL); }
                   | expression _GE_ expression                         { $$ = reduce_term(TERM_TYPE_GE, $1, $3, NULL); }
                   | expression _EQ_ expression                         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _IS_ expression                         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _NEQ_ expression                        { $$ = reduce_term(TERM_TYPE_NOT_EQ, $1, $3, NULL); }
                   ;    
                  

string_set  : '(' string_enumeration ')'            { $$ = $2; }
            | _THEM_                                { $$ = reduce_string_with_wildcard(yr_strdup("$*")); }
            ;                           
                            
string_enumeration  : string_enumeration_item
                    | string_enumeration ',' string_enumeration_item
                      {
                         $$ = reduce_string_enumeration($1,$3);
                      }
                    ;
                    
string_enumeration_item : _STRING_IDENTIFIER_
                          {  
                              $$ = reduce_string($1);

                              if ($$ == NULL)
                              {
                                  yyerror(get_error_message(last_result));
                                  yynerrs++;
                                  YYERROR;
                              }
                          }
                        | _STRING_IDENTIFIER_WITH_WILDCARD_     
                          { 
                              $$ = reduce_string_with_wildcard($1); 
                              
                              if ($$ == NULL)
                              {
                                  yyerror(get_error_message(last_result));
                                  yynerrs++;
                                  YYERROR;
                              }
                          }
                        ;

                            
expression : _SIZE_                             { $$ = reduce_filesize(); }
           | _ENTRYPOINT_                       { $$ = reduce_entrypoint(); }
           | _INT8_  '(' expression ')'         { $$ = reduce_term(TERM_TYPE_INT8_AT_OFFSET, $3, NULL, NULL); }
           | _INT16_ '(' expression ')'         { $$ = reduce_term(TERM_TYPE_INT16_AT_OFFSET, $3, NULL, NULL); }
           | _INT32_ '(' expression ')'         { $$ = reduce_term(TERM_TYPE_INT32_AT_OFFSET, $3, NULL, NULL); }
           | _UINT8_  '(' expression ')'         { $$ = reduce_term(TERM_TYPE_UINT8_AT_OFFSET, $3, NULL, NULL); }
           | _UINT16_ '(' expression ')'         { $$ = reduce_term(TERM_TYPE_UINT16_AT_OFFSET, $3, NULL, NULL); }
           | _UINT32_ '(' expression ')'         { $$ = reduce_term(TERM_TYPE_UINT32_AT_OFFSET, $3, NULL, NULL); }
           | _STRING_COUNT_                         
             { 
                    $$ = reduce_string_count($1); 
                    
                    if ($$ == NULL)
                    {
                        yyerror(get_error_message(last_result));
                        yynerrs++;
                        YYERROR;
                    }
             }
           | _STRING_OFFSET_                         
             { 
                    $$ = reduce_string_offset($1); 

                    if ($$ == NULL)
                    {
                        yyerror(get_error_message(last_result));
                        yynerrs++;
                        YYERROR;
                    }
             }
           | '(' expression ')'                 { $$ = $2; }
           | expression '+' expression          { $$ = reduce_term(TERM_TYPE_ADD, $1, $3, NULL); }
           | expression '-' expression          { $$ = reduce_term(TERM_TYPE_SUB, $1, $3, NULL); }
           | expression '*' expression          { $$ = reduce_term(TERM_TYPE_MUL, $1, $3, NULL); }
           | expression '\\' expression         { $$ = reduce_term(TERM_TYPE_DIV, $1, $3, NULL); }
           | number
           ;
        
number   :  _NUMBER_                            { $$ = reduce_constant($1); }
         ;  
        
type : _MZ_
     | _PE_
     | _DLL_
     ;
        
%%


int count_strings(TERM_STRING* st)
{
    int count = 0;
    
    while(st != NULL)
    {
        count++;
        st = st->next;
    }
    
    return count;
}

int reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition)
{
    STRING* string;
    
    last_result = new_rule(rule_list, identifier, flags, tag_list_head, string_list_head, condition);
    
    if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        string = string_list_head;
        
        while (string != NULL)
        {
            if (! (string->flags & STRING_FLAGS_REFERENCED))
            {
                strcpy(last_error_extra_info, string->identifier);
                last_result = ERROR_UNREFERENCED_STRING;
                break;
            }
            
            string = string->next;
        }
    }
    
    return last_result;
}

STRING* reduce_string_declaration(char* identifier, SIZED_STRING* str, int flags)
{
    char tmp[200];
    STRING* string = NULL;
    
    if (strcmp(identifier,"$") == 0)
    {
        flags |= STRING_FLAGS_ANONYMOUS;
    }
    
    last_result = new_string(identifier, str, flags, &string);
    
    if (last_result == ERROR_INVALID_REGULAR_EXPRESSION) 
    {
        sprintf(tmp, "invalid regular expression in string \"%s\": %s", identifier, last_error_extra_info);
        strcpy(last_error_extra_info, tmp);
    }
    else if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    yr_free(str);
            
    return string;
}

STRING* reduce_strings(STRING* string_list_head, STRING* string)
{
    /* no strings with the same identifier, except for anonymous strings */
    
    if (IS_ANONYMOUS(string) || lookup_string(string_list_head,string->identifier) == NULL) 
    {
        string->next = string_list_head;    
        current_rule_strings = string;
        last_result = ERROR_SUCCESS;
        return string;
    }
    else
    {
        strcpy(last_error_extra_info, string->identifier);
        last_result = ERROR_DUPLICATE_STRING_IDENTIFIER;
        return NULL;
    }   
}

TAG* reduce_tags(TAG* tag_list_head, char* identifier)
{
    TAG* tag;

    if (lookup_tag(tag_list_head, identifier) == NULL) /* no tags with the same identifier */
    {
        tag = yr_malloc(sizeof(TAG));
        
        if (tag != NULL)
        {
            tag->identifier = identifier;
            tag->next = tag_list_head;  
            last_result = ERROR_SUCCESS;
        }
        else
        {
            last_result = ERROR_INSUFICIENT_MEMORY;
        }
        
        return tag;
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
        return NULL;
    }
}

TERM* reduce_filesize()
{
    TERM* term = NULL;
    
    last_result = new_simple_term(TERM_TYPE_FILESIZE, &term); 
    return (TERM*) term;    
}

TERM* reduce_entrypoint()
{
    TERM* term = NULL;
    
    last_result = new_simple_term(TERM_TYPE_ENTRYPOINT, &term); 
    return (TERM*) term;    
}

TERM* reduce_term(int type, TERM* op1, TERM* op2, TERM* op3)
{
    TERM* term = NULL;
    
    if (op2 == NULL && op3 == NULL)
    {
        last_result = new_unary_operation(type, op1, (TERM_UNARY_OPERATION**) &term);
    }
    else if (op3 == NULL)
    {
        last_result = new_binary_operation(type, op1, op2, (TERM_BINARY_OPERATION**) &term);
    }
    else
    {
        last_result = new_ternary_operation(type, op1, op2, op3, (TERM_TERNARY_OPERATION**) &term);
    }
    
    return (TERM*) term;
}

TERM* reduce_constant(unsigned int constant)
{
    TERM_CONST* term = NULL;
    
    last_result = new_constant(constant, &term); 
    return (TERM*) term;
}

TERM* reduce_string(char* identifier)
{
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || inside_for > 0) 
    {  
        last_result = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, identifier, &term);       
     
        if (last_result != ERROR_SUCCESS)
        {
            strcpy(last_error_extra_info, identifier);
        }
    }
    else
    {
        last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_with_wildcard(char* identifier)
{
    TERM_STRING* term = NULL;
    TERM_STRING* next;
    STRING* string;
    
    int len = 0;

    string = current_rule_strings;
    next = NULL;
    
    while (identifier[len] != '\0' && identifier[len] != '*')
    {
        len++;
    }
    
    while (string != NULL)
    {
        if (strncmp(string->identifier, identifier, len) == 0)
        {
            last_result = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, string->identifier, &term);
            
            if (last_result != ERROR_SUCCESS)
                break;
                
            string->flags |= STRING_FLAGS_REFERENCED;
            
            term->string = string;
            term->next = next;
            next = term;            
        }
        
        string = string->next;
    }
    
    yr_free(identifier);
    return (TERM*) term;  
}

TERM* reduce_string_at(char* identifier, TERM* offset)
{
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || inside_for > 0) 
    {  
        last_result = new_string_identifier(TERM_TYPE_STRING_AT, current_rule_strings, identifier, &term);       
     
        if (last_result != ERROR_SUCCESS)
        {
            strcpy(last_error_extra_info, identifier);
        }
        else
        {
            term->offset = offset;
        }  
    }
    else
    {
        last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset)
{
    TERM_STRING* term = NULL;
    
    last_result = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, current_rule_strings, identifier, &term);
    
    if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->lower_offset = lower_offset;
        term->upper_offset = upper_offset;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name(char* identifier, SIZED_STRING* section_name)
{
    TERM_STRING* term = NULL;
    
    last_result = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, current_rule_strings, identifier, &term);
    
    if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->section_name = yr_strdup(section_name->c_string);
    }
    
    yr_free(section_name);
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_count(char* identifier)
{
    TERM_STRING* term = NULL;

    last_result = new_string_identifier(TERM_TYPE_STRING_COUNT, current_rule_strings, identifier, &term);
    
    if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_string_offset(char* identifier)
{
    TERM_STRING* term = NULL;

    last_result = new_string_identifier(TERM_TYPE_STRING_OFFSET, current_rule_strings, identifier, &term);
    
    if (last_result != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_rule(char* identifier)
{
    TERM_BINARY_OPERATION* term;
    RULE* rule;
    
    rule = lookup_rule(rule_list, identifier);
    
    if (rule != NULL)
    {
        last_result = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, &term);        
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_result = ERROR_UNDEFINED_RULE;
        term = NULL;
    }
    
    yr_free(identifier);
    return (TERM*) term;
}

TERM* reduce_string_enumeration(TERM* string_list_head, TERM* string_identifier)
{
    TERM_STRING* term = (TERM_STRING*) string_identifier;
    
    term->next = (TERM_STRING*) string_list_head;
    term->string->flags |= STRING_FLAGS_REFERENCED;

    return string_identifier;
}

  







    
    
    