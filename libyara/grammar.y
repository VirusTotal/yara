
%{ 
    
#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "error.h"
#include "compile.h"

#define YYERROR_VERBOSE

/* Global variables */

STRING* current_rule_strings;

/* Function declarations */

void reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition);
TAG* reduce_tags(TAG* tag_list_head, char* identifier);

STRING* reduce_string_declaration(char* identifier, char* str, int flags);
STRING* reduce_strings(STRING* string_list_head, STRING* string);

TERM* reduce_string(char* identifier);
TERM* reduce_string_at(char* identifier, TERM* offset);
TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset);
TERM* reduce_string_in_section_by_name(char* identifier, char* section_name);
TERM* reduce_string_count(char* identifier);

TERM* reduce_filesize();
TERM* reduce_entrypoint();
TERM* reduce_term(int type, TERM* op1, TERM* op2);
TERM* reduce_constant(unsigned int constant);
TERM* reduce_rule(char* identifier);
TERM* reduce_boolean_expression_list(TERM* boolean_expression_list_head, TERM* boolean_expression);

%} 

%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token <string> _STRINGS_
%token _CONDITION_
%token _END_
%token <pchar> _IDENTIFIER_
%token <term> _STRING_IDENTIFIER_
%token <term> _STRING_COUNT_
%token <integer> _NUMBER_
%token _UNKNOWN_
%token <pchar> _TEXTSTRING_
%token <pchar> _HEXSTRING_
%token _WIDE_
%token _NOCASE_
%token _REGEXP_
%token _FULLWORD_
%token _AT_
%token _SIZE_
%token _ENTRYPOINT_
%token _RVA_
%token _OFFSET_
%token _FILE_
%token _IN_
%token _OF_
%token <term> _SECTION_

%token _MZ_
%token _PE_
%token _DLL_

%token _TRUE_
%token _FALSE_

%left _AND_ _OR_
%left _NOT_
%left _LT_ _LE_ _GT_ _GE_ _EQ_ _NEQ_ _IS_
%left '+' '-' 
%left '*' '/'

%type <string> strings
%type <string> string_declaration

%type <integer> string_modifier
%type <integer> string_modifiers

%type <integer> rule_modifier

%type <tag>  tags
%type <tag>  tag_list

%type <term> boolean_expression
%type <term> expression
%type <term> number
%type <term> boolean_expression_list
%type <term> boolean_expressions

%union { 
    unsigned int integer;
    char* pchar;
    void* string;
    void* term;
    void* tag;
};


%%

rules :  /* empty */
      | rules rule
      {
            if (last_error != ERROR_SUCCESS)
            {
                show_last_error();
                yynerrs++;
                YYERROR;
            }
      }
      | rules error '}' /* on error skip until end of rule*/
      ;

rule    :   rule_modifier _RULE_ _IDENTIFIER_ tags '{' _CONDITION_ ':' boolean_expression '}'                          { reduce_rule_declaration($3,$1,$4,0,$8);    }
        |   rule_modifier _RULE_ _IDENTIFIER_ tags '{' _STRINGS_ ':' strings _CONDITION_ ':' boolean_expression '}'    { reduce_rule_declaration($3,$1,$4,$8,$11);  }
        ;
        
rule_modifier   :  /* empty */    { $$ = 0; }
                | _PRIVATE_       { $$ = RULE_FLAGS_PRIVATE; }
				| _GLOBAL_	      { $$ = RULE_FLAGS_GLOBAL; }
                ;

tags    : /* empty */                       { $$ = NULL; }
        | ':' tag_list                      { $$ = $2;   }
        ;
        
tag_list : _IDENTIFIER_                     { 
                                                $$ = reduce_tags(NULL,$1); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
         | tag_list _IDENTIFIER_            {   
                                                $$ = reduce_tags($1,$2); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }  
                                            }

        
strings :   string_declaration              { 
                                                $$ = reduce_strings(NULL,$1); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    show_last_error();
                                                    yynerrs++;
                                                    YYERROR;
                                                }
                                            }
        |   strings string_declaration      { 
                                                $$ = reduce_strings($1,$2);
                                                
                                                if ($$ == NULL)
                                                {
                                                    show_last_error();
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
                                show_last_error();
                                yynerrs++;
                                YYERROR;
                            } 
                        }
                    |   _STRING_IDENTIFIER_ '=' _HEXSTRING_         
                        {
                            $$ = reduce_string_declaration($1, $3, STRING_FLAGS_HEXADECIMAL);
            
                            if ($$ == NULL)
                            {
                                show_last_error();
                                yynerrs++;
                                YYERROR;
                            }
                        }
                    ;
    
string_modifiers : /* empty */                              { $$ = 0;  }
                 | string_modifiers string_modifier         { $$ = $1 | $2; }
                 ;

string_modifier : _WIDE_        { $$ = STRING_FLAGS_WIDE; }
                | _NOCASE_      { $$ = STRING_FLAGS_NO_CASE; }
                | _REGEXP_      { $$ = STRING_FLAGS_REGEXP; }
                | _FULLWORD_    { $$ = STRING_FLAGS_FULL_WORD; }
                ;

boolean_expression : _TRUE_                                 { $$ = reduce_constant(1); }
                   | _FALSE_                                { $$ = reduce_constant(0); } 
                   | _IDENTIFIER_                                   
                     { 
                        $$ = reduce_rule($1);
                        
                        if ($$ == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_                                
                     {  
                        $$ = reduce_string($1);
                        
                        if ($$ == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ expression    
                     {          
                        $$ = reduce_string_at($1, $3);
                        
                        if ($$ == NULL)
                        {
                            show_last_error();
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ _RVA_ expression          
                     { 
                        $$ = NULL; 
                     }
                   | _STRING_IDENTIFIER_ _IN_ '[' expression '.' '.' expression ']'                     
                     {          
                        $$ = reduce_string_in_range($1, $4, $7);
                        
                        if ($$ == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _IN_ _SECTION_ '[' _TEXTSTRING_ ']'                    
                     {          
                        $$ = reduce_string_in_section_by_name($1, $5);

                        if ($$ == NULL)
                        {
                            show_last_error();
                            yynerrs++;
                            YYERROR;
                        }
                     }
                   | _FILE_ _IS_ type                                   { $$ = NULL; }
                   | '(' boolean_expression ')'                         { $$ = $2; }
                   | _NOT_ boolean_expression                           { $$ = reduce_term(TERM_TYPE_NOT, $2, NULL); }
                   | boolean_expression _AND_ boolean_expression        { $$ = reduce_term(TERM_TYPE_AND, $1, $3); }
                   | boolean_expression _OR_ boolean_expression         { $$ = reduce_term(TERM_TYPE_OR, $1, $3); }
                   | boolean_expression _IS_ boolean_expression         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3); }
                   | expression _LT_ expression                         { $$ = reduce_term(TERM_TYPE_LT, $1, $3); }
                   | expression _GT_ expression                         { $$ = reduce_term(TERM_TYPE_GT, $1, $3); }
                   | expression _LE_ expression                         { $$ = reduce_term(TERM_TYPE_LE, $1, $3); }
                   | expression _GE_ expression                         { $$ = reduce_term(TERM_TYPE_GE, $1, $3); }
                   | expression _EQ_ expression                         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3); }
                   | expression _IS_ expression                         { $$ = reduce_term(TERM_TYPE_EQ, $1, $3); }
                   | expression _NEQ_ expression                        { $$ = reduce_term(TERM_TYPE_NOT_EQ, $1, $3); }
                   | number _OF_ boolean_expression_list                { $$ = reduce_term(TERM_TYPE_OF, $1, $3); }
                   ;    

//TODO: controla que el numero en el operador OF sea menor o igual que la cantidad de elementos en la lista

boolean_expression_list : '(' boolean_expressions ')'   { $$ = $2; }
                        ;                           
                            
boolean_expressions : boolean_expression
                      {
                         $$ = reduce_boolean_expression_list(NULL,$1);
                      }
                    | boolean_expressions ',' boolean_expression
                      {
                         $$ = reduce_boolean_expression_list($1,$3);
                      }
                    ;
                            
expression : _SIZE_                             { $$ = reduce_filesize(); }
           | _ENTRYPOINT_                       { $$ = reduce_entrypoint(); }
           | _STRING_COUNT_                         
             { 
                    $$ = reduce_string_count($1); 
                    
                    if ($$ == NULL)
                    {
                        show_last_error();
                        yynerrs++;
                        YYERROR;
                    }
             }
           | '(' expression ')'                 { $$ = $2; }
           | expression '+' expression          { $$ = reduce_term(TERM_TYPE_ADD, $1, $3); }
           | expression '-' expression          { $$ = reduce_term(TERM_TYPE_SUB, $1, $3); }
           | expression '*' expression          { $$ = reduce_term(TERM_TYPE_MUL, $1, $3); }
           | expression '/' expression          { $$ = reduce_term(TERM_TYPE_DIV, $1, $3); }
           | number
           ;
        
number   :  _NUMBER_                            { $$ = reduce_constant($1); }
         ;  
        
type : _MZ_
     | _PE_
     | _DLL_
     ;
        
%%


void reduce_rule_declaration(char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition)
{
    STRING* string;
    
    last_error = new_rule(rule_list, identifier, flags, tag_list_head, string_list_head, condition);
    
    if (last_error != ERROR_SUCCESS)
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
                last_error = ERROR_UNREFERENCED_STRING;
                break;
            }
            
            string = string->next;
        }
    }
}

STRING* reduce_string_declaration(char* identifier, char* str, int flags)
{
    char tmp[200];
    STRING* string = NULL;

    last_error = new_string(identifier, str, flags, &string);
    
    if (last_error == ERROR_INVALID_REGULAR_EXPRESSION) 
    {
        sprintf(tmp, "invalid regular expression in string \"%s\": %s", identifier, last_error_extra_info);
        strcpy(last_error_extra_info, tmp);
    }
    else if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    free(str);
            
    return string;
}

STRING* reduce_strings(STRING* string_list_head, STRING* string)
{
    if (lookup_string(string_list_head,string->identifier) == NULL) /* no strings with the same identifier */
    {
        string->next = string_list_head;    
        current_rule_strings = string;
        last_error = ERROR_SUCCESS;
        return string;
    }
    else
    {
        strcpy(last_error_extra_info, string->identifier);
        last_error = ERROR_DUPLICATE_STRING_IDENTIFIER;
        return NULL;
    }   
}

TAG* reduce_tags(TAG* tag_list_head, char* identifier)
{
    TAG* tag;

    if (lookup_tag(tag_list_head, identifier) == NULL) /* no tags with the same identifier */
    {
        tag = malloc(sizeof(TAG));
        
        if (tag != NULL)
        {
            tag->identifier = identifier;
            tag->next = tag_list_head;  
            last_error = ERROR_SUCCESS;
        }
        else
        {
            last_error = ERROR_INSUFICIENT_MEMORY;
        }
        
        return tag;
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_error = ERROR_DUPLICATE_TAG_IDENTIFIER;
        return NULL;
    }
}

TERM* reduce_filesize()
{
    TERM* term = NULL;
    
    last_error = new_simple_term(TERM_TYPE_FILESIZE, &term); 
    return (TERM*) term;    
}

TERM* reduce_entrypoint()
{
    TERM* term = NULL;
    
    last_error = new_simple_term(TERM_TYPE_ENTRYPOINT, &term); 
    return (TERM*) term;    
}

TERM* reduce_term(int type, TERM* op1, TERM* op2)
{
    TERM_BINARY_OPERATION* term = NULL;
    
    last_error = new_binary_operation(type, op1, op2, &term);
    return (TERM*) term;
}

TERM* reduce_constant(unsigned int constant)
{
    TERM_CONST* term = NULL;
    
    last_error = new_constant(constant, &term); 
    return (TERM*) term;
}

TERM* reduce_string(char* identifier)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_at(char* identifier, TERM* offset)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_AT, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->offset = offset;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(char* identifier, TERM* lower_offset, TERM* upper_offset)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->lower_offset = lower_offset;
        term->upper_offset = upper_offset;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name(char* identifier, char* section_name)
{
    TERM_STRING* term = NULL;
    
    last_error = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    else
    {
        term->section_name = section_name;
    }
    
    free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_count(char* identifier)
{
    TERM_STRING* term = NULL;

    last_error = new_string_identifier(TERM_TYPE_STRING_COUNT, current_rule_strings, identifier, &term);
    
    if (last_error != ERROR_SUCCESS)
    {
        strcpy(last_error_extra_info, identifier);
    }
    
    free(identifier);           
    return (TERM*) term;
}

TERM* reduce_rule(char* identifier)
{
    TERM_BINARY_OPERATION* term;
    RULE* rule;
    
    rule = lookup_rule(rule_list, identifier);
    
    if (rule != NULL)
    {
        last_error = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, &term);        
    }
    else
    {
        strcpy(last_error_extra_info, identifier);
        last_error = ERROR_UNDEFINED_RULE;
        term = NULL;
    }
    
    free(identifier);
    return (TERM*) term;
}

TERM* reduce_boolean_expression_list(TERM* boolean_expression_list_head, TERM* boolean_expression)
{
    boolean_expression->next = boolean_expression_list_head;
    return boolean_expression;
}



    
    
    