
%{ 
    
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "ast.h"
#include "sizedstr.h"
#include "mem.h"
#include "lex.h"

#define YYERROR_VERBOSE
//#define YYDEBUG 1

%} 

%pure-parser
%parse-param {void *yyscanner}
%lex-param {yyscan_t yyscanner}

%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
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
%token _MATCHES_
%token _CONTAINS_
%token _OCCURRENCE_

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
%type <string> string_declarations

%type <meta> meta
%type <meta> meta_declaration
%type <meta> meta_declarations

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
%type <term> condition

%union {
    
    void*           sized_string;
    char*           c_string;
    size_t          integer;
    void*           string;
    void*           term;
    void*           tag;
    void*           meta;

}

//%destructor { free ($$); } _TEXTSTRING_ _HEXSTRING_ _REGEXP_ _IDENTIFIER_


%{ 

/* Function declarations */

int reduce_rule_declaration(    yyscan_t yyscanner, 
                                char* identifier, 
                                int flags, 
                                TAG* tag_list_head, 
                                META* meta_list_head,
                                STRING* string_list_head, 
                                TERM* condition);
                            
TAG* reduce_tags(   yyscan_t yyscanner,
                    TAG* tag_list_head,
                    char* identifier);
                    
                    
META* reduce_meta_declaration(  yyscan_t yyscanner,
                                int type,
                                char* identifier,
                                unsigned int integer_value,                 
                                SIZED_STRING* string_value);
                    
META* reduce_metas( yyscan_t yyscanner, 
                    META* meta_list_head,
                    META* meta);

STRING* reduce_string_declaration(  yyscan_t yyscanner,
                                    char* identifier, 
                                    SIZED_STRING* str, 
                                    int flags);
                                
STRING* reduce_strings( yyscan_t yyscanner, 
                        STRING* string_list_head, 
                        STRING* string);

TERM* reduce_string_enumeration(    yyscan_t yyscanner,
                                    TERM* string_list_head, 
                                    TERM* string_identifier);
                                    
TERM* reduce_string_with_wildcard(  yyscan_t yyscanner,
                                    char* identifier);

TERM* reduce_string(    yyscan_t yyscanner, 
                        char* identifier);
                        
TERM* reduce_string_at( yyscan_t yyscanner,
                        char* identifier, 
                        TERM* offset);
                        
TERM* reduce_string_in_range(   yyscan_t yyscanner,
                                char* identifier, 
                                TERM* lower_offset, 
                                TERM* upper_offset);
                                
TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, 
                                        SIZED_STRING* section_name);
                                        
TERM* reduce_string_count(  yyscan_t yyscanner, 
                            char* identifier);
                            
TERM* reduce_string_offset( yyscan_t yyscanner,  
                            char* identifier); 

TERM* reduce_filesize(yyscan_t yyscanner);

TERM* reduce_entrypoint(yyscan_t yyscanner);

TERM* reduce_term(  yyscan_t yyscanner, 
                    int type, 
                    TERM* op1, 
                    TERM* op2, 
                    TERM* op3);
                    
TERM* reduce_constant(  yyscan_t yyscanner,
                        size_t constant);

TERM* reduce_identifier( yyscan_t yyscanner,
                         char* identifier);
                         
TERM* reduce_external_string_operation( yyscan_t yyscanner,
                                        int type,
                                        char* identifier,
                                        SIZED_STRING* string);

int count_strings(TERM_STRING* st);

%} 

%%

rules :  /* empty */
      | rules rule
      | rules error rule      /* on error skip until next rule..*/
      | rules error 'include' /* .. or include statement */
      ;

rule    :   rule_modifiers _RULE_ _IDENTIFIER_ tags '{' meta strings condition '}'    
            { 
                if (reduce_rule_declaration(yyscanner, $3,$1,$4,$6,$7,$8) != ERROR_SUCCESS)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR; 
                }  
            }
        ;
        
meta      : /* empty */                               { $$ = NULL; }
          | _META_ ':' meta_declarations              { $$ = $3; }
          ;
                           
strings   : /* empty */                               { $$ = NULL; }
          | _STRINGS_ ':' string_declarations         { $$ = $3; }
          ;
        
condition : _CONDITION_ ':' boolean_expression        { $$ = $3; }
          ;
        
rule_modifiers : /* empty */                          { $$ = 0;  }
               | rule_modifiers rule_modifier         { $$ = $1 | $2; }
               ;
        
rule_modifier : _PRIVATE_       { $$ = RULE_FLAGS_PRIVATE; }
              | _GLOBAL_        { $$ = RULE_FLAGS_GLOBAL; }
              ;

tags    : /* empty */                       { $$ = NULL; }
        | ':' tag_list                      { $$ = $2;   }
        ;
        
tag_list : _IDENTIFIER_                     { 
                                                $$ = reduce_tags(yyscanner,NULL,$1); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }
         | tag_list _IDENTIFIER_            {   
                                                $$ = reduce_tags(yyscanner,$1,$2); 
                                                
                                                if ($$ == NULL)
                                                {
                                                    yyerror(yyscanner, NULL);
                                                    YYERROR;
                                                }
                                            }

meta_declarations : meta_declaration                        { 
                                                                $$ = reduce_metas(yyscanner, NULL, $1); 
                                                                
                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
                  | meta_declarations meta_declaration      { 
                                                                $$ = reduce_metas(yyscanner, $1, $2); 
                                                                
                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                            }
                  ;
                  
meta_declaration :  _IDENTIFIER_ '=' _TEXTSTRING_            { 
                                                                $$ = reduce_meta_declaration(yyscanner, META_TYPE_STRING, $1, 0, $3);
                                                                
                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
                 |  _IDENTIFIER_ '=' _NUMBER_                { 
                                                                $$ = reduce_meta_declaration(yyscanner, META_TYPE_INTEGER, $1, $3, NULL); 
                                                                
                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
                 |  _IDENTIFIER_ '=' _TRUE_                 { 
                                                                $$ = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, $1, TRUE, NULL); 

                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
                 |  _IDENTIFIER_ '=' _FALSE_                 { 
                                                                $$ = reduce_meta_declaration(yyscanner, META_TYPE_BOOLEAN, $1, FALSE, NULL); 

                                                                if ($$ == NULL)
                                                                {
                                                                    yyerror(yyscanner, NULL);
                                                                    YYERROR;
                                                                }
                                                             }
                 ; 
        
string_declarations :   string_declaration  
                        { 
                            $$ = reduce_strings(yyscanner,NULL,$1); 
                            
                            if ($$ == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
                    |   string_declarations string_declaration      
                        { 
                            $$ = reduce_strings(yyscanner,$1,$2);
                        
                            if ($$ == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }  
                        }
                    ;
        
string_declaration  :   _STRING_IDENTIFIER_ '=' _TEXTSTRING_ string_modifiers   
                        { 
                            $$ = reduce_string_declaration(yyscanner, $1, $3, $4); 
                
                            if ($$ == NULL)
                            {
                                yyerror(yyscanner, NULL);
                                YYERROR;
                            }
                        }
                    |   _STRING_IDENTIFIER_ '=' _REGEXP_ string_modifiers   
                       { 
                           $$ = reduce_string_declaration(yyscanner, $1, $3, $4 | STRING_FLAGS_REGEXP); 

                           if ($$ == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                       }
                    |   _STRING_IDENTIFIER_ '=' _HEXSTRING_         
                        {
                            $$ = reduce_string_declaration(yyscanner, $1, $3, STRING_FLAGS_HEXADECIMAL);
            
                            if ($$ == NULL)
                            {
                                yyerror(yyscanner, NULL);
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

boolean_expression : _TRUE_                                 { $$ = reduce_constant(yyscanner, 1); }
                   | _FALSE_                                { $$ = reduce_constant(yyscanner, 0); } 
                   | _IDENTIFIER_                                   
                     { 
                        $$ = reduce_identifier(yyscanner, $1);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _IDENTIFIER_ _MATCHES_ _REGEXP_                                   
                     { 
                        $$ = reduce_external_string_operation(yyscanner, TERM_TYPE_EXTERNAL_STRING_MATCH, $1, $3);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _IDENTIFIER_ _CONTAINS_ _TEXTSTRING_                                   
                     { 
                        $$ = reduce_external_string_operation(yyscanner, TERM_TYPE_EXTERNAL_STRING_CONTAINS, $1, $3);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_                                
                     {  
                        $$ = reduce_string(yyscanner, $1);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ expression    
                     {          
                        $$ = reduce_string_at(yyscanner, $1, $3);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _AT_ _RVA_ expression          
                     { 
                        $$ = NULL; 
                     }
                   | _STRING_IDENTIFIER_ _IN_ '(' expression '.' '.' expression ')'                     
                     {          
                        $$ = reduce_string_in_range(yyscanner, $1, $4, $7);
                        
                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _STRING_IDENTIFIER_ _IN_ _SECTION_ '(' _TEXTSTRING_ ')'                    
                     {          
                        $$ = reduce_string_in_section_by_name(yyscanner, $1, $5);

                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                   | _FOR_ expression _OCCURRENCE_ _OF_ _STRING_IDENTIFIER_ ':'
                     { 
                        yyget_extra(yyscanner)->inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                        yyget_extra(yyscanner)->inside_for--; 

                        $$ = reduce_term(yyscanner, TERM_TYPE_FOR_OCCURRENCES, $2, reduce_string(yyscanner, $5), $9); 

                        if ($$ == NULL)
                        {
                            yyerror(yyscanner, NULL);
                            YYERROR;
                        }
                     }
                     | _FOR_ _ALL_ _OCCURRENCE_ _OF_ _STRING_IDENTIFIER_ ':'
                       { 
                          yyget_extra(yyscanner)->inside_for++; 
                       }           
                       '(' boolean_expression ')'                     
                       { 
                          yyget_extra(yyscanner)->inside_for--;

                          $$ = reduce_term( yyscanner, 
                                            TERM_TYPE_FOR_OCCURRENCES, 
                                            reduce_string_count(yyscanner, yr_strdup($5)), /* dup string identifier reduce_xx functions calls free */
                                            reduce_string(yyscanner, $5),
                                            $9); 

                          if ($$ == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                      }                   
                      | _FOR_ _ANY_ _OCCURRENCE_ _OF_ _STRING_IDENTIFIER_ ':'
                        { 
                           yyget_extra(yyscanner)->inside_for++; 
                        }           
                        '(' boolean_expression ')'                     
                        { 
                           yyget_extra(yyscanner)->inside_for--;

                           $$ = reduce_term( yyscanner, 
                                             TERM_TYPE_FOR_OCCURRENCES, 
                                             reduce_constant(yyscanner, 1),
                                             reduce_string(yyscanner, $5),
                                             $9); 

                           if ($$ == NULL)
                           {
                               yyerror(yyscanner, NULL);
                               YYERROR;
                           }
                       }
                   | _FOR_ expression _OF_ string_set ':'
                     { 
                         yyget_extra(yyscanner)->inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                         yyget_extra(yyscanner)->inside_for--; 
                           
                         $$ = reduce_term(yyscanner, TERM_TYPE_FOR, $2, $4, $8); 
                           
                         if ($$ == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
                   | _FOR_ _ALL_ _OF_ string_set ':'
                     { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                          yyget_extra(yyscanner)->inside_for--; 
                          
                          $$ = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, count_strings($4)), $4, $8); 
                          
                          if ($$ == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
                   | _FOR_ _ANY_ _OF_ string_set ':'
                     { 
                          yyget_extra(yyscanner)->inside_for++; 
                     }           
                     '(' boolean_expression ')'                     
                     { 
                          yyget_extra(yyscanner)->inside_for--; 
                                                    
                          $$ = reduce_term(yyscanner, TERM_TYPE_FOR, reduce_constant(yyscanner, 1), $4, $8); 
                          
                          if ($$ == NULL)
                          {
                              yyerror(yyscanner, NULL);
                              YYERROR;
                          }
                     }
                   | expression _OF_ string_set                         
                     { 
                         $$ = reduce_term(yyscanner, TERM_TYPE_OF, $1, $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
                   | _ALL_ _OF_ string_set                              
                     { 
                         $$ = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, count_strings($3)), $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
                   | _ANY_ _OF_ string_set                              
                     { 
                         $$ = reduce_term(yyscanner, TERM_TYPE_OF, reduce_constant(yyscanner, 1), $3, NULL); 
                         
                         if ($$ == NULL)
                         {
                             yyerror(yyscanner, NULL);
                             YYERROR;
                         }
                     }
                   | _FILE_ _IS_ type                                   { $$ = NULL; }
                   | '(' boolean_expression ')'                         { $$ = $2; }
                   | _NOT_ boolean_expression                           { $$ = reduce_term(yyscanner, TERM_TYPE_NOT, $2, NULL, NULL); }
                   | boolean_expression _AND_ boolean_expression        { $$ = reduce_term(yyscanner, TERM_TYPE_AND, $1, $3, NULL); }
                   | boolean_expression _OR_ boolean_expression         { $$ = reduce_term(yyscanner, TERM_TYPE_OR, $1, $3, NULL); }
                   | boolean_expression _IS_ boolean_expression         { $$ = reduce_term(yyscanner, TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _LT_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_LT, $1, $3, NULL); }
                   | expression _GT_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_GT, $1, $3, NULL); }
                   | expression _LE_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_LE, $1, $3, NULL); }
                   | expression _GE_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_GE, $1, $3, NULL); }
                   | expression _EQ_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _IS_ expression                         { $$ = reduce_term(yyscanner, TERM_TYPE_EQ, $1, $3, NULL); }
                   | expression _NEQ_ expression                        { $$ = reduce_term(yyscanner, TERM_TYPE_NOT_EQ, $1, $3, NULL); }
                   ;    
                  

string_set  : '(' string_enumeration ')'            { $$ = $2; }
            | _THEM_                                { $$ = reduce_string_with_wildcard(yyscanner, yr_strdup("$*")); }
            ;                           
                            
string_enumeration  : string_enumeration_item
                    | string_enumeration ',' string_enumeration_item
                      {
                         $$ = reduce_string_enumeration(yyscanner, $1,$3);
                      }
                    ;
                    
string_enumeration_item : _STRING_IDENTIFIER_
                          {  
                              $$ = reduce_string(yyscanner, $1);

                              if ($$ == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
                        | _STRING_IDENTIFIER_WITH_WILDCARD_     
                          { 
                              $$ = reduce_string_with_wildcard(yyscanner, $1); 
                              
                              if ($$ == NULL)
                              {
                                  yyerror(yyscanner, NULL);
                                  YYERROR;
                              }
                          }
                        ;

                            
expression : _SIZE_                             { $$ = reduce_filesize(yyscanner); }
           | _ENTRYPOINT_                       { $$ = reduce_entrypoint(yyscanner); }
           | _INT8_  '(' expression ')'         { $$ = reduce_term(yyscanner, TERM_TYPE_INT8_AT_OFFSET, $3, NULL, NULL); }
           | _INT16_ '(' expression ')'         { $$ = reduce_term(yyscanner, TERM_TYPE_INT16_AT_OFFSET, $3, NULL, NULL); }
           | _INT32_ '(' expression ')'         { $$ = reduce_term(yyscanner, TERM_TYPE_INT32_AT_OFFSET, $3, NULL, NULL); }
           | _UINT8_  '(' expression ')'        { $$ = reduce_term(yyscanner, TERM_TYPE_UINT8_AT_OFFSET, $3, NULL, NULL); }
           | _UINT16_ '(' expression ')'        { $$ = reduce_term(yyscanner, TERM_TYPE_UINT16_AT_OFFSET, $3, NULL, NULL); }
           | _UINT32_ '(' expression ')'        { $$ = reduce_term(yyscanner, TERM_TYPE_UINT32_AT_OFFSET, $3, NULL, NULL); }
           | _STRING_COUNT_                         
             { 
                $$ = reduce_string_count(yyscanner, $1); 
                
                if ($$ == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
           | _STRING_OFFSET_                         
             { 
                $$ = reduce_string_offset(yyscanner, $1); 

                if ($$ == NULL)
                {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                }
             }
           | _IDENTIFIER_
             {
                 $$ = reduce_identifier(yyscanner, $1);
                    
                 if ($$ == NULL)
                 {
                    yyerror(yyscanner, NULL);
                    YYERROR;
                 }
             }
           | '(' expression ')'                 { $$ = $2; }
           | expression '+' expression          { $$ = reduce_term(yyscanner, TERM_TYPE_ADD, $1, $3, NULL); }
           | expression '-' expression          { $$ = reduce_term(yyscanner, TERM_TYPE_SUB, $1, $3, NULL); }
           | expression '*' expression          { $$ = reduce_term(yyscanner, TERM_TYPE_MUL, $1, $3, NULL); }
           | expression '\\' expression         { $$ = reduce_term(yyscanner, TERM_TYPE_DIV, $1, $3, NULL); }
           | number
           ;
        
number   :  _NUMBER_                            { $$ = reduce_constant(yyscanner, $1); }
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

int reduce_rule_declaration(    yyscan_t yyscanner,
                                char* identifier, 
                                int flags, 
                                TAG* tag_list_head,
                                META* meta_list_head,
                                STRING* string_list_head, 
                                TERM* condition
                            )
{
    STRING*         string;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);

    context->last_result = new_rule(&context->rule_list, 
                                    identifier, 
                                    context->current_namespace, 
                                    flags, 
                                    tag_list_head, 
                                    meta_list_head, 
                                    string_list_head, 
                                    condition);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        string = string_list_head;
        
        while (string != NULL)
        {
            if (! (string->flags & STRING_FLAGS_REFERENCED))
            {
                context->last_result = ERROR_UNREFERENCED_STRING;
                strncpy(context->last_error_extra_info, string->identifier, sizeof(context->last_error_extra_info));
                break;
            }
            
            string = string->next;
        }
    }
    
    return context->last_result;
}

STRING* reduce_string_declaration(  yyscan_t yyscanner,
                                    char* identifier, 
                                    SIZED_STRING* str, 
                                    int flags)
{
    char            tmp[200];
    STRING*         string = NULL;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);
    
    if (strcmp(identifier,"$") == 0)
    {
        flags |= STRING_FLAGS_ANONYMOUS;
    }
    
    context->last_result = new_string(context, identifier, str, flags, &string);
    
    if (context->last_result == ERROR_INVALID_REGULAR_EXPRESSION) 
    {
        sprintf(tmp, "invalid regular expression in string \"%s\": %s", identifier, context->last_error_extra_info);
        strncpy(context->last_error_extra_info, tmp, sizeof(context->last_error_extra_info));
    }
    else if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(str);

    if (context->fast_match)
    {
        string->flags |= STRING_FLAGS_FAST_MATCH;
    }
            
    return string;
}

STRING* reduce_strings( yyscan_t yyscanner,
                        STRING* string_list_head, 
                        STRING* string)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    /* no strings with the same identifier, except for anonymous strings */
    
    if (IS_ANONYMOUS(string) || lookup_string(string_list_head,string->identifier) == NULL) 
    {
        string->next = string_list_head;    
        context->current_rule_strings = string;
        context->last_result = ERROR_SUCCESS;
        return string;
    }
    else
    {
        strncpy(context->last_error_extra_info, string->identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_STRING_IDENTIFIER;
        return NULL;
    }   
}

META* reduce_meta_declaration(  yyscan_t yyscanner,
                                int type,
                                char* identifier,
                                unsigned int integer_value,
                                SIZED_STRING* string_value)
{
    META*           meta = NULL;
    YARA_CONTEXT*   context = yyget_extra(yyscanner);
    
    meta = yr_malloc(sizeof(META));
    
    if (meta != NULL)
    {
        meta->identifier = identifier;
        meta->type = type;
        
        if (type == META_TYPE_INTEGER)
        {
            meta->integer = integer_value;
        }
        else if (type == META_TYPE_BOOLEAN)
        {
            meta->boolean = integer_value;
        }
        else
        {
            meta->string = yr_strdup(string_value->c_string);
            yr_free(string_value);
        }    
    }
    else
    {
        context->last_result = ERROR_INSUFICIENT_MEMORY;
    }
    
    return meta;  
}

META* reduce_metas( yyscan_t yyscanner,
                    META* meta_list_head, 
                    META* meta)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    /* no metas with the same identifier */

    if (lookup_meta(meta_list_head, meta->identifier) == NULL) 
    {
        meta->next = meta_list_head;    
        context->last_result = ERROR_SUCCESS;
        return meta;
    }
    else
    {
        strncpy(context->last_error_extra_info, meta->identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_META_IDENTIFIER;
        return NULL;
    }   
}

TAG* reduce_tags(   yyscan_t yyscanner, 
                    TAG* tag_list_head,
                    char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TAG* tag;

    if (lookup_tag(tag_list_head, identifier) == NULL) /* no tags with the same identifier */
    {
        tag = yr_malloc(sizeof(TAG));
        
        if (tag != NULL)
        {
            tag->identifier = identifier;
            tag->next = tag_list_head;  
            context->last_result = ERROR_SUCCESS;
        }
        else
        {
            context->last_result = ERROR_INSUFICIENT_MEMORY;
        }
        
        return tag;
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
        return NULL;
    }
}

TERM* reduce_filesize(yyscan_t yyscanner)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    context->last_result = new_simple_term(TERM_TYPE_FILESIZE, &term); 
    return (TERM*) term;    
}

TERM* reduce_entrypoint(yyscan_t yyscanner)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    context->last_result = new_simple_term(TERM_TYPE_ENTRYPOINT, &term); 
    return (TERM*) term;    
}

TERM* reduce_term(yyscan_t yyscanner, int type, TERM* op1, TERM* op2, TERM* op3)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    
    if (op2 == NULL && op3 == NULL)
    {
        context->last_result = new_unary_operation(type, op1, (TERM_UNARY_OPERATION**) &term);
    }
    else if (op3 == NULL)
    {
        context->last_result = new_binary_operation(type, op1, op2, (TERM_BINARY_OPERATION**) &term);
    }
    else
    {
        context->last_result = new_ternary_operation(type, op1, op2, op3, (TERM_TERNARY_OPERATION**) &term);
    }
    
    return (TERM*) term;
}

TERM* reduce_constant(  yyscan_t yyscanner,
                        size_t constant)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_CONST* term = NULL;
    
    context->last_result = new_constant(constant, &term); 
    return (TERM*) term;
}

TERM* reduce_string(    yyscan_t yyscanner,
                        char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || context->inside_for > 0) 
    {  
        context->last_result = new_string_identifier(TERM_TYPE_STRING, context->current_rule_strings, identifier, &term);       
     
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
    }
    else
    {
        context->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_with_wildcard(  yyscan_t yyscanner,
                                    char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    TERM_STRING* next;
    STRING* string;
    
    int len = 0;

    string = context->current_rule_strings;
    next = NULL;
    
    while (identifier[len] != '\0' && identifier[len] != '*')
    {
        len++;
    }
    
    while (string != NULL)
    {
        if (strncmp(string->identifier, identifier, len) == 0)
        {
            context->last_result = new_string_identifier(TERM_TYPE_STRING, context->current_rule_strings, string->identifier, &term);
            
            if (context->last_result != ERROR_SUCCESS)
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

TERM* reduce_string_at( yyscan_t yyscanner, 
                        char* identifier, 
                        TERM* offset)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    if (strcmp(identifier, "$") != 0 || context->inside_for > 0) 
    {  
        context->last_result = new_string_identifier(TERM_TYPE_STRING_AT, context->current_rule_strings, identifier, &term);       
     
        if (context->last_result != ERROR_SUCCESS)
        {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        }
        else
        {
            term->offset = offset;
        }  
    }
    else
    {
        context->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_range(   yyscan_t yyscanner,    
                                char* identifier, 
                                TERM* lower_offset, 
                                TERM* upper_offset)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_RANGE, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        term->lower_offset = lower_offset;
        term->upper_offset = upper_offset;
    }
    
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_in_section_by_name( yyscan_t yyscanner,
                                        char* identifier, SIZED_STRING* section_name)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;
    
    context->last_result = new_string_identifier(TERM_TYPE_STRING_IN_SECTION_BY_NAME, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    else
    {
        term->section_name = yr_strdup(section_name->c_string);
    }
    
    yr_free(section_name);
    yr_free(identifier);   
    return (TERM*) term;
}

TERM* reduce_string_count(  yyscan_t yyscanner,
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;

    context->last_result = new_string_identifier(TERM_TYPE_STRING_COUNT, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_string_offset( yyscan_t yyscanner,
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = NULL;

    context->last_result = new_string_identifier(TERM_TYPE_STRING_OFFSET, context->current_rule_strings, identifier, &term);
    
    if (context->last_result != ERROR_SUCCESS)
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
    }
    
    yr_free(identifier);           
    return (TERM*) term;
}

TERM* reduce_identifier(    yyscan_t yyscanner, 
                            char* identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM* term = NULL;
    RULE* rule;
      
    rule = lookup_rule(&context->rule_list, identifier, context->current_namespace);
        
    if (rule != NULL)
    {
        context->last_result = new_binary_operation(TERM_TYPE_RULE, rule->condition, NULL, (TERM_BINARY_OPERATION**) &term);        
    }
    else
    {
        context->last_result = new_external_variable(context, identifier, (TERM_EXTERNAL_VARIABLE**) &term);
    }
    
    yr_free(identifier);
    return (TERM*) term;
}

TERM* reduce_string_enumeration(    yyscan_t yyscanner,
                                    TERM* string_list_head, 
                                    TERM* string_identifier)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    TERM_STRING* term = (TERM_STRING*) string_identifier;
    
    term->next = (TERM_STRING*) string_list_head;
    term->string->flags |= STRING_FLAGS_REFERENCED;

    return string_identifier;
}

TERM* reduce_external_string_operation( yyscan_t yyscanner,
                                        int type,
                                        char* identifier,
                                        SIZED_STRING* string)
{
    YARA_CONTEXT* context = yyget_extra(yyscanner);
    
    const char *error;
    int erroffset;
    
    EXTERNAL_VARIABLE* ext_var;  
    TERM_EXTERNAL_STRING_OPERATION* term = NULL;
    
    ext_var = lookup_external_variable(context->external_variables, identifier);
    
    if (ext_var != NULL)
    {
        if (ext_var->type == EXTERNAL_VARIABLE_TYPE_STRING)
        {    
            term = (TERM_EXTERNAL_STRING_OPERATION*) yr_malloc(sizeof(TERM_EXTERNAL_STRING_OPERATION));
            
            if (term != NULL)
            {
                term->type = type;
                term->ext_var = ext_var;
                
                if (type == TERM_TYPE_EXTERNAL_STRING_MATCH)
                {
                    term->re.regexp = pcre_compile(string->c_string, 0, &error, &erroffset, NULL); 
                    
                    if (term->re.regexp != NULL)  
                    {
                        term->re.extra = pcre_study(term->re.regexp, 0, &error);
                        context->last_result = ERROR_SUCCESS;
                    }
                    else /* compilation failed */
                    {
                        yr_free(term);
                        term = NULL;
                        strncpy(context->last_error_extra_info, error, sizeof(context->last_error_extra_info));
                        context->last_result = ERROR_INVALID_REGULAR_EXPRESSION;
                    }
                }
                else
                {
                    term->string = yr_strdup(string->c_string);
                }
                                
                yr_free(string);             
            }
            else
            {
                context->last_result = ERROR_INSUFICIENT_MEMORY;
            }
         }
         else
         {
            strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
            context->last_result = ERROR_INCORRECT_EXTERNAL_VARIABLE_TYPE;
         }
    }
    else
    {
        strncpy(context->last_error_extra_info, identifier, sizeof(context->last_error_extra_info));
        context->last_result = ERROR_UNDEFINED_IDENTIFIER;
    }
    
    return (TERM*) term;

}

  







    
    
    