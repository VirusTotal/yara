/* Lexical analyzer for YARA */

%{

#include <math.h>
#include <stdio.h>
#include <string.h>
#include "grammar.h"
#include "xtoi.h"
#include "mem.h"
#include "sizedstr.h"
#include "lex.h"
#include "yara.h"

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option yylineno

%option verbose
%option warn

%x str
%x regexp

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]

%%

"<"                  { return _LT_;	        }
">"                  { return _GT_;	        }
"<="                 { return _LE_;	        }
">="                 { return _GE_;	        }
"=="				 { return _EQ_;		    }
"!="				 { return _NEQ_;	    }
"private"            { return _PRIVATE_;    }
"global"             { return _GLOBAL_;     }
"rule"               { return _RULE_;       }
"strings"            { return _STRINGS_;    }
"ascii"              { return _ASCII_;      }
"wide"               { return _WIDE_;       }
"fullword"           { return _FULLWORD_;   }
"nocase"             { return _NOCASE_;     }
"condition"          { return _CONDITION_;  }
"true"               { return _TRUE_;       }
"false"              { return _FALSE_;      }
"not"                { return _NOT_;        }
"and"                { return _AND_;        }
"or"                 { return _OR_;         }
"at"                 { return _AT_;         }
"in"                 { return _IN_;         }
"of"                 { return _OF_;         }
"them"				 { return _THEM_;		}
"for"				 { return _FOR_;        }
"all"				 { return _ALL_;		}
"any"				 { return _ANY_;		}
"entrypoint"         { return _ENTRYPOINT_; }
"filesize"			 { return _SIZE_;       }
"rva"			     { return _RVA_;   	    }
"offset"			 { return _OFFSET_;     }
"file"				 { return _FILE_;       }
"is"				 { return _IS_;         }
"section"			 { return _SECTION_;    }
"uint8"				 { return _UINT8_;    	}
"uint16"			 { return _UINT16_;    	}
"uint32"		 	 { return _UINT32_;    	}
"int8"				 { return _INT8_;    	}
"int16"				 { return _INT16_;    	}
"int32"		 		 { return _INT32_;    	}



"/*"([^\*]|\*[^\/])*"*/"    {	/* skip comments */ }

"//".*\n					{   /* skip single-line comments */ }
							
$({letter}|{digit}|_)*"*" {
                       		yylval->c_string = (char*) yr_strdup(yytext);
                       		return _STRING_IDENTIFIER_WITH_WILDCARD_;      
					 	}

$({letter}|{digit}|_)* {
                       		yylval->c_string = (char*) yr_strdup(yytext);
                       		return _STRING_IDENTIFIER_;      
					 }
				
					
#({letter}|{digit}|_)* {	
                       		yylval->c_string = (char*) yr_strdup(yytext);
							yylval->c_string[0] = '$'; 					/* replace # by $*/
		                    return _STRING_COUNT_;      
					 }
					
@({letter}|{digit}|_)* {	
	                      	yylval->c_string = (char*) yr_strdup(yytext);
							yylval->c_string[0] = '$'; 					/* replace @ by $*/
		                    return _STRING_OFFSET_;      
					 }					

({letter}|_)({letter}|{digit}|_)*	{ 
										if (strlen(yytext) > 128)
										{
											yyerror(yyscanner, "indentifier too long");
										}
										
										yylval->c_string = (char*) yr_strdup(yytext);
                   						return _IDENTIFIER_;
									}
							
{digit}+(MB|KB){0,1}  { 
						yylval->integer = (unsigned int) atoi(yytext);
						
						if (strstr(yytext, "KB") != NULL)
						{
							yylval->integer *= 1024;
						}
						else if (strstr(yytext, "MB") != NULL)
						{
							yylval->integer *= 1048576;
						}
						
                       	return _NUMBER_;     
					}
					
0x{hexdigit}+		{
						yylval->integer = xtoi(yytext + 2);
						return _NUMBER_;
					}
	
<str>\"        		{ 	/* saw closing quote - all done */

						SIZED_STRING* s;

						if (yyextra->lex_string_buf_len == 0)
						{
							yyerror(yyscanner, "empty string");
						}

						*yyextra->lex_string_buf_ptr = '\0';

						BEGIN(INITIAL);
						
						s = (SIZED_STRING*) yr_malloc(yyextra->lex_string_buf_len + sizeof(SIZED_STRING));
						
						s->length = yyextra->lex_string_buf_len;
						
						strcpy(s->c_string, yyextra->lex_string_buf);
					
						yylval->sized_string = s;
												
						return _TEXTSTRING_;
			  		}

<str>\\t  			{ *yyextra->lex_string_buf_ptr++ = '\t'; yyextra->lex_string_buf_len++; }
<str>\\\"  			{ *yyextra->lex_string_buf_ptr++ = '\"'; yyextra->lex_string_buf_len++; }
<str>\\\\  			{ *yyextra->lex_string_buf_ptr++ = '\\'; yyextra->lex_string_buf_len++; }

<str>\\x{hexdigit}{2}   	{
        						int result;

        						sscanf( yytext + 2, "%x", &result );
                					
        						*yyextra->lex_string_buf_ptr++ = result;
								yyextra->lex_string_buf_len++;
        					}

<str>[^\\\n\"]+      {
						char *yptr = yytext;

						while ( *yptr )
						{
        					*yyextra->lex_string_buf_ptr++ = *yptr++;
							yyextra->lex_string_buf_len++;
						}
					 }

<str>\n  		    {
						yyerror(yyscanner, "unterminated string");
						yyterminate();
					}					

<str>\\(.|\n)  		{
						yyerror(yyscanner, "illegal escape sequence");
					}

					
<regexp>"/"         { 	
						SIZED_STRING* s;

						if (yyextra->lex_string_buf_len == 0)
						{
							yyerror(yyscanner, "empty regular expression");
						}

						*yyextra->lex_string_buf_ptr = '\0';

						BEGIN(INITIAL);

						s = (SIZED_STRING*) yr_malloc(yyextra->lex_string_buf_len + sizeof(SIZED_STRING));

						s->length = yyextra->lex_string_buf_len;

						strcpy(s->c_string, yyextra->lex_string_buf);
					
						yylval->sized_string = s;

						return _REGEXP_;
			  		}
			
<regexp>\\\/		{ 				
						*yyextra->lex_string_buf_ptr++ = '/';
						yyextra->lex_string_buf_len++ ;
					}

<regexp>\\.			{ 				
						*yyextra->lex_string_buf_ptr++ = yytext[0];
						*yyextra->lex_string_buf_ptr++ = yytext[1];
						yyextra->lex_string_buf_len += 2;
					}

<regexp>[^/\n\\]+    {
						char *yptr = yytext;

						while ( *yptr )
						{
        					*yyextra->lex_string_buf_ptr++ = *yptr++;
							yyextra->lex_string_buf_len++;
						}
					 }

<regexp>\n  		{
						yyerror(yyscanner, "unterminated regular expression");
						yyterminate();
					}
					
\"     				{
 						yyextra->lex_string_buf_ptr = yyextra->lex_string_buf; 
						yyextra->lex_string_buf_len = 0;
						BEGIN(str);
					}
			
"/"     			{
 						yyextra->lex_string_buf_ptr = yyextra->lex_string_buf; 
						yyextra->lex_string_buf_len = 0;
						BEGIN(regexp);
					}
					
					
\{({hexdigit}|[ \-|\?\[\]\(\)])+\}	{ 
										int len = strlen(yytext);
										
										SIZED_STRING* s = (SIZED_STRING*) yr_malloc(len + sizeof(SIZED_STRING));

										s->length = len;

										strcpy(s->c_string, yytext);

										yylval->sized_string = s;
									
										return _HEXSTRING_;
									}
					

[ \t\r\n]				/* skip whitespace */


.                  	{ 
                       	return yytext[0];    
					}
%%



void yyerror(yyscan_t yyscanner, const char *error_message)
{    
	YARA_CONTEXT* context = yyget_extra(yyscanner);
	
	char message[512];
	
	/* 
		if error_message != NULL the error comes from yyparse internal code
		else the error comes from my code and the error code is set in context->last_result 
	*/
		
	context->errors++;
	context->last_error_line = yyget_lineno(yyscanner) + 1; // yyget_lineno is zero-based
	
	if (error_message != NULL)
	{
		context->last_error = ERROR_SYNTAX_ERROR;
		strncpy(context->last_error_extra_info, error_message, sizeof(message));
	
    	if (context->error_report_function != NULL)
    	{
        	context->error_report_function(context->file_name, context->last_error_line, error_message);
    	}
	}
	else
	{
		context->last_error = context->last_result;
	
		if (context->error_report_function != NULL)
    	{	
			yr_get_error_message(context, message, sizeof(message));
        	context->error_report_function(context->file_name, context->last_error_line, message);
    	}
	}
	
	context->last_result = ERROR_SUCCESS;
}


int parse_string(const char* string, YARA_CONTEXT* context)
{
	yyscan_t yyscanner;
	YY_BUFFER_STATE state;
			
    yylex_init(&yyscanner);

	yyset_extra(context, yyscanner);

	state = yy_scan_string(string, yyscanner);
	
	yyset_lineno(0, yyscanner);
    yyparse(yyscanner);

	yy_delete_buffer(state, yyscanner);  
	yylex_destroy(yyscanner);
	
	return context->errors;
}


int parse_file(FILE* rules_file, YARA_CONTEXT* context)
{	
	yyscan_t yyscanner;	
	
    yylex_init(&yyscanner);

	#ifdef DEBUG
	yyset_debug(1, yyscanner);
	#endif
	
	yyset_in(rules_file, yyscanner);
	yyset_extra(context, yyscanner);	

    yyparse(yyscanner);

    yylex_destroy(yyscanner);

	return context->errors;
}






