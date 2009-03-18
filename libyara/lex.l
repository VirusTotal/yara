/* Lexical analyzer for YARA */

%{

#include <math.h>
#include <stdio.h>
#include <string.h>
#include "grammar.h"
#include "error.h"
#include "xtoi.h"
#include "mem.h"
#include "sizedstr.h"

extern int line_number;

char string_buf[256];
char *string_buf_ptr;
unsigned short string_buf_len;


%}

%option noyywrap

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



"/*"([^\*]|\*[^\/])*"*/"    {	/* skip comments */
								
								char* line_break = strchr( yytext, '\n' );
								
							   	while( line_break != NULL ) 
								{
									line_number++;
							    	line_break = strchr(line_break + 1, '\n');
							   	}
							}

"//".*\n					{   /* skip single-line comments */

								line_number++;
							}
							
$({letter}|{digit}|_)*"*" {
                       		yylval.c_string = (char*) yr_strdup(yytext);
                       		return _STRING_IDENTIFIER_WITH_WILDCARD_;      
					 	}

$({letter}|{digit}|_)* {
                       		yylval.c_string = (char*) yr_strdup(yytext);
                       		return _STRING_IDENTIFIER_;      
					 }
				
					
#({letter}|{digit}|_)* {	
                       		yylval.c_string = (char*) yr_strdup(yytext);
							yylval.c_string[0] = '$'; 					/* replace # by $*/
		                    return _STRING_COUNT_;      
					 }
					
@({letter}|{digit}|_)* {	
	                      	yylval.c_string = (char*) yr_strdup(yytext);
							yylval.c_string[0] = '$'; 					/* replace @ by $*/
		                    return _STRING_OFFSET_;      
					 }					

({letter}|_)({letter}|{digit}|_)*	{ 
										if (strlen(yytext) > 128)
										{
											yyerror("indentifier too long");
											yynerrs++;
										}
										
										yylval.c_string = (char*) yr_strdup(yytext);
                   						return _IDENTIFIER_;
									}
							
{digit}+(MB|KB){0,1}  { 
						yylval.integer = (unsigned int) atoi(yytext);
						
						if (strstr(yytext, "KB") != NULL)
						{
							yylval.integer *= 1024;
						}
						else if (strstr(yytext, "MB") != NULL)
						{
							yylval.integer *= 1048576;
						}
						
                       	return _NUMBER_;     
					}
					
0x{hexdigit}+		{
						yylval.integer = xtoi(yytext + 2);
						return _NUMBER_;
					}
	
<str>\"        		{ 	/* saw closing quote - all done */

						SIZED_STRING* s;

						if (string_buf_len == 0)
						{
							yyerror("empty string");
							yynerrs++;
						}

						*string_buf_ptr = '\0';

						BEGIN(INITIAL);
						
						s = (SIZED_STRING*) yr_malloc(string_buf_len + sizeof(SIZED_STRING));
						
						s->length = string_buf_len;
						
						strcpy(s->c_string, string_buf);
					
						yylval.sized_string = s;
												
						return _TEXTSTRING_;
			  		}

<str>\\t  			{ *string_buf_ptr++ = '\t'; string_buf_len++; }
<str>\\\"  			{ *string_buf_ptr++ = '\"'; string_buf_len++; }
<str>\\\\  			{ *string_buf_ptr++ = '\\'; string_buf_len++; }

<str>\\x{hexdigit}{2}   	{
        						int result;

        						sscanf( yytext + 2, "%x", &result );
                					
        						*string_buf_ptr++ = result;
								string_buf_len++;
        					}

<str>[^\\\n\"]+      {
						char *yptr = yytext;

						while ( *yptr )
						{
        					*string_buf_ptr++ = *yptr++;
							string_buf_len++;
						}
					 }

<str>\n  		    {
						yyerror("unterminated string");
						yyterminate();
						yynerrs++;
					}					

<str>\\(.|\n)  		{
						yyerror("illegal escape sequence");
						yynerrs++;
					}

					
<regexp>"/"         { 	
						SIZED_STRING* s;

						if (string_buf_len == 0)
						{
							yyerror("empty regular expression");
							yynerrs++;
						}

						*string_buf_ptr = '\0';

						BEGIN(INITIAL);

						s = (SIZED_STRING*) yr_malloc(string_buf_len + sizeof(SIZED_STRING));

						s->length = string_buf_len;

						strcpy(s->c_string, string_buf);
					
						yylval.sized_string = s;

						return _REGEXP_;
			  		}
			
<regexp>\\\/		{ 				
						*string_buf_ptr++ = '/';
						string_buf_len++ ;
					}

<regexp>\\.			{ 				
						*string_buf_ptr++ = yytext[0];
						*string_buf_ptr++ = yytext[1];
						string_buf_len += 2;
					}

<regexp>[^/\n\\]+    {
						char *yptr = yytext;

						while ( *yptr )
						{
        					*string_buf_ptr++ = *yptr++;
							string_buf_len++;
						}
					 }

<regexp>\n  		{
						yyerror("unterminated regular expression");
						yyterminate();
						yynerrs++;
					}
					
\"     				{
 						string_buf_ptr = string_buf; 
						string_buf_len = 0;
						BEGIN(str);
					}
			
"/"     			{
 						string_buf_ptr = string_buf; 
						string_buf_len = 0;
						BEGIN(regexp);
					}
					
					
\{({hexdigit}|[ \-|\?\[\]\(\)])+\}		{ 
										int len = strlen(yytext);
										
										SIZED_STRING* s = (SIZED_STRING*) yr_malloc(len + sizeof(SIZED_STRING));

										s->length = len;

										strcpy(s->c_string, yytext);

										yylval.sized_string = s;
									
										return _HEXSTRING_;
									}
					

[ \t\r]				/* skip whitespace */

[\n]           		{
						line_number++;
						
					}

.                  	{ 
                       	return yytext[0];    
					}
%%




