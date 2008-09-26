/* Lexical analyzer for YARA */

%{

#include <math.h>
#include <stdio.h>
#include <string.h>
#include "grammar.h"
#include "compile.h"
#include "error.h"
#include "xtoi.h"

char string_buf[255];
char *string_buf_ptr;

#ifdef WIN32
#define strdup _strdup
#endif

%}

%option noyywrap

%x str

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
"widechar"           { return _WIDE_;       }
"fullword"           { return _FULLWORD_;   }
"nocase"             { return _NOCASE_;     }
"regexp"             { return _REGEXP_;     }
"condition"          { return _CONDITION_;  }
"true"               { return _TRUE_;       }
"false"              { return _FALSE_;      }
"not"                { return _NOT_;        }
"and"                { return _AND_;        }
"or"                 { return _OR_;         }
"at"                 { return _AT_;         }
"in"                 { return _IN_;         }
"of"                 { return _OF_;         }
"entrypoint"         { return _ENTRYPOINT_; }
"filesize"			 { return _SIZE_;       }
"rva"			     { return _RVA_;   	    }
"offset"			 { return _OFFSET_;     }
"file"				 { return _FILE_;       }
"is"				 { return _IS_;         }
"section"			 { return _SECTION_;    }


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

$({letter}|{digit})* {
                       		yylval.pchar = (char*) strdup(yytext);
                       		return _STRING_IDENTIFIER_;      
					 }
					
#({letter}|{digit})* {	
                       		yylval.pchar = (char*) strdup(yytext);
							yylval.pchar[0] = '$'; 					/* replace # by $*/
		                    return _STRING_COUNT_;      
					 }					

({letter}|_)({letter}|{digit}|_)*	{ 
										if (strlen(yytext) > 128)
										{
											yyerror("indentifier too long");
											yynerrs++;
										}
										
										yylval.pchar = (char*) strdup(yytext);
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
	
	
\"     				{
 						string_buf_ptr = string_buf; 
						BEGIN(str);
					}

<str>\"        		{ 	/* saw closing quote - all done */

						int len;

						BEGIN(INITIAL);
						*string_buf_ptr = '\0';
						
						len = strlen(string_buf);
						
						yylval.pchar = strdup(string_buf);
						
						return _TEXTSTRING_;
			  		}

<str>\\t  			*string_buf_ptr++ = '\t';
<str>\\\"  			*string_buf_ptr++ = '\"';
<str>\\\\  			*string_buf_ptr++ = '\\';

<str>\\x{hexdigit}{2}   	{
        						int result;

        						sscanf( yytext + 2, "%x", &result );

								if (result == 0)
								{
									yyerror("illegal escape sequence");
									yynerrs++;
								}
                					
        						*string_buf_ptr++ = result;
        					}

<str>[^\\\n\"]+      {
						char *yptr = yytext;

						while ( *yptr )
        					*string_buf_ptr++ = *yptr++;
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
					
					
					
\{({hexdigit}|[ \?\[\]-])+\}		{ 
										yylval.pchar = (char*) strdup(yytext);
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


