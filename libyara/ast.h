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

#ifndef _AST_H
#define _AST_H

#include "yara.h"
#include "sizedstr.h"

/* 
    Mask examples:
    
    string : B1 (  01 02 |  03 04 )  3? ?? 45 
    mask:    FF AA FF FF AA FF FF BB F0 00 FF

    string : C5 45 [3]   00 45|
    mask:    FF FF CC 03 FF FF
    
    string : C5 45 [2-5]    00 45
    mask:    FF FF DD 02 03 FF FF
    
*/

#define MASK_OR                                 0xAA
#define MASK_OR_END                             0xBB
#define MASK_EXACT_SKIP                         0xCC
#define MASK_RANGE_SKIP                         0xDD
#define MASK_END                                0xEE
#define MASK_MAX_SKIP                           255

#define TERM_TYPE_CONST                              0           
#define TERM_TYPE_AND                                1           
#define TERM_TYPE_OR                                 2           
#define TERM_TYPE_NOT                                3           
#define TERM_TYPE_ADD                                4           
#define TERM_TYPE_SUB                                5           
#define TERM_TYPE_MUL                                6           
#define TERM_TYPE_DIV                                7           
#define TERM_TYPE_GT                                 8           
#define TERM_TYPE_LT                                 9           
#define TERM_TYPE_GE                                 10          
#define TERM_TYPE_LE                                 11          
#define TERM_TYPE_EQ                                 12  
#define TERM_TYPE_NOT_EQ                             13       
#define TERM_TYPE_RANGE                              14          
#define TERM_TYPE_STRING                             15       
#define TERM_TYPE_STRING_AT                          16          
#define TERM_TYPE_STRING_IN_RANGE                    17 
#define TERM_TYPE_STRING_IN_SECTION_BY_NAME		 	 18     
#define TERM_TYPE_STRING_IN_SECTION_BY_INDEX		 19      
#define TERM_TYPE_STRING_COUNT                       20     
#define TERM_TYPE_STRING_OFFSET                      21      
#define TERM_TYPE_OF                                 22 
#define TERM_TYPE_FOR                                23         
#define TERM_TYPE_FILESIZE              	         24          
#define TERM_TYPE_ENTRYPOINT						 25			
#define TERM_TYPE_RULE                               26
#define TERM_TYPE_INT8_AT_OFFSET                     27
#define TERM_TYPE_INT16_AT_OFFSET                    28
#define TERM_TYPE_INT32_AT_OFFSET                    29
#define TERM_TYPE_UINT8_AT_OFFSET                    30
#define TERM_TYPE_UINT16_AT_OFFSET                   31
#define TERM_TYPE_UINT32_AT_OFFSET                   32
                  


typedef struct _TERM_CONST
{
	int				type;
	int         	value;

} TERM_CONST;


typedef struct _TERM_UNARY_OPERATION
{
	int				type;
    TERM*			op;
	
} TERM_UNARY_OPERATION;


typedef struct _TERM_BINARY_OPERATION
{
	int				type;
	TERM*			op1;
	TERM*			op2;
	
} TERM_BINARY_OPERATION;


typedef struct _TERM_TERNARY_OPERATION
{
	int				type;
	TERM*			op1;
	TERM*			op2;
    TERM*           op3;
	
} TERM_TERNARY_OPERATION;


typedef struct _TERM_STRING
{
	int			        	type;
    struct _TERM_STRING*	next;           /* used to link a set of terms for the OF operator e.g: 2 OF ($A,$B,$C) */
	STRING*		        	string;
	
	union {
		TERM*			offset;
		TERM*			lower_offset;
		char* 			section_name;
		unsigned int	section_index;
	};
	
	TERM*			upper_offset;
	
} TERM_STRING;



int new_rule(RULE_LIST* rules, char* identifier, int flags, TAG* tag_list_head, STRING* string_list_head, TERM* condition);

int new_string(char* identifier, SIZED_STRING* charstr, int flags, STRING** string);

int new_simple_term(int type, TERM** term);

int new_unary_operation(int type, TERM* op1, TERM_UNARY_OPERATION** term);

int new_binary_operation(int type, TERM* op1, TERM* op2, TERM_BINARY_OPERATION** term);

int new_ternary_operation(int type, TERM* op1, TERM* op2, TERM* op3, TERM_TERNARY_OPERATION** term);

int new_constant(unsigned int constant, TERM_CONST** term);

int new_string_identifier(int type, STRING* defined_strings, char* identifier, TERM_STRING** term);



#endif

