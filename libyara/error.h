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

#ifndef _ERROR_H
#define _ERROR_H

extern int yynerrs;
void yyerror (char const *);

extern int line_number;
extern int last_error;
extern int abort_on_first_error;

extern char last_error_extra_info[100];
extern const char* file_name;

void show_last_error();


#endif

