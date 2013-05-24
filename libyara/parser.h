/*
Copyright (c) 2013. Victor M. Alvarez [plusvic@gmail.com].

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PARSER_H
#define _PARSER_H

#include "arena.h"
#include "compiler.h"
#include "lex.h"
#include "sizedstr.h"


int emit(
    yyscan_t yyscanner,
    int8_t instruction,
    int8_t** instruction_address);


int emit_with_arg(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address);


int emit_with_arg_reloc(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address);


STRING* lookup_string(
  yyscan_t yyscanner,
  const char* identifier);


EXTERNAL_VARIABLE* lookup_external_variable(
  yyscan_t yyscanner,
  const char* identifier);


void push_string_pointers(
    yyscan_t yyscanner,
    const char* identifier);


int reduce_rule_declaration(
    yyscan_t yyscanner,
    int flags,
    const char* identifier,
    char* tags,
    STRING* strings,
    META* metas);


STRING* reduce_string_declaration(
    yyscan_t yyscanner,
    int flags,
    const char* identifier,
    SIZED_STRING* str);


META* reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int32_t integer);


int reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t instruction);


int reduce_external(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t intruction);

#endif