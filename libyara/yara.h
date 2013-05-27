/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#ifndef _YARA_H
#define _YARA_H

#include <stdio.h>
#include <stdint.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

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
#define ERROR_INCLUDE_DEPTH_EXCEEDED            32
#define ERROR_INVALID_OR_CORRUPT_FILE           33
#define ERROR_STACK_OVERFLOW                    34

#define MAX_INCLUDE_DEPTH 16
#define LEX_BUF_SIZE  1024

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

/*
    Mask examples:

    string : B1 (  01 02 |  03 04 )  3? ?? 45
    mask:    FF AA FF FF AA FF FF BB F0 00 FF

    string : C5 45 [3]   00 45|
    mask:    FF FF CC 03 FF FF

    string : C5 45 [2-5]    00 45
    mask:    FF FF DD 02 03 FF FF

*/

#define MASK_OR            0xAA
#define MASK_OR_END        0xBB
#define MASK_EXACT_SKIP    0xCC
#define MASK_RANGE_SKIP    0xDD
#define MASK_END           0xEE

#define MASK_MAX_SKIP      255

#define META_TYPE_NULL                  0
#define META_TYPE_INTEGER               1
#define META_TYPE_STRING                2
#define META_TYPE_BOOLEAN               3

#define META_IS_NULL(x) \
    ((x) != NULL ? (x)->type == META_TYPE_NULL : TRUE)

#define EXTERNAL_VARIABLE_TYPE_NULL     0
#define EXTERNAL_VARIABLE_TYPE_ANY      1
#define EXTERNAL_VARIABLE_TYPE_INTEGER  2
#define EXTERNAL_VARIABLE_TYPE_STRING   3
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN  4

#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)

#define CALLBACK_CONTINUE  0
#define CALLBACK_ABORT     1
#define CALLBACK_ERROR     2

#define STRING_FLAGS_FOUND        0x01
#define STRING_FLAGS_REFERENCED   0x02
#define STRING_FLAGS_HEXADECIMAL  0x04
#define STRING_FLAGS_NO_CASE      0x08
#define STRING_FLAGS_ASCII        0x10
#define STRING_FLAGS_WIDE         0x20
#define STRING_FLAGS_REGEXP       0x40
#define STRING_FLAGS_FULL_WORD    0x80
#define STRING_FLAGS_ANONYMOUS    0x100
#define STRING_FLAGS_FAST_MATCH   0x200
#define STRING_FLAGS_NULL         0x1000

#define STRING_IS_HEX(x) \
    (((x)->flags) & STRING_FLAGS_HEXADECIMAL)
#define STRING_IS_NO_CASE(x) \
    (((x)->flags) & STRING_FLAGS_NO_CASE)
#define STRING_IS_ASCII(x) \
    (((x)->flags) & STRING_FLAGS_ASCII)
#define STRING_IS_WIDE(x) \
    (((x)->flags) & STRING_FLAGS_WIDE)
#define STRING_IS_REGEXP(x) \
    (((x)->flags) & STRING_FLAGS_REGEXP)
#define STRING_IS_FULL_WORD(x) \
    (((x)->flags) & STRING_FLAGS_FULL_WORD)
#define STRING_IS_ANONYMOUS(x) \
    (((x)->flags) & STRING_FLAGS_ANONYMOUS)
#define STRING_IS_REFERENCED(x) \
    (((x)->flags) & STRING_FLAGS_REFERENCED)
#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->flags) & STRING_FLAGS_NULL)

#define RULE_FLAGS_MATCH                0x01
#define RULE_FLAGS_PRIVATE              0x02
#define RULE_FLAGS_GLOBAL               0x04
#define RULE_FLAGS_REQUIRE_EXECUTABLE   0x08
#define RULE_FLAGS_REQUIRE_FILE         0x10
#define RULE_FLAGS_NULL                 0x1000

#define RULE_IS_NULL(x) \
    (((x)->flags) & RULE_FLAGS_NULL)


#define NAMESPACE_FLAGS_UNSATISFIED_GLOBAL      0x01

#define MAX_ARENA_PAGES 32

#define EOL ((size_t) -1)

#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }


#define UINT64_TO_PTR(type, x)  ((type)(size_t) x)

#define PTR_TO_UINT64(x)  ((uint64_t) (size_t) x)


typedef struct _RELOC
{
  int32_t offset;
  struct _RELOC* next;

} RELOC;


typedef struct _ARENA_PAGE
{

  void* new_address;
  void* address;

  int32_t size;
  int32_t used;

  RELOC* reloc_list_head;
  RELOC* reloc_list_tail;

  struct _ARENA_PAGE* next;

} ARENA_PAGE;


typedef struct _ARENA
{
  int8_t      is_coalesced;
  ARENA_PAGE* page_list_head;
  ARENA_PAGE* current_page;

} ARENA;


#pragma pack(push)
#pragma pack(1)


typedef struct _REGEXP
{
  DECLARE_REFERENCE(void*, regexp);
  DECLARE_REFERENCE(void*, extra);

} REGEXP;


typedef struct _MATCH
{
  size_t          first_offset;
  size_t          last_offset;
  uint8_t*        data;
  uint32_t        length;
  struct _MATCH*  next;

} MATCH;


typedef struct _NAMESPACE
{
  int32_t flags;
  DECLARE_REFERENCE(char*, name);

} NAMESPACE;


typedef struct _META
{
  int32_t   type;
  int32_t   integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} META;


typedef struct _STRING
{
  int32_t flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(uint8_t*, string);
  DECLARE_REFERENCE(uint8_t*, mask);
  DECLARE_REFERENCE(MATCH*, matches_list_head);
  DECLARE_REFERENCE(MATCH*, matches_list_tail);

  REGEXP re;

} STRING;


typedef struct _RULE
{
  int32_t flags;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, tags);
  DECLARE_REFERENCE(META*, metas);
  DECLARE_REFERENCE(STRING*, strings);
  DECLARE_REFERENCE(NAMESPACE*, namespace);

} RULE;


typedef struct _EXTERNAL_VARIABLE
{
  int32_t type;
  int64_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} EXTERNAL_VARIABLE;


typedef struct _AC_MATCH
{
  int8_t backtrack;

  DECLARE_REFERENCE(STRING*, string);
  DECLARE_REFERENCE(struct _AC_MATCH*, next);

} AC_MATCH;


typedef struct _AC_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(struct _AC_STATE*, failure);
  DECLARE_REFERENCE(AC_MATCH*, matches);
  DECLARE_REFERENCE(struct _AC_STATE*, state) transitions[256];

} AC_STATE;


typedef struct _AC_AUTOMATON
{
  DECLARE_REFERENCE(AC_STATE*, root);

} AC_AUTOMATON;


typedef struct _YARA_RULES_FILE_HEADER
{
  uint32_t version;

  DECLARE_REFERENCE(RULE*, rules_list_head);
  DECLARE_REFERENCE(EXTERNAL_VARIABLE*, externals_list_head);
  DECLARE_REFERENCE(int8_t*, code_start);
  DECLARE_REFERENCE(AC_AUTOMATON*, automaton);

} YARA_RULES_FILE_HEADER;

#pragma pack(pop)


typedef struct _HASH_TABLE_ENTRY
{
  char* key;
  void* value;
  struct _HASH_TABLE_ENTRY* next;

} HASH_TABLE_ENTRY;


typedef struct _HASH_TABLE
{
  int size;
  HASH_TABLE_ENTRY* buckets[0];

} HASH_TABLE;


typedef void (*YARAREPORT)(
    const char* file_name,
    int line_number,
    const char* error_message);


typedef int (*YARACALLBACK)(
    RULE* rule,
    void* data);


typedef struct _YARA_COMPILER
{
  int              last_result;
  YARAREPORT       error_report_function;
  int              errors;
  int              last_error;
  int              last_error_line;

  ARENA*           sz_arena;
  ARENA*           rules_arena;
  ARENA*           strings_arena;
  ARENA*           code_arena;
  ARENA*           automaton_arena;
  ARENA*           compiled_rules_arena;
  ARENA*           externals_arena;
  ARENA*           namespaces_arena;
  ARENA*           metas_arena;

  AC_AUTOMATON*    automaton;

  HASH_TABLE*      rules_table;

  NAMESPACE*       current_namespace;

  STRING*          current_rule_strings;
  int              current_rule_flags;

  int              externals_count;
  int              namespaces_count;

  int8_t*          loop_address;
  char*            loop_identifier;

  int              inside_for;
  int              allow_includes;

  char*            file_name_stack[MAX_INCLUDE_DEPTH];
  int              file_name_stack_ptr;

  FILE*            file_stack[MAX_INCLUDE_DEPTH];
  int              file_stack_ptr;

  char             last_error_extra_info[256];

  char             lex_buf[LEX_BUF_SIZE];
  char*            lex_buf_ptr;
  unsigned short   lex_buf_len;

  char             include_base_dir[MAX_PATH];

} YARA_COMPILER;


typedef struct _MEMORY_BLOCK
{
  unsigned char*          data;
  size_t                  size;
  size_t                  base;
  struct _MEMORY_BLOCK*   next;

} MEMORY_BLOCK;


typedef struct _YARA_RULES {

  ARENA*               arena;
  RULE*                rules_list_head;
  EXTERNAL_VARIABLE*   externals_list_head;
  AC_AUTOMATON*        automaton;
  int8_t*              code_start;
  int                  scanning_process_memory;
  int                  last_error;
  char                 last_error_extra_info[256];

} YARA_RULES;


extern char isregexescapable[256];
extern char isregexhashable[256];
extern char isalphanum[256];
extern char lowercase[256];


void yr_init(void);


void yr_finalize(void);


int yr_compiler_create(
    YARA_COMPILER** compiler);


void yr_compiler_destroy(
    YARA_COMPILER* compiler);


int yr_compiler_add_file(
    YARA_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace);


int yr_compiler_add_string(
    YARA_COMPILER* compiler,
    const char* rules_string,
    const char* namespace);


int yr_compiler_push_file_name(
    YARA_COMPILER* compiler,
    const char* file_name);


void yr_compiler_pop_file_name(
    YARA_COMPILER* compiler);


char* yr_compiler_get_error_message(
    YARA_COMPILER* compiler,
    char* buffer,
    int buffer_size);


char* yr_compiler_get_current_file_name(
    YARA_COMPILER* context);


int yr_compiler_define_integer_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    int64_t value);


int yr_compiler_define_boolean_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    int value);


int yr_compiler_define_string_variable(
    YARA_COMPILER* compiler,
    const char* identifier,
    const char* value);


int yr_compiler_get_rules(
    YARA_COMPILER* compiler,
    YARA_RULES** rules);


int yr_rules_scan_mem(
    YARA_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YARACALLBACK callback,
    void* user_data);


int yr_rules_scan_file(
    YARA_RULES* rules,
    const char* filename,
    YARACALLBACK callback,
    void* user_data);


int yr_rules_save(
    YARA_RULES* rules,
    const char* filename);


int yr_rules_load(
  const char* filename,
  YARA_RULES** rules);


int yr_rules_destroy(
    YARA_RULES* rules);


int yr_rules_define_integer_variable(
    YARA_RULES* rules,
    const char* identifier,
    int64_t value);


int yr_rules_define_boolean_variable(
    YARA_RULES* rules,
    const char* identifier,
    int value);


int yr_rules_define_string_variable(
    YARA_RULES* rules,
    const char* identifier,
    const char* value);


int yr_ac_create_automaton(
    ARENA* arena,
    AC_AUTOMATON** automaton);


int yr_ac_add_string(
    ARENA* arena,
    AC_AUTOMATON* automaton,
    STRING* string);


void yr_ac_create_failure_links(
    ARENA* arena,
    AC_AUTOMATON* automaton);


void yr_ac_print_automaton(
    AC_AUTOMATON* automaton);

#endif

