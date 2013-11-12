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

#ifdef WIN32
#include <windows.h>
typedef HANDLE mutex_t;
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#define FAIL_ON_ERROR(x) { \
  int result = (x); \
  if (result != ERROR_SUCCESS) \
    return result; \
}

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS                           0
#endif

#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_DUPLICATE_RULE_IDENTIFIER         2
#define ERROR_INVALID_HEX_STRING                3
#define ERROR_UNDEFINED_STRING                  4
#define ERROR_UNDEFINED_IDENTIFIER              5
#define ERROR_COULD_NOT_OPEN_FILE               6
#define ERROR_INVALID_REGULAR_EXPRESSION        7
#define ERROR_SYNTAX_ERROR                      8
#define ERROR_DUPLICATE_TAG_IDENTIFIER          9
#define ERROR_UNREFERENCED_STRING               10
#define ERROR_DUPLICATE_STRING_IDENTIFIER       11
#define ERROR_CALLBACK_ERROR                    12
#define ERROR_MISPLACED_OR_OPERATOR             13
#define ERROR_INVALID_OR_OPERATION_SYNTAX       14
#define ERROR_SKIP_INSIDE_OR_OPERATION          15
#define ERROR_NESTED_OR_OPERATION               16
#define ERROR_MISPLACED_ANONYMOUS_STRING        17
#define ERROR_COULD_NOT_MAP_FILE                18
#define ERROR_ZERO_LENGTH_FILE                  19
#define ERROR_INVALID_ARGUMENT                  20
#define ERROR_DUPLICATE_META_IDENTIFIER         21
#define ERROR_INCLUDES_CIRCULAR_REFERENCE       22
#define ERROR_INCORRECT_VARIABLE_TYPE           23
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS       24
#define ERROR_VECTOR_TOO_LONG                   25
#define ERROR_INCLUDE_DEPTH_EXCEEDED            26
#define ERROR_INVALID_FILE                      27
#define ERROR_CORRUPT_FILE                      28
#define ERROR_UNSUPPORTED_FILE_VERSION          29
#define ERROR_EXEC_STACK_OVERFLOW               30
#define ERROR_SCAN_TIMEOUT                      31
#define ERROR_LOOP_NESTING_LIMIT_EXCEEDED       32
#define ERROR_DUPLICATE_LOOP_IDENTIFIER         33
#define ERROR_TOO_MANY_SCAN_THREADS             34


#define CALLBACK_MSG_RULE_MATCHING            1
#define CALLBACK_MSG_RULE_NOT_MATCHING        2
#define CALLBACK_MSG_SCAN_FINISHED            3

#define CALLBACK_CONTINUE  0
#define CALLBACK_ABORT     1
#define CALLBACK_ERROR     2


#define MAX_ATOM_LENGTH 4
#define LOOP_LOCAL_VARS 4
#define MAX_LOOP_NESTING 4
#define MAX_INCLUDE_DEPTH 16
#define MAX_THREADS 32
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

#define EXTERNAL_VARIABLE_TYPE_NULL          0
#define EXTERNAL_VARIABLE_TYPE_ANY           1
#define EXTERNAL_VARIABLE_TYPE_INTEGER       2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN       3
#define EXTERNAL_VARIABLE_TYPE_FIXED_STRING  4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING 5

#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)


#define STRING_TFLAGS_FOUND          0x01

#define STRING_GFLAGS_REFERENCED     0x01
#define STRING_GFLAGS_HEXADECIMAL    0x02
#define STRING_GFLAGS_NO_CASE        0x04
#define STRING_GFLAGS_ASCII          0x08
#define STRING_GFLAGS_WIDE           0x10
#define STRING_GFLAGS_REGEXP         0x20
#define STRING_GFLAGS_FULL_WORD      0x40
#define STRING_GFLAGS_ANONYMOUS      0x80
#define STRING_GFLAGS_SINGLE_MATCH   0x100
#define STRING_GFLAGS_LITERAL        0x200
#define STRING_GFLAGS_START_ANCHORED 0x400
#define STRING_GFLAGS_END_ANCHORED   0x800
#define STRING_GFLAGS_FITS_IN_ATOM   0x1000
#define STRING_GFLAGS_NULL           0x2000

#define STRING_IS_HEX(x) \
    (((x)->g_flags) & STRING_GFLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) \
    (((x)->g_flags) & STRING_GFLAGS_NO_CASE)

#define STRING_IS_ASCII(x) \
    (((x)->g_flags) & STRING_GFLAGS_ASCII)

#define STRING_IS_WIDE(x) \
    (((x)->g_flags) & STRING_GFLAGS_WIDE)

#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP)

#define STRING_IS_FULL_WORD(x) \
    (((x)->g_flags) & STRING_GFLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_GFLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) \
    (((x)->g_flags) & STRING_GFLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->g_flags) & STRING_GFLAGS_SINGLE_MATCH)

#define STRING_IS_LITERAL(x) \
    (((x)->g_flags) & STRING_GFLAGS_LITERAL)

#define STRING_IS_START_ANCHORED(x) \
    (((x)->g_flags) & STRING_GFLAGS_START_ANCHORED)

#define STRING_IS_END_ANCHORED(x) \
    (((x)->g_flags) & STRING_GFLAGS_END_ANCHORED)

#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)

#define STRING_FOUND(x) \
    ((x)->matches[yr_get_tidx()].tail != NULL)


#define RULE_TFLAGS_MATCH                0x01

#define RULE_GFLAGS_PRIVATE              0x01
#define RULE_GFLAGS_GLOBAL               0x02
#define RULE_GFLAGS_REQUIRE_EXECUTABLE   0x04
#define RULE_GFLAGS_REQUIRE_FILE         0x08
#define RULE_GFLAGS_NULL                 0x1000

#define RULE_IS_PRIVATE(x) \
    (((x)->g_flags) & RULE_GFLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) \
    (((x)->g_flags) & RULE_GFLAGS_GLOBAL)

#define RULE_IS_NULL(x) \
    (((x)->g_flags) & RULE_GFLAGS_NULL)

#define RULE_MATCHES(x) \
    ((x)->t_flags[yr_get_tidx()] & RULE_TFLAGS_MATCH)



#define NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL      0x01

#define NAMESPACE_HAS_UNSATISFIED_GLOBAL(x) \
    ((x)->t_flags[yr_get_tidx()] & NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL)



#define MAX_ARENA_PAGES 32

#define EOL ((size_t) -1)

#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }


#define UINT64_TO_PTR(type, x)  ((type)(size_t) x)

#define PTR_TO_UINT64(x)  ((uint64_t) (size_t) x)

#define STRING_MATCHES(x) (x->matches[yr_get_tidx()])


typedef struct _RELOC
{
  int32_t offset;
  struct _RELOC* next;

} RELOC;


typedef struct _ARENA_PAGE
{

  uint8_t* new_address;
  uint8_t* address;

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


typedef struct _MATCH
{
  size_t          first_offset;
  size_t          last_offset;
  uint8_t*        data;
  uint32_t        length;

  struct _MATCH*  prev;
  struct _MATCH*  next;

} MATCH;


typedef struct _NAMESPACE
{
  int32_t t_flags[MAX_THREADS];     // Thread-specific flags
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
  int32_t g_flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(uint8_t*, string);

  struct {
    DECLARE_REFERENCE(MATCH*, head);
    DECLARE_REFERENCE(MATCH*, tail);
  } matches[MAX_THREADS];

} STRING;


typedef struct _RULE
{
  int32_t g_flags;               // Global flags
  int32_t t_flags[MAX_THREADS];  // Thread-specific flags

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, tags);
  DECLARE_REFERENCE(META*, metas);
  DECLARE_REFERENCE(STRING*, strings);
  DECLARE_REFERENCE(NAMESPACE*, ns);

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
  uint16_t backtrack;

  DECLARE_REFERENCE(STRING*, string);
  DECLARE_REFERENCE(uint8_t*, forward_code);
  DECLARE_REFERENCE(uint8_t*, backward_code);
  DECLARE_REFERENCE(struct _AC_MATCH*, next);

} AC_MATCH;


typedef struct _AC_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(struct _AC_STATE*, failure);
  DECLARE_REFERENCE(AC_MATCH*, matches);

} AC_STATE;


typedef struct _AC_STATE_TRANSITION
{
  uint8_t input;
  DECLARE_REFERENCE(AC_STATE*, state);
  DECLARE_REFERENCE(struct _AC_STATE_TRANSITION*, next);

} AC_STATE_TRANSITION;


typedef struct _AC_TABLE_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(AC_STATE*, failure);
  DECLARE_REFERENCE(AC_MATCH*, matches);
  DECLARE_REFERENCE(AC_STATE*, state) transitions[256];

} AC_TABLE_BASED_STATE;


typedef struct _AC_LIST_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(AC_STATE*, failure);
  DECLARE_REFERENCE(AC_MATCH*, matches);
  DECLARE_REFERENCE(AC_STATE_TRANSITION*, transitions);

} AC_LIST_BASED_STATE;


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
  char* ns;
  void* value;
  struct _HASH_TABLE_ENTRY* next;

} HASH_TABLE_ENTRY;


typedef struct _HASH_TABLE
{
  int size;
  HASH_TABLE_ENTRY* buckets[0];

} HASH_TABLE;


#define YARA_ERROR_LEVEL_ERROR   0
#define YARA_ERROR_LEVEL_WARNING 1

typedef void (*YARAREPORT)(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message);


typedef int (*YARACALLBACK)(
    int message,
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
  ARENA*           re_code_arena;
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

  int8_t*          loop_address[MAX_LOOP_NESTING];
  char*            loop_identifier[MAX_LOOP_NESTING];
  int              loop_depth;
  
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

  int                  threads_count;
  ARENA*               arena;
  RULE*                rules_list_head;
  EXTERNAL_VARIABLE*   externals_list_head;
  AC_AUTOMATON*        automaton;
  int8_t*              code_start;
  mutex_t              mutex;

} YARA_RULES;


extern char lowercase[256];


void yr_initialize(void);


void yr_finalize(void);


int yr_get_tidx(void);


void yr_set_tidx(int);


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
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_file(
    YARA_RULES* rules,
    const char* filename,
    YARACALLBACK callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_proc(
    YARA_RULES* rules,
    int pid,
    YARACALLBACK callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


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

//TODO: put this structure in a better place

typedef struct _ATOM_LIST_ITEM
{
  uint8_t atom_length;
  uint8_t atom[MAX_ATOM_LENGTH];

  uint16_t backtrack;
  
  void* forward_code;
  void* backward_code;

  struct _ATOM_LIST_ITEM* next;

} ATOM_LIST_ITEM;


int yr_ac_add_string(
    ARENA* arena,
    AC_AUTOMATON* automaton,
    STRING* string,
    ATOM_LIST_ITEM* atom);


AC_STATE* yr_ac_next_state(
    AC_STATE* state,
    uint8_t input);


void yr_ac_create_failure_links(
    ARENA* arena,
    AC_AUTOMATON* automaton);


void yr_ac_print_automaton(
    AC_AUTOMATON* automaton);

#endif

