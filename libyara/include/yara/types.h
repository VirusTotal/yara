/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef YR_TYPES_H
#define YR_TYPES_H

#include <yara/arena.h>
#include <yara/bitmask.h>
#include <yara/hash.h>
#include <yara/limits.h>
#include <yara/sizedstr.h>
#include <yara/stopwatch.h>
#include <yara/threading.h>
#include <yara/utils.h>

#include "notebook.h"

#define DECLARE_REFERENCE(type, name) \
  union                               \
  {                                   \
    type name;                        \
    YR_ARENA_REF name##_;             \
  } YR_ALIGN(8)

// Flags for YR_RULE
#define RULE_FLAGS_PRIVATE  0x01
#define RULE_FLAGS_GLOBAL   0x02
#define RULE_FLAGS_NULL     0x04
#define RULE_FLAGS_DISABLED 0x08

#define RULE_IS_PRIVATE(x) (((x)->flags) & RULE_FLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) (((x)->flags) & RULE_FLAGS_GLOBAL)

#define RULE_IS_NULL(x) (((x)->flags) & RULE_FLAGS_NULL)

#define RULE_IS_DISABLED(x) (((x)->flags) & RULE_FLAGS_DISABLED)

// Flags for YR_STRING
#define STRING_FLAGS_REFERENCED    0x01
#define STRING_FLAGS_HEXADECIMAL   0x02
#define STRING_FLAGS_NO_CASE       0x04
#define STRING_FLAGS_ASCII         0x08
#define STRING_FLAGS_WIDE          0x10
#define STRING_FLAGS_REGEXP        0x20
#define STRING_FLAGS_FAST_REGEXP   0x40
#define STRING_FLAGS_FULL_WORD     0x80
#define STRING_FLAGS_ANONYMOUS     0x100
#define STRING_FLAGS_SINGLE_MATCH  0x200
#define STRING_FLAGS_LITERAL       0x400
#define STRING_FLAGS_FITS_IN_ATOM  0x800
#define STRING_FLAGS_LAST_IN_RULE  0x1000
#define STRING_FLAGS_CHAIN_PART    0x2000
#define STRING_FLAGS_CHAIN_TAIL    0x4000
#define STRING_FLAGS_FIXED_OFFSET  0x8000
#define STRING_FLAGS_GREEDY_REGEXP 0x10000
#define STRING_FLAGS_DOT_ALL       0x20000
#define STRING_FLAGS_DISABLED      0x40000
#define STRING_FLAGS_XOR           0x80000
#define STRING_FLAGS_PRIVATE       0x100000
#define STRING_FLAGS_BASE64        0x200000
#define STRING_FLAGS_BASE64_WIDE   0x400000

#define STRING_IS_HEX(x) (((x)->flags) & STRING_FLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) (((x)->flags) & STRING_FLAGS_NO_CASE)

#define STRING_IS_DOT_ALL(x) (((x)->flags) & STRING_FLAGS_DOT_ALL)

#define STRING_IS_ASCII(x) (((x)->flags) & STRING_FLAGS_ASCII)

#define STRING_IS_WIDE(x) (((x)->flags) & STRING_FLAGS_WIDE)

#define STRING_IS_REGEXP(x) (((x)->flags) & STRING_FLAGS_REGEXP)

#define STRING_IS_GREEDY_REGEXP(x) (((x)->flags) & STRING_FLAGS_GREEDY_REGEXP)

#define STRING_IS_FULL_WORD(x) (((x)->flags) & STRING_FLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) (((x)->flags) & STRING_FLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) (((x)->flags) & STRING_FLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) (((x)->flags) & STRING_FLAGS_SINGLE_MATCH)

#define STRING_IS_FIXED_OFFSET(x) (((x)->flags) & STRING_FLAGS_FIXED_OFFSET)

#define STRING_IS_LITERAL(x) (((x)->flags) & STRING_FLAGS_LITERAL)

#define STRING_IS_FAST_REGEXP(x) (((x)->flags) & STRING_FLAGS_FAST_REGEXP)

#define STRING_IS_CHAIN_PART(x) (((x)->flags) & STRING_FLAGS_CHAIN_PART)

#define STRING_IS_CHAIN_TAIL(x) (((x)->flags) & STRING_FLAGS_CHAIN_TAIL)

#define STRING_IS_LAST_IN_RULE(x) (((x)->flags) & STRING_FLAGS_LAST_IN_RULE)

#define STRING_FITS_IN_ATOM(x) (((x)->flags) & STRING_FLAGS_FITS_IN_ATOM)

#define STRING_IS_DISABLED(x) (((x)->flags) & STRING_FLAGS_DISABLED)

#define STRING_IS_XOR(x) (((x)->flags) & STRING_FLAGS_XOR)

#define STRING_IS_BASE64(x) (((x)->flags) & STRING_FLAGS_BASE64)

#define STRING_IS_BASE64_WIDE(x) (((x)->flags) & STRING_FLAGS_BASE64_WIDE)

#define STRING_IS_PRIVATE(x) (((x)->flags) & STRING_FLAGS_PRIVATE)

#define META_TYPE_INTEGER 1
#define META_TYPE_STRING  2
#define META_TYPE_BOOLEAN 3

#define META_FLAGS_LAST_IN_RULE 1

#define META_IS_LAST_IN_RULE(x) (((x)->flags) & META_FLAGS_LAST_IN_RULE)

#define EXTERNAL_VARIABLE_TYPE_NULL          0
#define EXTERNAL_VARIABLE_TYPE_FLOAT         1
#define EXTERNAL_VARIABLE_TYPE_INTEGER       2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN       3
#define EXTERNAL_VARIABLE_TYPE_STRING        4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING 5

#define EXTERNAL_VARIABLE_IS_NULL(x) \
  ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : true)

typedef struct RE RE;
typedef struct RE_AST RE_AST;
typedef struct RE_NODE RE_NODE;
typedef struct RE_CLASS RE_CLASS;
typedef struct RE_ERROR RE_ERROR;
typedef struct RE_FIBER RE_FIBER;
typedef struct RE_FIBER_LIST RE_FIBER_LIST;
typedef struct RE_FIBER_POOL RE_FIBER_POOL;

typedef struct YR_AC_STATE YR_AC_STATE;
typedef struct YR_AC_AUTOMATON YR_AC_AUTOMATON;
typedef struct YR_AC_TABLES YR_AC_TABLES;
typedef struct YR_AC_MATCH_LIST_ENTRY YR_AC_MATCH_LIST_ENTRY;
typedef struct YR_AC_MATCH YR_AC_MATCH;

typedef struct YR_NAMESPACE YR_NAMESPACE;
typedef struct YR_META YR_META;
typedef struct YR_MATCHES YR_MATCHES;
typedef struct YR_STRING YR_STRING;
typedef struct YR_RULE YR_RULE;
typedef struct YR_RULES YR_RULES;
typedef struct YR_SUMMARY YR_SUMMARY;
typedef struct YR_RULES_STATS YR_RULES_STATS;
typedef struct YR_PROFILING_INFO YR_PROFILING_INFO;
typedef struct YR_RULE_PROFILING_INFO YR_RULE_PROFILING_INFO;
typedef struct YR_EXTERNAL_VARIABLE YR_EXTERNAL_VARIABLE;
typedef struct YR_MATCH YR_MATCH;
typedef struct YR_SCAN_CONTEXT YR_SCAN_CONTEXT;

typedef union YR_VALUE YR_VALUE;
typedef struct YR_VALUE_STACK YR_VALUE_STACK;

typedef struct YR_OBJECT YR_OBJECT;
typedef struct YR_OBJECT_STRUCTURE YR_OBJECT_STRUCTURE;
typedef struct YR_OBJECT_ARRAY YR_OBJECT_ARRAY;
typedef struct YR_OBJECT_DICTIONARY YR_OBJECT_DICTIONARY;
typedef struct YR_OBJECT_FUNCTION YR_OBJECT_FUNCTION;

typedef struct YR_STRUCTURE_MEMBER YR_STRUCTURE_MEMBER;
typedef struct YR_ARRAY_ITEMS YR_ARRAY_ITEMS;
typedef struct YR_DICTIONARY_ITEMS YR_DICTIONARY_ITEMS;

typedef struct YR_MODULE YR_MODULE;
typedef struct YR_MODULE_IMPORT YR_MODULE_IMPORT;

typedef struct YR_MEMORY_BLOCK YR_MEMORY_BLOCK;
typedef struct YR_MEMORY_BLOCK_ITERATOR YR_MEMORY_BLOCK_ITERATOR;

typedef struct YR_MODIFIER YR_MODIFIER;

typedef struct YR_ITERATOR YR_ITERATOR;

typedef uint32_t YR_AC_TRANSITION;

#pragma pack(push)
#pragma pack(8)

struct YR_NAMESPACE
{
  // Pointer to namespace's name.
  DECLARE_REFERENCE(const char*, name);

  // Index of this namespace in the array of YR_NAMESPACE structures stored
  // in YR_NAMESPACES_TABLE.
  //
  // YR_ALIGN(8) forces the idx field to be treated as a 8-bytes field
  // and therefore the struct's size is 16 bytes. This is necessary only for
  // 32-bits versions of YARA compiled with Visual Studio. See: #1358.
  YR_ALIGN(8) uint32_t idx;
};

struct YR_META
{
  DECLARE_REFERENCE(const char*, identifier);
  DECLARE_REFERENCE(const char*, string);

  int64_t integer;
  int32_t type;
  int32_t flags;
};

struct YR_STRING
{
  // Flags, see STRING_FLAGS_XXX macros defined above.
  uint32_t flags;

  // Index of this string in the array of YR_STRING structures stored in
  // YR_STRINGS_TABLE.
  uint32_t idx;

  // If the string can only match at a specific offset (for example if the
  // condition is "$a at 0" the string $a can only match at offset 0), the
  // fixed_offset field contains the offset, it have the YR_UNDEFINED value for
  // strings that can match anywhere.
  int64_t fixed_offset;

  // Index of the rule containing this string in the array of YR_RULE
  // structures stored in YR_RULES_TABLE.
  uint32_t rule_idx;

  // String's length.
  int32_t length;

  // Pointer to the string itself, the length is indicated by the "length"
  // field.
  DECLARE_REFERENCE(uint8_t*, string);

  // Strings are splitted in two or more parts when they contain a "gap" that
  // is larger than YR_STRING_CHAINING_THRESHOLD. This happens in strings like
  // { 01 02 03 04 [X-Y] 05 06 07 08 } if Y >= X + YR_STRING_CHAINING_THRESHOLD
  // and also in { 01 02 03 04 [-] 05 06 07 08 }. In both cases the strings are
  // split in { 01 02 03 04 } and { 05 06 07 08 }, and the two smaller strings
  // are searched for independently. If some string S is splitted in S1 and S2,
  // S2 is chained to S1. In the example above { 05 06 07 08 } is chained to
  // { 01 02 03 04 }. The same applies when the string is splitted in more than
  // two parts, if S is split in S1, S2, and S3. S3 is chained to S2 and S2 is
  // chained to S1 (it can represented as: S1 <- S2 <- S3).
  DECLARE_REFERENCE(YR_STRING*, chained_to);

  // When this string is chained to some other string, chain_gap_min and
  // chain_gap_max contain the minimum and maximum distance between the two
  // strings. For example in { 01 02 03 04 [X-Y] 05 06 07 08 }, the string
  // { 05 06 07 08 } is chained to { 01 02 03 04 } and chain_gap_min is X
  // and chain_gap_max is Y. These fields are ignored for strings that are not
  // part of a string chain.
  int32_t chain_gap_min;
  int32_t chain_gap_max;

  // Identifier of this string.
  DECLARE_REFERENCE(const char*, identifier);
};

struct YR_RULE
{
  int32_t flags;

  // Number of atoms generated for this rule.
  int32_t num_atoms;

  DECLARE_REFERENCE(const char*, identifier);
  DECLARE_REFERENCE(const char*, tags);
  DECLARE_REFERENCE(YR_META*, metas);
  DECLARE_REFERENCE(YR_STRING*, strings);
  DECLARE_REFERENCE(YR_NAMESPACE*, ns);
};

struct YR_SUMMARY
{
  uint32_t num_rules;
  uint32_t num_strings;
  uint32_t num_namespaces;
};

struct YR_EXTERNAL_VARIABLE
{
  int32_t type;

  YR_ALIGN(8) union
  {
    int64_t i;
    double f;
    char* s;
  } value;

  DECLARE_REFERENCE(const char*, identifier);
};

struct YR_AC_MATCH
{
  DECLARE_REFERENCE(YR_STRING*, string);
  DECLARE_REFERENCE(const uint8_t*, forward_code);
  DECLARE_REFERENCE(const uint8_t*, backward_code);
  DECLARE_REFERENCE(YR_AC_MATCH*, next);

  // When the Aho-Corasick automaton reaches some state that has associated
  // matches, the current position in the input buffer is a few bytes past
  // the point where the match actually occurs, for example, when looking for
  // string "bar" in "foobarbaz", when the automaton reaches the state
  // associated to the ending "r" in "bar, which is the one that has a match,
  // the current position in the input is 6 (the "b" after the "r"), but the
  // match is at position 3. The backtrack field indicates how many bytes the
  // scanner has to go back to find the point where the match actually start.
  //
  // YR_ALIGN(8) forces the backtrack field to be treated as a 8-bytes field
  // and therefore the struct's size is 40 bytes. This is necessary only for
  // 32-bits versions of YARA compiled with Visual Studio. See: #1358.
  YR_ALIGN(8) uint16_t backtrack;
};

#pragma pack(pop)

//
// Structs defined below are never stored in the compiled rules file
//

struct RE_NODE
{
  int type;

  union
  {
    int value;
    int count;
    int start;
  };

  union
  {
    int mask;
    int end;
  };

  int greedy;

  RE_CLASS* re_class;

  RE_NODE* children_head;
  RE_NODE* children_tail;
  RE_NODE* prev_sibling;
  RE_NODE* next_sibling;

  YR_ARENA_REF forward_code_ref;
  YR_ARENA_REF backward_code_ref;
};

struct RE_CLASS
{
  uint8_t negated;
  uint8_t bitmap[32];
};

struct RE_AST
{
  uint32_t flags;
  RE_NODE* root_node;
};

// Disable warning due to zero length array in Microsoft's compiler
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200)
#endif

struct RE
{
  uint32_t flags;
  uint8_t code[0];
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

struct RE_ERROR
{
  char message[384];
};

struct RE_FIBER
{
  const uint8_t* ip;  // instruction pointer
  int32_t sp;         // stack pointer
  int32_t rc;         // repeat counter

  RE_FIBER* prev;
  RE_FIBER* next;

  uint16_t stack[RE_MAX_STACK];
};

struct RE_FIBER_LIST
{
  RE_FIBER* head;
  RE_FIBER* tail;
};

struct RE_FIBER_POOL
{
  int fiber_count;
  RE_FIBER_LIST fibers;
};

struct YR_MODIFIER
{
  int32_t flags;
  uint8_t xor_min;
  uint8_t xor_max;
  SIZED_STRING* alphabet;
};

struct YR_MATCHES
{
  YR_MATCH* head;
  YR_MATCH* tail;

  int32_t count;
};

struct YR_MATCH
{
  int64_t base;          // Base address for the match
  int64_t offset;        // Offset relative to base for the match
  int32_t match_length;  // Match length
  int32_t data_length;

  // Pointer to a buffer containing a portion of the matched data. The size of
  // the buffer is data_length. data_length is always <= length and is limited
  // to YR_CONFIG_MAX_MATCH_DATA bytes.
  const uint8_t* data;

  YR_MATCH* prev;
  YR_MATCH* next;

  // If the match belongs to a chained string chain_length contains the
  // length of the chain. This field is used only in unconfirmed matches.
  int32_t chain_length;

  // True if this is match for a private string.
  bool is_private;
};

struct YR_AC_STATE
{
  YR_AC_STATE* failure;
  YR_AC_STATE* first_child;
  YR_AC_STATE* siblings;

  // Reference to the YR_AC_MATCH structure that heads the list of matches
  // for this state.
  YR_ARENA_REF matches_ref;

  uint8_t depth;
  uint8_t input;

  uint32_t t_table_slot;
};

struct YR_AC_MATCH_LIST_ENTRY
{
  uint16_t backtrack;
  uint32_t string_idx;

  YR_ARENA_REF ref;
  YR_ARENA_REF forward_code_ref;
  YR_ARENA_REF backward_code_ref;

  YR_AC_MATCH_LIST_ENTRY* next;
};

struct YR_AC_AUTOMATON
{
  // Arena used by this automaton to store the transition and match tables.
  YR_ARENA* arena;

  // Both m_table and t_table have the same number of elements, which is
  // stored in tables_size.
  uint32_t tables_size;

  // The first slot in the transition table (t_table) that may be be unused.
  // Used for speeding up the construction of the transition table.
  uint32_t t_table_unused_candidate;

  // Bitmask where each bit indicates if the corresponding slot in the
  // transition table is already in use.
  YR_BITMASK* bitmask;

  // Pointer to the root Aho-Corasick state.
  YR_AC_STATE* root;
};

struct YR_RULES
{
  YR_ARENA* arena;

  // Array of pointers with an entry for each rule. The rule_idx field in the
  // YR_STRING structure is an index within this array.
  union
  {
    YR_RULE* rules_table;
    // The previous name for rules_table was rules_list_head, because this
    // was previously a linked list. The old name is maintained but marked as
    // deprecated, which will raise a warning if used.
    // TODO(vmalvarez): Remove this field when a reasonable a few versions
    // after 4.1 has been released.
    YR_RULE* rules_list_head YR_DEPRECATED;
  };

  // Array of pointers with an entry for each of the defined strings. The idx
  // field in the YR_STRING structure is an index within this array.
  union
  {
    YR_STRING* strings_table;
    // The previous name for strings_table was strings_list_head, because this
    // was previously a linked list. The old name is maintained but marked as
    // deprecated, which will raise a warning if used.
    // TODO(vmalvarez): Remove this field when a reasonable a few versions
    // after 4.1 has been released.
    YR_STRING* strings_list_head YR_DEPRECATED;
  };

  // Array of pointers with an entry for each external variable.
  union
  {
    YR_EXTERNAL_VARIABLE* ext_vars_table;
    // The previous name for ext_vars_table was externals_list_head, because
    // this was previously a linked list. The old name is maintained but marked
    // as deprecated, which will raise a warning if used.
    // TODO(vmalvarez): Remove this field when a reasonable a few versions
    // after 4.1 has been released.
    YR_EXTERNAL_VARIABLE* externals_list_head YR_DEPRECATED;
  };

  // Pointer to the Aho-Corasick transition table.
  YR_AC_TRANSITION* ac_transition_table;

  // A pointer to the arena where YR_AC_MATCH structures are allocated.
  YR_AC_MATCH* ac_match_pool;

  // Table that translates from Aho-Corasick states (which are identified by
  // numbers 0, 1, 2.. and so on) to the index in ac_match_pool where the
  // YR_AC_MATCH structures for the corresponding state start.
  // If the entry corresponding to state N in ac_match_table is zero, it
  // means that there's no match associated to the state. If it's non-zero,
  // its value is the 1-based index within ac_match_pool where the first
  // match resides.
  uint32_t* ac_match_table;

  // Pointer to the first instruction that is executed whan evaluating the
  // conditions for all rules. The code is executed by yr_execute_code and
  // the instructions are defined by the OP_X macros in exec.h.
  const uint8_t* code_start;

  // Total number of rules.
  uint32_t num_rules;

  // Total number of strings.
  uint32_t num_strings;

  // Total number of namespaces.
  uint32_t num_namespaces;
};

struct YR_RULES_STATS
{
  // Total number of rules
  uint32_t num_rules;

  // Total number of strings across all rules.
  uint32_t num_strings;

  // Total number of Aho-Corasick matches. Each node in the Aho-Corasick
  // automaton has a list of YR_AC_MATCH_LIST_ENTRY structures (match list)
  // pointing to strings that are potential matches. This field holds the total
  // number of those structures across all nodes in the automaton.
  uint32_t ac_matches;

  // Length of the match list for the root node in the Aho-Corasick automaton.
  uint32_t ac_root_match_list_length;

  // Average number of matches per match list.
  float ac_average_match_list_length;

  // Top 10 longest match lists.
  uint32_t top_ac_match_list_lengths[100];

  // Percentiles of match lists' lengths. If the i-th value in the array is N
  // then i percent of the match lists have N or less items.
  uint32_t ac_match_list_length_pctls[101];

  // Size of Aho-Corasick transition & match tables.
  uint32_t ac_tables_size;
};

//
// YR_PROFILING_INFO contains profiling information for a rule.
//
struct YR_PROFILING_INFO
{
  // Number of times that some atom belonging to the rule matched. Each
  // matching atom means a potential string match that needs to be verified.
  uint32_t atom_matches;

  // Amount of time (in nanoseconds) spent verifying atom matches for
  // determining if the corresponding string actually matched or not. This
  // time is not measured for all atom matches, only 1 out of 1024 matches
  // are actually measured.
  uint64_t match_time;

  // Amount of time (in nanoseconds) spent evaluating the rule condition.
  uint64_t exec_time;
};

////////////////////////////////////////////////////////////////////////////////
// YR_RULE_PROFILING_INFO is the structure returned by
// yr_scanner_get_profiling_info
//
struct YR_RULE_PROFILING_INFO
{
  YR_RULE* rule;
  uint64_t cost;
};

typedef const uint8_t* (*YR_MEMORY_BLOCK_FETCH_DATA_FUNC)(
    YR_MEMORY_BLOCK* self);

typedef YR_MEMORY_BLOCK* (*YR_MEMORY_BLOCK_ITERATOR_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);

typedef uint64_t (*YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);

struct YR_MEMORY_BLOCK
{
  size_t size;
  uint64_t base;

  void* context;

  YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data;
};

///////////////////////////////////////////////////////////////////////////////
// YR_MEMORY_BLOCK_ITERATOR represents an iterator that returns a series of
// memory blocks to be scanned by yr_scanner_scan_mem_blocks. The iterator have
// pointers to three functions: "first", "next" and "file_size". The "first"
// function is invoked for retrieving the first memory block, followed by calls
// to "next" for retrieving the following blocks until "next" returns a NULL
// pointer. The "file_size" function is called for obtaining the size of the
// file.
struct YR_MEMORY_BLOCK_ITERATOR
{
  // A pointer that can be used by specific implementations of an iterator for
  // storing the iterator's state.
  void* context;

  // Pointers to functions for iterating over the memory blocks.
  YR_MEMORY_BLOCK_ITERATOR_FUNC first;
  YR_MEMORY_BLOCK_ITERATOR_FUNC next;

  // Pointer to a function that returns the file size as computed by the
  // iterator. This is a the size returned by the filesize keyword in YARA
  // rules. If this pointer is NULL the file size will be undefined.
  YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC file_size;

  // Error occurred during the last call to "first" or "next" functions. These
  // functions must set the value of last_error to ERROR_SUCCESS or to some
  // other error code if appropriate. Alternatively, last_error can be set to
  // ERROR_SUCCESS before using the iterator and changed by "first" or "next"
  // only when they want to report an error.
  int last_error;
};

typedef int (*YR_CALLBACK_FUNC)(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data);

struct YR_SCAN_CONTEXT
{
  // File size of the file being scanned.
  uint64_t file_size;

  // Entry point of the file being scanned, if the file is PE or ELF.
  uint64_t entry_point;

  // Scanning flags.
  int flags;

  // Canary value used for preventing hand-crafted objects from being embedded
  // in compiled rules and used to exploit YARA. The canary value is initialized
  // to a random value and is subsequently set to all objects created by
  // yr_object_create. The canary is verified when objects are used by
  // yr_execute_code.
  int canary;

  // Scan timeout in nanoseconds.
  uint64_t timeout;

  // Pointer to user-provided data passed to the callback function.
  void* user_data;

  // Pointer to the user-provided callback function that is called when an
  // event occurs during the scan (a rule matching, a module being loaded, etc)
  YR_CALLBACK_FUNC callback;

  // Pointer to the YR_RULES object associated to this scan context.
  YR_RULES* rules;

  // Pointer to the YR_STRING causing the most recent scan error.
  YR_STRING* last_error_string;

  // Pointer to the iterator used for scanning
  YR_MEMORY_BLOCK_ITERATOR* iterator;

  // Pointer to a table mapping identifiers to YR_OBJECT structures. This table
  // contains entries for external variables and modules.
  YR_HASH_TABLE* objects_table;

  // Notebook used for storing YR_MATCH structures associated to the matches
  // found.
  YR_NOTEBOOK* matches_notebook;

  // Stopwatch used for measuring the time elapsed during the scan.
  YR_STOPWATCH stopwatch;

  // Fiber pool used by yr_re_exec.
  RE_FIBER_POOL re_fiber_pool;

  // A bitmap with one bit per rule, bit N is set when the rule with index N
  // has matched.
  YR_BITMASK* rule_matches_flags;

  // A bitmap with one bit per namespace, bit N is set if the namespace with
  // index N has some global rule that is not satisfied.
  YR_BITMASK* ns_unsatisfied_flags;

  // A bitmap with one bit per string, bit N is set if the string with index
  // N has too many matches.
  YR_BITMASK* strings_temp_disabled;

  // Array with pointers to lists of matches. Item N in the array has the
  // list of matches for string with index N.
  YR_MATCHES* matches;

  // "unconfirmed_matches" is like "matches" but for strings that are part of
  // a chain. Let's suppose that the string S is split in two chained strings
  // S1 <- S2. When a match is found for S1, we can't be sure that S matches
  // until a match for S2 is found (within the range defined by chain_gap_min
  // and chain_gap_max), so the matches for S1 are put in "unconfirmed_matches"
  // until they can be confirmed or discarded.
  YR_MATCHES* unconfirmed_matches;

  // profiling_info is a pointer to an array of YR_PROFILING_INFO structures,
  // one per rule. Entry N has the profiling information for rule with index N.
  YR_PROFILING_INFO* profiling_info;
};

union YR_VALUE
{
  int64_t i;
  double d;
  void* p;
  YR_OBJECT* o;
  YR_STRING* s;
  YR_ITERATOR* it;
  SIZED_STRING* ss;
  RE* re;
};

struct YR_VALUE_STACK
{
  int32_t sp;
  int32_t capacity;
  YR_VALUE* items;
};

#define OBJECT_COMMON_FIELDS \
  int canary;                \
  int8_t type;               \
  const char* identifier;    \
  YR_OBJECT* parent;         \
  void* data;

struct YR_OBJECT
{
  OBJECT_COMMON_FIELDS
  YR_VALUE value;
};

struct YR_OBJECT_STRUCTURE
{
  OBJECT_COMMON_FIELDS
  YR_STRUCTURE_MEMBER* members;
};

struct YR_OBJECT_ARRAY
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* prototype_item;
  YR_ARRAY_ITEMS* items;
};

struct YR_OBJECT_DICTIONARY
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* prototype_item;
  YR_DICTIONARY_ITEMS* items;
};

typedef int (*YR_MODULE_FUNC)(
    YR_VALUE* args,
    YR_SCAN_CONTEXT* context,
    YR_OBJECT_FUNCTION* function_obj);

struct YR_OBJECT_FUNCTION
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* return_obj;

  struct
  {
    const char* arguments_fmt;
    YR_MODULE_FUNC code;
  } prototypes[YR_MAX_OVERLOADED_FUNCTIONS];
};

#define object_as_structure(obj)  ((YR_OBJECT_STRUCTURE*) (obj))
#define object_as_array(obj)      ((YR_OBJECT_ARRAY*) (obj))
#define object_as_dictionary(obj) ((YR_OBJECT_DICTIONARY*) (obj))
#define object_as_function(obj)   ((YR_OBJECT_FUNCTION*) (obj))

struct YR_STRUCTURE_MEMBER
{
  YR_OBJECT* object;
  YR_STRUCTURE_MEMBER* next;
};

struct YR_ARRAY_ITEMS
{
  // Capacity is the size of the objects array.
  int capacity;

  // Length is determined by the last element in the array. If the index of the
  // last element is N, then length is N+1 because indexes start at 0.
  int length;

  YR_OBJECT* objects[1];
};

struct YR_DICTIONARY_ITEMS
{
  int used;
  int free;

  struct
  {
    SIZED_STRING* key;
    YR_OBJECT* obj;
  } objects[1];
};

// Iterators are used in loops of the form:
//
// for <any|all|number> <identifier> in <iterator> : ( <expression> )
//
// The YR_ITERATOR struct abstracts the many different types of objects that
// can be iterated. Each type of iterator must provide a "next" function which
// is called multiple times for retrieving elements from the iterator. This
// function is responsible for pushing the next item in the stack and a boolean
// indicating if the end of the iterator has been reached. The boolean must be
// pushed first, so that the next item is in the top of the stack when the
// function returns.
//
//  +------------+
//  | next item  |  <- top of the stack
//  +------------+
//  | false      |  <- false indicates that there are more items
//  +------------+
//  |   . . .    |
//
// The boolean shouldn't be true if the next item was pushed in the stack, it
// can be true only when all the items have been returned in previous calls,
// in which case the value for the next item should be YR_UNDEFINED. The stack
// should look like this after the last call to "next":
//
//  +------------+
//  | undefined  |  <- next item is undefined.
//  +------------+
//  | true       |  <- true indicates that are no more items.
//  +------------+
//  |   . . .    |
//
// We can't use the YR_UNDEFINED value in the stack as an indicator of the end
// of the iterator, because it's legitimate for an iterator to return
// YR_UNDEFINED items in the middle of the iteration.
//
// The "next" function should return ERROR_SUCCESS if everything went fine or
// an error code in case of error.

typedef int (*YR_ITERATOR_NEXT_FUNC)(YR_ITERATOR* self, YR_VALUE_STACK* stack);

struct YR_ARRAY_ITERATOR
{
  YR_OBJECT* array;
  int index;
};

struct YR_DICT_ITERATOR
{
  YR_OBJECT* dict;
  int index;
};

struct YR_INT_RANGE_ITERATOR
{
  int64_t next;
  int64_t last;
};

struct YR_INT_ENUM_ITERATOR
{
  int64_t next;
  int64_t count;
  int64_t items[1];
};

struct YR_ITERATOR
{
  YR_ITERATOR_NEXT_FUNC next;

  union
  {
    struct YR_ARRAY_ITERATOR array_it;
    struct YR_DICT_ITERATOR dict_it;
    struct YR_INT_RANGE_ITERATOR int_range_it;
    struct YR_INT_ENUM_ITERATOR int_enum_it;
  };
};

#endif
