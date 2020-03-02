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
#include <yara/arena2.h>
#include <yara/bitmask.h>
#include <yara/limits.h>
#include <yara/hash.h>
#include <yara/utils.h>
#include <yara/sizedstr.h>
#include <yara/stopwatch.h>
#include <yara/threading.h>


#define DECLARE_REFERENCE(type, name) \
    union { \
      type name; \
      YR_ARENA2_REF name##_; \
    } YR_ALIGN(8)


// Flags for YR_RULE
#define RULE_FLAGS_PRIVATE              0x01
#define RULE_FLAGS_GLOBAL               0x02
#define RULE_FLAGS_NULL                 0x04
#define RULE_FLAGS_DISABLED             0x08

#define RULE_IS_PRIVATE(x) \
    (((x)->flags) & RULE_FLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) \
    (((x)->flags) & RULE_FLAGS_GLOBAL)

#define RULE_IS_NULL(x) \
    (((x)->flags) & RULE_FLAGS_NULL)

#define RULE_IS_DISABLED(x) \
    (((x)->flags) & RULE_FLAGS_DISABLED)


// Flags for YR_STRING
#define STRING_FLAGS_REFERENCED        0x01
#define STRING_FLAGS_HEXADECIMAL       0x02
#define STRING_FLAGS_NO_CASE           0x04
#define STRING_FLAGS_ASCII             0x08
#define STRING_FLAGS_WIDE              0x10
#define STRING_FLAGS_REGEXP            0x20
#define STRING_FLAGS_FAST_REGEXP       0x40
#define STRING_FLAGS_FULL_WORD         0x80
#define STRING_FLAGS_ANONYMOUS         0x100
#define STRING_FLAGS_SINGLE_MATCH      0x200
#define STRING_FLAGS_LITERAL           0x400
#define STRING_FLAGS_FITS_IN_ATOM      0x800
#define STRING_FLAGS_LAST_IN_RULE      0x1000
#define STRING_FLAGS_CHAIN_PART        0x2000
#define STRING_FLAGS_CHAIN_TAIL        0x4000
#define STRING_FLAGS_FIXED_OFFSET      0x8000
#define STRING_FLAGS_GREEDY_REGEXP     0x10000
#define STRING_FLAGS_DOT_ALL           0x20000
#define STRING_FLAGS_DISABLED          0x40000
#define STRING_FLAGS_XOR               0x80000
#define STRING_FLAGS_PRIVATE           0x100000
#define STRING_FLAGS_BASE64            0x200000
#define STRING_FLAGS_BASE64_WIDE       0x400000

#define STRING_IS_HEX(x) \
    (((x)->flags) & STRING_FLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) \
    (((x)->flags) & STRING_FLAGS_NO_CASE)

#define STRING_IS_DOT_ALL(x) \
    (((x)->flags) & STRING_FLAGS_DOT_ALL)

#define STRING_IS_ASCII(x) \
    (((x)->flags) & STRING_FLAGS_ASCII)

#define STRING_IS_WIDE(x) \
    (((x)->flags) & STRING_FLAGS_WIDE)

#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_FLAGS_REGEXP)

#define STRING_IS_GREEDY_REGEXP(x) \
    (((x)->flags) & STRING_FLAGS_GREEDY_REGEXP)

#define STRING_IS_FULL_WORD(x) \
    (((x)->flags) & STRING_FLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_FLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) \
    (((x)->flags) & STRING_FLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->flags) & STRING_FLAGS_SINGLE_MATCH)

#define STRING_IS_FIXED_OFFSET(x) \
    (((x)->flags) & STRING_FLAGS_FIXED_OFFSET)

#define STRING_IS_LITERAL(x) \
    (((x)->flags) & STRING_FLAGS_LITERAL)

#define STRING_IS_FAST_REGEXP(x) \
    (((x)->flags) & STRING_FLAGS_FAST_REGEXP)

#define STRING_IS_CHAIN_PART(x) \
    (((x)->flags) & STRING_FLAGS_CHAIN_PART)

#define STRING_IS_CHAIN_TAIL(x) \
    (((x)->flags) & STRING_FLAGS_CHAIN_TAIL)

#define STRING_IS_LAST_IN_RULE(x) \
    (((x)->flags) & STRING_FLAGS_LAST_IN_RULE)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->flags) & STRING_FLAGS_FITS_IN_ATOM)

#define STRING_IS_DISABLED(x) \
    (((x)->flags) & STRING_FLAGS_DISABLED)

#define STRING_IS_XOR(x) \
    (((x)->flags) & STRING_FLAGS_XOR)

#define STRING_IS_BASE64(x) \
    (((x)->flags) & STRING_FLAGS_BASE64)

#define STRING_IS_BASE64_WIDE(x) \
    (((x)->flags) & STRING_FLAGS_BASE64_WIDE)

#define STRING_IS_PRIVATE(x) \
    (((x)->flags) & STRING_FLAGS_PRIVATE)


#define META_TYPE_NULL      0
#define META_TYPE_INTEGER   1
#define META_TYPE_STRING    2
#define META_TYPE_BOOLEAN   3

#define META_IS_NULL(x) \
    ((x) != NULL ? (x)->type == META_TYPE_NULL : true)


#define EXTERNAL_VARIABLE_TYPE_NULL           0
#define EXTERNAL_VARIABLE_TYPE_FLOAT          1
#define EXTERNAL_VARIABLE_TYPE_INTEGER        2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN        3
#define EXTERNAL_VARIABLE_TYPE_STRING         4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING  5

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

typedef YR_AC_MATCH_LIST_ENTRY* YR_AC_MATCH_TABLE_ENTRY;

typedef struct YR_NAMESPACE YR_NAMESPACE;
typedef struct YR_META YR_META;
typedef struct YR_MATCHES YR_MATCHES;
typedef struct YR_STRING YR_STRING;
typedef struct YR_RULE YR_RULE;
typedef struct YR_RULES YR_RULES;
typedef struct YR_SUMMARY YR_SUMMARY;
typedef struct YR_RULES_STATS YR_RULES_STATS;
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

typedef uint32_t  YR_AC_TRANSITION;

#pragma pack(push)
#pragma pack(8)

struct YR_NAMESPACE
{
  // Index of this namespace in the array of YR_NAMESPACE structures stored
  // in YR_NAMESPACES_TABLE.
  uint32_t idx;

  // Pointer to namespace's name.
  DECLARE_REFERENCE(const char*, name);
};


struct YR_META
{
  int32_t type;
  int64_t integer;

  DECLARE_REFERENCE(const char*, identifier);
  DECLARE_REFERENCE(const char*, string);
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
  // fixed_offset field contains the offset, it have the UNDEFINED value for
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

  YR_ALIGN(8) union {
    int64_t i;
    double f;
    char* s;
  } value;

  DECLARE_REFERENCE(const char*, identifier);
};


#define YR_AC_MATCH_FLAG_LAST   1

struct YR_AC_MATCH
{
  // When the Aho-Corasick automaton reaches some state that has associated
  // matches, the current position in the input buffer is a few bytes past
  // the point where the match actually occurs, for example, when looking for
  // string "bar" in "foobarbaz", when the automaton reaches the state associated
  // to the ending "r" in "bar, which is the one that has a match, the current
  // position in the input is 6 (the "b" after the "r"), but the match is at
  // position 3. The backtrack field indicates how many bytes the scanner has
  // to go back to find the point where the match actually start.
  uint16_t backtrack;

  int8_t  flags;

  DECLARE_REFERENCE(YR_STRING*, string);
  DECLARE_REFERENCE(const uint8_t*, forward_code);
  DECLARE_REFERENCE(const uint8_t*, backward_code);
};

#pragma pack(pop)


//
// Structs defined below are never stored in the compiled rules file
//

struct RE_NODE
{
  int type;

  union {
    int value;
    int count;
    int start;
  };

  union {
    int mask;
    int end;
  };

  int greedy;

  RE_CLASS* re_class;

  RE_NODE* children_head;
  RE_NODE* children_tail;
  RE_NODE* prev_sibling;
  RE_NODE* next_sibling;

  YR_ARENA2_REF forward_code_ref;
  YR_ARENA2_REF backward_code_ref;
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
#pragma warning(disable:4200)
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
  const uint8_t* ip;    // instruction pointer
  int32_t  sp;          // stack pointer
  int32_t  rc;          // repeat counter

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
  SIZED_STRING *alphabet;
};


struct YR_MATCHES
{
  YR_MATCH* head;
  YR_MATCH* tail;

  int32_t count;
};


struct YR_MATCH
{
  int64_t base;              // Base address for the match
  int64_t offset;            // Offset relative to base for the match
  int32_t match_length;      // Match length
  int32_t data_length;

  // Pointer to a buffer containing a portion of the matched data. The size of
  // the buffer is data_length. data_length is always <= length and is limited
  // to MAX_MATCH_DATA bytes.
  const uint8_t* data;

  YR_MATCH* prev;
  YR_MATCH* next;

  // If the match belongs to a chained string chain_length contains the
  // length of the chain. This field is used only in unconfirmed matches.
  int32_t chain_length;
};


struct YR_AC_STATE
{
  YR_AC_STATE* failure;
  YR_AC_STATE* first_child;
  YR_AC_STATE* siblings;
  YR_AC_MATCH_LIST_ENTRY* matches;

  uint8_t depth;
  uint8_t input;

  uint32_t t_table_slot;
};


struct YR_AC_MATCH_LIST_ENTRY
{
  uint16_t backtrack;
  uint32_t string_idx;
  uint32_t xref;

  YR_ARENA2_REF ref;
  YR_ARENA2_REF forward_code_ref;
  YR_ARENA2_REF backward_code_ref;

  YR_AC_MATCH_LIST_ENTRY* next;
};


struct YR_AC_AUTOMATON
{
  // Both m_table and t_table have the same number of elements, which is
  // stored in tables_size.
  uint32_t tables_size;

  // The first slot in the transition table (t_table) that may be be unused.
  // Used for speeding up the construction of the transition table.
  uint32_t t_table_unused_candidate;

  // Bitmask where each bit indicates if the corresponding slot in m_table
  // and t_table is already in use.
  YR_BITMASK* bitmask;

  // Transition table. See comment in _yr_ac_build_transition_table for more
  // details.
  YR_AC_TRANSITION* t_table;

  // Pointer to an array of YR_AC_MATCH_LIST_ENTRY* pointers. This array has the same
  // number of entries than the transition table. If entry N in the transition
  // table corresponds to an Aho-Corasick state, the N-th entry in the array
  // points to the first item of the list of matches corresponding to that state.
  // If entry N in the transition table does not corresponds to a state, or the
  // state doesn't have any match, the N-th entry in this array will be a NULL
  // pointer.
  YR_AC_MATCH_TABLE_ENTRY* m_table;

  // Pointer to the root Aho-Corasick state.
  YR_AC_STATE* root;
};


struct YR_RULES
{
  YR_ARENA2* arena;

  YR_RULE* rules_list_head;
  YR_STRING* strings_list_head;
  YR_EXTERNAL_VARIABLE* externals_list_head;

  YR_AC_TRANSITION* ac_transition_table;
  YR_AC_MATCH* ac_match_pool;

  uint32_t* ac_match_table;

  const uint8_t* code_start;

  // Total number of rules.
  uint32_t num_rules;

  // Total number of strings.
  uint32_t num_strings;

  // Total number of namespaces.
  uint32_t num_namespaces;

  // Size of ac_match_table and ac_transition_table in number of items (both
  // tables have the same number of items).
  uint32_t ac_tables_size;
};


struct YR_RULES_STATS
{
  // Total number of rules
  uint32_t rules;

  // Total number of strings across all rules.
  uint32_t strings;

  // Total number of Aho-Corasick matches. Each node in the  Aho-Corasick
  // automaton has a list of YR_AC_MATCH_LIST_ENTRY structures (match list) pointing to
  // strings that are potential matches. This field holds the total number of
  // those structures across all nodes in the automaton.
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


typedef const uint8_t* (*YR_MEMORY_BLOCK_FETCH_DATA_FUNC)(
    YR_MEMORY_BLOCK* self);


typedef YR_MEMORY_BLOCK* (*YR_MEMORY_BLOCK_ITERATOR_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);


struct YR_MEMORY_BLOCK
{
  size_t size;
  uint64_t base;

  void* context;

  YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data;
};


struct YR_MEMORY_BLOCK_ITERATOR
{
  void* context;

  YR_MEMORY_BLOCK_ITERATOR_FUNC  first;
  YR_MEMORY_BLOCK_ITERATOR_FUNC  next;
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

  // Arena used for storing YR_MATCH structures associated to the matches found.
  YR_ARENA* matches_arena;

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

  // Array with pointers to lists of matches. Item N in the array has the
  // list of matches for string with index N.
  YR_MATCHES* matches;

  // Similar to matches, but matches corresponding to private strings.
  YR_MATCHES* private_matches;

  // "unconfirmed_matches" is like "matches" but for strings that are part of
  // a chain. Let's suppose that the string S is split in two chained strings
  // S1 <- S2. When a match is found for S1, we can't be sure that S matches
  // until a match for S2 is found (within the range defined by chain_gap_min
  // and chain_gap_max), so the matches for S1 are put in "unconfirmed_matches"
  // until they can be confirmed or discarded.
  YR_MATCHES* unconfirmed_matches;

  // rule_cost is a pointer to an array of 64-bit integers with one entry per
  // rule. Entry N has the time cost for rule with index N.
  #ifdef PROFILING_ENABLED
  uint64_t* time_cost;
  #endif
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
  int32_t   sp;
  int32_t   capacity;
  YR_VALUE* items;
};


#define OBJECT_COMMON_FIELDS \
    int canary; \
    int8_t type; \
    const char* identifier; \
    YR_OBJECT* parent; \
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

  struct {
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
// in which case the value for the next item should be UNDEFINED. The stack
// should look like this after the last call to "next":
//
//  +------------+
//  | undefined  |  <- next item is undefined.
//  +------------+
//  | true       |  <- true indicates that are no more items.
//  +------------+
//  |   . . .    |
//
// We can't use the UNDEFINED value in the stack as an indicator of the end
// of the iterator, because it's legitimate for an iterator to return UNDEFINED
// items in the middle of the iteration.
//
// The "next" function should return ERROR_SUCCESS if everything went fine or
// an error code in case of error.

typedef int (*YR_ITERATOR_NEXT_FUNC)(
    YR_ITERATOR* self,
    YR_VALUE_STACK* stack);


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
  int next;
  int count;
  int64_t items[1];
};


struct YR_ITERATOR
{
  YR_ITERATOR_NEXT_FUNC next;

  union {
    struct YR_ARRAY_ITERATOR array_it;
    struct YR_DICT_ITERATOR dict_it;
    struct YR_INT_RANGE_ITERATOR int_range_it;
    struct YR_INT_ENUM_ITERATOR int_enum_it;
  };
};


#endif
