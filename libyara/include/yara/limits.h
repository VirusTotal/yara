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

#ifndef YR_LIMITS_H
#define YR_LIMITS_H

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#endif

#include "utils.h"

// Maximum lenght of file paths. This is the only limit that doesn't have the
// YR_ prefix. The intention is using the default MAX_PATH if defined.
#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

// Maximum number of threads that can use a YR_RULES structure simultaneously.
// Increasing this number also increase memory usage as each YR_STRING structure
// has an array with YR_MAX_THREADS entries for storing pointers to YR_MATCH
// structures.
#ifndef YR_MAX_THREADS
#define YR_MAX_THREADS 32
#endif

// Capacity of the buffer used for storing compiler error messages. Messages
// will be truncated at this size.
#ifndef YR_MAX_COMPILER_ERROR_EXTRA_INFO
#define YR_MAX_COMPILER_ERROR_EXTRA_INFO  256
#endif

// Maximum size for the substring (atoms) extracted from strings and regular
// expressions and put into the Aho-Corasick automaton. The maximum allows size
// for this constant is 255.
#ifndef YR_MAX_ATOM_LENGTH
#define YR_MAX_ATOM_LENGTH  4
#endif

#ifndef YR_MAX_ATOM_QUALITY
#define YR_MAX_ATOM_QUALITY 255
#endif

#ifndef YR_MIN_ATOM_QUALITY
#define YR_MIN_ATOM_QUALITY 0
#endif

// If the minimum atom quality for a string or regexp is below this constant,
// a warning like "<string> is slowing down the scan" is shown. This used only
// with heuristic atom quality, when using an atom quality table the user must
// specify the threshold when calling yr_compiler_set_atom_quality_table
#ifndef YR_ATOM_QUALITY_WARNING_THRESHOLD
#define YR_ATOM_QUALITY_WARNING_THRESHOLD \
    (YR_MAX_ATOM_QUALITY - 2 * YR_MAX_ATOM_LENGTH + 3)
#endif


// Maximum number of nested "for" loops in rule. Rules ith nested loops
// exceeding this number will be rejected by the compiler.
#ifndef YR_MAX_LOOP_NESTING
#define YR_MAX_LOOP_NESTING 4
#endif

#ifndef YR_MAX_ARENA_PAGES
#define YR_MAX_ARENA_PAGES 32
#endif

// Maximum number of nested included files.
#ifndef YR_MAX_INCLUDE_DEPTH
#define YR_MAX_INCLUDE_DEPTH 16
#endif

// Maximum number of matches allowed for a string. If more matches are found
// the scan will fail with ERROR_TOO_MANY_MATCHES.
#ifndef YR_MAX_STRING_MATCHES
#define YR_MAX_STRING_MATCHES 1000000
#endif

// Maximum number of argument that a function in a YARA module can have.
#ifndef YR_MAX_FUNCTION_ARGS
#define YR_MAX_FUNCTION_ARGS 128
#endif

// How many overloaded functions can share the same name in a YARA module.
#ifndef YR_MAX_OVERLOADED_FUNCTIONS
#define YR_MAX_OVERLOADED_FUNCTIONS 10
#endif

// Size of the stack used by yr_re_fast_exec.
#ifndef YR_MAX_FAST_RE_STACK
#define YR_MAX_FAST_RE_STACK 300
#endif


// Regular expressions like /foo.{x,y}bar/ are split in two separate ones /foo/
// and /bar/ if x is larger than YR_STRING_CHAINING_THRESHOLD. This also applies to
// hex strings like { 01 02 03 [x-y] 004 05 06 }.
#ifndef YR_STRING_CHAINING_THRESHOLD
#define YR_STRING_CHAINING_THRESHOLD 200
#endif

// Size of the buffer used by the lexer for storing strings like include file
// paths and regular expressions.
#ifndef YR_LEX_BUF_SIZE
#define YR_LEX_BUF_SIZE 8192
#endif

// Maximum allowed split ID, also limiting the number of split instructions
// allowed in a regular expression. This number can't be increased
// over 255 without changing RE_SPLIT_ID_TYPE.
#ifndef RE_MAX_SPLIT_ID
#define RE_MAX_SPLIT_ID 128
#endif

// Maximum stack size for regexp evaluation
#ifndef RE_MAX_STACK
#define RE_MAX_STACK 1024
#endif

// Maximum code size for a compiled regexp
#ifndef RE_MAX_CODE_SIZE
#define RE_MAX_CODE_SIZE 32768
#endif

// Maximum input size scanned by yr_re_exec
#ifndef RE_SCAN_LIMIT
#define RE_SCAN_LIMIT 4096
#endif

// Maximum number of fibers
#ifndef RE_MAX_FIBERS
#define RE_MAX_FIBERS 1024
#endif

// Maximum number of levels in regexp's AST
#ifndef RE_MAX_AST_LEVELS
#define RE_MAX_AST_LEVELS 5000
#endif

#endif
