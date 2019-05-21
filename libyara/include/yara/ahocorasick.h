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

#ifndef _AHOCORASICK_H
#define _AHOCORASICK_H

#include <yara/limits.h>
#include <yara/atoms.h>
#include <yara/types.h>

// Number of bits dedicated to store the offset of the slot relative to its
// own state.
#define YR_AC_SLOT_OFFSET_BITS              9

// Max number of slots in the transition table. This is the maximum number of
// slots that can be addressed with 23-bit indexes.
#define YR_AC_MAX_TRANSITION_TABLE_SIZE     0x800000

#define YR_AC_ROOT_STATE                    0
#define YR_AC_NEXT_STATE(t)                 (t >> YR_AC_SLOT_OFFSET_BITS)
#define YR_AC_INVALID_TRANSITION(t, c)      (((t) & 0x1FF) != c)

#define YR_AC_MAKE_TRANSITION(state, code) \
  ((YR_AC_TRANSITION) \
    ((((YR_AC_TRANSITION) state) << YR_AC_SLOT_OFFSET_BITS) | (code)))


int yr_ac_automaton_create(
    YR_AC_AUTOMATON** automaton);


int yr_ac_automaton_destroy(
    YR_AC_AUTOMATON* automaton);


int yr_ac_add_string(
    YR_AC_AUTOMATON* automaton,
    YR_STRING* string,
    YR_ATOM_LIST_ITEM* atom,
    YR_ARENA* matches_arena);


int yr_ac_compile(
    YR_AC_AUTOMATON* automaton,
    YR_ARENA* arena,
    YR_AC_TABLES* tables);


void yr_ac_print_automaton(
    YR_AC_AUTOMATON* automaton);


#endif
