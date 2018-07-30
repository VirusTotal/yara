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

#ifndef YR_ATOMS_H
#define YR_ATOMS_H

#include <yara/limits.h>
#include <yara/re.h>

#define ATOM_TREE_LEAF  1
#define ATOM_TREE_AND   2
#define ATOM_TREE_OR    3


typedef struct ATOM_TREE_NODE ATOM_TREE_NODE;
typedef struct ATOM_TREE ATOM_TREE;

typedef struct YR_ATOM_LIST_ITEM YR_ATOM_LIST_ITEM;

typedef struct YR_ATOM_QUALITY_TABLE_ENTRY YR_ATOM_QUALITY_TABLE_ENTRY;
typedef struct YR_ATOMS_CONFIG YR_ATOMS_CONFIG;


struct ATOM_TREE_NODE
{
  uint8_t type;
  uint8_t atom_length;
  uint8_t atom[YR_MAX_ATOM_LENGTH];

  uint8_t* forward_code;
  uint8_t* backward_code;

  RE_NODE* recent_nodes[YR_MAX_ATOM_LENGTH];

  ATOM_TREE_NODE* children_head;
  ATOM_TREE_NODE* children_tail;
  ATOM_TREE_NODE* next_sibling;
};


struct ATOM_TREE
{
  ATOM_TREE_NODE* current_leaf;
  ATOM_TREE_NODE* root_node;
};


struct YR_ATOM_LIST_ITEM
{
  uint8_t atom_length;
  uint8_t atom[YR_MAX_ATOM_LENGTH];

  uint16_t backtrack;

  uint8_t* forward_code;
  uint8_t* backward_code;

  YR_ATOM_LIST_ITEM* next;
};


#pragma pack(push)
#pragma pack(1)

struct YR_ATOM_QUALITY_TABLE_ENTRY
{
  const uint8_t  atom[YR_MAX_ATOM_LENGTH];
  const uint8_t quality;
};

#pragma pack(pop)


typedef int (*YR_ATOMS_QUALITY_FUNC)(
    YR_ATOMS_CONFIG* config,
    uint8_t* atom,
    int atom_length);


struct YR_ATOMS_CONFIG
{
  YR_ATOMS_QUALITY_FUNC get_atom_quality;
  YR_ATOM_QUALITY_TABLE_ENTRY* quality_table;

  int quality_warning_threshold;
  int quality_table_entries;
  bool free_quality_table;
};


int yr_atoms_extract_from_re(
    YR_ATOMS_CONFIG* config,
    RE_AST* re_ast,
    int flags,
    YR_ATOM_LIST_ITEM** atoms);


int yr_atoms_extract_from_string(
    YR_ATOMS_CONFIG* config,
    uint8_t* string,
    int string_length,
    int flags,
    YR_ATOM_LIST_ITEM** atoms);


int yr_atoms_extract_triplets(
    RE_NODE* re_node,
    YR_ATOM_LIST_ITEM** atoms);


int yr_atoms_heuristic_quality(
    YR_ATOMS_CONFIG* config,
    uint8_t* atom,
    int atom_length);


int yr_atoms_table_quality(
    YR_ATOMS_CONFIG* config,
    uint8_t* atom,
    int atom_length);


int yr_atoms_min_quality(
    YR_ATOMS_CONFIG* config,
    YR_ATOM_LIST_ITEM* atom_list);


void yr_atoms_list_destroy(
    YR_ATOM_LIST_ITEM* list_head);

#endif
