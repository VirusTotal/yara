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


#ifndef _ATOMS_H
#define _ATOMS_H

#include "re.h"
#include "yara.h"


#define ATOM_TREE_LEAF  1
#define ATOM_TREE_AND   2
#define ATOM_TREE_OR    3


typedef struct _ATOM_TREE_NODE
{
  uint8_t type;
  uint8_t atom_length;
  uint8_t atom[MAX_ATOM_LENGTH];

  void* forward_code;
  void* backward_code;

  RE_NODE* recent_nodes[MAX_ATOM_LENGTH];

  struct _ATOM_TREE_NODE* children_head;
  struct _ATOM_TREE_NODE* children_tail;
  struct _ATOM_TREE_NODE* next_sibling;

} ATOM_TREE_NODE;


typedef struct _ATOM_TREE
{
  ATOM_TREE_NODE* current_leaf;
  ATOM_TREE_NODE* root_node;

} ATOM_TREE;


int yr_atoms_extract_from_re(
    RE* re,
    int flags,
    ATOM_LIST_ITEM** atoms);

int yr_atoms_extract_from_string(
    char* string,
    int string_length,
    int flags,
    ATOM_LIST_ITEM** atoms);

void yr_atoms_list_destroy(
    ATOM_LIST_ITEM* list_head);

#endif