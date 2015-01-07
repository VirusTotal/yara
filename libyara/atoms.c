/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

/*

This module handles atom extraction from regexps and hex strings. Atoms are
undivided substrings found in a regexps and hex strings. Let's consider this
hex string:

{ 01 02 03 04 05 ?? 06 07 08 [1-2] 09 0A }

In the above string, byte sequences 0102030405, 060708 and 090A are atoms.
Similarly, in this regexp:

/abc.*ed[0-9]+fgh/

The strings "abc", "ed" and "fgh" are atoms.

When searching for regexps/hex strings matching a file, YARA uses these
atoms to find locations inside the file where the regexp/hex string could
match. If the atom "abc" is found somewhere inside the file, there is a chance
for /abc.*ed[0-9]+fgh/ to match the file, if "abc" doesn't appear in the file
there's no chance for the regexp to match. When the atom is found in the file
YARA proceeds to fully evaluate the regexp/hex string to determine if it's
actually a match.

For each regexp/hex string YARA extracts one or more atoms. Sometimes a
single atom is enough (like in the previous example "abc" is enough for finding
/abc.*ed[0-9]+fgh/), but sometimes a single atom isn't enough like in the
regexp /(abc|efg)/. In this case YARA must search for both "abc" AND "efg" and
fully evaluate the regexp whenever one of these atoms is found.

In the regexp /Look(at|into)this/ YARA can search for "Look", or search for
"this", or search for both "at" and "into". This is what we call an atoms tree,
because it can be represented by the following tree structure:

-OR
  |- "Look"
  |
  |- AND
  |   |
  |   |- "at"
  |    - "into"
  |
   - "this"

From an atom tree YARA chooses the best combination, trying to minimize the
number of required atoms, but also using high quality atoms (long atoms with
not too many zeroes and a bit of byte diversity). In the previous example YARA
will end up using the "Look" atom alone, but in /a(bcd|efg)h/ atoms "bcd" and
"efg" will be used because "a" and "h" are too short.

*/

#include <assert.h>
#include <string.h>

#include <yara/utils.h>
#include <yara/atoms.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/error.h>
#include <yara/types.h>


#define append_current_leaf_to_node(node) \
    if (atom_tree->current_leaf != NULL) \
    { \
      _yr_atoms_tree_node_append(node, atom_tree->current_leaf); \
      atom_tree->current_leaf = NULL; \
    } \


//
// _yr_atoms_quality
//
// Returns a numeric value indicating the quality of an atom. The quality
// depends on some characteristics of the atom, including its length, number
// of very common bytes like 00 and FF and number of unique distinct bytes.
// Atom 00 00 has a very low quality, because it's only two bytes long and
// both bytes are zeroes. Atom 01 01 01 01 is better but still not optimal,
// because the same byte is repeated. Atom 01 02 03 04 is an optimal one.
//
// Args:
//    uint8_t* atom   - Pointer to the atom's bytes.
//    int atom_length - Atom's length.
//
// Returns:
//    An integer indicating the atom's quality
//

int _yr_atoms_quality(
    uint8_t* atom,
    int atom_length)
{
  int penalty = 0;
  int unique_bytes = 0;
  int is_unique;
  int i, j;

  for (i = 0; i < atom_length; i++)
  {
    if (atom[i] == 0x00 || atom[i] == 0xFF || atom[i] == 0x20 ||
        atom[i] == 0x0A || atom[i] == 0x0D)
    {
      // Penalize common bytes, specially if they are in the first two positions.

      switch(i)
      {
        case 0:
          penalty += 3;
          break;
        case 1:
          penalty += 2;
          break;
        default:
          penalty += 1;
          break;
      }
    }

    is_unique = TRUE;

    for (j = i + 1; j < atom_length; j++)
      if (atom[i] == atom[j])
      {
        is_unique = FALSE;
        break;
      }

    if (is_unique)
      unique_bytes += 1;
  }

  return atom_length + unique_bytes - penalty;
}

//
// yr_atoms_min_quality
//
// Returns the quality for the worst quality atom in a list.
//

int yr_atoms_min_quality(
    YR_ATOM_LIST_ITEM* atom_list)
{
  YR_ATOM_LIST_ITEM* atom;

  int quality;
  int min_quality = 100000;

  if (atom_list == NULL)
    return 0;

  atom = atom_list;

  while (atom != NULL)
  {
    quality = _yr_atoms_quality(atom->atom, atom->atom_length);

    if (quality < min_quality)
      min_quality = quality;

    atom = atom->next;
  }

  return min_quality;
}


//
// _yr_atoms_tree_node_create
//
// Creates a new node for an atoms tree.
//

ATOM_TREE_NODE* _yr_atoms_tree_node_create(
    uint8_t type)
{
  ATOM_TREE_NODE* new_node;

  new_node = (ATOM_TREE_NODE*) yr_malloc(sizeof(ATOM_TREE_NODE));
  new_node->type = type;
  new_node->atom_length = 0;
  new_node->next_sibling = NULL;
  new_node->children_head = NULL;
  new_node->children_tail = NULL;
  new_node->forward_code = NULL;
  new_node->backward_code = NULL;

  return new_node;
}


//
// _yr_atoms_tree_node_destroy
//
// Destroys a node from an atoms tree.
//

void _yr_atoms_tree_node_destroy(
    ATOM_TREE_NODE* node)
{
  ATOM_TREE_NODE* child;
  ATOM_TREE_NODE* next_child;

  if (node == NULL)
    return;

  if (node->type == ATOM_TREE_OR || node->type == ATOM_TREE_AND)
  {
    child = node->children_head;

    while (child != NULL)
    {
      next_child = child->next_sibling;
      _yr_atoms_tree_node_destroy(child);
      child = next_child;
    }
  }

  yr_free(node);
}


//
// _yr_atoms_tree_node_append
//
// Appends a new child node to another atoms tree node.
//

void _yr_atoms_tree_node_append(
    ATOM_TREE_NODE* dest,
    ATOM_TREE_NODE* node)
{
  if (dest->children_head == NULL)
    dest->children_head = node;

  if (dest->children_tail != NULL)
    dest->children_tail->next_sibling = node;

  dest->children_tail = node;
}


//
// _yr_atoms_tree_destroy
//
// Destroys an atoms tree.
//

void _yr_atoms_tree_destroy(
    ATOM_TREE* atom_tree)
{
  _yr_atoms_tree_node_destroy(atom_tree->root_node);
  yr_free(atom_tree);
}


//
// yr_atoms_list_destroy
//
// Destroys an atoms list.
//

void yr_atoms_list_destroy(
    YR_ATOM_LIST_ITEM* list_head)
{
  YR_ATOM_LIST_ITEM* item = list_head;
  YR_ATOM_LIST_ITEM* next;

  while (item != NULL)
  {
    next = item->next;
    yr_free(item);
    item = next;
  }
}


//
// yr_atoms_list_destroy
//
// Concats two atoms lists.
//

YR_ATOM_LIST_ITEM* _yr_atoms_list_concat(
    YR_ATOM_LIST_ITEM* list1,
    YR_ATOM_LIST_ITEM* list2)
{
  YR_ATOM_LIST_ITEM* item;

  if (list1 == NULL)
    return list2;

  item = list1;

  while (item->next != NULL)
  {
    item = item->next;
  }

  item->next = list2;
  return list1;
}


//
// _yr_atoms_choose
//
// Chooses which atoms from an atoms tree will be used to feed the
// Aho-Corasick automaton, and puts them in a list.
//

int _yr_atoms_choose(
    ATOM_TREE_NODE* node,
    YR_ATOM_LIST_ITEM** choosen_atoms)
{
  ATOM_TREE_NODE* child;
  YR_ATOM_LIST_ITEM* item;
  YR_ATOM_LIST_ITEM* tail;

  int i, quality;
  int max_quality = 0;
  int min_quality = 10000;

  *choosen_atoms = NULL;

  if (node == NULL)
    return 0;

  switch (node->type)
  {
  case ATOM_TREE_LEAF:

    item = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

    for (i = 0; i < node->atom_length; i++)
      item->atom[i] = node->atom[i];

    item->atom_length = node->atom_length;
    item->forward_code = node->forward_code;
    item->backward_code = node->backward_code;
    item->backtrack = 0;
    item->next = NULL;

    *choosen_atoms = item;

    return _yr_atoms_quality(node->atom, node->atom_length);

  case ATOM_TREE_OR:

    child = node->children_head;

    while (child != NULL)
    {
      quality = _yr_atoms_choose(child, &item);

      if (quality > max_quality)
      {
        max_quality = quality;
        yr_atoms_list_destroy(*choosen_atoms);
        *choosen_atoms = item;
      }
      else
      {
        yr_atoms_list_destroy(item);
      }

      child = child->next_sibling;
    }

    return max_quality;

  case ATOM_TREE_AND:

    child = node->children_head;

    while (child != NULL)
    {
      quality = _yr_atoms_choose(child, &item);

      if (quality < min_quality)
        min_quality = quality;

      tail = item;
      while (tail->next != NULL)
        tail = tail->next;

      tail->next = *choosen_atoms;
      *choosen_atoms = item;

      child = child->next_sibling;
    }

    return min_quality;
  }

  return 0;
}


//
// _yr_atoms_case_combinations
//
// Returns all combinations of lower and upper cases for a given atom. For
// atom "abc" the output would be "abc" "abC" "aBC" and so on. Resulting
// atoms are written into the output buffer in this format:
//
//  [size 1] [backtrack 1] [atom 1]  ... [size N] [backtrack N] [atom N] [0]
//
// Notice the zero at the end to indicate where the output ends.
//
// The caller is responsible of providing a buffer large enough to hold the
// returned atoms.
//

uint8_t* _yr_atoms_case_combinations(
    uint8_t* atom,
    int atom_length,
    int atom_offset,
    uint8_t* output_buffer)
{
  uint8_t c;
  uint8_t* new_atom;

  if (atom_offset + 1 < atom_length)
    output_buffer = _yr_atoms_case_combinations(
        atom,
        atom_length,
        atom_offset + 1,
        output_buffer);

  c = atom[atom_offset];

  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
  {
    // Write atom length.
    *((int*) output_buffer) = atom_length;
    output_buffer += sizeof(int);

    memcpy(output_buffer, atom, atom_length);

    new_atom = output_buffer;
    output_buffer += atom_length;

    // Swap character case.
    if (c >= 'a' && c <= 'z')
      new_atom[atom_offset] -= 32;
    else
      new_atom[atom_offset] += 32;

    if (atom_offset + 1 < atom_length)
      output_buffer = _yr_atoms_case_combinations(
          new_atom,
          atom_length,
          atom_offset + 1,
          output_buffer);
  }

  if (atom_offset == 0)
    *((int*) output_buffer) = 0;

  return output_buffer;
}


#define CASE_COMBINATIONS_BUFFER_SIZE \
    MAX_ATOM_LENGTH * MAX_ATOM_LENGTH * MAX_ATOM_LENGTH + \
    MAX_ATOM_LENGTH * MAX_ATOM_LENGTH * sizeof(int) + \
    sizeof(int)

//
// _yr_atoms_case_insentive
//
// For a given list of atoms returns another list of atoms
// with every case combination.
//

int _yr_atoms_case_insentive(
    YR_ATOM_LIST_ITEM* atoms,
    YR_ATOM_LIST_ITEM** case_insensitive_atoms)
{
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* new_atom;

  uint8_t buffer[CASE_COMBINATIONS_BUFFER_SIZE];
  uint8_t* atoms_cursor;

  int i, atom_length;

  *case_insensitive_atoms = NULL;
  atom = atoms;

  while (atom != NULL)
  {
    _yr_atoms_case_combinations(
        atom->atom,
        atom->atom_length,
        0,
        buffer);

    atoms_cursor = buffer;
    atom_length = *((int*) atoms_cursor);
    atoms_cursor += sizeof(int);

    while (atom_length != 0)
    {
      new_atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

      if (new_atom == NULL)
        return ERROR_INSUFICIENT_MEMORY;

      for (i = 0; i < atom_length; i++)
        new_atom->atom[i] = atoms_cursor[i];

      new_atom->atom_length = atom_length;
      new_atom->forward_code = atom->forward_code;
      new_atom->backward_code = atom->backward_code;
      new_atom->backtrack = atom->backtrack;
      new_atom->next = *case_insensitive_atoms;

      *case_insensitive_atoms = new_atom;

      atoms_cursor += atom_length;
      atom_length = *((int*) atoms_cursor);
      atoms_cursor += sizeof(int);
    }

    atom = atom->next;
  }

  return ERROR_SUCCESS;
}


//
// _yr_atoms_wide
//
// For a given list of atoms returns another list with the corresponding
// wide atoms. Wide atoms are just the original atoms with interleaved zeroes,
// for example: 01 02 -> 01 00 02 00
//

int _yr_atoms_wide(
    YR_ATOM_LIST_ITEM* atoms,
    YR_ATOM_LIST_ITEM** wide_atoms)
{
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* new_atom;

  int i;

  *wide_atoms = NULL;
  atom = atoms;

  while (atom != NULL)
  {
    new_atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

    if (new_atom == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    for (i = 0; i < MAX_ATOM_LENGTH; i++)
      new_atom->atom[i] = 0;

    for (i = 0; i < atom->atom_length; i++)
    {
      if (i * 2 < MAX_ATOM_LENGTH)
        new_atom->atom[i * 2] = atom->atom[i];
      else
        break;
    }

    new_atom->atom_length = min(atom->atom_length * 2, MAX_ATOM_LENGTH);
    new_atom->forward_code = atom->forward_code;
    new_atom->backward_code = atom->backward_code;
    new_atom->backtrack = atom->backtrack * 2;
    new_atom->next = *wide_atoms;

    *wide_atoms = new_atom;

    atom = atom->next;
  }

  return ERROR_SUCCESS;
}


//
// _yr_atoms_extract_from_re_node
//
// Extract atoms from a regular expression node. See description for
// _yr_atoms_extract_from_re for more details.
//

ATOM_TREE_NODE* _yr_atoms_extract_from_re_node(
  RE_NODE* re_node,
  ATOM_TREE* atom_tree,
  ATOM_TREE_NODE* current_node)
{
  ATOM_TREE_NODE* left_node;
  ATOM_TREE_NODE* right_node;
  ATOM_TREE_NODE* and_node;
  ATOM_TREE_NODE* current_leaf;
  ATOM_TREE_NODE* temp;

  int quality;
  int new_quality;
  int i;

  uint8_t new_atom[MAX_ATOM_LENGTH];

  switch(re_node->type)
  {
    case RE_NODE_LITERAL:

      if (atom_tree->current_leaf == NULL)
      {
        atom_tree->current_leaf = _yr_atoms_tree_node_create(ATOM_TREE_LEAF);
        atom_tree->current_leaf->forward_code = re_node->forward_code;
        atom_tree->current_leaf->backward_code = re_node->backward_code;
      }

      current_leaf = atom_tree->current_leaf;

      if (current_leaf->atom_length < MAX_ATOM_LENGTH)
      {
        current_leaf->atom[current_leaf->atom_length] = re_node->value;
        current_leaf->recent_nodes[current_leaf->atom_length] = re_node;
        current_leaf->atom_length++;
      }
      else
      {
        for (i = 1; i < MAX_ATOM_LENGTH; i++)
          current_leaf->recent_nodes[i - 1] = current_leaf->recent_nodes[i];

        current_leaf->recent_nodes[MAX_ATOM_LENGTH - 1] = re_node;

        for (i = 0; i < MAX_ATOM_LENGTH; i++)
          new_atom[i] = current_leaf->recent_nodes[i]->value;

        quality = _yr_atoms_quality(
            current_leaf->atom,
            MAX_ATOM_LENGTH);

        new_quality = _yr_atoms_quality(
            new_atom,
            MAX_ATOM_LENGTH);

        if (new_quality > quality)
        {
          for (i = 0; i < MAX_ATOM_LENGTH; i++)
            current_leaf->atom[i] = new_atom[i];

          current_leaf->forward_code = \
              current_leaf->recent_nodes[0]->forward_code;

          current_leaf->backward_code = \
              current_leaf->recent_nodes[0]->backward_code;
        }
      }

      return current_node;

    case RE_NODE_CONCAT:

      current_node = _yr_atoms_extract_from_re_node(
          re_node->left, atom_tree, current_node);
      current_node = _yr_atoms_extract_from_re_node(
          re_node->right, atom_tree, current_node);

      return current_node;

    case RE_NODE_ALT:

      append_current_leaf_to_node(current_node);

      left_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);
      left_node = _yr_atoms_extract_from_re_node(
          re_node->left, atom_tree, left_node);

      append_current_leaf_to_node(left_node);

      if (left_node->children_head == NULL)
      {
        _yr_atoms_tree_node_destroy(left_node);
        return current_node;
      }

      if (left_node->children_head == left_node->children_tail)
      {
        temp = left_node;
        left_node = left_node->children_head;
        yr_free(temp);
      }

      right_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);
      right_node = _yr_atoms_extract_from_re_node(
          re_node->right, atom_tree, right_node);

      append_current_leaf_to_node(right_node);

      if (right_node->children_head == NULL)
      {
        _yr_atoms_tree_node_destroy(left_node);
        _yr_atoms_tree_node_destroy(right_node);
        return current_node;
      }

      if (right_node->children_head == right_node->children_tail)
      {
        temp = right_node;
        right_node = right_node->children_head;
        yr_free(temp);
      }

      and_node = _yr_atoms_tree_node_create(ATOM_TREE_AND);
      and_node->children_head = left_node;
      and_node->children_tail = right_node;
      left_node->next_sibling = right_node;

      _yr_atoms_tree_node_append(current_node, and_node);

      return current_node;

    case RE_NODE_RANGE:

      append_current_leaf_to_node(current_node);

      for (i = 0; i < re_node->start; i++)
      {
        current_node = _yr_atoms_extract_from_re_node(
            re_node->left, atom_tree, current_node);
      }

      if (re_node->start > 0)
        append_current_leaf_to_node(current_node);

      return current_node;

    case RE_NODE_PLUS:

      current_node = _yr_atoms_extract_from_re_node(
          re_node->left, atom_tree, current_node);

      append_current_leaf_to_node(current_node);
      return current_node;

    case RE_NODE_ANY:
    case RE_NODE_STAR:
    case RE_NODE_CLASS:
    case RE_NODE_MASKED_LITERAL:
    case RE_NODE_WORD_CHAR:
    case RE_NODE_NON_WORD_CHAR:
    case RE_NODE_SPACE:
    case RE_NODE_NON_SPACE:
    case RE_NODE_DIGIT:
    case RE_NODE_NON_DIGIT:
    case RE_NODE_EMPTY:
    case RE_NODE_ANCHOR_START:
    case RE_NODE_ANCHOR_END:

      append_current_leaf_to_node(current_node);
      return current_node;

    default:
      assert(FALSE);
  }

  return NULL;
}

//
// yr_atoms_extract_triplets
//
// On certain cases YARA can not extract long enough atoms from a regexp, but
// can infer them. For example, in the hex string { 01 ?? 02 } the only explict
// atoms are 01 and 02, and both of them are too short to be efficiently used.
// However YARA can use simultaneously atoms 01 00 02, 01 01 02, 01 02 02,
// 01 03 02, and so on up to 01 FF 02. Searching for 256 three-bytes atoms is
// faster than searching for a single one-byte atom.
//
// This function extracts these three-bytes atoms from a regexp node if
// possible.
//

int yr_atoms_extract_triplets(
    RE_NODE* re_node,
    YR_ATOM_LIST_ITEM** atoms)
 {
    RE_NODE* left_child;
    RE_NODE* left_grand_child;

    *atoms = NULL;

    if (re_node->type == RE_NODE_CONCAT)
      left_child = re_node->left;
    else
      return ERROR_SUCCESS;

    if (left_child->type == RE_NODE_CONCAT)
      left_grand_child = left_child->left;
    else
      return ERROR_SUCCESS;

    if (re_node->right->type != RE_NODE_LITERAL)
      return yr_atoms_extract_triplets(left_child, atoms);

    if (left_child->left->type == RE_NODE_LITERAL &&
        (left_child->right->type == RE_NODE_ANY))
    {
      int i;
      YR_ATOM_LIST_ITEM* atom;

      for (i = 0; i < 256; i++)
      {
        atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

        if (atom == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        atom->atom[0] = left_child->left->value;
        atom->atom[1] = i;
        atom->atom[2] = re_node->right->value;

        atom->atom_length = 3;
        atom->forward_code = left_child->left->forward_code;
        atom->backward_code = left_child->left->backward_code;
        atom->backtrack = 0;
        atom->next = *atoms;

        *atoms = atom;
      }

      return ERROR_SUCCESS;
    }

    if (left_child->left->type == RE_NODE_LITERAL &&
        (left_child->right->type == RE_NODE_MASKED_LITERAL))
    {
      int i;
      int shift;

      YR_ATOM_LIST_ITEM* atom;

      for (i = 0; i < 16; i++)
      {
        atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

        if (atom == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        if (left_child->right->mask == 0xF0)
          shift = 0;
        else
          shift = 4;

        atom->atom[0] = left_child->left->value;
        atom->atom[1] = left_child->right->value | (i << shift);
        atom->atom[2] = re_node->right->value;

        atom->atom_length = 3;
        atom->forward_code = left_child->left->forward_code;
        atom->backward_code = left_child->left->backward_code;
        atom->backtrack = 0;
        atom->next = *atoms;

        *atoms = atom;
      }

      return ERROR_SUCCESS;
    }

    if (left_grand_child->type == RE_NODE_CONCAT &&
        left_grand_child->right->type == RE_NODE_LITERAL &&
        (left_child->right->type == RE_NODE_ANY))
    {
      int i;
      YR_ATOM_LIST_ITEM* atom;

      for (i = 0; i < 256; i++)
      {
        atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

        if (atom == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        atom->atom[0] = left_grand_child->right->value;
        atom->atom[1] = i;
        atom->atom[2] = re_node->right->value;

        atom->atom_length = 3;
        atom->forward_code = left_grand_child->right->forward_code;
        atom->backward_code = left_grand_child->right->backward_code;
        atom->backtrack = 0;
        atom->next = *atoms;

        *atoms = atom;
      }
      return ERROR_SUCCESS;
    }

    if (left_grand_child->type == RE_NODE_CONCAT &&
        left_grand_child->right->type == RE_NODE_LITERAL &&
        (left_child->right->type == RE_NODE_MASKED_LITERAL))
    {
      int i;
      int shift;

      YR_ATOM_LIST_ITEM* atom;

      for (i = 0; i < 16; i++)
      {
        atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

        if (atom == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        if (left_child->right->mask == 0xF0)
          shift = 0;
        else
          shift = 4;

        atom->atom[0] = left_grand_child->right->value;
        atom->atom[1] = left_child->right->value | (i << shift);
        atom->atom[2] = re_node->right->value;

        atom->atom_length = 3;
        atom->forward_code = left_grand_child->right->forward_code;
        atom->backward_code = left_grand_child->right->backward_code;
        atom->backtrack = 0;
        atom->next = *atoms;

        *atoms = atom;
      }

      return ERROR_SUCCESS;
    }

    return yr_atoms_extract_triplets(left_child, atoms);;
 }

//
// _yr_atoms_extract_from_re
//
// Extract atoms from a regular expression.
//

int yr_atoms_extract_from_re(
    RE* re,
    int flags,
    YR_ATOM_LIST_ITEM** atoms)
{
  ATOM_TREE* atom_tree = (ATOM_TREE*) yr_malloc(sizeof(ATOM_TREE));
  ATOM_TREE_NODE* temp;
  YR_ATOM_LIST_ITEM* wide_atoms;
  YR_ATOM_LIST_ITEM* case_insentive_atoms;
  YR_ATOM_LIST_ITEM* triplet_atoms;

  int min_atom_quality = 0;

  atom_tree->root_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);;
  atom_tree->current_leaf = NULL;

  atom_tree->root_node = _yr_atoms_extract_from_re_node(
      re->root_node, atom_tree, atom_tree->root_node);

  if (atom_tree->current_leaf != NULL)
    _yr_atoms_tree_node_append(atom_tree->root_node, atom_tree->current_leaf);

  if (atom_tree->root_node->children_head ==
      atom_tree->root_node->children_tail)
  {
    // The root OR node has a single child, there's no need for the OR node so
    // we proceed to destroy it and use its child as root.

    temp = atom_tree->root_node;
    atom_tree->root_node = atom_tree->root_node->children_head;
    yr_free(temp);
  }

  // Choose the atoms that will be used.
  min_atom_quality = _yr_atoms_choose(atom_tree->root_node, atoms);

  _yr_atoms_tree_destroy(atom_tree);

  if (min_atom_quality <= 2)
  {
    // Choosen atoms contain low quality ones, let's try infering some higher
    // quality atoms.

    yr_atoms_extract_triplets(re->root_node, &triplet_atoms);

    if (min_atom_quality < yr_atoms_min_quality(triplet_atoms))
    {
      yr_atoms_list_destroy(*atoms);
      *atoms = triplet_atoms;
    }
    else
    {
      yr_atoms_list_destroy(triplet_atoms);
    }
  }

  if (flags & STRING_GFLAGS_WIDE)
  {
    FAIL_ON_ERROR(_yr_atoms_wide(
        *atoms, &wide_atoms));

    if (flags & STRING_GFLAGS_ASCII)
    {
      *atoms = _yr_atoms_list_concat(*atoms, wide_atoms);
    }
    else
    {
      yr_atoms_list_destroy(*atoms);
      *atoms = wide_atoms;
    }
  }

  if (flags & STRING_GFLAGS_NO_CASE)
  {
    FAIL_ON_ERROR(_yr_atoms_case_insentive(
        *atoms, &case_insentive_atoms));

    *atoms = _yr_atoms_list_concat(*atoms, case_insentive_atoms);
  }

  return ERROR_SUCCESS;
}


//
// yr_atoms_extract_from_string
//
// Extract atoms from a string.
//

int yr_atoms_extract_from_string(
    uint8_t* string,
    int string_length,
    int flags,
    YR_ATOM_LIST_ITEM** atoms)
{
  YR_ATOM_LIST_ITEM* item;
  YR_ATOM_LIST_ITEM* case_insentive_atoms;
  YR_ATOM_LIST_ITEM* wide_atoms;

  int max_quality;
  int quality;
  int i, j, length;

  item = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

  if (item == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  item->forward_code = NULL;
  item->backward_code = NULL;
  item->next = NULL;
  item->backtrack = 0;

  length = min(string_length, MAX_ATOM_LENGTH);

  for (i = 0; i < length; i++)
    item->atom[i] = string[i];

  item->atom_length = i;

  max_quality = _yr_atoms_quality(string, length);

  for (i = MAX_ATOM_LENGTH; i < string_length; i++)
  {
    quality = _yr_atoms_quality(
        string + i - MAX_ATOM_LENGTH + 1, MAX_ATOM_LENGTH);

    if (quality > max_quality)
    {
      for (j = 0; j < MAX_ATOM_LENGTH; j++)
        item->atom[j] = string[i + j - MAX_ATOM_LENGTH + 1];

      item->backtrack = i - MAX_ATOM_LENGTH + 1;
      max_quality = quality;
    }
  }

  if (flags & STRING_GFLAGS_WIDE)
  {
    FAIL_ON_ERROR(_yr_atoms_wide(
        item, &wide_atoms));

    if (flags & STRING_GFLAGS_ASCII)
    {
      item = _yr_atoms_list_concat(item, wide_atoms);
    }
    else
    {
      yr_atoms_list_destroy(item);
      item = wide_atoms;
    }
  }

  if (flags & STRING_GFLAGS_NO_CASE)
  {
    FAIL_ON_ERROR(_yr_atoms_case_insentive(
        item, &case_insentive_atoms));

    item = _yr_atoms_list_concat(item, case_insentive_atoms);
  }

  *atoms = item;
  return ERROR_SUCCESS;
}


//
// yr_atoms_tree_node_print
//
// Prints an atom tree node. Used only for debugging purposes.
//

void yr_atoms_tree_node_print(
    ATOM_TREE_NODE* node)
{
  ATOM_TREE_NODE* child;
  int i;

  if (node == NULL)
  {
    printf("Empty tree node\n");
    return;
  }

  switch(node->type)
  {
  case ATOM_TREE_LEAF:
    for (i = 0; i < node->atom_length; i++)
      printf("%02X", node->atom[i]);
    break;

  case ATOM_TREE_AND:
  case ATOM_TREE_OR:
    if (node->type == ATOM_TREE_AND)
      printf("AND");
    else
      printf("OR");
    printf("(");
    child = node->children_head;
    while (child != NULL)
    {
      yr_atoms_tree_node_print(child);
      child = child->next_sibling;
      if (child != NULL)
        printf(",");
    }
    printf(")");
    break;
  }
}
