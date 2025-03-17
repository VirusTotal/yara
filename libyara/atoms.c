/*
Copyright (c) 2013-2018. The YARA Authors. All Rights Reserved.

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
#include <yara/atoms.h>
#include <yara/error.h>
#include <yara/globals.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/stack.h>
#include <yara/types.h>
#include <yara/utils.h>

////////////////////////////////////////////////////////////////////////////////
// Returns a numeric value indicating the quality of an atom. The quality
// depends on some characteristics of the atom, including its length, number
// of very common bytes like 00 and FF and number of unique distinct bytes.
// Atom 00 00 has a very low quality, because it's only two bytes long and
// both bytes are zeroes. Atom 01 01 01 01 is better but still not optimal,
// because the same byte is repeated. Atom 01 02 03 04 is an optimal one.
//
// Args:
//    config: Pointer to YR_ATOMS_CONFIG struct.
//    atom: Pointer to YR_ATOM struct.
//
// Returns:
//    An integer indicating the atom's quality
//
int yr_atoms_heuristic_quality(YR_ATOMS_CONFIG* config, YR_ATOM* atom)
{
  YR_BITMASK seen_bytes[YR_BITMASK_SIZE(256)];

  int quality = 0;
  int unique_bytes = 0;

  assert(atom->length <= YR_MAX_ATOM_LENGTH);

  yr_bitmask_clear_all(seen_bytes);

  // Each byte in the atom contributes a certain amount of points to the
  // quality. Bytes [a-zA-Z] contribute 18 points each, common bytes like
  // 0x00, 0x20 and 0xFF contribute only 12 points, and the rest of the
  // bytes contribute 20 points. The ?? mask substracts 10 points, and masks
  // X? and ?X contribute 4 points. An additional boost consisting in 2x the
  // number of unique bytes in the atom is added to the quality. This are
  // some examples of the quality of atoms:
  //
  //   01 02 03 04   quality = 20 + 20 + 20 + 20 + 8 = 88
  //   01 ?? 03 04   quality = 20 - 10 + 20 + 20 + 6 = 56
  //   01 0? 03      quality = 20 +  4 + 20      + 4 = 48
  //   01 02         quality = 20 + 20           + 4 = 44
  //   01 ?? ?3 04   quality = 20 - 10 +  2 + 20 + 4 = 36
  //   61 62         quality = 18 + 18           + 4 = 40
  //   61 61         quality = 18 + 18           + 2 = 38  <- warning threshold
  //   00 01         quality = 12 + 20           + 4 = 36
  //   01 ?? 02      quality = 20 - 10 + 20      + 4 = 34
  //   01            quality = 20                + 1 = 21

  for (int i = 0; i < atom->length; i++)
  {
    switch (atom->mask[i])
    {
    case 0x00:
      quality -= 10;
      break;
    case 0x0F:
      quality += 4;
      break;
    case 0xF0:
      quality += 4;
      break;
    case 0xFF:
      switch (atom->bytes[i])
      {
      case 0x00:
      case 0x20:
      case 0xCC:
      case 0xFF:
        // Common bytes contribute less to the quality than the rest.
        quality += 12;
        break;
      default:
        // Bytes in the a-z and A-Z ranges have a slightly lower quality
        // than the rest. We want to favor atoms that contain bytes outside
        // those ranges because they generate less additional atoms during
        // calls to _yr_atoms_case_combinations.
        if (yr_lowercase[atom->bytes[i]] >= 'a' &&
            yr_lowercase[atom->bytes[i]] <= 'z')
          quality += 18;
        else
          quality += 20;
      }

      if (!yr_bitmask_is_set(seen_bytes, atom->bytes[i]))
      {
        yr_bitmask_set(seen_bytes, atom->bytes[i]);
        unique_bytes++;
      }
    }
  }

  // If all the bytes in the atom are equal and very common, let's penalize
  // it heavily.
  if (unique_bytes == 1 && (yr_bitmask_is_set(seen_bytes, 0x00) ||
                            yr_bitmask_is_set(seen_bytes, 0x20) ||
                            yr_bitmask_is_set(seen_bytes, 0x90) ||
                            yr_bitmask_is_set(seen_bytes, 0xCC) ||
                            yr_bitmask_is_set(seen_bytes, 0xFF)))
  {
    quality -= 10 * atom->length;
  }
  // In general atoms with more unique bytes have a better quality, so let's
  // boost the quality in the amount of unique bytes.
  else
  {
    quality += 2 * unique_bytes;
  }

  // The final quality is not zero-based, we start at YR_MAX_ATOM_QUALITY
  // for the best possible atom and substract from there. The best possible
  // quality is 21 * YR_MAX_ATOM_LENGTH (20 points per byte + 2 additional point
  // per unique byte, with a maximum of 2*YR_MAX_ATOM_LENGTH unique bytes).

  return YR_MAX_ATOM_QUALITY - 22 * YR_MAX_ATOM_LENGTH + quality;
}

////////////////////////////////////////////////////////////////////////////////
// Compares the byte sequence in a1 with the YR_ATOM in a2, taking atom's mask
// into account.
//
// Returns:
//   < 0 if the first byte that does not match has a lower value in a1 than
//       in a2.
//   > 0 if the first byte that does not match has a greater value in a1 than
//       in a2.
//   = 0 if a1 is equal or matches a2.
//
static int _yr_atoms_cmp(const uint8_t* a1, YR_ATOM* a2)
{
  int result = 0;
  int i = 0;

  while (result == 0 && i < a2->length)
  {
    switch (a2->mask[i])
    {
    case 0xFF:
    case 0x0F:
    case 0xF0:
    case 0x00:
      result = (a1[i] & a2->mask[i]) - a2->bytes[i];
      break;
    default:
      assert(false);
    }

    i++;
  }

  return result;
}

////////////////////////////////////////////////////////////////////////////////
// Returns a numeric value indicating the quality of an atom. The quality is
// based in the atom quality table passed in "config". Very common atoms
// (i.e: those with greater quality) have lower quality than those that are
// uncommon. See the comment for yr_compiler_set_atom_quality_table for
// details about the quality table's format.
//
// Args:
//    YR_ATOMS_CONFIG* config   - Pointer to YR_ATOMS_CONFIG struct.
//    YR_ATOM* atom             - Pointer to YR_ATOM struct.
//
// Returns:
//    An integer indicating the atom's quality
//
int yr_atoms_table_quality(YR_ATOMS_CONFIG* config, YR_ATOM* atom)
{
  YR_ATOM_QUALITY_TABLE_ENTRY* table = config->quality_table;

  int begin = 0;
  int end = config->quality_table_entries;

  assert(atom->length <= YR_MAX_ATOM_LENGTH);

  while (end > begin)
  {
    int middle = begin + (end - begin) / 2;
    int c = _yr_atoms_cmp(table[middle].atom, atom);

    if (c < 0)
    {
      begin = middle + 1;
    }
    else if (c > 0)
    {
      end = middle;
    }
    else
    {
      int i = middle + 1;
      int quality = table[middle].quality;
      int min_quality = quality;

      while (i < end && _yr_atoms_cmp(table[i].atom, atom) == 0)
      {
        if (min_quality > table[i].quality)
          min_quality = table[i].quality;

        i++;
      }

      i = middle - 1;

      while (i >= begin && _yr_atoms_cmp(table[i].atom, atom) == 0)
      {
        if (min_quality > table[i].quality)
          min_quality = table[i].quality;

        i--;
      }

      return min_quality >> (YR_MAX_ATOM_LENGTH - atom->length);
    }
  }

  return YR_MAX_ATOM_QUALITY;
}

////////////////////////////////////////////////////////////////////////////////
// Returns the quality for the worst quality atom in a list.
//
int yr_atoms_min_quality(YR_ATOMS_CONFIG* config, YR_ATOM_LIST_ITEM* atom_list)
{
  YR_ATOM_LIST_ITEM* atom;

  int quality;
  int min_quality = YR_MAX_ATOM_QUALITY;

  if (atom_list == NULL)
    return YR_MIN_ATOM_QUALITY;

  atom = atom_list;

  while (atom != NULL)
  {
    quality = config->get_atom_quality(config, &atom->atom);

    if (quality < min_quality)
      min_quality = quality;

    atom = atom->next;
  }

  return min_quality;
}

////////////////////////////////////////////////////////////////////////////////
// Creates a new node for an atoms tree.
//
static YR_ATOM_TREE_NODE* _yr_atoms_tree_node_create(uint8_t type)
{
  YR_ATOM_TREE_NODE* new_node = (YR_ATOM_TREE_NODE*) yr_malloc(
      sizeof(YR_ATOM_TREE_NODE));

  if (new_node != NULL)
  {
    new_node->type = type;
    new_node->atom.length = 0;
    new_node->next_sibling = NULL;
    new_node->children_head = NULL;
    new_node->children_tail = NULL;
  }

  return new_node;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys a node from an atoms tree.
//
static void _yr_atoms_tree_node_destroy(YR_ATOM_TREE_NODE* node)
{
  YR_ATOM_TREE_NODE* child;
  YR_ATOM_TREE_NODE* next_child;

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

////////////////////////////////////////////////////////////////////////////////
// Appends a new child node to another atoms tree node.
//
static void _yr_atoms_tree_node_append(
    YR_ATOM_TREE_NODE* dest,
    YR_ATOM_TREE_NODE* node)
{
  if (dest->children_head == NULL)
    dest->children_head = node;

  if (dest->children_tail != NULL)
    dest->children_tail->next_sibling = node;

  dest->children_tail = node;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys an atoms tree.
//
static void _yr_atoms_tree_destroy(YR_ATOM_TREE* atom_tree)
{
  _yr_atoms_tree_node_destroy(atom_tree->root_node);
  yr_free(atom_tree);
}

////////////////////////////////////////////////////////////////////////////////
// Destroys an atoms list.
//
void yr_atoms_list_destroy(YR_ATOM_LIST_ITEM* list_head)
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

////////////////////////////////////////////////////////////////////////////////
// Concats two atoms lists.
//
static YR_ATOM_LIST_ITEM* _yr_atoms_list_concat(
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

////////////////////////////////////////////////////////////////////////////////
// If the atom starts or ends with an unknown byte (mask == 0x00), trim
// those bytes out of the atom. We don't want to expand an atom like
// { ?? 01 02 } into { 00 01 02 }, { 01 01 02}, { 02 01 02} .. { FF 01 02}
// in those cases it's better to simply have a shorter atom { 01 02 }.
//
// Args:
//   atom: Pointer to the YR_ATOM to be trimmed.
//
// Returns:
//   The number of bytes that were trimmed from the beginning of the atom.
//
int _yr_atoms_trim(YR_ATOM* atom)
{
  int mask_00 = 0;
  int mask_ff = 0;

  int trim_left = 0;

  while (trim_left < atom->length && atom->mask[trim_left] == 0) trim_left++;

  while (atom->length > trim_left && atom->mask[atom->length - 1] == 0)
    atom->length--;

  atom->length -= trim_left;

  if (atom->length == 0)
    return 0;

  // The trimmed atom goes from trim_left to trim_left + atom->length and the
  // first and last byte in the atom are known (mask == 0xFF). Now count the
  // number of known and unknown bytes in the atom (mask == 0xFF and
  // mask == 0x00 respectively).

  for (int i = 0; i < atom->length; i++)
  {
    if (atom->mask[trim_left + i] == 0xFF)
      mask_ff++;
    else if (atom->mask[trim_left + i] == 0x00)
      mask_00++;
  }

  // If the number of unknown bytes is >= than the number of known bytes
  // it doesn't make sense the to use this atom, so we use a single byte atom
  // containing the first known byte. If YR_MAX_ATOM_LENGTH == 4 this happens
  // only when the atom is like { XX ?? ?? YY }, so using the first known
  // byte is good enough. For larger values of YR_MAX_ATOM_LENGTH this is not
  // the most efficient solution, as better atoms could be choosen. For
  // example, in { XX ?? ?? ?? YY ZZ } the best atom is { YY ZZ } not { XX }.
  // But let's keep it like this for simplicity.

  if (mask_00 >= mask_ff)
    atom->length = 1;

  if (trim_left == 0)
    return 0;

  // Shift bytes and mask trim_left positions to the left.

  for (int i = 0; i < YR_MAX_ATOM_LENGTH - trim_left; i++)
  {
    atom->bytes[i] = atom->bytes[trim_left + i];
    atom->mask[i] = atom->mask[trim_left + i];
  }

  return trim_left;
}

////////////////////////////////////////////////////////////////////////////////
// This function receives an atom tree and returns a list of atoms to be added
// to the Aho-Corasick automaton.
//
static int _yr_atoms_choose(
    YR_ATOMS_CONFIG* config,
    YR_ATOM_TREE_NODE* node,
    YR_ATOM_LIST_ITEM** chosen_atoms,
    int* atoms_quality)
{
  YR_ATOM_TREE_NODE* child;
  YR_ATOM_LIST_ITEM* item;
  YR_ATOM_LIST_ITEM* tail;

  int shift, quality;

  int max_quality = YR_MIN_ATOM_QUALITY;
  int min_quality = YR_MAX_ATOM_QUALITY;

  *chosen_atoms = NULL;
  *atoms_quality = YR_MIN_ATOM_QUALITY;

  switch (node->type)
  {
  case ATOM_TREE_LEAF:

    item = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

    if (item == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    memcpy(&item->atom, &node->atom, sizeof(YR_ATOM));

    shift = _yr_atoms_trim(&item->atom);

    if (item->atom.length > 0)
    {
      item->forward_code_ref = node->re_nodes[shift]->forward_code_ref;
      item->backward_code_ref = node->re_nodes[shift]->backward_code_ref;
      item->backtrack = 0;
      item->next = NULL;

      *chosen_atoms = item;
      *atoms_quality = config->get_atom_quality(config, &item->atom);
    }
    else
    {
      yr_free(item);
    }

    break;

  case ATOM_TREE_OR:

    // The choosen nodes are those coming from the highest quality child.

    child = node->children_head;

    while (child != NULL)
    {
      FAIL_ON_ERROR(_yr_atoms_choose(config, child, &item, &quality));

      if (quality > max_quality)
      {
        max_quality = quality;
        yr_atoms_list_destroy(*chosen_atoms);
        *chosen_atoms = item;
      }
      else
      {
        yr_atoms_list_destroy(item);
      }

      if (max_quality == YR_MAX_ATOM_QUALITY)
        break;

      child = child->next_sibling;
    }

    *atoms_quality = max_quality;
    break;

  case ATOM_TREE_AND:

    // The choosen nodes are the concatenation of the the nodes choosen from
    // all the children.

    child = node->children_head;

    while (child != NULL)
    {
      FAIL_ON_ERROR(_yr_atoms_choose(config, child, &item, &quality));

      if (quality < min_quality)
        min_quality = quality;

      if (item != NULL)
      {
        tail = item;
        while (tail->next != NULL) tail = tail->next;

        tail->next = *chosen_atoms;
        *chosen_atoms = item;
      }

      child = child->next_sibling;
    }

    *atoms_quality = min_quality;
    break;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Returns all combinations of lower and upper cases for a given atom. For
// atom "abc" the output would be "abc" "abC" "aBC" and so on. Resulting
// atoms are written into the output buffer in this format:
//
//  [size of atom 1] [atom 1]  ... [size of atom N] [atom N] [0]
//
// Notice the zero at the end to indicate where the output ends.
//
// The caller is responsible of providing a buffer large enough to hold the
// returned atoms.
//
static uint8_t* _yr_atoms_case_combinations(
    uint8_t* atom,
    int atom_length,
    int atom_offset,
    uint8_t* output_buffer)
{
  uint8_t c;
  uint8_t* new_atom;

  if (atom_offset + 1 < atom_length)
    output_buffer = _yr_atoms_case_combinations(
        atom, atom_length, atom_offset + 1, output_buffer);

  c = atom[atom_offset];

  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
  {
    // Write atom length.
    *output_buffer = atom_length;
    output_buffer++;

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
          new_atom, atom_length, atom_offset + 1, output_buffer);
  }

  if (atom_offset == 0)
    *output_buffer = 0;

  return output_buffer;
}

// Size of buffer used in _yr_atoms_case_insensitive for storing the all
// the possible combinations for an atom. Each atom has up to YR_MAX_ATOM_LENGTH
// characters and each character has two possible values (upper and lower case).
// That means 2 ^ YR_MAX_ATOM_LENGTH combinations for an atom, where each atom
// occupies YR_MAX_ATOM_LENGTH + 1 bytes (the atom itself +1 byte for its
// length). One extra bytes is allocated for the zero value indicating the end.

#define CASE_COMBINATIONS_BUFFER_SIZE \
  (1 << YR_MAX_ATOM_LENGTH) * (YR_MAX_ATOM_LENGTH + 1) + 1

////////////////////////////////////////////////////////////////////////////////
// For a given list of atoms returns another list of atoms
// with every case combination.
//
static int _yr_atoms_case_insensitive(
    YR_ATOM_LIST_ITEM* atoms,
    YR_ATOM_LIST_ITEM** case_insensitive_atoms)
{
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* new_atom;

  uint8_t buffer[CASE_COMBINATIONS_BUFFER_SIZE];
  uint8_t atom_length;
  uint8_t* atoms_cursor;

  int i;

  *case_insensitive_atoms = NULL;
  atom = atoms;

  while (atom != NULL)
  {
    _yr_atoms_case_combinations(atom->atom.bytes, atom->atom.length, 0, buffer);

    atoms_cursor = buffer;
    atom_length = *atoms_cursor;
    atoms_cursor++;

    while (atom_length != 0)
    {
      new_atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

      if (new_atom == NULL)
        return ERROR_INSUFFICIENT_MEMORY;

      for (i = 0; i < atom_length; i++)
      {
        new_atom->atom.bytes[i] = atoms_cursor[i];
        new_atom->atom.mask[i] = 0xFF;
      }

      new_atom->atom.length = atom_length;
      new_atom->forward_code_ref = atom->forward_code_ref;
      new_atom->backward_code_ref = atom->backward_code_ref;
      new_atom->backtrack = atom->backtrack;
      new_atom->next = *case_insensitive_atoms;

      *case_insensitive_atoms = new_atom;

      atoms_cursor += atom_length;
      atom_length = *atoms_cursor;
      atoms_cursor++;
    }

    atom = atom->next;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// For a given list of atoms returns another list after a single byte xor
// has been applied to it.
//
static int _yr_atoms_xor(
    YR_ATOM_LIST_ITEM* atoms,
    uint8_t min,
    uint8_t max,
    YR_ATOM_LIST_ITEM** xor_atoms)
{
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* new_atom;

  int i, j;
  *xor_atoms = NULL;
  atom = atoms;

  while (atom != NULL)
  {
    for (j = min; j <= max; j++)
    {
      new_atom = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

      if (new_atom == NULL)
        return ERROR_INSUFFICIENT_MEMORY;

      for (i = 0; i < atom->atom.length; i++)
      {
        new_atom->atom.bytes[i] = atom->atom.bytes[i] ^ j;
        new_atom->atom.mask[i] = 0xFF;
      }

      new_atom->atom.length = yr_min(atom->atom.length, YR_MAX_ATOM_LENGTH);
      new_atom->forward_code_ref = atom->forward_code_ref;
      new_atom->backward_code_ref = atom->backward_code_ref;
      new_atom->backtrack = atom->backtrack;
      new_atom->next = *xor_atoms;

      *xor_atoms = new_atom;
    }

    atom = atom->next;
  }
  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// For a given list of atoms returns another list with the corresponding
// wide atoms. Wide atoms are just the original atoms with interleaved zeroes,
// for example: 01 02 -> 01 00 02 00
//
static int _yr_atoms_wide(
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
      return ERROR_INSUFFICIENT_MEMORY;

    for (i = 0; i < YR_MAX_ATOM_LENGTH; i++)
    {
      new_atom->atom.bytes[i] = 0;
      new_atom->atom.mask[i] = 0xFF;
    }

    for (i = 0; i < atom->atom.length; i++)
    {
      if (i * 2 < YR_MAX_ATOM_LENGTH)
        new_atom->atom.bytes[i * 2] = atom->atom.bytes[i];
      else
        break;
    }

    new_atom->atom.length = yr_min(atom->atom.length * 2, YR_MAX_ATOM_LENGTH);
    new_atom->forward_code_ref = atom->forward_code_ref;
    new_atom->backward_code_ref = atom->backward_code_ref;
    new_atom->backtrack = atom->backtrack * 2;
    new_atom->next = *wide_atoms;

    *wide_atoms = new_atom;

    atom = atom->next;
  }

  return ERROR_SUCCESS;
}

struct STACK_ITEM
{
  RE_NODE* re_node;
  YR_ATOM_TREE_NODE* new_appending_node;
};

#define make_atom_from_re_nodes(atom, nodes_length, nodes)   \
  {                                                          \
    atom.length = nodes_length;                              \
    for (i = 0; i < atom.length; i++)                        \
    {                                                        \
      atom.bytes[i] = (uint8_t) (recent_re_nodes)[i]->value; \
      atom.mask[i] = (uint8_t) (recent_re_nodes)[i]->mask;   \
    }                                                        \
  }

////////////////////////////////////////////////////////////////////////////////
// Extract atoms from a regular expression. This is a helper function used by
// yr_atoms_extract_from_re that receives the abstract syntax tree for a regexp
// (or hex pattern) and builds an atom tree. The appending_node argument is a
// pointer to the ATOM_TREE_OR node at the root of the atom tree. This function
// creates the tree by appending new nodes to it.
//
static int _yr_atoms_extract_from_re(
    YR_ATOMS_CONFIG* config,
    RE_AST* re_ast,
    YR_ATOM_TREE_NODE* appending_node)
{
  YR_STACK* stack;
  RE_NODE* re_node;

  YR_ATOM atom = {0};
  YR_ATOM best_atom = {0};

  struct STACK_ITEM si;

  int i, shift;
  int quality;
  int best_quality = -1;
  int n = 0;

  YR_ATOM_TREE_NODE* and_node;
  YR_ATOM_TREE_NODE* left_node;
  YR_ATOM_TREE_NODE* right_node;

  // The RE_NODEs most recently visited that can conform an atom (ie:
  // RE_NODE_LITERAL, RE_NODE_MASKED_LITERAL and RE_NODE_ANY). The number of
  // items in this array is n.
  RE_NODE* recent_re_nodes[YR_MAX_ATOM_LENGTH];

  // The RE_NODEs corresponding to the best atom found so far for the current
  // appending node.
  RE_NODE* best_atom_re_nodes[YR_MAX_ATOM_LENGTH];

  // This holds the ATOM_TREE_OR node where leaves (ATOM_TREE_LEAF) are
  // currently being appended.
  YR_ATOM_TREE_NODE* current_appending_node = NULL;

  // This holds the ATOM_TREE_LEAF node whose atom is currently being updated.
  YR_ATOM_TREE_NODE* leaf = NULL;

  FAIL_ON_ERROR(yr_stack_create(1024, sizeof(si), &stack));

  // This first item pushed in the stack is the last one to be poped out, the
  // sole purpose of this item is forcing that any pending leaf is appended to
  // appending_node during the last iteration of the loop.
  si.re_node = NULL;
  si.new_appending_node = appending_node;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_stack_push(stack, (void*) &si), yr_stack_destroy(stack));

  // Start processing the root node.
  si.re_node = re_ast->root_node;

  // Leaf nodes are initially appended to the node passed in the appending_node,
  // argument which is the root ATOM_TREE_OR node that is empty at this point.
  si.new_appending_node = appending_node;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_stack_push(stack, (void*) &si), yr_stack_destroy(stack));

  while (yr_stack_pop(stack, (void*) &si))
  {
    // Change the appending node if the item poped from the stack says so.
    if (si.new_appending_node != NULL)
    {
      // Before changing the appending node let's append any pending leaf to
      // the current appending node.
      if (n > 0)
      {
        make_atom_from_re_nodes(atom, n, recent_re_nodes);
        shift = _yr_atoms_trim(&atom);
        quality = config->get_atom_quality(config, &atom);

        FAIL_ON_NULL_WITH_CLEANUP(
            leaf = _yr_atoms_tree_node_create(ATOM_TREE_LEAF),
            yr_stack_destroy(stack));

        if (quality > best_quality)
        {
          memcpy(&leaf->atom, &atom, sizeof(atom));
          memcpy(
              &leaf->re_nodes,
              &recent_re_nodes[shift],
              sizeof(recent_re_nodes) - shift * sizeof(recent_re_nodes[0]));
        }
        else
        {
          memcpy(&leaf->atom, &best_atom, sizeof(best_atom));
          memcpy(
              &leaf->re_nodes, &best_atom_re_nodes, sizeof(best_atom_re_nodes));
        }

        _yr_atoms_tree_node_append(current_appending_node, leaf);
        n = 0;
      }

      current_appending_node = si.new_appending_node;
      best_quality = -1;
    }

    if (si.re_node != NULL)
    {
      switch (si.re_node->type)
      {
      case RE_NODE_LITERAL:
      case RE_NODE_MASKED_LITERAL:
      case RE_NODE_ANY:

        if (n < YR_MAX_ATOM_LENGTH)
        {
          recent_re_nodes[n] = si.re_node;
          best_atom_re_nodes[n] = si.re_node;
          best_atom.bytes[n] = (uint8_t) si.re_node->value;
          best_atom.mask[n] = (uint8_t) si.re_node->mask;
          best_atom.length = ++n;
        }
        else if (best_quality < YR_MAX_ATOM_QUALITY)
        {
          make_atom_from_re_nodes(atom, n, recent_re_nodes);
          shift = _yr_atoms_trim(&atom);
          quality = config->get_atom_quality(config, &atom);

          if (quality > best_quality)
          {
            for (i = 0; i < atom.length; i++)
            {
              best_atom.bytes[i] = atom.bytes[i];
              best_atom.mask[i] = atom.mask[i];
              best_atom_re_nodes[i] = recent_re_nodes[i + shift];
            }

            best_atom.length = atom.length;
            best_quality = quality;
          }

          for (i = 1; i < YR_MAX_ATOM_LENGTH; i++)
            recent_re_nodes[i - 1] = recent_re_nodes[i];

          recent_re_nodes[YR_MAX_ATOM_LENGTH - 1] = si.re_node;
        }

        break;

      case RE_NODE_CONCAT:

        re_node = si.re_node->children_tail;

        // Push children right to left, they are poped left to right.
        while (re_node != NULL)
        {
          si.new_appending_node = NULL;
          si.re_node = re_node;

          FAIL_ON_ERROR_WITH_CLEANUP(
              yr_stack_push(stack, &si), yr_stack_destroy(stack));

          re_node = re_node->prev_sibling;
        }

        break;

      case RE_NODE_ALT:

        // Create ATOM_TREE_AND node with two ATOM_TREE_OR children nodes.
        and_node = _yr_atoms_tree_node_create(ATOM_TREE_AND);
        left_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);
        right_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);

        if (and_node == NULL || left_node == NULL || right_node == NULL)
        {
          _yr_atoms_tree_node_destroy(and_node);
          _yr_atoms_tree_node_destroy(left_node);
          _yr_atoms_tree_node_destroy(right_node);

          yr_stack_destroy(stack);

          return ERROR_INSUFFICIENT_MEMORY;
        }

        and_node->children_head = left_node;
        and_node->children_tail = right_node;
        left_node->next_sibling = right_node;

        // Add the ATOM_TREE_AND as children of the current node.
        _yr_atoms_tree_node_append(current_appending_node, and_node);

        re_node = si.re_node;

        si.new_appending_node = current_appending_node;
        si.re_node = NULL;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        // RE_NODE_ALT nodes has only two children, so children_head is the
        // left one, and children_tail is right one.
        si.new_appending_node = right_node;
        si.re_node = re_node->children_tail;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        si.new_appending_node = left_node;
        si.re_node = re_node->children_head;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        break;

      case RE_NODE_PLUS:

        re_node = si.re_node;

        si.new_appending_node = current_appending_node;
        si.re_node = NULL;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        si.new_appending_node = NULL;
        // RE_NODE_PLUS nodes has a single child, which is children_head.
        si.re_node = re_node->children_head;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        break;

      case RE_NODE_RANGE:

        re_node = si.re_node;

        si.new_appending_node = current_appending_node;
        si.re_node = NULL;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        si.new_appending_node = NULL;

        // RE_NODE_RANGE nodes has a single child, which is children_head.
        si.re_node = re_node->children_head;

        // In a regexp like /a{10,20}/ the optimal atom is 'aaaa' (assuming
        // that YR_MAX_ATOM_LENGTH = 4) because the 'a' character must appear
        // at least 10 times in the matching string. Each call in the loop
        // will append one 'a' to the atom, so YR_MAX_ATOM_LENGTH iterations
        // are enough.

        for (i = 0; i < yr_min(re_node->start, YR_MAX_ATOM_LENGTH); i++)
        {
          FAIL_ON_ERROR_WITH_CLEANUP(
              yr_stack_push(stack, &si), yr_stack_destroy(stack));
        }

        break;

      case RE_NODE_RANGE_ANY:
      case RE_NODE_STAR:
      case RE_NODE_CLASS:
      case RE_NODE_WORD_CHAR:
      case RE_NODE_NON_WORD_CHAR:
      case RE_NODE_SPACE:
      case RE_NODE_NON_SPACE:
      case RE_NODE_DIGIT:
      case RE_NODE_NON_DIGIT:
      case RE_NODE_EMPTY:
      case RE_NODE_ANCHOR_START:
      case RE_NODE_ANCHOR_END:
      case RE_NODE_WORD_BOUNDARY:
      case RE_NODE_NON_WORD_BOUNDARY:
      case RE_NODE_NOT_LITERAL:
      case RE_NODE_MASKED_NOT_LITERAL:

        si.new_appending_node = current_appending_node;
        si.re_node = NULL;

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_stack_push(stack, &si), yr_stack_destroy(stack));

        break;

      default:
        assert(false);
      }
    }
  }

  yr_stack_destroy(stack);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Makes an exact copy of an YR_ATOM_LIST_ITEM.
//
static YR_ATOM_LIST_ITEM* _yr_atoms_clone_list_item(YR_ATOM_LIST_ITEM* item)
{
  YR_ATOM_LIST_ITEM* clone = (YR_ATOM_LIST_ITEM*) yr_malloc(
      sizeof(YR_ATOM_LIST_ITEM));

  if (clone == NULL)
    return NULL;

  memcpy(clone, item, sizeof(YR_ATOM_LIST_ITEM));

  return clone;
}

////////////////////////////////////////////////////////////////////////////////
// Given list of atoms that may contain wildcards, replace those wildcarded
// atoms with a list of non-wildcarded atoms covering all the combinations
// allowed by the wildcarded atom. For example, the atom {01 ?2 03} will be
// replaced by {01 02 03}, {01 12 03}, {01 22 03} .. {01 F2 03}. The list
// is modified in-place.
//
// Args:
//   atoms: Pointer to first element of the list.
//
// Returns:
//   ERROR_SUCCESS or ERROR_INSUFFICIENT_MEMORY.
//
static int _yr_atoms_expand_wildcards(YR_ATOM_LIST_ITEM* atoms)
{
  int i;

  YR_ATOM_LIST_ITEM* atom = atoms;
  YR_ATOM_LIST_ITEM* new_atom;
  YR_ATOM_LIST_ITEM* prev_atom;
  YR_ATOM_LIST_ITEM* next_atom;

  while (atom != NULL)
  {
    bool expanded = false;

    for (i = 0; i < atom->atom.length; i++)
    {
      uint16_t a, s, e, incr = 1;

      switch (atom->atom.mask[i])
      {
      case 0x00:
        expanded = true;
        s = 0x00;
        e = 0xFF;
        break;

      case 0x0F:
        expanded = true;
        s = atom->atom.bytes[i];
        e = atom->atom.bytes[i] | 0xF0;
        incr = 0x10;
        break;

      case 0xF0:
        expanded = true;
        s = atom->atom.bytes[i];
        e = atom->atom.bytes[i] | 0x0F;
        break;

      default:
        s = 0;
        e = 0;
      }

      if (s != e)
      {
        atom->atom.bytes[i] = (uint8_t) s;
        atom->atom.mask[i] = 0xFF;
      }

      prev_atom = atom;
      next_atom = atom->next;

      for (a = s + incr; a <= e; a += incr)
      {
        new_atom = _yr_atoms_clone_list_item(atom);

        if (new_atom == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        new_atom->atom.bytes[i] = (uint8_t) a;
        new_atom->atom.mask[i] = 0xFF;
        new_atom->next = next_atom;
        prev_atom->next = new_atom;
        prev_atom = new_atom;
      }
    }

    if (!expanded)
      atom = atom->next;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Extract atoms from a regular expression. This function receives the abstract
// syntax tree for a regexp (or hex pattern) and returns a list of atoms that
// should be added to the Aho-Corasick automaton.
//
int yr_atoms_extract_from_re(
    YR_ATOMS_CONFIG* config,
    RE_AST* re_ast,
    YR_MODIFIER modifier,
    YR_ATOM_LIST_ITEM** atoms,
    int* min_atom_quality)
{
  YR_ATOM_TREE* atom_tree = (YR_ATOM_TREE*) yr_malloc(sizeof(YR_ATOM_TREE));

  YR_ATOM_LIST_ITEM* wide_atoms;
  YR_ATOM_LIST_ITEM* case_insensitive_atoms;

  if (atom_tree == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  atom_tree->root_node = _yr_atoms_tree_node_create(ATOM_TREE_OR);

  if (atom_tree->root_node == NULL)
  {
    _yr_atoms_tree_destroy(atom_tree);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  FAIL_ON_ERROR_WITH_CLEANUP(
      _yr_atoms_extract_from_re(config, re_ast, atom_tree->root_node),
      _yr_atoms_tree_destroy(atom_tree));

  // Initialize atom list
  *atoms = NULL;

  // Choose the atoms that will be used.
  FAIL_ON_ERROR_WITH_CLEANUP(
      _yr_atoms_choose(config, atom_tree->root_node, atoms, min_atom_quality),
      _yr_atoms_tree_destroy(atom_tree));

  _yr_atoms_tree_destroy(atom_tree);

  FAIL_ON_ERROR_WITH_CLEANUP(
      _yr_atoms_expand_wildcards(*atoms),
      {  // Cleanup
        yr_atoms_list_destroy(*atoms);
        *atoms = NULL;
      });

  // Don't do convert atoms to wide here if either base64 modifier is used.
  // This is to avoid the situation where we have "base64 wide" because
  // the wide has already been applied BEFORE the base64 encoding.
  if (modifier.flags & STRING_FLAGS_WIDE &&
      !(modifier.flags & STRING_FLAGS_BASE64 ||
        modifier.flags & STRING_FLAGS_BASE64_WIDE))
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        _yr_atoms_wide(*atoms, &wide_atoms),
        {  // Cleanup
          yr_atoms_list_destroy(*atoms);
          yr_atoms_list_destroy(wide_atoms);
          *atoms = NULL;
        });

    if (modifier.flags & STRING_FLAGS_ASCII)
    {
      *atoms = _yr_atoms_list_concat(*atoms, wide_atoms);
    }
    else
    {
      yr_atoms_list_destroy(*atoms);
      *atoms = wide_atoms;
    }
  }

  if (modifier.flags & STRING_FLAGS_NO_CASE)
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        _yr_atoms_case_insensitive(*atoms, &case_insensitive_atoms),
        {  // Cleanup
          yr_atoms_list_destroy(*atoms);
          yr_atoms_list_destroy(case_insensitive_atoms);
          *atoms = NULL;
        });

    *atoms = _yr_atoms_list_concat(*atoms, case_insensitive_atoms);
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Extract atoms from a string.
//
int yr_atoms_extract_from_string(
    YR_ATOMS_CONFIG* config,
    uint8_t* string,
    int32_t string_length,
    YR_MODIFIER modifier,
    YR_ATOM_LIST_ITEM** atoms,
    int* min_atom_quality)
{
  YR_ATOM_LIST_ITEM* item;
  YR_ATOM_LIST_ITEM* case_insensitive_atoms;
  YR_ATOM_LIST_ITEM* xor_atoms;
  YR_ATOM_LIST_ITEM* wide_atoms;

  YR_ATOM atom;

  int quality, max_quality;
  int i;

  item = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

  if (item == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  item->forward_code_ref = YR_ARENA_NULL_REF;
  item->backward_code_ref = YR_ARENA_NULL_REF;
  item->next = NULL;
  item->backtrack = 0;

  item->atom.length = yr_min(string_length, YR_MAX_ATOM_LENGTH);

  for (i = 0; i < item->atom.length; i++)
  {
    item->atom.bytes[i] = string[i];
    item->atom.mask[i] = 0xFF;
  }

  max_quality = config->get_atom_quality(config, &item->atom);

  atom.length = YR_MAX_ATOM_LENGTH;
  memset(atom.mask, 0xFF, atom.length);

  for (i = YR_MAX_ATOM_LENGTH;
       i < string_length && max_quality < YR_MAX_ATOM_QUALITY;
       i++)
  {
    atom.length = YR_MAX_ATOM_LENGTH;
    memcpy(atom.bytes, string + i - YR_MAX_ATOM_LENGTH + 1, atom.length);

    quality = config->get_atom_quality(config, &atom);

    if (quality > max_quality)
    {
      memcpy(&item->atom, &atom, sizeof(atom));
      item->backtrack = i - YR_MAX_ATOM_LENGTH + 1;
      max_quality = quality;
    }
  }

  *atoms = item;
  *min_atom_quality = max_quality;

  if (modifier.flags & STRING_FLAGS_WIDE)
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        _yr_atoms_wide(*atoms, &wide_atoms),
        {  // Cleanup
          yr_atoms_list_destroy(*atoms);
          yr_atoms_list_destroy(wide_atoms);
          *atoms = NULL;
        });

    if (modifier.flags & STRING_FLAGS_ASCII)
    {
      *atoms = _yr_atoms_list_concat(*atoms, wide_atoms);
    }
    else
    {
      yr_atoms_list_destroy(*atoms);
      *atoms = wide_atoms;
    }
  }

  if (modifier.flags & STRING_FLAGS_NO_CASE)
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        _yr_atoms_case_insensitive(*atoms, &case_insensitive_atoms),
        {  // Cleanup
          yr_atoms_list_destroy(*atoms);
          yr_atoms_list_destroy(case_insensitive_atoms);
          *atoms = NULL;
        });

    *atoms = _yr_atoms_list_concat(*atoms, case_insensitive_atoms);
  }

  if (modifier.flags & STRING_FLAGS_XOR)
  {
    FAIL_ON_ERROR_WITH_CLEANUP(
        _yr_atoms_xor(*atoms, modifier.xor_min, modifier.xor_max, &xor_atoms),
        {  // Cleanup
          yr_atoms_list_destroy(*atoms);
          yr_atoms_list_destroy(xor_atoms);
          *atoms = NULL;
        });

    yr_atoms_list_destroy(*atoms);
    *atoms = xor_atoms;
  }

  // Recheck the atom quality, in case we have just generated some poor atoms.
  // https://github.com/VirusTotal/yara/issues/1172
  for (item = *atoms; item != NULL; item = item->next)
  {
    quality = config->get_atom_quality(config, &item->atom);
    if (quality < *min_atom_quality)
      *min_atom_quality = quality;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Prints an atom tree node. Used only for debugging purposes.
//
void yr_atoms_tree_node_print(YR_ATOM_TREE_NODE* node)
{
  YR_ATOM_TREE_NODE* child;

  if (node == NULL)
  {
    printf("Empty tree node\n");
    return;
  }

  switch (node->type)
  {
  case ATOM_TREE_LEAF:
    for (int i = 0; i < node->atom.length; i++)
      printf("%02X", node->atom.bytes[i]);
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
