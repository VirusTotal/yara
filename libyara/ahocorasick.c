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

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/compiler.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/utils.h>

typedef struct _QUEUE_NODE
{
  YR_AC_STATE* value;

  struct _QUEUE_NODE* previous;
  struct _QUEUE_NODE* next;

} QUEUE_NODE;

typedef struct _QUEUE
{
  QUEUE_NODE* head;
  QUEUE_NODE* tail;

} QUEUE;

////////////////////////////////////////////////////////////////////////////////
// Pushes an automaton state into the tail of a queue.
//
// Args:
//   queue: Pointer to the queue.
//   state: Pointer to the state being pushed into the queue.
//
// Returns:
//   ERROR_SUCCESS
//   ERROR_INSUFFICIENT_MEMORY
//
static int _yr_ac_queue_push(QUEUE* queue, YR_AC_STATE* state)
{
  QUEUE_NODE* pushed_node;

  pushed_node = (QUEUE_NODE*) yr_malloc(sizeof(QUEUE_NODE));

  if (pushed_node == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  pushed_node->previous = queue->tail;
  pushed_node->next = NULL;
  pushed_node->value = state;

  if (queue->tail != NULL)
    queue->tail->next = pushed_node;
  else  // queue is empty
    queue->head = pushed_node;

  queue->tail = pushed_node;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Pops an automaton state from the head of a queue.
//
// Args:
//   queue: Pointer to the queue.
//
// Returns:
//   Pointer to the poped state.
//
static YR_AC_STATE* _yr_ac_queue_pop(QUEUE* queue)
{
  YR_AC_STATE* result;
  QUEUE_NODE* popped_node;

  if (queue->head == NULL)
    return NULL;

  popped_node = queue->head;
  queue->head = popped_node->next;

  if (queue->head)
    queue->head->previous = NULL;
  else  // queue is empty
    queue->tail = NULL;

  result = popped_node->value;

  yr_free(popped_node);
  return result;
}

////////////////////////////////////////////////////////////////////////////////
// Checks if a queue is empty.
//
// Args:
//   queue: Pointer to the queue.
//
// Returns:
//   true if queue is empty, false otherwise.
//
static int _yr_ac_queue_is_empty(QUEUE* queue)
{
  return queue->head == NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
// Returns true if the bitmap1 and bitmap2 are the same.
//
static bool _yr_ac_compare_classes(YR_BITMASK* bitmap1, YR_BITMASK* bitmap2)
{
  return memcmp(bitmap1, bitmap2, YR_BITMAP_SIZE * sizeof(YR_BITMASK)) == 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Returns true if the bitmap2 is a subset for bitmap1.
//
static bool _yr_ac_bitmap_subset(YR_BITMASK* bitmap1, YR_BITMASK* bitmap2)
{
  for (int i = 0; i < YR_BITMAP_SIZE; i++)
  {
    if ((bitmap1[i] & bitmap2[i]) != bitmap2[i])
      return false;
  }
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// Given an automaton state and an input symbol, returns the new state
// after reading the input symbol.
//
// Args:
//    state: Pointer to automaton state.
//    state2: Pointer to automaton state with input.
//
// Returns:
//    Pointer to the next automaton state.
//
static YR_AC_STATE* _yr_ac_next_state_bitmap(
    YR_AC_STATE* state,
    YR_AC_STATE* state2)
{
  YR_AC_STATE* next_state = state->first_child;

  while (next_state != NULL)
  {
    switch (next_state->type)
    {
    // Literal - the input byte has to be the same
    case YR_ATOM_TYPE_LITERAL:
      if (state2->type == YR_ATOM_TYPE_LITERAL)
      {
        if (next_state->input == state2->input)
          return next_state;
      }
      break;
    // Atom - accepts everything
    case YR_ATOM_TYPE_ANY:
      return next_state;
    // Class - the input has to be set in the class
    case YR_ATOM_TYPE_CLASS:
      if (state2->type == YR_ATOM_TYPE_LITERAL)
      {
        if (yr_bitmask_is_set(next_state->bitmap, state2->input))
          return next_state;
      }
      else if (state2->type == YR_ATOM_TYPE_CLASS)
      {
        if (_yr_ac_bitmap_subset(next_state->bitmap, state2->bitmap))
          return next_state;
      }
      break;
    }
    next_state = next_state->siblings;
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
// Given an automaton state and an input information, returns the new state.
//
// Args:
//    state: Automaton state
//    input: Input symbol
//    type: Type of input
//    bitmap: Bitmap for input (classes)
//
// Returns:
//    Pointer to the next automaton state.
//
static YR_AC_STATE* _yr_ac_next_state_typed(
    YR_AC_STATE* state,
    uint8_t input,
    uint8_t type,
    YR_BITMASK* bitmap)
{
  YR_AC_STATE* next_state = state->first_child;

  while (next_state != NULL)
  {
    if (next_state->type == type)
    {
      switch (type)
      {
      case YR_ATOM_TYPE_LITERAL:
        if (next_state->input == input)
          return next_state;
        break;
      case YR_ATOM_TYPE_ANY:
        return next_state;
      case YR_ATOM_TYPE_CLASS:
        if (_yr_ac_compare_classes(next_state->bitmap, bitmap))
          return next_state;
        break;
      }
    }
    next_state = next_state->siblings;
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Creates a new automaton state, the automaton will transition from
// the given state to the new state after reading the input symbol.
//
// Args:
//   state: Pointer to the origin state.
//   input: Input symbol.
//   type: Type of the state.
//   bitmap: Input symbols coded in bitmap.
//
// Returns:
//     YR_AC_STATE* pointer to the newly allocated state or NULL in case
//     of error.
static YR_AC_STATE* _yr_ac_state_create_append(
    YR_AC_STATE* state,
    uint8_t input,
    uint8_t type,
    YR_BITMASK* bitmap)
{
  YR_AC_STATE* new_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_state == NULL)
    return NULL;

  new_state->input = input;
  new_state->type = type;
  memcpy(new_state->bitmap, bitmap, sizeof(YR_BITMASK) * YR_BITMAP_SIZE);
  new_state->depth = state->depth + 1;
  new_state->matches_ref = YR_ARENA_NULL_REF;
  new_state->failure = NULL;
  new_state->t_table_slot = 0;
  new_state->first_child = NULL;
  new_state->siblings = NULL;
  if (state->first_child == NULL)
    state->first_child = new_state;
  else
  {
    YR_AC_STATE* help_state;
    help_state = state->first_child;
    while (help_state->siblings != NULL) help_state = help_state->siblings;
    help_state->siblings = new_state;
  }
  new_state->parent = state;

  return new_state;
}

////////////////////////////////////////////////////////////////////////////////
// Creates a new automaton state, the automaton will transition from
// the given state to the new state after reading the input symbol.
//
// Args:
//   state: Origin state
//   input: Input symbol
//   type: Type of the state
//   bitmap: Input symbols coded in bitmap
//
// Returns:
//   YR_AC_STATE* pointer to the newly allocated state or NULL in case
//   of error.
static YR_AC_STATE* _yr_ac_state_create(
    YR_AC_STATE* state,
    uint8_t input,
    uint8_t type,
    YR_BITMASK* bitmap)
{
  YR_AC_STATE* new_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_state == NULL)
    return NULL;

  new_state->input = input;
  new_state->type = type;
  memcpy(new_state->bitmap, bitmap, sizeof(YR_BITMASK) * YR_BITMAP_SIZE);
  new_state->depth = state->depth + 1;
  new_state->matches_ref = YR_ARENA_NULL_REF;
  new_state->failure = NULL;
  new_state->t_table_slot = 0;
  new_state->first_child = NULL;
  new_state->siblings = state->first_child;
  state->first_child = new_state;
  new_state->parent = state;

  return new_state;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys an automaton state.
//
static int _yr_ac_state_destroy(YR_AC_STATE* state)
{
  YR_AC_STATE* child_state = state->first_child;

  while (child_state != NULL)
  {
    YR_AC_STATE* next_child_state = child_state->siblings;
    _yr_ac_state_destroy(child_state);
    child_state = next_child_state;
  }

  yr_free(state);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys an automaton state.
//
static int _yr_ac_state_destroy_updated(YR_AC_STATE* state)
{
  YR_AC_STATE* child_state = state->first_child;

  while (child_state != NULL)
  {
    YR_AC_STATE* next_child_state = child_state->siblings;
    _yr_ac_state_destroy(child_state);
    child_state = next_child_state;
  }

  // The state itself will not be deallocated

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//
// creates a copy of the list of matches and joins it with the list of the state
//
static int _yr_ac_copy_matches(
    YR_AC_STATE* state,
    YR_AC_STATE* copy_state,
    YR_ARENA* matches_arena)
{
  YR_AC_MATCH* match = yr_arena_ref_to_ptr(
      matches_arena, &copy_state->matches_ref);
  YR_ARENA_REF new_match_ref;
  int counter = 0;

  if (match == NULL)
    return ERROR_SUCCESS;

  while (match != NULL)
  {
    counter++;
    match = match->next;
  }

  for (int i = 0; i < counter; i++)
  {
    FAIL_ON_ERROR(yr_arena_allocate_struct(
        matches_arena,
        YR_AC_STATE_MATCHES_POOL,
        sizeof(YR_AC_MATCH),
        &new_match_ref,
        offsetof(YR_AC_MATCH, string),
        offsetof(YR_AC_MATCH, forward_code),
        offsetof(YR_AC_MATCH, backward_code),
        offsetof(YR_AC_MATCH, next),
        EOL));

    YR_AC_MATCH* new_match = yr_arena_ref_to_ptr(matches_arena, &new_match_ref);
    new_match->next = yr_arena_ref_to_ptr(matches_arena, &state->matches_ref);
    state->matches_ref = new_match_ref;
  }

  match = yr_arena_ref_to_ptr(matches_arena, &copy_state->matches_ref);
  YR_AC_MATCH* new_match = yr_arena_ref_to_ptr(
      matches_arena, &state->matches_ref);

  while (match != NULL)
  {
    new_match->backtrack = match->backtrack;
    new_match->string = match->string;
    new_match->forward_code = match->forward_code;
    new_match->backward_code = match->backward_code;

    new_match = new_match->next;
    match = match->next;
  }
  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//
// Creates a new state with values of add_state and creates a new matches list
//
static YR_AC_STATE* _yr_ac_create_copied_state(
    YR_AC_STATE* current_state,
    YR_AC_STATE* add_state,
    YR_ARENA* matches_arena)
{
  YR_AC_STATE* new_state = NULL;

  new_state = _yr_ac_state_create_append(
      current_state, add_state->input, add_state->type, add_state->bitmap);
  new_state->failure = current_state->failure;
  _yr_ac_copy_matches(new_state, add_state, matches_arena);

  return new_state;
}

////////////////////////////////////////////////////////////////////////////////
//
// Creates a copy of subpart of AC automaton starting with state `path` into
// `new_path`. If given `input_char`, it rewrites the input of the state `path`
// with it. Example:
//   o - a - b - c
//    |- d - e - f
//    _yr_ac_copy_path(d, o, k)
//   o - a - b - c
//    |- d - e - f
//    |- k - e - f
//
static void _yr_ac_copy_path(
    YR_AC_STATE* path,
    YR_AC_STATE* new_path,
    YR_AC_STATE* child_state,
    YR_ARENA* arena)
{
  YR_AC_STATE* state;
  YR_AC_STATE* current_state = new_path;
  YR_AC_STATE* new_state = NULL;

  // "root" node
  if (path != NULL)
  {
    if (child_state != NULL)
    {
      new_state = _yr_ac_next_state_typed(
          current_state,
          child_state->input,
          child_state->type,
          child_state->bitmap);
      if (new_state != NULL)
      {
        if (YR_ARENA_IS_NULL_REF(new_state->matches_ref))
          new_state->matches_ref = child_state->matches_ref;
        else
          _yr_ac_copy_matches(new_state, child_state, arena);
      }
    }
    else
    {
      new_state = _yr_ac_next_state_typed(
          current_state, path->input, path->type, path->bitmap);
      if (new_state != NULL)
      {
        if (YR_ARENA_IS_NULL_REF(new_state->matches_ref))
          new_state->matches_ref = path->matches_ref;
        else
          _yr_ac_copy_matches(new_state, path, arena);
      }
    }

    if (new_state == NULL)
    {
      if (child_state != NULL)
        new_state = _yr_ac_create_copied_state(
            current_state, child_state, arena);
      else
        new_state = _yr_ac_create_copied_state(current_state, path, arena);
    }

    // child_state->first_child = path->first_child;
    state = path->first_child;

    while (state != NULL)
    {
      _yr_ac_copy_path(state, new_state, NULL, arena);
      state = state->siblings;
    }
  }
}

static uint8_t num_to_bits[16] =
    {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
static uint8_t num_to_pos[16] =
    {0, 1, 2, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0};

////////////////////////////////////////////////////////////////////////////////
//
// If only one bit is set in the element of array the encoded literal is return.
// If the element is empty, 0 is returned.
// Otherwise, the -1 is returned.
//
static int _yr_ac_return_literal(uint64_t number, uint8_t index)
{
  uint8_t bits;
  uint8_t nibble = 0;
  uint64_t num;
  int result = 0;
  int counter = 0;

  num = number;

  if (0 == num)
    return result;

  for (int i = 0; i < sizeof(uint64_t) * 2; i++)
  {
    // find last nibble
    nibble = num & 0xf;
    bits = num_to_bits[nibble];
    if (bits > 1)
      return -1;
    else if (bits == 1)
    {
      // character decoding (+1 to detect bit on zero position)
      result = (index * YR_BITMASK_SLOT_BITS) + (4 * i + num_to_pos[nibble]);
      counter++;
    }
    num = num >> 4;
  }

  if (counter > 1)
    return -1;
  else
    return result;
}

////////////////////////////////////////////////////////////////////////////////
// If the class represented by the bitmap can be reduced to a literal, return
// that literal, otherwise return -1.
//
// For example, a class like [a] actually contains a single character, and is
// equivalent to literal "a", the class [a-z] however can't be represented by a
// single literal.
//
static int _yr_ac_class_get_literal(YR_BITMASK* bitmap)
{
  int bits = 0;
  int counter = 0;
  int literal = 0;
  int non_literal = -1;

  for (int i = 0; i < YR_BITMAP_SIZE; i++)
  {
    bits = _yr_ac_return_literal(bitmap[i], i);

    if (bits == -1)
      return non_literal;
    else if (bits != 0)
    {
      literal = bits;
      counter++;
    }
  }

  if (counter == 1)
  {
    // _yr_ac_return_literal return literal + 1
    return literal - 1;
  }

  return non_literal;
}

////////////////////////////////////////////////////////////////////////////////
//
// Detect if two states are in a collision for failure function.
// If they are, start to create their deterministic versions - dfa_state1 and
// dfa_state2 If we are changing the inputs of the states, we need later also
// update matches and the children of these states
//
static bool _yr_ac_find_conflict_states(
    YR_AC_STATE* child_state,
    YR_AC_STATE* next_state,
    YR_AC_STATE* dfa_state1,
    YR_AC_STATE* dfa_state2)
{
  // Conflict `[..a..] vs `a` or `.` vs `a`
  if ((next_state->type == YR_ATOM_TYPE_LITERAL) &&
      (yr_bitmask_is_set(child_state->bitmap, next_state->input)))
  {
    // New state with input from next_state
    memcpy(dfa_state1, child_state, sizeof(YR_AC_STATE));
    dfa_state1->input = next_state->input;
    dfa_state1->type = next_state->type;
    memcpy(
        dfa_state1->bitmap,
        next_state->bitmap,
        sizeof(YR_BITMASK) * YR_BITMAP_SIZE);

    // Updated child_state (without input from next_state)
    memcpy(dfa_state2, child_state, sizeof(YR_AC_STATE));
    yr_bitmask_clear(dfa_state2->bitmap, next_state->input);
    if (dfa_state2->type == YR_ATOM_TYPE_CLASS)
    {
      int literal = _yr_ac_class_get_literal(dfa_state2->bitmap);
      if (literal >= 0)
      {
        dfa_state2->input = literal;
        dfa_state2->type = YR_ATOM_TYPE_LITERAL;
      }
    }
    else
    {
      // YR_ATOM_TYPE_ANY -> YR_ATOM_TYPE_CLASS
      dfa_state2->type = YR_ATOM_TYPE_CLASS;
    }
    return false;
  }
  else if (next_state->type == YR_ATOM_TYPE_CLASS)
  {
    // Conflicts `.` vs. [...]
    if (child_state->type == YR_ATOM_TYPE_ANY)
    {
      // New state with input from next_state (class)
      memcpy(dfa_state1, child_state, sizeof(YR_AC_STATE));
      dfa_state1->input = next_state->input;
      dfa_state1->type = next_state->type;
      memcpy(
          dfa_state1->bitmap,
          next_state->bitmap,
          sizeof(YR_BITMASK) * YR_BITMAP_SIZE);

      // Updated child_state (without class from next_state)
      memcpy(dfa_state2, child_state, sizeof(YR_AC_STATE));
      dfa_state2->type = YR_ATOM_TYPE_CLASS;
      for (int i = 0; i < YR_BITMAP_SIZE; i++)
        dfa_state2->bitmap[i] = dfa_state2->bitmap[i] - next_state->bitmap[i];

      int literal = _yr_ac_class_get_literal(dfa_state2->bitmap);
      if (literal >= 0)
      {
        dfa_state2->input = literal;
        dfa_state2->type = YR_ATOM_TYPE_LITERAL;
      }
      return false;
    }  // if (child_state->type == YR_ATOM_TYPE_ANY)
    // Conflicts [...] vs. [...]
    else if (child_state->type == YR_ATOM_TYPE_CLASS)
    {
      int int_counter = 0;
      int diff_counter = 0;
      YR_BITMASK intersetion[YR_BITMAP_SIZE];
      YR_BITMASK diff[YR_BITMAP_SIZE];
      yr_bitmask_clear_all(intersetion, sizeof(intersetion));
      yr_bitmask_clear_all(diff, sizeof(diff));

      for (int i = 0; i < YR_BITMAP_SIZE; i++)
      {
        intersetion[i] = (next_state->bitmap[i] & child_state->bitmap[i]);
        if (intersetion[i] != 0)
          int_counter++;

        diff[i] = child_state->bitmap[i] - intersetion[i];
        if (diff[i] != 0)
          diff_counter++;
      }

      if ((int_counter != 0) && (diff_counter != 0))
      {
        // New state with intersected input from next_state
        memcpy(dfa_state1, child_state, sizeof(YR_AC_STATE));
        memcpy(
            dfa_state1->bitmap,
            intersetion,
            sizeof(YR_BITMASK) * YR_BITMAP_SIZE);
        int literal = _yr_ac_class_get_literal(dfa_state1->bitmap);
        if (literal >= 0)
        {
          dfa_state1->input = literal;
          dfa_state1->type = YR_ATOM_TYPE_LITERAL;
        }

        // Updated child_state (without input from itersection)
        memcpy(dfa_state2, child_state, sizeof(YR_AC_STATE));
        memcpy(dfa_state2->bitmap, diff, sizeof(YR_BITMASK) * YR_BITMAP_SIZE);
        literal = _yr_ac_class_get_literal(dfa_state2->bitmap);
        if (literal >= 0)
        {
          dfa_state2->input = literal;
          dfa_state2->type = YR_ATOM_TYPE_LITERAL;
        }
        return false;
      }
    }  // else if (child_state->type == YR_ATOM_TYPE_CLASS)
  }    // else if (next_state->type == YR_ATOM_TYPE_CLASS)

  return true;
}

////////////////////////////////////////////////////////////////////////////////
//
// In case of collision, some symbols have to be excluded from the state,
// and the copy of the state is created
// dfa_state1 and dfa_state2 are deterministic copies of child_state and state
// that caused the conflics
//
static bool _yr_ac_exclude_from_state(
    YR_AC_STATE* child_state,
    YR_AC_STATE* dfa_state1,
    YR_AC_STATE* dfa_state2,
    YR_ARENA* arena)
{
  YR_AC_STATE* next1 = NULL;
  YR_AC_STATE* next2 = NULL;
  YR_AC_STATE* temp_state;
  YR_AC_STATE* prev_state = NULL;

  next1 = _yr_ac_next_state_typed(
      child_state->parent,
      dfa_state1->input,
      dfa_state1->type,
      dfa_state1->bitmap);
  next2 = _yr_ac_next_state_typed(
      child_state->parent,
      dfa_state2->input,
      dfa_state2->type,
      dfa_state2->bitmap);

  if ((next1 != NULL) && (next2 != NULL))
  {
    // Both version of the child_state already exist in the AC
    _yr_ac_copy_path(child_state, child_state->parent, dfa_state1, arena);
    _yr_ac_copy_path(child_state, child_state->parent, dfa_state2, arena);
    temp_state = child_state->parent->first_child;

    if (temp_state == child_state)
    {
      child_state->parent->first_child = temp_state->siblings;
      _yr_ac_state_destroy_updated(child_state);
      child_state->type = YR_ATOM_TYPE_REMOVE;
      return true;
    }

    while (temp_state != NULL && temp_state != child_state)
    {
      prev_state = temp_state;
      temp_state = temp_state->siblings;
    }

    if (prev_state != NULL)
      prev_state->siblings = temp_state->siblings;

    _yr_ac_state_destroy_updated(child_state);
    child_state->type = YR_ATOM_TYPE_REMOVE;
    return true;
  }
  else if (next2 != NULL)
  {
    // The updated state aleady exists in the AC
    memcpy(child_state, dfa_state1, sizeof(YR_AC_STATE));
    _yr_ac_copy_path(child_state, child_state->parent, dfa_state2, arena);
  }
  else
  {
    // Neither version of the child_state already exist in the AC or there is
    // only literal state
    memcpy(child_state, dfa_state2, sizeof(YR_AC_STATE));
    _yr_ac_copy_path(child_state, child_state->parent, dfa_state1, arena);
  }

  return false;
}

////////////////////////////////////////////////////////////////////////////////
//
// Creates deterministic AC for failure function
//
static bool dfa_subtree(
    YR_AC_STATE* parent_state,
    YR_AC_STATE* child_state,
    YR_ARENA* arena)
{
  bool pop = true;

  // If type of child_state if literal, we do not have to do nothing
  // We return true - we can pop the state from queue and move to another state
  if (child_state->type == YR_ATOM_TYPE_LITERAL)
    return pop;
  else if (child_state->type == YR_ATOM_TYPE_CLASS)
  {
    int literal = _yr_ac_class_get_literal(child_state->bitmap);
    if (literal >= 0)
    {
      child_state->input = literal;
      child_state->type = YR_ATOM_TYPE_LITERAL;
      return pop;
    }
  }

  YR_AC_STATE* next_state = parent_state->first_child;

  // Deterministic version of child_state and next_state
  YR_AC_STATE* dfa_state1 = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));
  YR_AC_STATE* dfa_state2 = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  while (next_state != NULL)
  {
    pop = true;
    // Skip the input state
    if (child_state == next_state)
    {
      next_state = next_state->siblings;
      continue;
    }

    // Find if there are conflicts in failure function
    pop = _yr_ac_find_conflict_states(
        child_state, next_state, dfa_state1, dfa_state2);

    // We found conflicts we need to change the child_state
    if (!pop)
    {
      if (_yr_ac_exclude_from_state(child_state, dfa_state1, dfa_state2, arena))
      {
        yr_free(dfa_state1);
        yr_free(dfa_state2);
        return true;
      }

      // The child_state can not cause any other conflicts anymore
      if (child_state->type == YR_ATOM_TYPE_LITERAL)
        break;
    }

    next_state = next_state->siblings;
  }

  yr_free(dfa_state1);
  yr_free(dfa_state2);

  return pop;
}

////////////////////////////////////////////////////////////////////////////////
//
// Create failure links for each automaton state. This function must
// be called after all the strings have been added to the automaton.
//
static int _yr_ac_create_failure_links(
    YR_AC_AUTOMATON* automaton,
    YR_ARENA* arena)
{
  YR_AC_STATE* current_state;
  YR_AC_STATE* failure_state;
  YR_AC_STATE* temp_state;
  YR_AC_STATE* state;
  YR_AC_STATE* transition_state;
  YR_AC_STATE* root_state;
  YR_AC_STATE* check_state;
  YR_AC_STATE* res_state;
  YR_AC_MATCH* match;

  QUEUE queue;

  queue.head = NULL;
  queue.tail = NULL;

  root_state = automaton->root;

  // Set the failure link of root state to itself.
  root_state->failure = root_state;

  state = root_state->first_child;

  // Check if the root's states are derermnistic
  while (state != NULL)
  {
    dfa_subtree(root_state, state, arena);
    res_state = state;
    state = state->siblings;
    if (res_state->type == YR_ATOM_TYPE_REMOVE)
    {
      yr_free(res_state);
    }
  }

  // Push root's children and set their failure link to root.
  state = root_state->first_child;

  while (state != NULL)
  {
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
    state->failure = root_state;
    state = state->siblings;
  }

  // Traverse the trie in BFS order calculating the failure link
  // for each state.
  while (!_yr_ac_queue_is_empty(&queue))
  {
    current_state = _yr_ac_queue_pop(&queue);
    match = yr_arena_ref_to_ptr(automaton->arena, &current_state->matches_ref);

    if (match != NULL)
    {
      // Find the last match in the list of matches.
      while (match->next != NULL) match = match->next;

      if (match->backtrack > 0)
        match->next = yr_arena_ref_to_ptr(
            automaton->arena, &root_state->matches_ref);
    }
    else
    {
      // This state doesn't have any matches, its matches will be those
      // in the root state, if any.
      current_state->matches_ref = root_state->matches_ref;
    }

    // Check if states are determnistic
    check_state = current_state->first_child;

    while (check_state != NULL)
    {
      dfa_subtree(current_state, check_state, arena);
      res_state = check_state;
      check_state = check_state->siblings;
      if (res_state->type == YR_ATOM_TYPE_REMOVE)
      {
        yr_free(res_state);
      }
    }

    // Iterate over all the states that the current state can transition to.
    transition_state = current_state->first_child;

    while (transition_state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, transition_state));
      failure_state = current_state->failure;

      while (1)
      {
        // Check if states are determnistic
        // If some changes were done to automaton, do not pop (check these
        // states twice)
        if (!dfa_subtree(failure_state, transition_state, arena))
          continue;

        res_state = transition_state;
        if (res_state->type == YR_ATOM_TYPE_REMOVE)
        {
          transition_state = transition_state->siblings;
          yr_free(res_state);
        }

        temp_state = _yr_ac_next_state_bitmap(failure_state, transition_state);

        if (temp_state != NULL)
        {
          transition_state->failure = temp_state;

          if (YR_ARENA_IS_NULL_REF(transition_state->matches_ref))
          {
            transition_state->matches_ref = temp_state->matches_ref;
          }
          else
          {
            _yr_ac_copy_matches(transition_state, temp_state, arena);
          }

          break;
        }
        else
        {
          if (failure_state == root_state)
          {
            transition_state->failure = root_state;
            break;
          }
          else
          {
            failure_state = failure_state->failure;
          }
        }
      }  // while(1)

      transition_state = transition_state->siblings;
    }

  }  // while(!__yr_ac_queue_is_empty(&queue))

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Returns true if the transitions for state s2 are a subset of the transitions
// for state s1. In other words, if at state s2 input X is accepted, it must be
// accepted in s1 too.
//
static bool _yr_ac_transitions_subset(YR_AC_STATE* s1, YR_AC_STATE* s2)
{
  YR_BITMASK set[YR_BITMAP_SIZE];

  YR_AC_STATE* state;

  yr_bitmask_clear_all(set, sizeof(set));

  state = s1->first_child;
  while (state != NULL)
  {
    if (state->type == YR_ATOM_TYPE_LITERAL)
    {
      yr_bitmask_set(set, state->input);
    }
    else
    {
      for (int i = 0; i < YR_BITMAP_SIZE; i++) set[i] |= state->bitmap[i];
    }

    state = state->siblings;
  }

  state = s2->first_child;
  while (state != NULL)
  {
    if (state->type == YR_ATOM_TYPE_LITERAL)
    {
      if (!yr_bitmask_is_set(set, state->input))
        return false;
    }
    else
    {
      for (int i = 0; i < YR_BITMAP_SIZE; i++)
      {
        if ((set[i] & state->bitmap[i]) != state->bitmap[i])
          return false;
      }
    }
    state = state->siblings;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// Removes unnecessary failure links.
//
static int _yr_ac_optimize_failure_links(YR_AC_AUTOMATON* automaton)
{
  QUEUE queue = {NULL, NULL};

  // Push root's children.
  YR_AC_STATE* root_state = automaton->root;
  YR_AC_STATE* state = root_state->first_child;

  while (state != NULL)
  {
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
    state = state->siblings;
  }

  while (!_yr_ac_queue_is_empty(&queue))
  {
    YR_AC_STATE* current_state = _yr_ac_queue_pop(&queue);

    if (current_state->failure != root_state)
    {
      if (_yr_ac_transitions_subset(current_state, current_state->failure))
        current_state->failure = current_state->failure->failure;
    }

    // Push children of current_state
    state = current_state->first_child;

    while (state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
      state = state->siblings;
    }
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Find a place within the automaton's transition table where the transitions
// for the given state can be put. The function first create a bitmask for the
// state's transition table, then searches for an offset within the automaton's
// bitmask where the state's bitmask can be put without bit collisions.
//
static int _yr_ac_find_suitable_transition_table_slot(
    YR_AC_AUTOMATON* automaton,
    YR_ARENA* arena,
    YR_AC_STATE* state,
    uint32_t* slot)
{
  // The state's transition table has 257 entries, 1 for the failure link and
  // 256 for each possible input byte, so the state's bitmask has 257 bits.
  YR_BITMASK state_bitmask[YR_BITMASK_SIZE(257)];

  YR_AC_STATE* child_state = state->first_child;

  // Start with all bits set to zero.
  yr_bitmask_clear_all(state_bitmask, sizeof(state_bitmask));

  // The first slot in the transition table is for the state's failure link,
  // so the first bit in the bitmask must be set to one.
  yr_bitmask_set(state_bitmask, 0);

  while (child_state != NULL)
  {
    if (child_state->type == YR_ATOM_TYPE_LITERAL)
    {
      yr_bitmask_set(state_bitmask, child_state->input + 1);
    }
    else
    {
      for (int i = 0; i < YR_BITMAP_SIZE; i++)
      {
        if (child_state->bitmap[i] != 0)
        {
          for (int k = 0; k < YR_BITMASK_SLOT_BITS; k++)
          {
            if (yr_bitmask_is_set(
                    child_state->bitmap, i * YR_BITMASK_SLOT_BITS + k))
              yr_bitmask_set(state_bitmask, i * YR_BITMASK_SLOT_BITS + k + 1);
          }
        }
      }
    }
    child_state = child_state->siblings;
  }

  *slot = yr_bitmask_find_non_colliding_offset(
      automaton->bitmask,
      state_bitmask,
      automaton->tables_size,
      257,
      &automaton->t_table_unused_candidate);

  // Make sure that we are not going beyond the maximum size of the transition
  // table, starting at the slot found there must be at least 257 other slots
  // for accommodating the state's transition table.
  assert(*slot + 257 < YR_AC_MAX_TRANSITION_TABLE_SIZE);

  if (*slot > automaton->tables_size - 257)
  {
    FAIL_ON_ERROR(yr_arena_allocate_zeroed_memory(
        arena, YR_AC_TRANSITION_TABLE, 257 * sizeof(YR_AC_TRANSITION), NULL));

    FAIL_ON_ERROR(yr_arena_allocate_zeroed_memory(
        arena, YR_AC_STATE_MATCHES_TABLE, 257 * sizeof(uint8_t*), NULL));

    size_t bm_len = YR_BITMASK_SIZE(automaton->tables_size) *
                    sizeof(YR_BITMASK);

    size_t bm_len_incr = YR_BITMASK_SIZE(257) * sizeof(YR_BITMASK);

    automaton->bitmask = yr_realloc(automaton->bitmask, bm_len + bm_len_incr);

    if (automaton->bitmask == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    memset((uint8_t*) automaton->bitmask + bm_len, 0, bm_len_incr);

    automaton->tables_size += 257;
  }

  return ERROR_SUCCESS;
}

static void _yr_ac_add_children_state(
    YR_AC_AUTOMATON* automaton,
    YR_AC_TRANSITION* t_table,
    YR_AC_STATE* state,
    uint32_t slot)
{
  if (state->type == YR_ATOM_TYPE_LITERAL)
  {
    state->t_table_slot = slot + state->input + 1;
    t_table[state->t_table_slot] = YR_AC_MAKE_TRANSITION(0, state->input + 1);
    yr_bitmask_set(automaton->bitmask, state->t_table_slot);
  }
  else
  {
    uint32_t prev = 0;

    for (int i = 0; i < YR_BITMAP_SIZE; i++)
    {
      if (state->bitmap[i] != 0)
      {
        for (int k = 0; k < YR_BITMASK_SLOT_BITS; k++)
        {
          if (yr_bitmask_is_set(state->bitmap, i * YR_BITMASK_SLOT_BITS + k))
          {
            uint32_t input_slot = i * YR_BITMASK_SLOT_BITS + k + 1;
            state->t_table_slot = slot + input_slot;
            t_table[state->t_table_slot] = YR_AC_MAKE_TRANSITION(
                prev, input_slot);
            prev = state->t_table_slot;
            yr_bitmask_set(automaton->bitmask, state->t_table_slot);
          }
        }
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// Builds the transition table for the automaton. The transition table (T) is a
// large array of 32-bits integers. Each state in the automaton is represented
// by an index S within the array. The integer stored in T[S] is the failure
// link for state S, it contains the index of the next state when no valid
// transition exists for the next input byte.
//
// At position T[S+1+B] (where B is a byte) we can find the transition (if any)
// that must be followed from state S if the next input is B. The value in
// T[S+1+B] contains the index for next state or zero. A zero value means that
// no valid transition exists from state S when next input is B, and the failure
// link must be used instead.
//
// The transition table for state S starts at T[S] and spans the next 257
// slots in the array (1 for the failure link and 256 for all the possible
// transitions). But many of those slots are for invalid transitions, so
// the transitions for multiple states can be interleaved as long as they don't
// collide. For example, instead of having this transition table with state S1
// and S2 separated by a large number of slots:
//
// S1                                             S2
// +------+------+------+------+--   ~   --+------+------+------+--   ~   --+
// | FLS1 |   X  |   -  |   -  |     -     |  Y   | FLS2 |   Z  |     -     |
// +------+------+------+------+--   ~   --+------+------+------+--   ~   --+
//
// We can interleave the transitions for states S1 and S2 and get this other
// transition table, which is more compact:
//
// S1            S2
// +------+------+------+------+--   ~   --+------+
// | FLS1 |  X   | FLS2 |   Z  |     -     |  Y   |
// +------+------+------+------+--   ~   --+------+
//
// And how do we know that transition Z belongs to state S2 and not S1? Or that
// transition Y belongs to S1 and not S2? Because each slot of the array not
// only contains the index for the state where the transition points to, it
// also contains the offset of the transition relative to its owner state. So,
// the value for the owner offset would be 1 for transitions X, because X
// belongs to state S1 and it's located 1 position away from S1. The same occurs
// for Z, it belongs to S2 and it's located one position away from S2 so its
// owner offset is 1. If we are in S1 and next byte is 2, we are going to read
// the transition at T[S1+1+2] which is Z. But we know that transition Z is not
// a valid transition for state S1 because the owner offset for Z is 1 not 3.
//
// Each 32-bit slot in the transition table has 23 bits for storing the index
// of the target state and 9 bits for storing the offset of the slot relative
// to its own state. The offset can be any value from 0 to 256, both inclusive,
// hence 9 bits are required for it. The layout for the slot goes like:
//
// 32                      23        0
// +-----------------------+---------+
// | Target state's index  |  Offset |
// +-----------------------+---------+
//
// A more detailed description can be found in: http://goo.gl/lE6zG
//
static int _yr_ac_build_transition_table(YR_AC_AUTOMATON* automaton)
{
  YR_AC_TRANSITION* t_table;
  uint32_t* m_table;
  YR_AC_STATE* state;
  YR_AC_STATE* child_state;
  YR_AC_STATE* root_state = automaton->root;

  uint32_t slot;

  QUEUE queue = {NULL, NULL};

  // Both t_table and m_table have 512 slots initially, which is enough for the
  // root node's transition table.
  automaton->tables_size = 512;

  automaton->bitmask = yr_calloc(
      YR_BITMASK_SIZE(automaton->tables_size), sizeof(YR_BITMASK));

  if (automaton->bitmask == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  FAIL_ON_ERROR(yr_arena_allocate_zeroed_memory(
      automaton->arena,
      YR_AC_TRANSITION_TABLE,
      automaton->tables_size * sizeof(YR_AC_TRANSITION),
      NULL));

  FAIL_ON_ERROR(yr_arena_allocate_zeroed_memory(
      automaton->arena,
      YR_AC_STATE_MATCHES_TABLE,
      automaton->tables_size * sizeof(uint32_t),
      NULL));

  t_table = yr_arena_get_ptr(automaton->arena, YR_AC_TRANSITION_TABLE, 0);
  m_table = yr_arena_get_ptr(automaton->arena, YR_AC_STATE_MATCHES_TABLE, 0);

  // The failure link for the root node points to itself.
  t_table[0] = YR_AC_MAKE_TRANSITION(0, 0);

  // Initialize the entry corresponding to the root node in the match table.
  // Entries in this table are the index within YR_AC_MATCH_POOL where resides
  // the YR_AC_MATCH structure that corresponds to the head of the matches list
  // for the node. The indexes start counting at 1, the zero is used for
  // indicating that the node has no associated matches.
  if (!YR_ARENA_IS_NULL_REF(root_state->matches_ref))
    m_table[0] = root_state->matches_ref.offset / sizeof(YR_AC_MATCH) + 1;

  // Mark the first slot in the transition table as used.
  yr_bitmask_set(automaton->bitmask, 0);

  // Index 0 is for root node. Unused indexes start at 1.
  automaton->t_table_unused_candidate = 1;

  child_state = root_state->first_child;

  while (child_state != NULL)
  {
    _yr_ac_add_children_state(automaton, t_table, child_state, 0);
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));
    child_state = child_state->siblings;
  }

  while (!_yr_ac_queue_is_empty(&queue))
  {
    state = _yr_ac_queue_pop(&queue);

    FAIL_ON_ERROR(_yr_ac_find_suitable_transition_table_slot(
        automaton, automaton->arena, state, &slot));

    // _yr_ac_find_suitable_transition_table_slot can allocate more space in
    // both tables and cause the tables to be moved to a different memory
    // location, we must get their up-to-date addresses.
    t_table = yr_arena_get_ptr(automaton->arena, YR_AC_TRANSITION_TABLE, 0);
    m_table = yr_arena_get_ptr(automaton->arena, YR_AC_STATE_MATCHES_TABLE, 0);

    // 0x1FF = 1 1111 1111
    uint32_t input = 0;
    uint32_t prev = 0;
    do
    {
      input = (t_table[state->t_table_slot] & 0x1FF);
      prev = YR_AC_NEXT_STATE(t_table[state->t_table_slot]);
      t_table[state->t_table_slot] = YR_AC_MAKE_TRANSITION(slot, input);
      state->t_table_slot = prev;
    } while (prev != 0);

    t_table[state->t_table_slot] |= (slot << YR_AC_SLOT_OFFSET_BITS);
    t_table[slot] = YR_AC_MAKE_TRANSITION(state->failure->t_table_slot, 0);

    // The match table is an array of indexes within YR_AC_MATCHES_POOL. The
    // N-th item in the array is the index for the YR_AC_MATCH structure that
    // represents the head of the matches list for state N. The indexes start
    // at 1, the 0 indicates that there are no matches for the state.
    if (YR_ARENA_IS_NULL_REF(state->matches_ref))
      m_table[slot] = 0;
    else
      m_table[slot] = state->matches_ref.offset / sizeof(YR_AC_MATCH) + 1;

    state->t_table_slot = slot;

    yr_bitmask_set(automaton->bitmask, slot);

    // Push children of current_state
    child_state = state->first_child;

    while (child_state != NULL)
    {
      _yr_ac_add_children_state(automaton, t_table, child_state, slot);
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));

      child_state = child_state->siblings;
    }
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Prints automaton state for debug purposes. This function is invoked by
// yr_ac_print_automaton, is not intended to be used stand-alone.
//
static void _yr_ac_print_automaton_state(
    YR_AC_AUTOMATON* automaton,
    YR_AC_STATE* state)
{
  int child_count;

  YR_AC_MATCH* match;
  YR_AC_STATE* child_state;

  for (int i = 0; i < state->depth; i++) printf(" ");

  child_state = state->first_child;
  child_count = 0;

  while (child_state != NULL)
  {
    child_count++;
    child_state = child_state->siblings;
  }

  printf(
      "%p childs:%d depth:%d failure:%p",
      state,
      child_count,
      state->depth,
      state->failure);

  match = yr_arena_ref_to_ptr(automaton->arena, &state->matches_ref);

  while (match != NULL)
  {
    printf("\n");

    for (int i = 0; i < state->depth + 1; i++) printf(" ");

    printf("%s = ", match->string->identifier);

    if (STRING_IS_HEX(match->string))
    {
      printf("{ ");

      for (int i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%02x ", match->string->string[i]);

      printf("}");
    }
    else if (STRING_IS_REGEXP(match->string))
    {
      printf("/");

      for (int i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("/");
    }
    else
    {
      printf("\"");

      for (int i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("\"");
    }

    match = match->next;
  }

  printf("\n");

  child_state = state->first_child;

  while (child_state != NULL)
  {
    _yr_ac_print_automaton_state(automaton, child_state);
    child_state = child_state->siblings;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Creates a new automaton
//
int yr_ac_automaton_create(YR_ARENA* arena, YR_AC_AUTOMATON** automaton)
{
  YR_AC_AUTOMATON* new_automaton;
  YR_AC_STATE* root_state;

  new_automaton = (YR_AC_AUTOMATON*) yr_malloc(sizeof(YR_AC_AUTOMATON));
  root_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));
  yr_bitmask_clear_all(root_state->bitmap, sizeof(root_state->bitmap));
  root_state->input = 0;
  root_state->type = 0xDD;

  if (new_automaton == NULL || root_state == NULL)
  {
    yr_free(new_automaton);
    yr_free(root_state);

    return ERROR_INSUFFICIENT_MEMORY;
  }

  root_state->depth = 0;
  root_state->matches_ref = YR_ARENA_NULL_REF;
  root_state->failure = NULL;
  root_state->first_child = NULL;
  root_state->siblings = NULL;
  root_state->parent = NULL;
  root_state->t_table_slot = 0;

  new_automaton->arena = arena;
  new_automaton->root = root_state;
  new_automaton->bitmask = NULL;
  new_automaton->tables_size = 0;

  *automaton = new_automaton;

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Destroys automaton
//
int yr_ac_automaton_destroy(YR_AC_AUTOMATON* automaton)
{
  _yr_ac_state_destroy(automaton->root);

  yr_free(automaton->bitmask);
  yr_free(automaton);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Adds a string to the automaton. This function is invoked once for each
// string defined in the rules.
//
int yr_ac_add_string(
    YR_AC_AUTOMATON* automaton,
    YR_STRING* string,
    uint32_t string_idx,
    YR_ATOM_LIST_ITEM* atom,
    YR_ARENA* arena)
{
  YR_AC_STATE* next_state = NULL;
  while (atom != NULL)
  {
    YR_AC_STATE* state = automaton->root;

    for (int i = 0; i < atom->atom.length; i++)
    {
      int literal = -1;
      if (atom->atom.mask[i] == YR_ATOM_TYPE_CLASS)
      {
        // for a case like [a] - the class is a literal
        literal = _yr_ac_class_get_literal(atom->atom.bitmap[i]);
      }

      if (literal >= 0)
        next_state = _yr_ac_next_state_typed(
            state, literal, YR_ATOM_TYPE_LITERAL, atom->atom.bitmap[i]);
      else
        next_state = _yr_ac_next_state_typed(
            state,
            atom->atom.bytes[i],
            atom->atom.mask[i],
            atom->atom.bitmap[i]);

      if (next_state == NULL)
      {
        next_state = _yr_ac_state_create(
            state,
            atom->atom.bytes[i],
            atom->atom.mask[i],
            atom->atom.bitmap[i]);

        if (next_state == NULL)
          return ERROR_INSUFFICIENT_MEMORY;
      }

      state = next_state;
    }

    YR_ARENA_REF new_match_ref;

    FAIL_ON_ERROR(yr_arena_allocate_struct(
        arena,
        YR_AC_STATE_MATCHES_POOL,
        sizeof(YR_AC_MATCH),
        &new_match_ref,
        offsetof(YR_AC_MATCH, string),
        offsetof(YR_AC_MATCH, forward_code),
        offsetof(YR_AC_MATCH, backward_code),
        offsetof(YR_AC_MATCH, next),
        EOL));

    YR_AC_MATCH* new_match = yr_arena_ref_to_ptr(arena, &new_match_ref);

    new_match->backtrack = state->depth + atom->backtrack;
    new_match->string = yr_arena_get_ptr(
        arena, YR_STRINGS_TABLE, string_idx * sizeof(struct YR_STRING));

    new_match->forward_code = yr_arena_ref_to_ptr(
        arena, &atom->forward_code_ref);

    new_match->backward_code = yr_arena_ref_to_ptr(
        arena, &atom->backward_code_ref);

    // Add newly created match to the list of matches for the state.
    new_match->next = yr_arena_ref_to_ptr(arena, &state->matches_ref);
    state->matches_ref = new_match_ref;

    atom = atom->next;
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Compiles the Aho-Corasick automaton, the resulting data structures are
// are written in the provided arena.
//
int yr_ac_compile(YR_AC_AUTOMATON* automaton, YR_ARENA* arena)
{
  FAIL_ON_ERROR(_yr_ac_create_failure_links(automaton, arena));
  FAIL_ON_ERROR(_yr_ac_optimize_failure_links(automaton));
  FAIL_ON_ERROR(_yr_ac_build_transition_table(automaton));

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Prints automaton for debug purposes.
//
void yr_ac_print_automaton(YR_AC_AUTOMATON* automaton)
{
  printf("-------------------------------------------------------\n");
  _yr_ac_print_automaton_state(automaton, automaton->root);
  printf("-------------------------------------------------------\n");
}
