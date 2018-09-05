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

#include <yara/arena.h>
#include <yara/ahocorasick.h>
#include <yara/error.h>
#include <yara/utils.h>
#include <yara/mem.h>



typedef struct _QUEUE_NODE
{
  YR_AC_STATE* value;

  struct _QUEUE_NODE*  previous;
  struct _QUEUE_NODE*  next;

} QUEUE_NODE;


typedef struct _QUEUE
{
  QUEUE_NODE* head;
  QUEUE_NODE* tail;

} QUEUE;


//
// _yr_ac_queue_push
//
// Pushes a state in a queue.
//
// Args:
//    QUEUE* queue     - The queue
//    YR_AC_STATE* state  - The state
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

static int _yr_ac_queue_push(
    QUEUE* queue,
    YR_AC_STATE* value)
{
  QUEUE_NODE* pushed_node;

  pushed_node = (QUEUE_NODE*) yr_malloc(sizeof(QUEUE_NODE));

  if (pushed_node == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  pushed_node->previous = queue->tail;
  pushed_node->next = NULL;
  pushed_node->value = value;

  if (queue->tail != NULL)
    queue->tail->next = pushed_node;
  else // queue is empty
    queue->head = pushed_node;

  queue->tail = pushed_node;

  return ERROR_SUCCESS;
}


//
// _yr_ac_queue_pop
//
// Pops a state from a queue.
//
// Args:
//    QUEUE* queue     - The queue
//
// Returns:
//    Pointer to the poped state.
//

static YR_AC_STATE* _yr_ac_queue_pop(
    QUEUE* queue)
{
  YR_AC_STATE* result;
  QUEUE_NODE* popped_node;

  if (queue->head == NULL)
    return NULL;

  popped_node = queue->head;
  queue->head = popped_node->next;

  if (queue->head)
    queue->head->previous = NULL;
  else // queue is empty
    queue->tail = NULL;

  result = popped_node->value;

  yr_free(popped_node);
  return result;
}


//
// _yr_ac_queue_is_empty
//
// Checks if a queue is empty.
//
// Args:
//    QUEUE* queue     - The queue
//
// Returns:
//    true if queue is empty, false otherwise.
//

static int _yr_ac_queue_is_empty(
    QUEUE* queue)
{
  return queue->head == NULL;
}


//
// _yr_ac_next_state
//
// Given an automaton state and an input symbol, returns the new state
// after reading the input symbol.
//
// Args:
//    YR_AC_STATE* state     - Automaton state
//    uint8_t input       - Input symbol
//
// Returns:
//   Pointer to the next automaton state.
//

static YR_AC_STATE* _yr_ac_next_state(
    YR_AC_STATE* state,
    uint8_t input)
{
  YR_AC_STATE* next_state = state->first_child;

  while (next_state != NULL)
  {
    if (next_state->input == input)
      return next_state;

    next_state = next_state->siblings;
  }

  return NULL;
}


//
// _yr_ac_state_create
//
// Creates a new automaton state, the automaton will transition from
// the given state to the new state after reading the input symbol.
//
// Args:
//   YR_AC_STATE* state  - Origin state
//   uint8_t input       - Input symbol
//
// Returns:
//   YR_AC_STATE* pointer to the newly allocated state or NULL in case
//   of error.

static YR_AC_STATE* _yr_ac_state_create(
    YR_AC_STATE* state,
    uint8_t input)
{
  YR_AC_STATE* new_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_state == NULL)
    return NULL;

  new_state->input = input;
  new_state->depth = state->depth + 1;
  new_state->matches = NULL;
  new_state->failure = NULL;
  new_state->t_table_slot = 0;
  new_state->first_child = NULL;
  new_state->siblings = state->first_child;
  state->first_child = new_state;

  return new_state;
}


//
// _yr_ac_state_destroy
//

static int _yr_ac_state_destroy(
    YR_AC_STATE* state)
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


//
// _yr_ac_create_failure_links
//
// Create failure links for each automaton state. This function must
// be called after all the strings have been added to the automaton.
//

static int _yr_ac_create_failure_links(
    YR_AC_AUTOMATON* automaton)
{
  YR_AC_STATE* current_state;
  YR_AC_STATE* failure_state;
  YR_AC_STATE* temp_state;
  YR_AC_STATE* state;
  YR_AC_STATE* transition_state;
  YR_AC_STATE* root_state;
  YR_AC_MATCH* match;

  QUEUE queue;

  queue.head = NULL;
  queue.tail = NULL;

  root_state = automaton->root;

  // Set the failure link of root state to itself.
  root_state->failure = root_state;

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

    match = current_state->matches;

    if (match != NULL)
    {
      while (match->next != NULL)
        match = match->next;

      if (match->backtrack > 0)
        match->next = root_state->matches;
    }
    else
    {
      current_state->matches = root_state->matches;
    }

    transition_state = current_state->first_child;

    while (transition_state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, transition_state));
      failure_state = current_state->failure;

      while (1)
      {
        temp_state = _yr_ac_next_state(
            failure_state, transition_state->input);

        if (temp_state != NULL)
        {
          transition_state->failure = temp_state;

          if (transition_state->matches == NULL)
          {
            transition_state->matches = temp_state->matches;
          }
          else
          {
            match = transition_state->matches;

            while (match != NULL && match->next != NULL)
              match = match->next;

            match->next = temp_state->matches;
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
      } // while(1)

      transition_state = transition_state->siblings;
    }

  } // while(!__yr_ac_queue_is_empty(&queue))

  return ERROR_SUCCESS;
}


//
// _yr_ac_transitions_subset
//
// Returns true if the transitions for state s2 are a subset of the transitions
// for state s1. In other words, if at state s2 input X is accepted, it must be
// accepted in s1 too.
//

static bool _yr_ac_transitions_subset(
    YR_AC_STATE* s1,
    YR_AC_STATE* s2)
{
  uint8_t set[32];

  YR_AC_STATE* state = s1->first_child;

  memset(set, 0, 32);

  while (state != NULL)
  {
    set[state->input / 8] |= 1 << state->input % 8;
    state = state->siblings;
  }

  state = s2->first_child;

  while (state != NULL)
  {
    if (!(set[state->input / 8] & 1 << state->input % 8))
      return false;

    state = state->siblings;
  }

  return true;
}


//
// _yr_ac_optimize_failure_links
//
// Removes unnecessary failure links.
//

static int _yr_ac_optimize_failure_links(
    YR_AC_AUTOMATON* automaton)
{
  QUEUE queue = { NULL, NULL};

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

    // Push childrens of current_state
    state = current_state->first_child;

    while (state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
      state = state->siblings;
    }
  }

  return ERROR_SUCCESS;
}


//
// _yr_ac_find_suitable_transition_table_slot
//
// Find a place within the automaton's transition table where the transitions
// for the given state can be put. The function first create a bitmask for the
// state's transition table, then searches for an offset within the automaton's
// bitmask where the state's bitmask can be put without bit collisions.
//

static int _yr_ac_find_suitable_transition_table_slot(
    YR_AC_AUTOMATON* automaton,
    YR_AC_STATE* state,
    uint32_t* slot)
{
  // The state's transition table has 257 entries, 1 for the failure link and
  // 256 for each possible input byte, so the state's bitmask has 257 bits.
  YR_BITMASK state_bitmask[YR_BITMASK_SIZE(257)];

  YR_AC_STATE* child_state = state->first_child;

  // Start with all bits set to zero.
  yr_bitmask_clear_all(state_bitmask);

  // The first slot in the transition table is for the state's failure link,
  // so the first bit in the bitmask must be set to one.
  yr_bitmask_set(state_bitmask, 0);

  while (child_state != NULL)
  {
    yr_bitmask_set(state_bitmask, child_state->input + 1);
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
      size_t t_bytes_size = automaton->tables_size *
          sizeof(YR_AC_TRANSITION);

      size_t m_bytes_size = automaton->tables_size *
          sizeof(YR_AC_MATCH_TABLE_ENTRY);

      size_t b_bytes_size = YR_BITMASK_SIZE(automaton->tables_size) *
           sizeof(YR_BITMASK);

      automaton->t_table = (YR_AC_TRANSITION_TABLE) yr_realloc(
          automaton->t_table, t_bytes_size * 2);

      automaton->m_table = (YR_AC_MATCH_TABLE) yr_realloc(
          automaton->m_table, m_bytes_size * 2);

      automaton->bitmask = (YR_BITMASK*) yr_realloc(
          automaton->bitmask, b_bytes_size * 2);
      
      if (automaton->t_table == NULL ||
          automaton->m_table == NULL ||
          automaton->bitmask == NULL)
      {
        return ERROR_INSUFFICIENT_MEMORY;
      }

      memset((uint8_t*) automaton->t_table + t_bytes_size, 0, t_bytes_size);
      memset((uint8_t*) automaton->m_table + m_bytes_size, 0, m_bytes_size);
      memset((uint8_t*) automaton->bitmask + b_bytes_size, 0, b_bytes_size);

      automaton->tables_size *= 2;
  }

  return ERROR_SUCCESS;
}

//
// _yr_ac_build_transition_table
//
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


static int _yr_ac_build_transition_table(
    YR_AC_AUTOMATON* automaton)
{
  YR_AC_STATE* state;
  YR_AC_STATE* child_state;
  YR_AC_STATE* root_state = automaton->root;

  uint32_t slot;

  QUEUE queue = { NULL, NULL};

  automaton->tables_size = 1024;

  automaton->t_table = (YR_AC_TRANSITION_TABLE) yr_calloc(
      automaton->tables_size, sizeof(YR_AC_TRANSITION));

  automaton->m_table = (YR_AC_MATCH_TABLE) yr_calloc(
      automaton->tables_size, sizeof(YR_AC_MATCH_TABLE_ENTRY));

  automaton->bitmask = (YR_BITMASK*) yr_calloc(
      YR_BITMASK_SIZE(automaton->tables_size), sizeof(YR_BITMASK));

  if (automaton->t_table == NULL || 
      automaton->m_table == NULL ||
      automaton->bitmask == NULL)
  {
    yr_free(automaton->t_table);
    yr_free(automaton->m_table);
    yr_free(automaton->bitmask);

    return ERROR_INSUFFICIENT_MEMORY;
  }

  automaton->t_table[0] = YR_AC_MAKE_TRANSITION(0, 0);
  automaton->m_table[0].match = root_state->matches;

  yr_bitmask_set(automaton->bitmask, 0);

  // Index 0 is for root node. Unused indexes start at 1.
  automaton->t_table_unused_candidate = 1;

  child_state = root_state->first_child;

  while (child_state != NULL)
  {
    child_state->t_table_slot = child_state->input + 1;
    automaton->t_table[child_state->input + 1] = YR_AC_MAKE_TRANSITION(
        0, child_state->input + 1);

    yr_bitmask_set(automaton->bitmask, child_state->input + 1);

    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));
    child_state = child_state->siblings;
  }

  while (!_yr_ac_queue_is_empty(&queue))
  {
    state = _yr_ac_queue_pop(&queue);

    FAIL_ON_ERROR(_yr_ac_find_suitable_transition_table_slot(
        automaton, state, &slot));

    automaton->t_table[state->t_table_slot] |= (slot << YR_AC_SLOT_OFFSET_BITS);

    state->t_table_slot = slot;

    automaton->t_table[slot] = YR_AC_MAKE_TRANSITION(
        state->failure->t_table_slot, 0);

    yr_bitmask_set(automaton->bitmask, slot);

    automaton->m_table[slot].match = state->matches;

    // Push childrens of current_state

    child_state = state->first_child;

    while (child_state != NULL)
    {
      child_state->t_table_slot = slot + child_state->input + 1;
      automaton->t_table[child_state->t_table_slot] = YR_AC_MAKE_TRANSITION(
          0, child_state->input + 1);

      yr_bitmask_set(automaton->bitmask, child_state->t_table_slot);

      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));

      child_state = child_state->siblings;
    }
  }

  return ERROR_SUCCESS;
}


//
// _yr_ac_print_automaton_state
//
// Prints automaton state for debug purposes. This function is invoked by
// yr_ac_print_automaton, is not intended to be used stand-alone.
//

static void _yr_ac_print_automaton_state(
    YR_AC_STATE* state)
{
  int i;
  int child_count;

  YR_AC_MATCH* match;
  YR_AC_STATE* child_state;

  for (i = 0; i < state->depth; i++)
    printf(" ");

  child_state = state->first_child;
  child_count = 0;

  while(child_state != NULL)
  {
    child_count++;
    child_state = child_state->siblings;
  }

  printf("%p childs:%d depth:%d failure:%p",
         state, child_count, state->depth, state->failure);

  match = state->matches;

  while (match != NULL)
  {
    printf("\n");

    for (i = 0; i < state->depth + 1; i++)
      printf(" ");

    printf("%s = ", match->string->identifier);

    if (STRING_IS_HEX(match->string))
    {
      printf("{ ");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%02x ", match->string->string[i]);

      printf("}");
    }
    else if (STRING_IS_REGEXP(match->string))
    {
      printf("/");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("/");
    }
    else
    {
      printf("\"");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("\"");
    }

    match = match->next;
  }

  printf("\n");

  child_state = state->first_child;

  while(child_state != NULL)
  {
    _yr_ac_print_automaton_state(child_state);
    child_state = child_state->siblings;
  }
}


//
// yr_ac_automaton_create
//
// Creates a new automaton
//

int yr_ac_automaton_create(
    YR_AC_AUTOMATON** automaton)
{
  YR_AC_AUTOMATON* new_automaton;
  YR_AC_STATE* root_state;

  new_automaton = (YR_AC_AUTOMATON*) yr_malloc(sizeof(YR_AC_AUTOMATON));
  root_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_automaton == NULL || root_state == NULL)
  {
    yr_free(new_automaton);
    yr_free(root_state);

    return ERROR_INSUFFICIENT_MEMORY;
  }

  root_state->depth = 0;
  root_state->matches = NULL;
  root_state->failure = NULL;
  root_state->first_child = NULL;
  root_state->siblings = NULL;
  root_state->t_table_slot = 0;

  new_automaton->root = root_state;
  new_automaton->m_table = NULL;
  new_automaton->t_table = NULL;
  new_automaton->bitmask = NULL;
  new_automaton->tables_size = 0;

  *automaton = new_automaton;

  return ERROR_SUCCESS;
}


//
// yr_ac_automaton_destroy
//
// Destroys automaton
//

int yr_ac_automaton_destroy(
    YR_AC_AUTOMATON* automaton)
{
  _yr_ac_state_destroy(automaton->root);

  yr_free(automaton->t_table);
  yr_free(automaton->m_table);
  yr_free(automaton->bitmask);
  yr_free(automaton);

  return ERROR_SUCCESS;
}


//
// yr_ac_add_string
//
// Adds a string to the automaton. This function is invoked once for each
// string defined in the rules.
//

int yr_ac_add_string(
    YR_AC_AUTOMATON* automaton,
    YR_STRING* string,
    YR_ATOM_LIST_ITEM* atom,
    YR_ARENA* matches_arena)
{
  int result = ERROR_SUCCESS;
  int i;

  YR_AC_STATE* state;
  YR_AC_STATE* next_state;
  YR_AC_MATCH* new_match;

  // For each atom create the states in the automaton.

  while (atom != NULL)
  {
    state = automaton->root;

    for (i = 0; i < atom->atom_length; i++)
    {
      next_state = _yr_ac_next_state(state, atom->atom[i]);

      if (next_state == NULL)
      {
        next_state = _yr_ac_state_create(state, atom->atom[i]);

        if (next_state == NULL)
          return ERROR_INSUFFICIENT_MEMORY;
      }

      state = next_state;
    }

    result = yr_arena_allocate_struct(
        matches_arena,
        sizeof(YR_AC_MATCH),
        (void**) &new_match,
        offsetof(YR_AC_MATCH, string),
        offsetof(YR_AC_MATCH, forward_code),
        offsetof(YR_AC_MATCH, backward_code),
        offsetof(YR_AC_MATCH, next),
        EOL);

    if (result == ERROR_SUCCESS)
    {
      new_match->backtrack = state->depth + atom->backtrack;
      new_match->string = string;
      new_match->forward_code = atom->forward_code;
      new_match->backward_code = atom->backward_code;
      new_match->next = state->matches;
      state->matches = new_match;
    }
    else
    {
      break;
    }

    atom = atom->next;
  }

  return result;
}


//
// yr_ac_compile
//

int yr_ac_compile(
    YR_AC_AUTOMATON* automaton,
    YR_ARENA* arena,
    YR_AC_TABLES* tables)
{
  uint32_t i;

  FAIL_ON_ERROR(_yr_ac_create_failure_links(automaton));
  FAIL_ON_ERROR(_yr_ac_optimize_failure_links(automaton));
  FAIL_ON_ERROR(_yr_ac_build_transition_table(automaton));

  FAIL_ON_ERROR(yr_arena_reserve_memory(
      arena,
      automaton->tables_size * sizeof(tables->transitions[0]) +
      automaton->tables_size * sizeof(tables->matches[0])));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      automaton->t_table,
      sizeof(YR_AC_TRANSITION),
      (void**) &tables->transitions));

  for (i = 1; i < automaton->tables_size; i++)
  {
    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        automaton->t_table + i,
        sizeof(YR_AC_TRANSITION),
        NULL));
  }

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      automaton->m_table,
      sizeof(YR_AC_MATCH_TABLE_ENTRY),
      (void**) &tables->matches));

  FAIL_ON_ERROR(yr_arena_make_ptr_relocatable(
      arena,
      tables->matches,
      offsetof(YR_AC_MATCH_TABLE_ENTRY, match),
      EOL));

  for (i = 1; i < automaton->tables_size; i++)
  {
    void* ptr;

    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        automaton->m_table + i,
        sizeof(YR_AC_MATCH_TABLE_ENTRY),
        (void**) &ptr));

    FAIL_ON_ERROR(yr_arena_make_ptr_relocatable(
        arena,
        ptr,
        offsetof(YR_AC_MATCH_TABLE_ENTRY, match),
        EOL));
  }

  return ERROR_SUCCESS;
}


//
// yr_ac_print_automaton
//
// Prints automaton for debug purposes.
//

void yr_ac_print_automaton(YR_AC_AUTOMATON* automaton)
{
  printf("-------------------------------------------------------\n");
  _yr_ac_print_automaton_state(automaton->root);
  printf("-------------------------------------------------------\n");
}
