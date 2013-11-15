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

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "arena.h"
#include "atoms.h"
#include "mem.h"
#include "utils.h"
#include "yara.h"


#define MAX_TABLE_BASED_STATES_DEPTH 1

#ifdef _MSC_VER
#define inline __inline
#endif

#ifndef min
#define min(x, y) ((x < y) ? (x) : (y))
#endif

#ifndef max
#define max(x, y) ((x > y) ? (x) : (y))
#endif

typedef struct _QUEUE_NODE
{
  AC_STATE* value;

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
//    AC_STATE* state  - The state
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

int _yr_ac_queue_push(
    QUEUE* queue,
    AC_STATE* value)
{
  QUEUE_NODE* pushed_node;

  pushed_node = yr_malloc(sizeof(QUEUE_NODE));

  if (pushed_node == NULL)
    return ERROR_INSUFICIENT_MEMORY;

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

AC_STATE* _yr_ac_queue_pop(
    QUEUE* queue)
{
  AC_STATE* result;
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
//    TRUE if queue is empty, FALSE otherwise.
//

int _yr_ac_queue_is_empty(
    QUEUE* queue)
{
  return queue->head == NULL;
}


AC_STATE* _yr_ac_next_transition(
  AC_STATE* state,
  AC_STATE_TRANSITION* transition)
{
  int i;
  AC_TABLE_BASED_STATE* table_based_state;

  if (state->depth <= MAX_TABLE_BASED_STATES_DEPTH)
  {
    table_based_state = (AC_TABLE_BASED_STATE*) state;

    for (i = transition->input + 1; i < 256; i++)
    {
      if (table_based_state->transitions[i].state != NULL)
      {
        transition->state = table_based_state->transitions[i].state;
        transition->input = i;
        transition->next = NULL;
        return transition->state;
      }
    }
  }
  else
  {
    if (transition->next != NULL)
    {
      transition->state = transition->next->state;
      transition->input = transition->next->input;
      transition->next = transition->next->next;
      return transition->state;
    }
  }

  return NULL;
}


AC_STATE* _yr_ac_first_transition(
  AC_STATE* state,
  AC_STATE_TRANSITION* transition)
{
  int i;

  AC_LIST_BASED_STATE* list_based_state;
  AC_TABLE_BASED_STATE* table_based_state;

  if (state->depth <= MAX_TABLE_BASED_STATES_DEPTH)
  {
    table_based_state = (AC_TABLE_BASED_STATE*) state;

    for (i = 0; i < 256; i++)
    {
      if (table_based_state->transitions[i].state != NULL)
      {
        transition->state = table_based_state->transitions[i].state;
        transition->input = i;
        transition->next = NULL;
        return transition->state;
      }
    }
  }
  else
  {
    list_based_state = (AC_LIST_BASED_STATE*) state;

    if (list_based_state->transitions != NULL)
    {
      transition->state = list_based_state->transitions->state;
      transition->input = list_based_state->transitions->input;
      transition->next = list_based_state->transitions->next;
      return transition->state;
    }
  }

  return NULL;
}

//
// yr_ac_next_state
//
// Given an automaton state and an input symbol, returns the new state
// after reading the input symbol.
//
// Args:
//    AC_STATE* state     - Automaton state
//    uint8_t input       - Input symbol
//
// Returns:
//   Pointer to the next automaton state.
//

int c = 0;
int d = 0;

inline AC_STATE* yr_ac_next_state(
    AC_STATE* state,
    uint8_t input)
{
  AC_STATE_TRANSITION* transition;

  if (state->depth <= MAX_TABLE_BASED_STATES_DEPTH)
  {
    return ((AC_TABLE_BASED_STATE*) state)->transitions[input].state;
  }
  else
  {
    transition = ((AC_LIST_BASED_STATE*) state)->transitions;

    while (transition != NULL)
    {
      if (transition->input == input)
        return transition->state;

      transition = transition->next;
    }

    return NULL;
  }
}


//
// _yr_ac_create_state
//
// Creates a new automaton state, the automaton will transition from
// the given state to the new state after reading the input symbol.
//
// Args:
//   ARENA* arena     - Automaton's arena
//   AC_STATE* state  - Origin state
//   uint8_t input    - Input symbol
//
// Returns:
//   AC_STATE* pointer to the newly allocated state or NULL in case
//   of error.

AC_STATE* _yr_ac_create_state(
    ARENA* arena,
    AC_STATE* state,
    uint8_t input)
{
  int result;
  AC_STATE* new_state;
  AC_LIST_BASED_STATE* list_based_state;
  AC_TABLE_BASED_STATE* table_based_state;
  AC_STATE_TRANSITION* new_transition;

  if (state->depth < MAX_TABLE_BASED_STATES_DEPTH)
  {
    result = yr_arena_allocate_struct(
        arena,
        sizeof(AC_TABLE_BASED_STATE),
        (void**) &new_state,
        offsetof(AC_TABLE_BASED_STATE, failure),
        offsetof(AC_TABLE_BASED_STATE, matches),
        EOL);
  }
  else
  {
    result = yr_arena_allocate_struct(
        arena,
        sizeof(AC_LIST_BASED_STATE),
        (void**) &new_state,
        offsetof(AC_LIST_BASED_STATE, failure),
        offsetof(AC_LIST_BASED_STATE, matches),
        offsetof(AC_LIST_BASED_STATE, transitions),
        EOL);
  }

  if (result != ERROR_SUCCESS)
    return NULL;

  if (state->depth <= MAX_TABLE_BASED_STATES_DEPTH)
  {
    result = yr_arena_make_relocatable(
        arena,
        state,
        offsetof(AC_TABLE_BASED_STATE, transitions[input]),
        EOL);

    if (result != ERROR_SUCCESS)
      return NULL;

    table_based_state = (AC_TABLE_BASED_STATE*) state;
    table_based_state->transitions[input].state = new_state;
  }
  else
  {
    result = yr_arena_allocate_struct(
        arena,
        sizeof(AC_STATE_TRANSITION),
        (void**) &new_transition,
        offsetof(AC_STATE_TRANSITION, state),
        offsetof(AC_STATE_TRANSITION, next),
        EOL);

    if (result != ERROR_SUCCESS)
      return NULL;

    list_based_state = (AC_LIST_BASED_STATE*) state;

    new_transition->input = input;
    new_transition->state = new_state;
    new_transition->next = list_based_state->transitions;
    list_based_state->transitions = new_transition;
  }

  new_state->depth = state->depth + 1;

  return new_state;
}


//
// yr_ac_create_failure_links
//
// Create failure links for each automaton state. This function must
// be called after all the strings have been added to the automaton.
//

void yr_ac_create_failure_links(
    ARENA* arena,
    AC_AUTOMATON* automaton)
{
  AC_STATE_TRANSITION transition;

  AC_STATE* current_state;
  AC_STATE* failure_state;
  AC_STATE* temp_state;
  AC_STATE* state;
  AC_STATE* transition_state;
  AC_STATE* root_state;
  AC_MATCH* match;

  QUEUE queue;

  queue.head = NULL;
  queue.tail = NULL;

  root_state = automaton->root;

  // Set the failure link of root state to itself.
  root_state->failure = root_state;

  // Push root's children and set their failure link to root.

  state = _yr_ac_first_transition(root_state, &transition);

  while (state != NULL)
  {
    _yr_ac_queue_push(&queue, state);
    state->failure = root_state;
    state = _yr_ac_next_transition(root_state, &transition);
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

    transition_state = _yr_ac_first_transition(
        current_state,
        &transition);

    while (transition_state != NULL)
    {
      _yr_ac_queue_push(&queue, transition_state);
      failure_state = current_state->failure;

      while (1)
      {
        temp_state = yr_ac_next_state(
            failure_state,
            transition.input);

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

      transition_state = _yr_ac_next_transition(
          current_state,
          &transition);
    }

  } // while(!__yr_ac_queue_is_empty(&queue))
}


//
// yr_ac_create_automaton
//
// Creates a new automaton
//

int yr_ac_create_automaton(
    ARENA* arena,
    AC_AUTOMATON** automaton)
{
  int result;
  AC_STATE* root_state;

  result = yr_arena_allocate_struct(
      arena,
      sizeof(AC_AUTOMATON),
      (void**) automaton,
      offsetof(AC_AUTOMATON, root),
      EOL);

  if (result != ERROR_SUCCESS)
    return result;

  result = yr_arena_allocate_struct(
      arena,
      sizeof(AC_TABLE_BASED_STATE),
      (void**) &root_state,
      offsetof(AC_TABLE_BASED_STATE, failure),
      offsetof(AC_TABLE_BASED_STATE, matches),
      EOL);

  if (result != ERROR_SUCCESS)
    return result;

  (*automaton)->root = root_state;

  root_state->depth = 0;
  root_state->matches = NULL;

  return result;
}


int yr_ac_add_string(
    ARENA* arena,
    AC_AUTOMATON* automaton,
    STRING* string,
    ATOM_LIST_ITEM* atom)
{
  int result = ERROR_SUCCESS;
  int i;

  AC_STATE* state;
  AC_STATE* next_state;
  AC_MATCH* new_match;

  // For each atom create the states in the automaton.

  while (atom != NULL)
  {
    state = automaton->root;

    for(i = 0; i < atom->atom_length; i++)
    {
      next_state = yr_ac_next_state(
          state, atom->atom[i]);

      if (next_state == NULL)
      {
        next_state = _yr_ac_create_state(
            arena,
            state,
            atom->atom[i]);

        if (next_state == NULL)
          return ERROR_INSUFICIENT_MEMORY;
      }

      state = next_state;
    }

    result = yr_arena_allocate_struct(
        arena,
        sizeof(AC_MATCH),
        (void**) &new_match,
        offsetof(AC_MATCH, string),
        offsetof(AC_MATCH, forward_code),
        offsetof(AC_MATCH, backward_code),
        offsetof(AC_MATCH, next),
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
// _yr_ac_print_automaton_state
//
// Prints automaton state for debug purposes. This function is invoked by
// yr_ac_print_automaton, is not intended to be used stand-alone.
//

void _yr_ac_print_automaton_state(
  AC_STATE* state)
{
  int i;
  int child_count;

  AC_STATE_TRANSITION transition;
  AC_MATCH* match;
  AC_STATE* child_state;

  for (i = 0; i < state->depth; i++)
    printf(" ");

  child_state = _yr_ac_first_transition(state, &transition);
  child_count = 0;

  while(child_state != NULL)
  {
    child_count++;
    child_state = _yr_ac_next_transition(state, &transition);
  }

  printf("%p childs:%d depth:%d failure:%p",
         state, child_count, state->depth, state->failure);

  match = state->matches;

  while (match != NULL)
  {
    printf("\n");

    for (i = 0; i < state->depth + 1; i++)
      printf(" ");

    printf("%s = ", match->string->identifier, match->backtrack);

    if (STRING_IS_HEX(match->string))
    {
      printf("{ ");

      for (i = 0; i < min(match->string->length, 10); i++)
        printf("%02x ", match->string->string[i]);

      printf("}");
    }
    else if (STRING_IS_REGEXP(match->string))
    {
      printf("/%s/", match->string->string);
    }
    else
    {
      printf("\"%s\"", match->string->string);
    }

    match = match->next;
  }

  printf("\n");

  child_state = _yr_ac_first_transition(state, &transition);

  while(child_state != NULL)
  {
    _yr_ac_print_automaton_state(child_state);
    child_state = _yr_ac_next_transition(state, &transition);
  }
}

//
// yr_ac_print_automaton
//
// Prints automaton for debug purposes.
//

void yr_ac_print_automaton(AC_AUTOMATON* automaton)
{
  printf("-------------------------------------------------------\n");
  _yr_ac_print_automaton_state(automaton->root);
  printf("-------------------------------------------------------\n");
}



