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

#include <stddef.h>
#include <string.h>

#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/object.h>
#include <yara/strutils.h>
#include <yara/utils.h>
#include <yara/modules.h>
#include <yara/parser.h>
#include <yara/mem.h>

#define todigit(x)  ((x) >='A'&& (x) <='F')? \
                    ((uint8_t) (x - 'A' + 10)) : \
                    ((uint8_t) (x - '0'))


int yr_parser_emit(
    yyscan_t yyscanner,
    uint8_t instruction,
    uint8_t** instruction_address)
{
  return yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);
}


int yr_parser_emit_with_arg_double(
    yyscan_t yyscanner,
    uint8_t instruction,
    double argument,
    uint8_t** instruction_address,
    double** argument_address)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(uint8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(double),
        (void**) argument_address);

  return result;
}


int yr_parser_emit_with_arg(
    yyscan_t yyscanner,
    uint8_t instruction,
    int64_t argument,
    uint8_t** instruction_address,
    int64_t** argument_address)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(uint8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(int64_t),
        (void**) argument_address);

  return result;
}


int yr_parser_emit_with_arg_reloc(
    yyscan_t yyscanner,
    uint8_t instruction,
    void* argument,
    uint8_t** instruction_address,
    void** argument_address)
{
  int64_t* ptr = NULL;
  int result;

  DECLARE_REFERENCE(void*, ptr) arg;

  memset(&arg, 0, sizeof(arg));
  arg.ptr = argument;

  result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(uint8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &arg,
        sizeof(arg),
        (void**) &ptr);

  if (result == ERROR_SUCCESS)
    result = yr_arena_make_ptr_relocatable(
        yyget_extra(yyscanner)->code_arena,
        ptr,
        0,
        EOL);

  if (argument_address != NULL)
    *argument_address = (void*) ptr;

  return result;
}


int yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* string = compiler->current_rule->strings;

  const char* string_identifier;
  const char* target_identifier;

  int matching = 0;

  while(!STRING_IS_NULL(string))
  {
    // Don't generate pushes for strings chained to another one, we are
    // only interested in non-chained strings or the head of the chain.

    if (string->chained_to == NULL)
    {
      string_identifier = string->identifier;
      target_identifier = identifier;

      while (*target_identifier != '\0' &&
             *string_identifier != '\0' &&
             *target_identifier == *string_identifier)
      {
        target_identifier++;
        string_identifier++;
      }

      if ((*target_identifier == '\0' && *string_identifier == '\0') ||
           *target_identifier == '*')
      {
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_PUSH,
            string,
            NULL,
            NULL);

        string->g_flags |= STRING_GFLAGS_REFERENCED;
        string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        matching++;
      }
    }

    string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  if (matching == 0)
  {
    yr_compiler_set_error_extra_info(compiler, identifier);
    return ERROR_UNDEFINED_STRING;
  }

  return ERROR_SUCCESS;
}


int yr_parser_check_types(
    YR_COMPILER* compiler,
    YR_OBJECT_FUNCTION* function,
    const char* actual_args_fmt)
{
  int i;

  for (i = 0; i < YR_MAX_OVERLOADED_FUNCTIONS; i++)
  {
    if (function->prototypes[i].arguments_fmt == NULL)
      break;

    if (strcmp(function->prototypes[i].arguments_fmt, actual_args_fmt) == 0)
      return ERROR_SUCCESS;
  }

  yr_compiler_set_error_extra_info(compiler, function->identifier);

  return ERROR_WRONG_ARGUMENTS;
}


int yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier,
    YR_STRING** string)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  *string = compiler->current_rule->strings;

  while(!STRING_IS_NULL(*string))
  {
    // If some string $a gets fragmented into multiple chained
    // strings, all those fragments have the same $a identifier
    // but we are interested in the heading fragment, which is
    // that with chained_to == NULL

    if (strcmp((*string)->identifier, identifier) == 0 &&
        (*string)->chained_to == NULL)
    {
      return ERROR_SUCCESS;
    }

    *string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        *string,
        sizeof(YR_STRING));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);

  *string = NULL;

  return ERROR_UNDEFINED_STRING;
}


int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  for (i = 0; i < compiler->loop_depth; i++)
  {
    if (compiler->loop_identifier[i] != NULL &&
        strcmp(identifier, compiler->loop_identifier[i]) == 0)
      return i;
  }

  return -1;
}


static int _yr_parser_write_string(
    const char* identifier,
    int flags,
    YR_COMPILER* compiler,
    SIZED_STRING* str,
    RE_AST* re_ast,
    YR_STRING** string,
    int* min_atom_quality)
{
  SIZED_STRING* literal_string;
  YR_ATOM_LIST_ITEM* atom_list = NULL;

  int result;
  int max_string_len;
  bool free_literal = false;

  *string = NULL;

  result = yr_arena_allocate_struct(
      compiler->strings_arena,
      sizeof(YR_STRING),
      (void**) string,
      offsetof(YR_STRING, identifier),
      offsetof(YR_STRING, string),
      offsetof(YR_STRING, chained_to),
      offsetof(YR_STRING, rule),
      EOL);

  if (result != ERROR_SUCCESS)
    return result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &(*string)->identifier);

  if (result != ERROR_SUCCESS)
    return result;

  if (flags & STRING_GFLAGS_HEXADECIMAL ||
      flags & STRING_GFLAGS_REGEXP)
  {
    literal_string = yr_re_ast_extract_literal(re_ast);

    if (literal_string != NULL)
    {
      flags |= STRING_GFLAGS_LITERAL;
      free_literal = true;
    }
    else
    {
      // Non-literal strings can't be marked as fixed offset because once we
      // find a string atom in the scanned data we don't know the offset where
      // the string should start, as the non-literal strings can contain
      // variable-length portions.

      flags &= ~STRING_GFLAGS_FIXED_OFFSET;
    }
  }
  else
  {
    literal_string = str;
    flags |= STRING_GFLAGS_LITERAL;
  }

  (*string)->g_flags = flags;
  (*string)->chained_to = NULL;
  (*string)->fixed_offset = UNDEFINED;
  (*string)->rule = compiler->current_rule;

  memset((*string)->matches, 0,
         sizeof((*string)->matches));

  memset((*string)->unconfirmed_matches, 0,
         sizeof((*string)->unconfirmed_matches));

  if (flags & STRING_GFLAGS_LITERAL)
  {
    (*string)->length = (uint32_t) literal_string->length;

    result = yr_arena_write_data(
        compiler->sz_arena,
        literal_string->c_string,
        literal_string->length + 1,   // +1 to include terminating NULL
        (void**) &(*string)->string);

    if (result == ERROR_SUCCESS)
    {
      result = yr_atoms_extract_from_string(
          &compiler->atoms_config,
          (uint8_t*) literal_string->c_string,
          (int32_t) literal_string->length,
          flags,
          &atom_list);
    }
  }
  else
  {
    // Emit forwards code
    result = yr_re_ast_emit_code(re_ast, compiler->re_code_arena, false);

    // Emit backwards code
    if (result == ERROR_SUCCESS)
      result = yr_re_ast_emit_code(re_ast, compiler->re_code_arena, true);

    if (result == ERROR_SUCCESS)
      result = yr_atoms_extract_from_re(
          &compiler->atoms_config, re_ast, flags, &atom_list);
  }

  if (result == ERROR_SUCCESS)
  {
    // Add the string to Aho-Corasick automaton.
    result = yr_ac_add_string(
        compiler->automaton,
        *string,
        atom_list,
        compiler->matches_arena);
  }

  *min_atom_quality = yr_atoms_min_quality(
      &compiler->atoms_config, atom_list);

  if (flags & STRING_GFLAGS_LITERAL)
  {
    if (flags & STRING_GFLAGS_WIDE)
      max_string_len = (*string)->length * 2;
    else
      max_string_len = (*string)->length;

    if (max_string_len <= YR_MAX_ATOM_LENGTH)
      (*string)->g_flags |= STRING_GFLAGS_FITS_IN_ATOM;
  }

  if (free_literal)
    yr_free(literal_string);

  if (atom_list != NULL)
    yr_atoms_list_destroy(atom_list);

  return result;
}

#include <limits.h>

#include <yara/integers.h>


int yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t string_flags,
    const char* identifier,
    SIZED_STRING* str,
    YR_STRING** string)
{
  int min_atom_quality;
  int min_atom_quality_aux;

  int32_t min_gap;
  int32_t max_gap;

  char message[512];

  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* aux_string;
  YR_STRING* prev_string;

  RE_AST* re_ast = NULL;
  RE_AST* remainder_re_ast = NULL;

  RE_ERROR re_error;

  int result = ERROR_SUCCESS;

  // Determine if a string with the same identifier was already defined
  // by searching for the identifier in string_table.

  *string = (YR_STRING*) yr_hash_table_lookup(
      compiler->strings_table,
      identifier,
      NULL);

  if (*string != NULL)
  {
    result = ERROR_DUPLICATED_STRING_IDENTIFIER;
    yr_compiler_set_error_extra_info(compiler, identifier);
    goto _exit;
  }

  // Empty strings are not allowed

  if (str->length == 0)
  {
    result = ERROR_EMPTY_STRING;
    yr_compiler_set_error_extra_info(compiler, identifier);
    goto _exit;
  }

  if (str->flags & SIZED_STRING_FLAGS_NO_CASE)
    string_flags |= STRING_GFLAGS_NO_CASE;

  if (str->flags & SIZED_STRING_FLAGS_DOT_ALL)
    string_flags |= STRING_GFLAGS_DOT_ALL;

  if (strcmp(identifier,"$") == 0)
    string_flags |= STRING_GFLAGS_ANONYMOUS;

  if (!(string_flags & STRING_GFLAGS_WIDE) &&
      !(string_flags & STRING_GFLAGS_XOR))
    string_flags |= STRING_GFLAGS_ASCII;

  // Hex strings are always handled as DOT_ALL regexps.

  if (string_flags & STRING_GFLAGS_HEXADECIMAL)
    string_flags |= STRING_GFLAGS_DOT_ALL;

  // The STRING_GFLAGS_SINGLE_MATCH flag indicates that finding
  // a single match for the string is enough. This is true in
  // most cases, except when the string count (#) and string offset (@)
  // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
  // initially, and unmarked later if required.

  string_flags |= STRING_GFLAGS_SINGLE_MATCH;

  // The STRING_GFLAGS_FIXED_OFFSET indicates that the string doesn't
  // need to be searched all over the file because the user is using the
  // "at" operator. The string must be searched at a fixed offset in the
  // file. All strings are marked STRING_GFLAGS_FIXED_OFFSET initially,
  // and unmarked later if required.

  string_flags |= STRING_GFLAGS_FIXED_OFFSET;

  if (string_flags & STRING_GFLAGS_HEXADECIMAL ||
      string_flags & STRING_GFLAGS_REGEXP)
  {
    if (string_flags & STRING_GFLAGS_HEXADECIMAL)
      result = yr_re_parse_hex(str->c_string, &re_ast, &re_error);
    else
      result = yr_re_parse(str->c_string, &re_ast, &re_error);

    if (result != ERROR_SUCCESS)
    {
      snprintf(
          message,
          sizeof(message),
          "invalid %s \"%s\": %s",
          (string_flags & STRING_GFLAGS_HEXADECIMAL) ?
              "hex string" : "regular expression",
          identifier,
          re_error.message);

      yr_compiler_set_error_extra_info(
          compiler, message);

      goto _exit;
    }

    if (re_ast->flags & RE_FLAGS_FAST_REGEXP)
      string_flags |= STRING_GFLAGS_FAST_REGEXP;

    // Regular expressions in the strings section can't mix greedy and ungreedy
    // quantifiers like .* and .*?. That's because these regular expressions can
    // be matched forwards and/or backwards depending on the atom found, and we
    // need the regexp to be all-greedy or all-ungreedy to be able to properly
    // calculate the length of the match.

    if ((re_ast->flags & RE_FLAGS_GREEDY) &&
        (re_ast->flags & RE_FLAGS_UNGREEDY))
    {
      result = ERROR_INVALID_REGULAR_EXPRESSION;

      yr_compiler_set_error_extra_info(compiler,
          "greedy and ungreedy quantifiers can't be mixed in a regular "
          "expression");

      goto _exit;
    }

    if (re_ast->flags & RE_FLAGS_GREEDY)
      string_flags |= STRING_GFLAGS_GREEDY_REGEXP;

    if (yr_re_ast_contains_dot_star(re_ast))
    {
      yywarning(
          yyscanner,
          "%s contains .* or .+, consider using .{N} or .{1,N} with a reasonable value for N",
          identifier);
    }

    if (compiler->re_ast_callback != NULL)
    {
      compiler->re_ast_callback(
          compiler->current_rule,
          identifier,
          re_ast,
          compiler->re_ast_clbk_user_data);
    }

    result = yr_re_ast_split_at_chaining_point(
        re_ast, &re_ast, &remainder_re_ast, &min_gap, &max_gap);

    if (result != ERROR_SUCCESS)
      goto _exit;

    result = _yr_parser_write_string(
        identifier,
        string_flags,
        compiler,
        NULL,
        re_ast,
        string,
        &min_atom_quality);

    if (result != ERROR_SUCCESS)
      goto _exit;

    if (remainder_re_ast != NULL)
    {
      (*string)->g_flags |= STRING_GFLAGS_CHAIN_TAIL | STRING_GFLAGS_CHAIN_PART;
      (*string)->chain_gap_min = min_gap;
      (*string)->chain_gap_max = max_gap;
    }

    // Use "aux_string" from now on, we want to keep the value of "string"
    // because it will returned.

    aux_string = *string;

    while (remainder_re_ast != NULL)
    {
      // Destroy regexp pointed by 're_ast' before yr_re_split_at_chaining_point
      // overwrites 're_ast' with another value.

      yr_re_ast_destroy(re_ast);

      result = yr_re_ast_split_at_chaining_point(
          remainder_re_ast, &re_ast, &remainder_re_ast, &min_gap, &max_gap);

      if (result != ERROR_SUCCESS)
        goto _exit;

      prev_string = aux_string;

      result = _yr_parser_write_string(
          identifier,
          string_flags,
          compiler,
          NULL,
          re_ast,
          &aux_string,
          &min_atom_quality_aux);

      if (result != ERROR_SUCCESS)
        goto _exit;

      if (min_atom_quality_aux < min_atom_quality)
        min_atom_quality = min_atom_quality_aux;

      aux_string->g_flags |= STRING_GFLAGS_CHAIN_PART;
      aux_string->chain_gap_min = min_gap;
      aux_string->chain_gap_max = max_gap;

      prev_string->chained_to = aux_string;

      // prev_string is now chained to aux_string, an string chained
      // to another one can't have a fixed offset, only the head of the
      // string chain can have a fixed offset.

      prev_string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
    }
  }
  else
  {
    result = _yr_parser_write_string(
        identifier,
        string_flags,
        compiler,
        str,
        NULL,
        string,
        &min_atom_quality);

    if (result != ERROR_SUCCESS)
      goto _exit;
  }

  if (!STRING_IS_ANONYMOUS(*string))
  {
    result = yr_hash_table_add(
      compiler->strings_table,
      identifier,
      NULL,
      *string);

    if (result != ERROR_SUCCESS)
      goto _exit;
  }

  if (min_atom_quality < compiler->atoms_config.quality_warning_threshold)
  {
    yywarning(
        yyscanner,
        "%s is slowing down scanning",
        (*string)->identifier);
  }

_exit:

  if (re_ast != NULL)
    yr_re_ast_destroy(re_ast);

  if (remainder_re_ast != NULL)
    yr_re_ast_destroy(remainder_re_ast);

  return result;
}


int yr_parser_reduce_rule_declaration_phase_1(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    YR_RULE** rule)
{
  YR_FIXUP *fixup;
  YR_INIT_RULE_ARGS *init_rule_args;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  *rule = NULL;

  if (yr_hash_table_lookup(
        compiler->rules_table,
        identifier,
        compiler->current_namespace->name) != NULL ||
      yr_hash_table_lookup(
        compiler->objects_table,
        identifier,
        NULL) != NULL)
  {
    // A rule or variable with the same identifier already exists, return the
    // appropriate error.

    yr_compiler_set_error_extra_info(compiler, identifier);
    return ERROR_DUPLICATED_IDENTIFIER;
  }

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->rules_arena,
      sizeof(YR_RULE),
      (void**) rule,
      offsetof(YR_RULE, identifier),
      offsetof(YR_RULE, tags),
      offsetof(YR_RULE, strings),
      offsetof(YR_RULE, metas),
      offsetof(YR_RULE, ns),
      EOL))

  (*rule)->g_flags = flags;
  (*rule)->ns = compiler->current_namespace;

  #ifdef PROFILING_ENABLED
  (*rule)->time_cost = 0;

  memset(
      (*rule)->time_cost_per_thread, 0, sizeof((*rule)->time_cost_per_thread));
  #endif

  FAIL_ON_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      (char**) &(*rule)->identifier));

  FAIL_ON_ERROR(yr_parser_emit(
      yyscanner,
      OP_INIT_RULE,
      NULL));

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->code_arena,
      sizeof(YR_INIT_RULE_ARGS),
      (void**) &init_rule_args,
      offsetof(YR_INIT_RULE_ARGS, rule),
      offsetof(YR_INIT_RULE_ARGS, jmp_addr),
      EOL));

  init_rule_args->rule = *rule;

  // jmp_addr holds the address to jump to when we want to skip the code for
  // the rule. It is iniatialized as NULL at this point because we don't know
  // the address until emmiting the code for the rule's condition. The address
  // is set in yr_parser_reduce_rule_declaration_phase_2.
  init_rule_args->jmp_addr = NULL;

  // Create a fixup entry for the jump and push it in the stack
  fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

  if (fixup == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  fixup->address = (void*) &(init_rule_args->jmp_addr);
  fixup->next = compiler->fixup_stack_head;
  compiler->fixup_stack_head = fixup;

  // Clean strings_table as we are starting to parse a new rule.
  yr_hash_table_clean(compiler->strings_table, NULL);

  FAIL_ON_ERROR(yr_hash_table_add(
      compiler->rules_table,
      identifier,
      compiler->current_namespace->name,
      (void*) *rule));

  compiler->current_rule = *rule;

  return ERROR_SUCCESS;
}

int yr_parser_reduce_rule_declaration_phase_2(
    yyscan_t yyscanner,
    YR_RULE* rule)
{
  uint32_t max_strings_per_rule;
  uint32_t strings_in_rule = 0;
  uint8_t* nop_inst_addr = NULL;

  int result;

  YR_FIXUP *fixup;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  // Check for unreferenced (unused) strings.

  YR_STRING* string = rule->strings;

  yr_get_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &max_strings_per_rule);

  while (!STRING_IS_NULL(string))
  {
    // Only the heading fragment in a chain of strings (the one with
    // chained_to == NULL) must be referenced. All other fragments
    // are never marked as referenced.

    if (!STRING_IS_REFERENCED(string) &&
        string->chained_to == NULL)
    {
      yr_compiler_set_error_extra_info(compiler, string->identifier);
      return ERROR_UNREFERENCED_STRING;
    }

    strings_in_rule++;

    if (strings_in_rule > max_strings_per_rule)
    {
      yr_compiler_set_error_extra_info(compiler, rule->identifier);
      return ERROR_TOO_MANY_STRINGS;
    }

    string = (YR_STRING*) yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  result = yr_parser_emit_with_arg_reloc(
      yyscanner,
      OP_MATCH_RULE,
      rule,
      NULL,
      NULL);

  // Generate a do-nothing instruction (NOP) in order to get its address
  // and use it as the destination for the OP_INIT_RULE skip jump. We can not
  // simply use the address of the OP_MATCH_RULE instruction +1 because we
  // can't be sure that the instruction following the OP_MATCH_RULE is going to
  // be in the same arena page. As we don't have a reliable way of getting the
  // address of the next instruction we generate the OP_NOP.

  if (result == ERROR_SUCCESS)
    result = yr_parser_emit(yyscanner, OP_NOP, &nop_inst_addr);

  fixup = compiler->fixup_stack_head;
  *(void**)(fixup->address) = (void*) nop_inst_addr;
  compiler->fixup_stack_head = fixup->next;
  yr_free(fixup);

  return result;
}


int yr_parser_reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    uint8_t instruction,
    uint64_t at_offset)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0) // is an anonymous string ?
  {
    if (compiler->loop_for_of_mem_offset >= 0) // inside a loop ?
    {
      yr_parser_emit_with_arg(
          yyscanner,
          OP_PUSH_M,
          compiler->loop_for_of_mem_offset,
          NULL,
          NULL);

      yr_parser_emit(yyscanner, instruction, NULL);

      string = compiler->current_rule->strings;

      while(!STRING_IS_NULL(string))
      {
        if (instruction != OP_FOUND)
          string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

        if (instruction == OP_FOUND_AT)
        {
          // Avoid overwriting any previous fixed offset

          if (string->fixed_offset == UNDEFINED)
            string->fixed_offset = at_offset;

          // If a previous fixed offset was different, disable
          // the STRING_GFLAGS_FIXED_OFFSET flag because we only
          // have room to store a single fixed offset value

          if (string->fixed_offset != at_offset)
            string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        }
        else
        {
          string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
        }

        string = (YR_STRING*) yr_arena_next_address(
            compiler->strings_arena,
            string,
            sizeof(YR_STRING));
      }
    }
    else
    {
      // Anonymous strings not allowed outside of a loop
      return ERROR_MISPLACED_ANONYMOUS_STRING;
    }
  }
  else
  {
    FAIL_ON_ERROR(yr_parser_lookup_string(
        yyscanner, identifier, &string));

    FAIL_ON_ERROR(yr_parser_emit_with_arg_reloc(
        yyscanner,
        OP_PUSH,
        string,
        NULL,
        NULL));

    if (instruction != OP_FOUND)
      string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

    if (instruction == OP_FOUND_AT)
    {
      // Avoid overwriting any previous fixed offset

      if (string->fixed_offset == UNDEFINED)
        string->fixed_offset = at_offset;

      // If a previous fixed offset was different, disable
      // the STRING_GFLAGS_FIXED_OFFSET flag because we only
      // have room to store a single fixed offset value

      if (string->fixed_offset == UNDEFINED ||
          string->fixed_offset != at_offset)
      {
        string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
      }
    }
    else
    {
      string->g_flags &= ~STRING_GFLAGS_FIXED_OFFSET;
    }

    FAIL_ON_ERROR(yr_parser_emit(yyscanner, instruction, NULL));

    string->g_flags |= STRING_GFLAGS_REFERENCED;
  }

  return ERROR_SUCCESS;
}


int yr_parser_reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int64_t integer,
    YR_META** meta)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->metas_arena,
      sizeof(YR_META),
      (void**) meta,
      offsetof(YR_META, identifier),
      offsetof(YR_META, string),
      EOL));

  FAIL_ON_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      (char**) &(*meta)->identifier));

  if (string != NULL)
  {
    FAIL_ON_ERROR(yr_arena_write_string(
        compiler->sz_arena,
        string,
        &(*meta)->string));
  }
  else
  {
    (*meta)->string = NULL;
  }

  (*meta)->integer = integer;
  (*meta)->type = type;

  return ERROR_SUCCESS;
}


static int _yr_parser_valid_module_name(
    SIZED_STRING* module_name)
{
  if (module_name->length == 0)
    return false;

  if (strlen(module_name->c_string) != module_name->length)
    return false;

  return true;
}


int yr_parser_reduce_import(
    yyscan_t yyscanner,
    SIZED_STRING* module_name)
{
  int result;

  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_OBJECT* module_structure;

  char* name;

  if (!_yr_parser_valid_module_name(module_name))
  {
    yr_compiler_set_error_extra_info(compiler, module_name->c_string);
    return ERROR_INVALID_MODULE_NAME;
  }

  module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      compiler->objects_table,
      module_name->c_string,
      compiler->current_namespace->name);

  // if module already imported, do nothing

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_STRUCTURE,
      module_name->c_string,
      NULL,
      &module_structure));

  FAIL_ON_ERROR(yr_hash_table_add(
      compiler->objects_table,
      module_name->c_string,
      compiler->current_namespace->name,
      module_structure));

  result = yr_modules_do_declarations(
      module_name->c_string,
      module_structure);

  if (result == ERROR_UNKNOWN_MODULE)
    yr_compiler_set_error_extra_info(compiler, module_name->c_string);

  if (result != ERROR_SUCCESS)
    return result;

  FAIL_ON_ERROR(yr_arena_write_string(
      compiler->sz_arena,
      module_name->c_string,
      &name));

  FAIL_ON_ERROR(yr_parser_emit_with_arg_reloc(
        yyscanner,
        OP_IMPORT,
        name,
        NULL,
        NULL));

  return ERROR_SUCCESS;
}


static int _yr_parser_operator_to_opcode(
    const char* op,
    int expression_type)
{
  int opcode = 0;

  switch(expression_type)
  {
    case EXPRESSION_TYPE_INTEGER:
      opcode = OP_INT_BEGIN;
      break;
    case EXPRESSION_TYPE_FLOAT:
      opcode = OP_DBL_BEGIN;
      break;
    case EXPRESSION_TYPE_STRING:
      opcode = OP_STR_BEGIN;
      break;
    default:
      assert(false);
  }

  if (op[0] == '<')
  {
    if (op[1] == '=')
      opcode += _OP_LE;
    else
      opcode += _OP_LT;
  }
  else if (op[0] == '>')
  {
    if (op[1] == '=')
      opcode += _OP_GE;
    else
      opcode += _OP_GT;
  }
  else if (op[1] == '=')
  {
    if (op[0] == '=')
      opcode += _OP_EQ;
    else
      opcode += _OP_NEQ;
  }
  else if (op[0] == '+')
  {
    opcode += _OP_ADD;
  }
  else if (op[0] == '-')
  {
    opcode += _OP_SUB;
  }
  else if (op[0] == '*')
  {
    opcode += _OP_MUL;
  }
  else if (op[0] == '\\')
  {
    opcode += _OP_DIV;
  }

  if (IS_INT_OP(opcode) || IS_DBL_OP(opcode) || IS_STR_OP(opcode))
  {
    return opcode;
  }

  return OP_ERROR;
}


int yr_parser_reduce_operation(
    yyscan_t yyscanner,
    const char* op,
    EXPRESSION left_operand,
    EXPRESSION right_operand)
{
  int expression_type;

  YR_COMPILER* compiler = yyget_extra(yyscanner);

  if ((left_operand.type == EXPRESSION_TYPE_INTEGER ||
       left_operand.type == EXPRESSION_TYPE_FLOAT) &&
      (right_operand.type == EXPRESSION_TYPE_INTEGER ||
       right_operand.type == EXPRESSION_TYPE_FLOAT))
  {
    if (left_operand.type != right_operand.type)
    {
      // One operand is double and the other is integer,
      // cast the integer to double

      FAIL_ON_ERROR(yr_parser_emit_with_arg(
          yyscanner,
          OP_INT_TO_DBL,
          (left_operand.type == EXPRESSION_TYPE_INTEGER) ? 2 : 1,
          NULL,
          NULL));
    }

    expression_type = EXPRESSION_TYPE_FLOAT;

    if (left_operand.type == EXPRESSION_TYPE_INTEGER &&
        right_operand.type == EXPRESSION_TYPE_INTEGER)
    {
      expression_type = EXPRESSION_TYPE_INTEGER;
    }

    FAIL_ON_ERROR(yr_parser_emit(
        yyscanner,
        _yr_parser_operator_to_opcode(op, expression_type),
        NULL));
  }
  else if (left_operand.type == EXPRESSION_TYPE_STRING &&
           right_operand.type == EXPRESSION_TYPE_STRING)
  {
    int opcode = _yr_parser_operator_to_opcode(op, EXPRESSION_TYPE_STRING);

    if (opcode != OP_ERROR)
    {
      FAIL_ON_ERROR(yr_parser_emit(
          yyscanner,
          opcode,
          NULL));
    }
    else
    {
      yr_compiler_set_error_extra_info_fmt(
          compiler, "strings don't support \"%s\" operation", op);

      return ERROR_WRONG_TYPE;
    }
  }
  else
  {
    yr_compiler_set_error_extra_info(compiler, "type mismatch");

    return ERROR_WRONG_TYPE;
  }

  return ERROR_SUCCESS;
}
