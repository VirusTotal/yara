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

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/base64.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/integers.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/object.h>
#include <yara/parser.h>
#include <yara/re.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#define todigit(x)                                        \
  ((x) >= 'A' && (x) <= 'F') ? ((uint8_t) (x - 'A' + 10)) \
                             : ((uint8_t) (x - '0'))

int yr_parser_emit(
    yyscan_t yyscanner,
    uint8_t instruction,
    YR_ARENA_REF* instruction_ref)
{
  return yr_arena_write_data(
      yyget_extra(yyscanner)->arena,
      YR_CODE_SECTION,
      &instruction,
      sizeof(uint8_t),
      instruction_ref);
}

int yr_parser_emit_with_arg_double(
    yyscan_t yyscanner,
    uint8_t instruction,
    double argument,
    YR_ARENA_REF* instruction_ref,
    YR_ARENA_REF* argument_ref)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->arena,
      YR_CODE_SECTION,
      &instruction,
      sizeof(uint8_t),
      instruction_ref);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->arena,
        YR_CODE_SECTION,
        &argument,
        sizeof(double),
        argument_ref);

  return result;
}

int yr_parser_emit_with_arg_int32(
    yyscan_t yyscanner,
    uint8_t instruction,
    int32_t argument,
    YR_ARENA_REF* instruction_ref,
    YR_ARENA_REF* argument_ref)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->arena,
      YR_CODE_SECTION,
      &instruction,
      sizeof(uint8_t),
      instruction_ref);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->arena,
        YR_CODE_SECTION,
        &argument,
        sizeof(int32_t),
        argument_ref);

  return result;
}

int yr_parser_emit_with_arg(
    yyscan_t yyscanner,
    uint8_t instruction,
    int64_t argument,
    YR_ARENA_REF* instruction_ref,
    YR_ARENA_REF* argument_ref)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->arena,
      YR_CODE_SECTION,
      &instruction,
      sizeof(uint8_t),
      instruction_ref);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->arena,
        YR_CODE_SECTION,
        &argument,
        sizeof(int64_t),
        argument_ref);

  return result;
}

int yr_parser_emit_with_arg_reloc(
    yyscan_t yyscanner,
    uint8_t instruction,
    void* argument,
    YR_ARENA_REF* instruction_ref,
    YR_ARENA_REF* argument_ref)
{
  YR_ARENA_REF ref = YR_ARENA_NULL_REF;

  DECLARE_REFERENCE(void*, ptr) arg;

  memset(&arg, 0, sizeof(arg));
  arg.ptr = argument;

  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->arena,
      YR_CODE_SECTION,
      &instruction,
      sizeof(uint8_t),
      instruction_ref);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->arena,
        YR_CODE_SECTION,
        &arg,
        sizeof(arg),
        &ref);

  if (result == ERROR_SUCCESS)
    result = yr_arena_make_ptr_relocatable(
        yyget_extra(yyscanner)->arena, YR_CODE_SECTION, ref.offset, EOL);

  if (argument_ref != NULL)
    *argument_ref = ref;

  return result;
}

int yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier,
    int* count)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  YR_RULE* current_rule = _yr_compiler_get_rule_by_idx(
      compiler, compiler->current_rule_idx);

  YR_STRING* string;

  const char* string_identifier;
  const char* target_identifier;

  int matching = 0;

  yr_rule_strings_foreach(current_rule, string)
  {
    // Don't generate pushes for strings chained to another one, we are
    // only interested in non-chained strings or the head of the chain.

    if (string->chained_to == NULL)
    {
      string_identifier = string->identifier;
      target_identifier = identifier;

      while (*target_identifier != '\0' && *string_identifier != '\0' &&
             *target_identifier == *string_identifier)
      {
        target_identifier++;
        string_identifier++;
      }

      if ((*target_identifier == '\0' && *string_identifier == '\0') ||
          *target_identifier == '*')
      {
        yr_parser_emit_with_arg_reloc(yyscanner, OP_PUSH, string, NULL, NULL);

        string->flags |= STRING_FLAGS_REFERENCED;
        string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
        string->flags &= ~STRING_FLAGS_SINGLE_MATCH;
        matching++;
      }
    }
  }

  if (count != NULL)
  {
    *count = matching;
  }

  if (matching == 0)
  {
    yr_compiler_set_error_extra_info(
        compiler, identifier) return ERROR_UNDEFINED_STRING;
  }

  return ERROR_SUCCESS;
}

// Emit OP_PUSH_RULE instructions for all rules whose identifier has given
// prefix.
int yr_parser_emit_pushes_for_rules(
    yyscan_t yyscanner,
    const char* prefix,
    int* count)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  // Make sure the compiler is parsing a rule
  assert(compiler->current_rule_idx != UINT32_MAX);

  YR_RULE* rule;
  int matching = 0;

  YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
      compiler->arena,
      YR_NAMESPACES_TABLE,
      compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

  // Can't use yr_rules_foreach here as that requires the rules to have been
  // finalized (inserting a NULL rule at the end). This is done when
  // yr_compiler_get_rules() is called, which also inserts a HALT instruction
  // into the current position in the code arena. Obviously we aren't done
  // compiling the rules yet so inserting a HALT is a bad idea. To deal with
  // this I'm manually walking all the currently compiled rules (up to the
  // current rule index) and comparing identifiers to see if it is one we should
  // use.
  //
  // Further, we have to get compiler->current_rule_idx before we start because
  // if we emit an OP_PUSH_RULE
  rule = yr_arena_get_ptr(compiler->arena, YR_RULES_TABLE, 0);

  for (uint32_t i = 0; i <= compiler->current_rule_idx; i++)
  {
    // Is rule->identifier prefixed by prefix?
    if (strncmp(prefix, rule->identifier, strlen(prefix)) == 0)
    {
      uint32_t rule_idx = yr_hash_table_lookup_uint32(
          compiler->rules_table, rule->identifier, ns->name);

      if (rule_idx != UINT32_MAX)
      {
        FAIL_ON_ERROR(yr_parser_emit_with_arg(
            yyscanner, OP_PUSH_RULE, rule_idx, NULL, NULL));
        matching++;
      }
    }

    rule++;
  }

  if (count != NULL)
  {
    *count = matching;
  }

  if (matching == 0)
  {
    yr_compiler_set_error_extra_info(compiler, prefix);
    return ERROR_UNDEFINED_IDENTIFIER;
  }

  return ERROR_SUCCESS;
}

int yr_parser_emit_push_const(yyscan_t yyscanner, uint64_t argument)
{
  uint8_t opcode[9];
  int opcode_len = 1;

  if (argument == YR_UNDEFINED)
  {
    opcode[0] = OP_PUSH_U;
  }
  else if (argument <= 0xff)
  {
    opcode[0] = OP_PUSH_8;
    opcode[1] = (uint8_t) argument;
    opcode_len += sizeof(uint8_t);
  }
  else if (argument <= 0xffff)
  {
    opcode[0] = OP_PUSH_16;
    uint16_t u = (uint16_t) argument;
    memcpy(opcode + 1, &u, sizeof(uint16_t));
    opcode_len += sizeof(uint16_t);
  }
  else if (argument <= 0xffffffff)
  {
    opcode[0] = OP_PUSH_32;
    uint32_t u = (uint32_t) argument;
    memcpy(opcode + 1, &u, sizeof(uint32_t));
    opcode_len += sizeof(uint32_t);
  }
  else
  {
    opcode[0] = OP_PUSH;
    memcpy(opcode + 1, &argument, sizeof(uint64_t));
    opcode_len += sizeof(uint64_t);
  }

  return yr_arena_write_data(
      yyget_extra(yyscanner)->arena, YR_CODE_SECTION, opcode, opcode_len, NULL);
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

  yr_compiler_set_error_extra_info(compiler, function->identifier)

      return ERROR_WRONG_ARGUMENTS;
}

int yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier,
    YR_STRING** string)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  YR_RULE* current_rule = _yr_compiler_get_rule_by_idx(
      compiler, compiler->current_rule_idx);

  yr_rule_strings_foreach(current_rule, *string)
  {
    // If some string $a gets fragmented into multiple chained
    // strings, all those fragments have the same $a identifier
    // but we are interested in the heading fragment, which is
    // that with chained_to == NULL

    if ((*string)->chained_to == NULL &&
        strcmp((*string)->identifier, identifier) == 0)
    {
      return ERROR_SUCCESS;
    }
  }

  yr_compiler_set_error_extra_info(compiler, identifier)

      * string = NULL;

  return ERROR_UNDEFINED_STRING;
}

////////////////////////////////////////////////////////////////////////////////
// Searches for a variable with the given identifier in the scope of the current
// "for" loop. In case of nested "for" loops the identifier is searched starting
// at the top-level loop and going down thorough the nested loops until the
// current one. This is ok because inner loops can not re-define an identifier
// already defined by an outer loop.
//
// If the variable is found, the return value is the position that the variable
// occupies among all the currently defined variables. If the variable doesn't
// exist the return value is -1.
//
// The function can receive a pointer to a YR_EXPRESSION that will populated
// with information about the variable if found. This pointer can be NULL if
// the caller is not interested in getting that information.
//
int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier,
    YR_EXPRESSION* expr)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  int i, j;
  int var_offset = 0;

  for (i = 0; i <= compiler->loop_index; i++)
  {
    var_offset += compiler->loop[i].vars_internal_count;

    for (j = 0; j < compiler->loop[i].vars_count; j++)
    {
      if (compiler->loop[i].vars[j].identifier.ptr != NULL &&
          strcmp(identifier, compiler->loop[i].vars[j].identifier.ptr) == 0)
      {
        if (expr != NULL)
          *expr = compiler->loop[i].vars[j];

        return var_offset + j;
      }
    }

    var_offset += compiler->loop[i].vars_count;
  }

  return -1;
}

static int _yr_parser_write_string(
    const char* identifier,
    YR_MODIFIER modifier,
    YR_COMPILER* compiler,
    SIZED_STRING* str,
    RE_AST* re_ast,
    YR_ARENA_REF* string_ref,
    int* min_atom_quality,
    int* num_atom)
{
  SIZED_STRING* literal_string;
  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* atom_list = NULL;

  int c, result;
  int max_string_len;
  bool free_literal = false;

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->arena,
      YR_STRINGS_TABLE,
      sizeof(YR_STRING),
      string_ref,
      offsetof(YR_STRING, identifier),
      offsetof(YR_STRING, string),
      offsetof(YR_STRING, chained_to),
      EOL));

  YR_STRING* string = (YR_STRING*) yr_arena_ref_to_ptr(
      compiler->arena, string_ref);

  YR_ARENA_REF ref;

  FAIL_ON_ERROR(_yr_compiler_store_string(compiler, identifier, &ref));

  string->identifier = (const char*) yr_arena_ref_to_ptr(compiler->arena, &ref);
  string->rule_idx = compiler->current_rule_idx;
  string->idx = compiler->current_string_idx;
  string->fixed_offset = YR_UNDEFINED;

  compiler->current_string_idx++;

  if (modifier.flags & STRING_FLAGS_HEXADECIMAL ||
      modifier.flags & STRING_FLAGS_REGEXP ||
      modifier.flags & STRING_FLAGS_BASE64 ||
      modifier.flags & STRING_FLAGS_BASE64_WIDE)
  {
    literal_string = yr_re_ast_extract_literal(re_ast);

    if (literal_string != NULL)
      free_literal = true;
  }
  else
  {
    literal_string = str;
  }

  if (literal_string != NULL)
  {
    modifier.flags |= STRING_FLAGS_LITERAL;

    result = _yr_compiler_store_data(
        compiler,
        literal_string->c_string,
        literal_string->length + 1,  // +1 to include terminating NULL
        &ref);

    if (result != ERROR_SUCCESS)
      goto cleanup;

    string->length = (uint32_t) literal_string->length;
    string->string = (uint8_t*) yr_arena_ref_to_ptr(compiler->arena, &ref);

    if (modifier.flags & STRING_FLAGS_WIDE)
      max_string_len = string->length * 2;
    else
      max_string_len = string->length;

    if (max_string_len <= YR_MAX_ATOM_LENGTH)
      modifier.flags |= STRING_FLAGS_FITS_IN_ATOM;

    result = yr_atoms_extract_from_string(
        &compiler->atoms_config,
        (uint8_t*) literal_string->c_string,
        (int32_t) literal_string->length,
        modifier,
        &atom_list,
        min_atom_quality);

    if (result != ERROR_SUCCESS)
      goto cleanup;
  }
  else
  {
    // Non-literal strings can't be marked as fixed offset because once we
    // find a string atom in the scanned data we don't know the offset where
    // the string should start, as the non-literal strings can contain
    // variable-length portions.
    modifier.flags &= ~STRING_FLAGS_FIXED_OFFSET;

    // Save the position where the RE forward code starts for later reference.
    yr_arena_off_t forward_code_start = yr_arena_get_current_offset(
        compiler->arena, YR_RE_CODE_SECTION);

    // Emit forwards code
    result = yr_re_ast_emit_code(re_ast, compiler->arena, false);

    if (result != ERROR_SUCCESS)
      goto cleanup;

    // Emit backwards code
    result = yr_re_ast_emit_code(re_ast, compiler->arena, true);

    if (result != ERROR_SUCCESS)
      goto cleanup;

    // Extract atoms from the regular expression.
    result = yr_atoms_extract_from_re(
        &compiler->atoms_config,
        re_ast,
        modifier,
        &atom_list,
        min_atom_quality);

    if (result != ERROR_SUCCESS)
      goto cleanup;

    // If no atom was extracted let's add a zero-length atom.
    if (atom_list == NULL)
    {
      atom_list = (YR_ATOM_LIST_ITEM*) yr_malloc(sizeof(YR_ATOM_LIST_ITEM));

      if (atom_list == NULL)
      {
        result = ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
      }

      atom_list->atom.length = 0;
      atom_list->backtrack = 0;
      atom_list->backward_code_ref = YR_ARENA_NULL_REF;
      atom_list->next = NULL;

      yr_arena_ptr_to_ref(
          compiler->arena,
          yr_arena_get_ptr(
              compiler->arena, YR_RE_CODE_SECTION, forward_code_start),
          &(atom_list->forward_code_ref));
    }
  }

  string->flags = modifier.flags;

  // Add the string to Aho-Corasick automaton.
  result = yr_ac_add_string(
      compiler->automaton, string, string->idx, atom_list, compiler->arena);

  if (result != ERROR_SUCCESS)
    goto cleanup;

  atom = atom_list;
  c = 0;

  while (atom != NULL)
  {
    atom = atom->next;
    c++;
  }

  (*num_atom) += c;

cleanup:
  if (free_literal)
    yr_free(literal_string);

  if (atom_list != NULL)
    yr_atoms_list_destroy(atom_list);

  return result;
}

static int _yr_parser_check_string_modifiers(
    yyscan_t yyscanner,
    YR_MODIFIER modifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  // xor and nocase together is not implemented.
  if (modifier.flags & STRING_FLAGS_XOR &&
      modifier.flags & STRING_FLAGS_NO_CASE)
  {
    yr_compiler_set_error_extra_info(
        compiler, "invalid modifier combination: xor nocase");
    return ERROR_INVALID_MODIFIER;
  }

  // base64 and nocase together is not implemented.
  if (modifier.flags & STRING_FLAGS_NO_CASE &&
      (modifier.flags & STRING_FLAGS_BASE64 ||
       modifier.flags & STRING_FLAGS_BASE64_WIDE))
  {
    yr_compiler_set_error_extra_info(
        compiler,
        modifier.flags & STRING_FLAGS_BASE64
            ? "invalid modifier combination: base64 nocase"
            : "invalid modifier combination: base64wide nocase");
    return ERROR_INVALID_MODIFIER;
  }

  // base64 and fullword together is not implemented.
  if (modifier.flags & STRING_FLAGS_FULL_WORD &&
      (modifier.flags & STRING_FLAGS_BASE64 ||
       modifier.flags & STRING_FLAGS_BASE64_WIDE))
  {
    yr_compiler_set_error_extra_info(
        compiler,
        modifier.flags & STRING_FLAGS_BASE64
            ? "invalid modifier combination: base64 fullword"
            : "invalid modifier combination: base64wide fullword");
    return ERROR_INVALID_MODIFIER;
  }

  // base64 and xor together is not implemented.
  if (modifier.flags & STRING_FLAGS_XOR &&
      (modifier.flags & STRING_FLAGS_BASE64 ||
       modifier.flags & STRING_FLAGS_BASE64_WIDE))
  {
    yr_compiler_set_error_extra_info(
        compiler,
        modifier.flags & STRING_FLAGS_BASE64
            ? "invalid modifier combination: base64 xor"
            : "invalid modifier combination: base64wide xor");
    return ERROR_INVALID_MODIFIER;
  }

  return ERROR_SUCCESS;
}

int yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    YR_MODIFIER modifier,
    const char* identifier,
    SIZED_STRING* str,
    YR_ARENA_REF* string_ref)
{
  int result = ERROR_SUCCESS;
  int min_atom_quality = YR_MAX_ATOM_QUALITY;
  int atom_quality;

  char message[512];

  int32_t min_gap = 0;
  int32_t max_gap = 0;

  YR_COMPILER* compiler = yyget_extra(yyscanner);

  RE_AST* re_ast = NULL;
  RE_AST* remainder_re_ast = NULL;
  RE_ERROR re_error;

  YR_RULE* current_rule = _yr_compiler_get_rule_by_idx(
      compiler, compiler->current_rule_idx);

  // Determine if a string with the same identifier was already defined
  // by searching for the identifier in strings_table.
  uint32_t string_idx = yr_hash_table_lookup_uint32(
      compiler->strings_table, identifier, NULL);

  // The string was already defined, return an error.
  if (string_idx != UINT32_MAX)
  {
    yr_compiler_set_error_extra_info(compiler, identifier);
    return ERROR_DUPLICATED_STRING_IDENTIFIER;
  }

  // Empty strings are not allowed.
  if (str->length == 0)
  {
    yr_compiler_set_error_extra_info(compiler, identifier);
    return ERROR_EMPTY_STRING;
  }

  if (str->flags & SIZED_STRING_FLAGS_NO_CASE)
    modifier.flags |= STRING_FLAGS_NO_CASE;

  if (str->flags & SIZED_STRING_FLAGS_DOT_ALL)
    modifier.flags |= STRING_FLAGS_DOT_ALL;

  // Hex strings are always handled as DOT_ALL regexps.
  if (modifier.flags & STRING_FLAGS_HEXADECIMAL)
    modifier.flags |= STRING_FLAGS_DOT_ALL;

  if (!(modifier.flags & STRING_FLAGS_WIDE) &&
      !(modifier.flags & STRING_FLAGS_BASE64 ||
        modifier.flags & STRING_FLAGS_BASE64_WIDE))
  {
    modifier.flags |= STRING_FLAGS_ASCII;
  }

  // The STRING_FLAGS_SINGLE_MATCH flag indicates that finding
  // a single match for the string is enough. This is true in
  // most cases, except when the string count (#) and string offset (@)
  // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
  // initially, and unmarked later if required.
  modifier.flags |= STRING_FLAGS_SINGLE_MATCH;

  // The STRING_FLAGS_FIXED_OFFSET indicates that the string doesn't
  // need to be searched all over the file because the user is using the
  // "at" operator. The string must be searched at a fixed offset in the
  // file. All strings are marked STRING_FLAGS_FIXED_OFFSET initially,
  // and unmarked later if required.
  modifier.flags |= STRING_FLAGS_FIXED_OFFSET;

  // If string identifier is $ this is an anonymous string, if not add the
  // identifier to strings_table.
  if (strcmp(identifier, "$") == 0)
  {
    modifier.flags |= STRING_FLAGS_ANONYMOUS;
  }
  else
  {
    FAIL_ON_ERROR(yr_hash_table_add_uint32(
        compiler->strings_table,
        identifier,
        NULL,
        compiler->current_string_idx));
  }

  // Make sure that the the string does not have an invalid combination of
  // modifiers.
  FAIL_ON_ERROR(_yr_parser_check_string_modifiers(yyscanner, modifier));

  if (modifier.flags & STRING_FLAGS_HEXADECIMAL ||
      modifier.flags & STRING_FLAGS_REGEXP ||
      modifier.flags & STRING_FLAGS_BASE64 ||
      modifier.flags & STRING_FLAGS_BASE64_WIDE)
  {
    if (modifier.flags & STRING_FLAGS_HEXADECIMAL)
      result = yr_re_parse_hex(str->c_string, &re_ast, &re_error);
    else if (modifier.flags & STRING_FLAGS_REGEXP)
    {
      int flags = RE_PARSER_FLAG_NONE;
      if (compiler->strict_escape)
        flags |= RE_PARSER_FLAG_ENABLE_STRICT_ESCAPE_SEQUENCES;
      result = yr_re_parse(str->c_string, &re_ast, &re_error, flags);
    }
    else
      result = yr_base64_ast_from_string(str, modifier, &re_ast, &re_error);

    if (result != ERROR_SUCCESS)
    {
      if (result == ERROR_UNKNOWN_ESCAPE_SEQUENCE)
      {
        yywarning(yyscanner, "unknown escape sequence");
      }
      else
      {
        snprintf(
            message,
            sizeof(message),
            "invalid %s \"%s\": %s",
            (modifier.flags & STRING_FLAGS_HEXADECIMAL) ? "hex string"
                                                        : "regular expression",
            identifier,
            re_error.message);

        yr_compiler_set_error_extra_info(compiler, message);
        goto _exit;
      }
    }

    if (re_ast->flags & RE_FLAGS_FAST_REGEXP)
      modifier.flags |= STRING_FLAGS_FAST_REGEXP;

    if (re_ast->flags & RE_FLAGS_GREEDY)
      modifier.flags |= STRING_FLAGS_GREEDY_REGEXP;

    // Regular expressions in the strings section can't mix greedy and
    // ungreedy quantifiers like .* and .*?. That's because these regular
    // expressions can be matched forwards and/or backwards depending on the
    // atom found, and we need the regexp to be all-greedy or all-ungreedy to
    // be able to properly calculate the length of the match.

    if ((re_ast->flags & RE_FLAGS_GREEDY) &&
        (re_ast->flags & RE_FLAGS_UNGREEDY))
    {
      result = ERROR_INVALID_REGULAR_EXPRESSION;

      yr_compiler_set_error_extra_info(
          compiler,
          "greedy and ungreedy quantifiers can't be mixed in a regular "
          "expression");

      goto _exit;
    }

    if (yr_re_ast_has_unbounded_quantifier_for_dot(re_ast))
    {
      yywarning(
          yyscanner,
          "%s contains .*, .+ or .{x,} consider using .{,N}, .{1,N} or {x,N} "
          "with a reasonable value for N",
          identifier);
    }

    if (compiler->re_ast_callback != NULL)
    {
      compiler->re_ast_callback(
          current_rule, identifier, re_ast, compiler->re_ast_clbk_user_data);
    }

    *string_ref = YR_ARENA_NULL_REF;

    while (re_ast != NULL)
    {
      YR_ARENA_REF ref;

      uint32_t prev_string_idx = compiler->current_string_idx - 1;

      int32_t prev_min_gap = min_gap;
      int32_t prev_max_gap = max_gap;

      result = yr_re_ast_split_at_chaining_point(
          re_ast, &remainder_re_ast, &min_gap, &max_gap);

      if (result != ERROR_SUCCESS)
        goto _exit;

      result = _yr_parser_write_string(
          identifier,
          modifier,
          compiler,
          NULL,
          re_ast,
          &ref,
          &atom_quality,
          &current_rule->num_atoms);

      if (result != ERROR_SUCCESS)
        goto _exit;

      if (atom_quality < min_atom_quality)
        min_atom_quality = atom_quality;

      if (YR_ARENA_IS_NULL_REF(*string_ref))
      {
        // This is the first string in the chain, the string reference
        // returned by this function must point to this string.
        *string_ref = ref;
      }
      else
      {
        // This is not the first string in the chain, set the appropriate
        // flags and fill the chained_to, chain_gap_min and chain_gap_max
        // fields.
        YR_STRING* prev_string = (YR_STRING*) yr_arena_get_ptr(
            compiler->arena,
            YR_STRINGS_TABLE,
            prev_string_idx * sizeof(YR_STRING));

        YR_STRING* new_string = (YR_STRING*) yr_arena_ref_to_ptr(
            compiler->arena, &ref);

        new_string->chained_to = prev_string;
        new_string->chain_gap_min = prev_min_gap;
        new_string->chain_gap_max = prev_max_gap;

        // A string chained to another one can't have a fixed offset, only the
        // head of the string chain can have a fixed offset.
        new_string->flags &= ~STRING_FLAGS_FIXED_OFFSET;

        // There is a previous string, but that string wasn't marked as part
        // of a chain because we can't do that until knowing there will be
        // another string, let's flag it now the we know.
        prev_string->flags |= STRING_FLAGS_CHAIN_PART;

        // There is a previous string, so this string is part of a chain, but
        // there will be no more strings because there are no more AST to
        // split, which means that this is the chain's tail.
        if (remainder_re_ast == NULL)
          new_string->flags |= STRING_FLAGS_CHAIN_PART |
                               STRING_FLAGS_CHAIN_TAIL;
      }

      yr_re_ast_destroy(re_ast);
      re_ast = remainder_re_ast;
    }
  }
  else  // not a STRING_FLAGS_HEXADECIMAL or STRING_FLAGS_REGEXP or
        // STRING_FLAGS_BASE64 or STRING_FLAGS_BASE64_WIDE
  {
    result = _yr_parser_write_string(
        identifier,
        modifier,
        compiler,
        str,
        NULL,
        string_ref,
        &min_atom_quality,
        &current_rule->num_atoms);

    if (result != ERROR_SUCCESS)
      goto _exit;
  }

  if (min_atom_quality < compiler->atoms_config.quality_warning_threshold)
  {
    yywarning(yyscanner, "string \"%s\" may slow down scanning", identifier);
  }

_exit:

  if (re_ast != NULL)
    yr_re_ast_destroy(re_ast);

  if (remainder_re_ast != NULL)
    yr_re_ast_destroy(remainder_re_ast);

  return result;
}

static int wildcard_iterator(
    void* prefix,
    size_t prefix_len,
    void* _value,
    void* data)
{
  const char* identifier = (const char*) data;

  // If the identifier is prefixed by prefix, then it matches the wildcard.
  if (!strncmp(prefix, identifier, prefix_len))
    return ERROR_IDENTIFIER_MATCHES_WILDCARD;

  return ERROR_SUCCESS;
}

int yr_parser_reduce_rule_declaration_phase_1(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    YR_ARENA_REF* rule_ref)
{
  int result;
  YR_FIXUP* fixup;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
      compiler->arena,
      YR_NAMESPACES_TABLE,
      compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

  if (yr_hash_table_lookup_uint32(
          compiler->rules_table, identifier, ns->name) != UINT32_MAX ||
      yr_hash_table_lookup(compiler->objects_table, identifier, NULL) != NULL)
  {
    // A rule or variable with the same identifier already exists, return the
    // appropriate error.

    yr_compiler_set_error_extra_info(compiler, identifier);
    return ERROR_DUPLICATED_IDENTIFIER;
  }

  // Iterate over all identifiers in wildcard_identifiers_table, and check if
  // any of them are a prefix of the identifier being declared. If so, return
  // ERROR_IDENTIFIER_MATCHES_WILDCARD.
  result = yr_hash_table_iterate(
      compiler->wildcard_identifiers_table,
      ns->name,
      wildcard_iterator,
      (void*) identifier);

  if (result == ERROR_IDENTIFIER_MATCHES_WILDCARD)
  {
    // This rule matches an existing wildcard rule set.
    yr_compiler_set_error_extra_info(compiler, identifier);
  }

  FAIL_ON_ERROR(result);

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->arena,
      YR_RULES_TABLE,
      sizeof(YR_RULE),
      rule_ref,
      offsetof(YR_RULE, identifier),
      offsetof(YR_RULE, tags),
      offsetof(YR_RULE, strings),
      offsetof(YR_RULE, metas),
      offsetof(YR_RULE, ns),
      EOL));

  YR_RULE* rule = (YR_RULE*) yr_arena_ref_to_ptr(compiler->arena, rule_ref);

  YR_ARENA_REF ref;

  FAIL_ON_ERROR(_yr_compiler_store_string(compiler, identifier, &ref));

  rule->identifier = (const char*) yr_arena_ref_to_ptr(compiler->arena, &ref);
  rule->flags = flags;
  rule->ns = ns;
  rule->num_atoms = 0;

  YR_ARENA_REF jmp_offset_ref;

  // We are starting to parse a new rule, set current_rule_idx accordingly.
  compiler->current_rule_idx = compiler->next_rule_idx;
  compiler->next_rule_idx++;

  // The OP_INIT_RULE instruction behaves like a jump. When the rule is
  // disabled it skips over the rule's code and go straight to the next rule's
  // code. The jmp_offset_ref variable points to the jump's offset. The offset
  // is set to 0 as we don't know the jump target yet. When we finish
  // generating the rule's code in yr_parser_reduce_rule_declaration_phase_2
  // the jump offset is set to its final value.

  FAIL_ON_ERROR(yr_parser_emit_with_arg_int32(
      yyscanner, OP_INIT_RULE, 0, NULL, &jmp_offset_ref));

  FAIL_ON_ERROR(yr_arena_write_data(
      compiler->arena,
      YR_CODE_SECTION,
      &compiler->current_rule_idx,
      sizeof(compiler->current_rule_idx),
      NULL));

  // Create a fixup entry for the jump and push it in the stack
  fixup = (YR_FIXUP*) yr_malloc(sizeof(YR_FIXUP));

  if (fixup == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  fixup->ref = jmp_offset_ref;
  fixup->next = compiler->fixup_stack_head;
  compiler->fixup_stack_head = fixup;

  // Clean strings_table as we are starting to parse a new rule.
  yr_hash_table_clean(compiler->strings_table, NULL);

  FAIL_ON_ERROR(yr_hash_table_add_uint32(
      compiler->rules_table, identifier, ns->name, compiler->current_rule_idx));

  return ERROR_SUCCESS;
}

int yr_parser_reduce_rule_declaration_phase_2(
    yyscan_t yyscanner,
    YR_ARENA_REF* rule_ref)
{
  uint32_t max_strings_per_rule;
  uint32_t strings_in_rule = 0;

  YR_FIXUP* fixup;
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  yr_get_configuration_uint32(
      YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);

  YR_RULE* rule = (YR_RULE*) yr_arena_ref_to_ptr(compiler->arena, rule_ref);

  // Show warning if the rule is generating too many atoms. The warning is
  // shown if the number of atoms is greater than 20 times the maximum number
  // of strings allowed for a rule, as 20 is minimum number of atoms generated
  // for a string using *nocase*, *ascii* and *wide* modifiers simultaneously.

  if (rule->num_atoms > YR_ATOMS_PER_RULE_WARNING_THRESHOLD)
  {
    yywarning(yyscanner, "rule is slowing down scanning");
  }

  yr_rule_strings_foreach(rule, string)
  {
    // Only the heading fragment in a chain of strings (the one with
    // chained_to == NULL) must be referenced. All other fragments
    // are never marked as referenced.
    //
    // Any string identifier that starts with '_' can be unreferenced. Anonymous
    // strings must always be referenced.

    if (!STRING_IS_REFERENCED(string) && string->chained_to == NULL &&
        (STRING_IS_ANONYMOUS(string) ||
         (!STRING_IS_ANONYMOUS(string) && string->identifier[1] != '_')))
    {
      yr_compiler_set_error_extra_info(
          compiler, string->identifier) return ERROR_UNREFERENCED_STRING;
    }

    // If a string is unreferenced we need to unset the FIXED_OFFSET flag so
    // that it will match anywhere.
    if (!STRING_IS_REFERENCED(string) && string->chained_to == NULL &&
        STRING_IS_FIXED_OFFSET(string))
    {
      string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
    }

    strings_in_rule++;

    if (strings_in_rule > max_strings_per_rule)
    {
      yr_compiler_set_error_extra_info(
          compiler, rule->identifier) return ERROR_TOO_MANY_STRINGS;
    }
  }

  FAIL_ON_ERROR(yr_parser_emit_with_arg(
      yyscanner, OP_MATCH_RULE, compiler->current_rule_idx, NULL, NULL));

  fixup = compiler->fixup_stack_head;

  int32_t* jmp_offset_addr = (int32_t*) yr_arena_ref_to_ptr(
      compiler->arena, &fixup->ref);

  int32_t jmp_offset = yr_arena_get_current_offset(
                           compiler->arena, YR_CODE_SECTION) -
                       fixup->ref.offset + 1;

  memcpy(jmp_offset_addr, &jmp_offset, sizeof(jmp_offset));

  // Remove fixup from the stack.
  compiler->fixup_stack_head = fixup->next;
  yr_free(fixup);

  // We have finished parsing the current rule set current_rule_idx to
  // UINT32_MAX indicating that we are not currently parsing a rule.
  compiler->current_rule_idx = UINT32_MAX;

  return ERROR_SUCCESS;
}

int yr_parser_reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    uint8_t instruction,
    uint64_t at_offset)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0)  // is an anonymous string ?
  {
    if (compiler->loop_for_of_var_index >= 0)  // inside a loop ?
    {
      yr_parser_emit_with_arg(
          yyscanner, OP_PUSH_M, compiler->loop_for_of_var_index, NULL, NULL);

      yr_parser_emit(yyscanner, instruction, NULL);

      YR_RULE* current_rule = _yr_compiler_get_rule_by_idx(
          compiler, compiler->current_rule_idx);

      yr_rule_strings_foreach(current_rule, string)
      {
        if (instruction != OP_FOUND)
          string->flags &= ~STRING_FLAGS_SINGLE_MATCH;

        if (instruction == OP_FOUND_AT)
        {
          // Avoid overwriting any previous fixed offset
          if (string->fixed_offset == YR_UNDEFINED)
            string->fixed_offset = at_offset;

          // If a previous fixed offset was different, disable
          // the STRING_GFLAGS_FIXED_OFFSET flag because we only
          // have room to store a single fixed offset value
          if (string->fixed_offset != at_offset)
            string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
        }
        else
        {
          string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
        }
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
    FAIL_ON_ERROR(yr_parser_lookup_string(yyscanner, identifier, &string));

    FAIL_ON_ERROR(
        yr_parser_emit_with_arg_reloc(yyscanner, OP_PUSH, string, NULL, NULL));

    if (instruction != OP_FOUND)
      string->flags &= ~STRING_FLAGS_SINGLE_MATCH;

    if (instruction == OP_FOUND_AT)
    {
      // Avoid overwriting any previous fixed offset

      if (string->fixed_offset == YR_UNDEFINED)
        string->fixed_offset = at_offset;

      // If a previous fixed offset was different, disable
      // the STRING_GFLAGS_FIXED_OFFSET flag because we only
      // have room to store a single fixed offset value

      if (string->fixed_offset == YR_UNDEFINED ||
          string->fixed_offset != at_offset)
      {
        string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
      }
    }
    else
    {
      string->flags &= ~STRING_FLAGS_FIXED_OFFSET;
    }

    FAIL_ON_ERROR(yr_parser_emit(yyscanner, instruction, NULL));

    string->flags |= STRING_FLAGS_REFERENCED;
  }

  return ERROR_SUCCESS;
}

int yr_parser_reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int64_t integer,
    YR_ARENA_REF* meta_ref)
{
  YR_ARENA_REF ref;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  FAIL_ON_ERROR(yr_arena_allocate_struct(
      compiler->arena,
      YR_METAS_TABLE,
      sizeof(YR_META),
      meta_ref,
      offsetof(YR_META, identifier),
      offsetof(YR_META, string),
      EOL));

  YR_META* meta = (YR_META*) yr_arena_ref_to_ptr(compiler->arena, meta_ref);

  meta->type = type;
  meta->integer = integer;

  FAIL_ON_ERROR(_yr_compiler_store_string(compiler, identifier, &ref));

  meta->identifier = (const char*) yr_arena_ref_to_ptr(compiler->arena, &ref);

  if (string != NULL)
  {
    FAIL_ON_ERROR(_yr_compiler_store_string(compiler, string, &ref));

    meta->string = (const char*) yr_arena_ref_to_ptr(compiler->arena, &ref);
  }
  else
  {
    meta->string = NULL;
  }

  compiler->current_meta_idx++;

  return ERROR_SUCCESS;
}

static int _yr_parser_valid_module_name(SIZED_STRING* module_name)
{
  if (module_name->length == 0)
    return false;

  if (strlen(module_name->c_string) != module_name->length)
    return false;

  return true;
}

int yr_parser_reduce_import(yyscan_t yyscanner, SIZED_STRING* module_name)
{
  int result;

  YR_ARENA_REF ref;
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_OBJECT* module_structure;

  if (!_yr_parser_valid_module_name(module_name))
  {
    yr_compiler_set_error_extra_info(compiler, module_name->c_string);

    return ERROR_INVALID_MODULE_NAME;
  }

  YR_NAMESPACE* ns = (YR_NAMESPACE*) yr_arena_get_ptr(
      compiler->arena,
      YR_NAMESPACES_TABLE,
      compiler->current_namespace_idx * sizeof(struct YR_NAMESPACE));

  module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      compiler->objects_table, module_name->c_string, ns->name);

  // if module already imported, do nothing

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_STRUCTURE, module_name->c_string, NULL, &module_structure));

  FAIL_ON_ERROR(yr_hash_table_add(
      compiler->objects_table,
      module_name->c_string,
      ns->name,
      module_structure));

  result = yr_modules_do_declarations(module_name->c_string, module_structure);

  if (result == ERROR_UNKNOWN_MODULE)
    yr_compiler_set_error_extra_info(compiler, module_name->c_string);

  if (result != ERROR_SUCCESS)
    return result;

  FAIL_ON_ERROR(
      _yr_compiler_store_string(compiler, module_name->c_string, &ref));

  FAIL_ON_ERROR(yr_parser_emit_with_arg_reloc(
      yyscanner,
      OP_IMPORT,
      yr_arena_ref_to_ptr(compiler->arena, &ref),
      NULL,
      NULL));

  return ERROR_SUCCESS;
}

static int _yr_parser_operator_to_opcode(const char* op, int expression_type)
{
  int opcode = 0;

  switch (expression_type)
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
    YR_EXPRESSION left_operand,
    YR_EXPRESSION right_operand)
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
        yyscanner, _yr_parser_operator_to_opcode(op, expression_type), NULL));
  }
  else if (
      left_operand.type == EXPRESSION_TYPE_STRING &&
      right_operand.type == EXPRESSION_TYPE_STRING)
  {
    int opcode = _yr_parser_operator_to_opcode(op, EXPRESSION_TYPE_STRING);

    if (opcode != OP_ERROR)
    {
      FAIL_ON_ERROR(yr_parser_emit(yyscanner, opcode, NULL));
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
