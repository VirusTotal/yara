/*
Copyright (c) 2020. The YARA Authors. All Rights Reserved.

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

#include <string.h>
#include <yara/base64.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/sizedstr.h>

////////////////////////////////////////////////////////////////////////////////
// Given a pointer to a SIZED_STRING append 0, 1 or 2 bytes and base64 encode
// the string. The number of padding bytes is returned in "pad" and the caller
// is expected to trim the appropriate number of leading and trailing bytes.
//
// This is based upon the ideas at:
// https://www.leeholmes.com/searching-for-content-in-base-64-strings/
//
// The caller is responsible for freeing the returned string.
//
static SIZED_STRING* _yr_modified_base64_encode(
    SIZED_STRING* in,
    SIZED_STRING* alphabet,
    int i,
    int* pad)
{
  uint8_t* src = (uint8_t*) in->c_string;
  size_t len = in->length;
  SIZED_STRING* out;
  uint8_t* p;
  uint8_t* end;
  char* alphabet_str = alphabet->c_string;
  uint8_t* tmp;
  int j;

  *pad = ((i + len) % 3) ? 3 - ((i + len) % 3) : 0;

  // Add "i" for the number of prepended bytes.
  out = (SIZED_STRING*) yr_malloc(
      sizeof(SIZED_STRING) + i + ((len * 4 + 3) / 3) + *pad);

  if (out == NULL)
    return NULL;

  tmp = (uint8_t*) yr_malloc(sizeof(uint8_t) * (len + i));
  if (tmp == NULL)
  {
    yr_free(out);
    return NULL;
  }

  // Prepend appropriate number of bytes and copy remaining input bytes into
  // temporary buffer.
  for (j = 0; j < i; j++) tmp[j] = 'A';

  memcpy(tmp + j, src, len);
  src = tmp;

  p = (uint8_t*) out->c_string;
  end = src + len + j;

  while (end - src >= 3)
  {
    *p++ = alphabet_str[src[0] >> 2];
    *p++ = alphabet_str[((src[0] & 0x03) << 4 | src[1] >> 4)];
    *p++ = alphabet_str[((src[1] & 0x0f) << 2 | (src[2] >> 6))];
    *p++ = alphabet_str[src[2] & 0x3f];
    src += 3;
  }

  // Handle remaining bytes and padding.
  if (end - src)
  {
    *p++ = alphabet_str[src[0] >> 2];
    if (end - src == 1)
    {
      *p++ = alphabet_str[(src[0] & 0x03) << 4];
      *p++ = '=';
    }
    else
    {
      *p++ = alphabet_str[((src[0] & 0x03) << 4 | src[1] >> 4)];
      *p++ = alphabet_str[(src[1] & 0x0f) << 2];
    }
    *p++ = '=';
  }

  yr_free(tmp);
  out->length = (uint32_t)(p - (uint8_t*) out->c_string);

  return out;
}

////////////////////////////////////////////////////////////////////////////////
// Given a base64 encoded string, return a new string with leading and trailing
// bytes stripped appropriately. The number of leading bytes to skip is always
// (i + 1) or zero when no leading bytes are added and the number of trailing
// bytes is always (pad + 1) or zero when pad is zero. Also, convert the final
// string to wide if desired.
//
// Note: This implementation assumes you only prepend 0, 1 or 2 bytes.
//
static SIZED_STRING* _yr_base64_get_base64_substring(
    SIZED_STRING* encoded_str,
    int wide,
    int i,
    int pad)
{
  SIZED_STRING* new_str;
  SIZED_STRING* final_str;
  char* start;
  uint32_t length;
  int trailing;
  int leading;

  trailing = pad ? pad + 1 : 0;
  leading = i ? i + 1 : 0;

  length = encoded_str->length - (leading + trailing);

  new_str = (SIZED_STRING*) yr_malloc(sizeof(SIZED_STRING) + length);

  if (new_str == NULL)
    return NULL;

  start = encoded_str->c_string + leading;

  memcpy(new_str->c_string, start, length);

  new_str->length = length;
  new_str->c_string[length] = '\0';

  if (wide)
  {
    final_str = ss_convert_to_wide(new_str);
    yr_free(new_str);
  }
  else
  {
    final_str = new_str;
  }

  return final_str;
}

// RE metacharacters which need to be escaped when generating the final RE.
#define IS_METACHAR(x)                                                      \
  (x == '\\' || x == '^' || x == '$' || x == '|' || x == '(' || x == ')' || \
   x == '[' || x == ']' || x == '*' || x == '?' || x == '{' || x == ',' ||  \
   x == '.' || x == '+' || x == '}')

////////////////////////////////////////////////////////////////////////////////
// Given a SIZED_STRING return the number of characters which will need to be
// escaped when generating the final string to pass to the regexp compiler.
//
static int _yr_base64_count_escaped(SIZED_STRING* str)
{
  int c = 0;

  for (uint32_t i = 0; i < str->length; i++)
  {
    // We must be careful to escape null bytes because they break the RE lexer.
    if (IS_METACHAR(str->c_string[i]))
      c++;
    else if (str->c_string[i] == '\x00')
      c += 4;
  }

  return c;
}

////////////////////////////////////////////////////////////////////////////////
// Create nodes representing the different encodings of a base64 string.
//
static int _yr_base64_create_nodes(
    SIZED_STRING* str,
    SIZED_STRING* alphabet,
    int wide,
    BASE64_NODE** head,
    BASE64_NODE** tail)
{
  SIZED_STRING* encoded_str;
  SIZED_STRING* final_str;
  BASE64_NODE* node;

  int pad;

  for (int i = 0; i <= 2; i++)
  {
    if (i == 1 && str->length == 1)
      continue;

    node = (BASE64_NODE*) yr_malloc(sizeof(BASE64_NODE));
    if (node == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    FAIL_ON_NULL_WITH_CLEANUP(
        encoded_str = _yr_modified_base64_encode(str, alphabet, i, &pad),
        yr_free(node));

    // Now take the encoded string and strip the bytes which are affected by
    // the leading and trailing bytes of the plaintext.
    FAIL_ON_NULL_WITH_CLEANUP(
        final_str = _yr_base64_get_base64_substring(encoded_str, wide, i, pad),
        {
          yr_free(encoded_str);
          yr_free(node);
        });

    yr_free(encoded_str);

    node->str = final_str;
    node->escaped = _yr_base64_count_escaped(node->str);
    node->next = NULL;

    if (*head == NULL)
      *head = node;

    if (*tail == NULL)
    {
      *tail = node;
    }
    else
    {
      (*tail)->next = node;
      *tail = node;
    }
  }

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Useful for printing the encoded strings.
//
void _yr_base64_print_nodes(BASE64_NODE* head)
{
  BASE64_NODE* p = head;

  while (p != NULL)
  {
    for (size_t i = 0; i < p->str->length; i++)
    {
      if (p->str->c_string[i] >= 32 && p->str->c_string[i] <= 126)
        printf("%c", p->str->c_string[i]);
      else
        printf("\\x%02x", p->str->c_string[i]);
    }
    printf("\n");

    p = p->next;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Destroy a list of base64 nodes.
//
static void _yr_base64_destroy_nodes(BASE64_NODE* head)
{
  BASE64_NODE* p = head;
  BASE64_NODE* next;

  while (p != NULL)
  {
    yr_free(p->str);
    next = p->next;
    yr_free(p);
    p = next;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Create the regexp that is the alternatives of each of the strings collected
// in the BASE64_NODE list.
//
int _yr_base64_create_regexp(
    BASE64_NODE* head,
    RE_AST** re_ast,
    RE_ERROR* re_error)
{
  BASE64_NODE* p = head;
  char* re_str;
  char* s;
  uint32_t length = 0;

  // The number of nodes in the list, used to know how many '|'.
  uint32_t c = 0;

  while (p != NULL)
  {
    length += (p->str->length + p->escaped);
    c++;
    p = p->next;
  }

  if (c == 0)
    return ERROR_INSUFFICIENT_MEMORY;

  // Make sure to include '(' and ')'.
  // The number of '|' is number of nodes - 1.
  re_str = (char*) yr_malloc(length + 2 + (c - 1) + 1);
  if (re_str == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  s = re_str;
  p = head;
  *s++ = '(';
  while (p != NULL)
  {
    for (uint32_t i = 0; i < p->str->length; i++)
    {
      if (IS_METACHAR(p->str->c_string[i]))
        *s++ = '\\';

      if (p->str->c_string[i] == '\x00')
      {
        *s++ = '\\';
        *s++ = 'x';
        *s++ = '0';
        *s++ = '0';
      }
      else
        *s++ = p->str->c_string[i];
    }

    if (p->next != NULL)
      *s++ = '|';

    p = p->next;
  }
  *s++ = ')';
  *s = '\x00';

  // Useful for debugging as long as the string has no NULL bytes in it. ;)
  // printf("%s\n", re_str);

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_re_parse(re_str, re_ast, re_error, RE_PARSER_FLAG_NONE), yr_free(re_str));

  yr_free(re_str);

  return ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Given a string and an alphabet, generate the RE_AST suitable for representing
// the different encodings of the string. This means we generate
// "(ABCD|EFGH|IJKL)" and must be careful to escape any special characters as
// a result of the base64 encoding.
//
// This uses ideas from:
// https://www.leeholmes.com/searching-for-content-in-base-64-strings/
//
// This does not emit the code for the RE. A further call to yr_re_ast_emit_code
// is required to get the code.
//
int yr_base64_ast_from_string(
    SIZED_STRING* in_str,
    YR_MODIFIER modifier,
    RE_AST** re_ast,
    RE_ERROR* error)
{
  BASE64_NODE* head = NULL;
  BASE64_NODE* tail = NULL;
  SIZED_STRING* wide_str;

  if (modifier.flags & STRING_FLAGS_WIDE)
  {
    wide_str = ss_convert_to_wide(in_str);

    if (modifier.flags & STRING_FLAGS_BASE64)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(wide_str, modifier.alphabet, 0, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64 wide string");
            yr_free(wide_str);
            _yr_base64_destroy_nodes(head);
          });
    }

    if (modifier.flags & STRING_FLAGS_BASE64_WIDE)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(wide_str, modifier.alphabet, 1, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64wide wide string");
            yr_free(wide_str);
            _yr_base64_destroy_nodes(head);
          });
    }

    yr_free(wide_str);
  }

  if (modifier.flags & STRING_FLAGS_ASCII)
  {
    if (modifier.flags & STRING_FLAGS_BASE64)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(in_str, modifier.alphabet, 0, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64 ascii string");
            _yr_base64_destroy_nodes(head);
          });
    }

    if (modifier.flags & STRING_FLAGS_BASE64_WIDE)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(in_str, modifier.alphabet, 1, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64wide ascii string");
            _yr_base64_destroy_nodes(head);
          });
    }
  }

  if (!(modifier.flags & STRING_FLAGS_WIDE) &&
      !(modifier.flags & STRING_FLAGS_ASCII))
  {
    if (modifier.flags & STRING_FLAGS_BASE64)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(in_str, modifier.alphabet, 0, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64 string");
            _yr_base64_destroy_nodes(head);
          });
    }

    if (modifier.flags & STRING_FLAGS_BASE64_WIDE)
    {
      FAIL_ON_ERROR_WITH_CLEANUP(
          _yr_base64_create_nodes(in_str, modifier.alphabet, 1, &head, &tail),
          {  // Cleanup
            strcpy(error->message, "Failure encoding base64wide string");
            _yr_base64_destroy_nodes(head);
          });
    }
  }

  // Useful for printing the contents of the nodes, to make sure they were
  // encoded and stripped properly.
  //_yr_base64_print_nodes(head);

  // Create the final regex string to be parsed from all the nodes.
  // Error message is filled in by the caller in case of failure.
  FAIL_ON_ERROR_WITH_CLEANUP(
      _yr_base64_create_regexp(head, re_ast, error),
      _yr_base64_destroy_nodes(head));

  _yr_base64_destroy_nodes(head);

  return ERROR_SUCCESS;
}
