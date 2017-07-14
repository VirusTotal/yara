/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

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

#include <yara.h>
#include "blob.h"
#include "util.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#include <fileapi.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>

static void test_boolean_operators()
{
  assert_true_rule(
      "rule test { condition: true }", NULL);

  assert_true_rule(
      "rule test { condition: true or false }", NULL);

  assert_true_rule(
      "rule test { condition: true and true }", NULL);

  assert_true_rule(
      "rule test { condition: 0x1 and 0x2}", NULL);

  assert_false_rule(
      "rule test { condition: false }", NULL);

  assert_false_rule(
      "rule test { condition: true and false }", NULL);

  assert_false_rule(
      "rule test { condition: false or false }", NULL);
}


static void test_comparison_operators()
{
  assert_true_rule(
      "rule test { condition: 2 > 1 }", NULL);

  assert_true_rule(
      "rule test { condition: 1 < 2 }", NULL);

  assert_true_rule(
      "rule test { condition: 2 >= 1 }", NULL);

  assert_true_rule(
      "rule test { condition: 1 <= 1 }", NULL);

  assert_true_rule(
      "rule test { condition: 1 == 1 }", NULL);

  assert_true_rule(
      "rule test { condition: 1.5 == 1.5}", NULL);

  assert_true_rule(
      "rule test { condition: 1.0 == 1}", NULL);

  assert_true_rule(
      "rule test { condition: 1.5 >= 1.0}", NULL);

  assert_true_rule(
      "rule test { condition: 1.5 >= 1}", NULL);

  assert_true_rule(
      "rule test { condition: 1.0 >= 1}", NULL);

  assert_true_rule(
      "rule test { condition: 0.5 < 1}", NULL);

  assert_true_rule(
      "rule test { condition: 0.5 <= 1}", NULL);

  assert_true_rule(
      "rule rest { condition: 1.0 <= 1}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abc\" == \"abc\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abc\" <= \"abc\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abc\" >= \"abc\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"ab\" < \"abc\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abc\" > \"ab\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abc\" < \"abd\"}", NULL);

  assert_true_rule(
      "rule rest { condition: \"abd\" > \"abc\"}", NULL);

  assert_false_rule(
      "rule test { condition: 1 != 1}", NULL);

  assert_false_rule(
      "rule test { condition: 1 != 1.0}", NULL);

  assert_false_rule(
      "rule test { condition: 2 > 3}", NULL);

  assert_false_rule(
      "rule test { condition: 2.1 < 2}", NULL);

  assert_false_rule(
      "rule test { condition: \"abc\" != \"abc\"}", NULL);

  assert_false_rule(
      "rule test { condition: \"abc\" > \"abc\"}", NULL);

  assert_false_rule(
      "rule test { condition: \"abc\" < \"abc\"}", NULL);

}

static void test_arithmetic_operators()
{
  assert_true_rule(
      "rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }", NULL);

  assert_true_rule(
      "rule test { condition: 5 % 2 == 1 }", NULL);

  assert_true_rule(
      "rule test { condition: 1.5 + 1.5 == 3}", NULL);

  assert_true_rule(
      "rule test { condition: 3 \\ 2 == 1}", NULL);

  assert_true_rule(
      "rule test { condition: 3.0 \\ 2 == 1.5}", NULL);

  assert_true_rule(
      "rule test { condition: 1 + -1 == 0}", NULL);

  assert_true_rule(
      "rule test { condition: -1 + -1 == -2}", NULL);

  assert_true_rule(
      "rule test { condition: 4 --2 * 2 == 8}", NULL);

  assert_true_rule(
      "rule test { condition: -1.0 * 1 == -1.0}", NULL);

  assert_true_rule(
      "rule test { condition: 1-1 == 0}", NULL);

  assert_true_rule(
      "rule test { condition: -2.0-3.0 == -5}", NULL);

  assert_true_rule(
      "rule test { condition: --1 == 1}", NULL);

  assert_true_rule(
      "rule test { condition: 1--1 == 2}", NULL);

  assert_true_rule(
      "rule test { condition: -0x01 == -1}", NULL);

  assert_true_rule(
      "rule test { condition: 0o10 == 8 }", NULL);

  assert_true_rule(
      "rule test { condition: 0o100 == 64 }", NULL);

  assert_true_rule(
      "rule test { condition: 0o755 == 493 }", NULL);

}


static void test_bitwise_operators()
{
  assert_true_rule(
      "rule test { condition: 0x55 | 0xAA == 0xFF }",
      NULL);

  assert_true_rule(
      "rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }",
      NULL);

  assert_true_rule(
      "rule test { condition: ~0x55 & 0xFF == 0xAA }",
      NULL);

  assert_true_rule(
      "rule test { condition: 8 >> 2 == 2 }",
      NULL);

  assert_true_rule(
      "rule test { condition: 1 << 3 == 8 }",
      NULL);

  assert_true_rule(
      "rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }",
      NULL);

  assert_false_rule(
      "rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }",
      NULL);

  assert_false_rule(
      "rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}",
      NULL);

}


static void test_syntax()
{
  assert_error(
      "rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }",
      ERROR_DUPLICATED_STRING_IDENTIFIER);
}


static void test_anonymous_strings()
{
  assert_true_rule(
      "rule test { strings: $ = \"a\" $ = \"b\" condition: all of them }",
      "ab");
}


static void test_strings()
{
  char* str = "---- abc ---- xyz";
  uint8_t blob[] = "---- a\0b\0c\0 -\0-\0-\0-\0x\0y\0z\0";

  assert_true_rule(
      "rule test { strings: $a = \"a\" condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"ab\" condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"xyz\" condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" nocase fullword condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"aBc\" nocase  condition: $a }",
      str);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      str);

  assert_false_rule(
      "rule test { strings: $a = \"a\" fullword condition: $a }",
      str);

  assert_false_rule(
      "rule test { strings: $a = \"ab\" fullword condition: $a }",
      str);

  assert_false_rule(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      str);

  assert_true_rule_blob(
      "rule test { strings: $a = \"a\" wide condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"a\" wide ascii condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"ab\" wide condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"ab\" wide ascii condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide nocase fullword condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"aBc\" wide nocase condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"aBc\" wide ascii nocase condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"---xyz\" wide nocase condition: $a }",
      blob);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      "abc");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      "xabcx");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      "xabc");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      "abcx");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
      "abcx");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
      "a\0abc");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      "a\0b\0c\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      "x\0a\0b\0c\0x\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"ab\" wide fullword condition: $a }",
      "x\0a\0b\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      "x\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      "x\001a\0b\0c\0");

  assert_true_rule(
      "rule test {\n\
         strings:\n\
             $a = \"abcdef\"\n\
             $b = \"cdef\"\n\
             $c = \"ef\"\n\
         condition:\n\
             all of them\n\
       }", "abcdef");
}


static void test_wildcard_strings()
{
  assert_true_rule_blob(
      "rule test {\n\
         strings:\n\
             $s1 = \"abc\"\n\
             $s2 = \"xyz\"\n\
         condition:\n\
             for all of ($*) : ($)\n\
      }",
      "---- abc ---- A\x00""B\x00""C\x00 ---- xyz");
}


static void test_hex_strings()
{
  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 64 01 00 00 60 01 } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 64 0? 00 00 ?0 01 } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(\

      "rule test { \
        strings: $a = { 6? 01 00 00 60 0? } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 64 01 [1-3] 60 01 } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 64 01 [1-3] (60|61) 01 } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3} \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3} \
        condition: $a }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 2e 7? (65 | ?? ) 78 } \
        condition: $a }",
      PE32_FILE);

  assert_false_rule_blob(
      "rule test { \
        strings: $a = { 4D 5A [0-300] 6A 2A } \
        condition: $a }",
      PE32_FILE);

  assert_false_rule_blob(
      "rule test { \
        strings: $a = { 4D 5A [0-128] 45 [0-128] 01 [0-128]  C3 } \
        condition: $a }",
      PE32_FILE);

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] // Inline comment\n\r \
          38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline multi-line\n\r \
                                 comment */ [-] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = {\n 31 32 [-] 38 39 \n\r} \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [1] 34 35 [2] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test {\
         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 } \
         condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 33 } \
        condition: !a == 3}",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 34 } \
        condition: !a == 4}",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 34 } \
        condition: !a == 4 }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 38 39 } \
        condition: all of them }",
      "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 32 33 } \
        condition: $a }",
      "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 35 36 [-] 31 32 } \
        condition: $a }",
      "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [2-] 34 35 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 33 34 [0-2] 36 37 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 34 35 [0-2] 36 37 } \
        condition: $a }",
      "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [0-3] 37 38 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [1] 33 34 } \
        condition: $a }",
      "12\n34");

  assert_true_rule(
      "rule test { \
        strings: $a = {31 32 [3-6] 32} \
        condition: !a == 6 }",
      "12111222");

  assert_true_rule(
      "rule test { \
        strings: $a = {31 [0-3] (32|33)} \
        condition: !a == 2 }",
      "122222222");

  assert_error(
      "rule test { \
        strings: $a = { 01 [0] 02 } \
        condition: $a }",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { [-] 01 02 } condition: $a }",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 02 [-] } \
        condition: $a }",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 02 ([-] 03 | 04) } \
        condition: $a }",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 02 (03 [-] | 04) } \
        condition: $a }",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 02 (03 | 04 [-]) } \
        condition: $a ",
      ERROR_INVALID_HEX_STRING);

  /* TODO: tests.py:551 ff. */
}


static void test_count()
{
  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: #a == 2 }",
      "mississippi");
}


static void test_at()
{
  assert_true_rule(
      "rule test { \
        strings: $a = \"ssi\" \
        condition: $a at 2 and $a at 5 }",
      "mississippi");

  assert_true_rule(
      "rule test { \
        strings: $a = \"mis\" \
        condition: $a at ~0xFF & 0xFF }",
      "mississippi");

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 00 00 00 00 ?? 74 65 78 74 } \
        condition: $a at 308}",
      PE32_FILE);
}


static void test_in()
{
  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 6a 2a 58 c3 } \
        condition: $a in (entrypoint .. entrypoint + 1) }",
      PE32_FILE);
}


static void test_offset()
{
  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a == 2 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a == @a[1] }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a[2] == 5 }",
      "mississippi");
}


static void test_length()
{
  assert_true_rule(
      "rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*ssi/ condition: !a == 8 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } condition: !a == 11}",
      "mississippi");
}


static void test_of()
{
  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: any of them }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: 1 of them }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: 2 of them }",
      "mississippi");

  assert_true_rule(
      "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\""
      "condition: any of ($a*, $b*) }",
      "mississippi");

  assert_true_rule_blob(
      "rule test { \
         strings: \
           $ = /abc/ \
           $ = /def/ \
           $ = /ghi/ \
         condition: \
           for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )\
       }",
       "abc\000def\000ghi");

  assert_false_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mis\" \
          $c = \"oops\" \
        condition: \
          all of them \
      }",
      "mississippi");

  assert_error(
      "rule test { condition: all of ($a*) }",
      ERROR_UNDEFINED_STRING);

  assert_error(
      "rule test { condition: all of them }",
      ERROR_UNDEFINED_STRING);
}


void test_for()
{
  assert_true_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
        condition: \
          for all i in (1..#a) : (@a[i] >= 2 and @a[i] <= 5) \
      }",
      "mississippi");

  assert_true_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mi\" \
        condition: \
          for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j])) \
      }",
      "mississippi");

  assert_false_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
        condition: \
          for all i in (1..#a) : (@a[i] == 5) \
      }",
      "mississippi");
}


void test_re()
{
  assert_true_rule(
      "rule test { strings: $a = /ssi/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi(s|p)/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssim*/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssa?/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /Miss/ nocase condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /(M|N)iss/ nocase condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /[M-N]iss/ nocase condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ppi\\tmi/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ppi\\.mi/ condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /^mississippi/ fullword condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /mississippi.*mississippi$/s condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi");

  assert_false_rule(
      "rule test { strings: $a = /^ssi/ condition: $a }",
      "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /ssi$/ condition: $a }",
      "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /ssissi/ fullword condition: $a }",
      "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /^[isp]+/ condition: $a }",
      "mississippi");

  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 6 }",
      "a\0x\0b\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 8 }",
      "a\0x\0x\0b\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      "a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      "\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      "\ta\0b\0c\0");

  assert_false_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      "x\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      "x\ta\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      "a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      "a\0b\0c\0\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      "a\0b\0c\0\t");

  assert_false_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      "a\0b\0c\0x\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      "a\0b\0c\0b\t");

  assert_false_rule_blob(
      "rule test { strings: $a = /\\b/ wide condition: $a }",
      "abc");

  assert_regexp_syntax_error(")");
  assert_true_regexp("abc", "abc", "abc");
  assert_false_regexp("abc", "xbc");
  assert_false_regexp("abc", "axc");
  assert_false_regexp("abc", "abx");
  assert_true_regexp("abc", "xabcx", "abc");
  assert_true_regexp("abc", "ababc", "abc");
  assert_true_regexp("a.c", "abc", "abc");
  assert_false_regexp("a.b", "a\nb");
  assert_false_regexp("a.*b", "acc\nccb");
  assert_false_regexp("a.{4,5}b", "acc\nccb");
  assert_true_regexp("a.b", "a\rb", "a\rb");
  assert_true_regexp("ab*c", "abc", "abc");
  assert_true_regexp("ab*c", "ac", "ac");
  assert_true_regexp("ab*bc", "abc", "abc");
  assert_true_regexp("ab*bc", "abbc", "abbc");
  assert_true_regexp("a.*bb", "abbbb", "abbbb");
  assert_true_regexp("a.*?bbb", "abbbbbb", "abbb");
  assert_true_regexp("a.*c", "ac", "ac");
  assert_true_regexp("a.*c", "axyzc", "axyzc");
  assert_true_regexp("ab+c", "abbc", "abbc");
  assert_false_regexp("ab+c", "ac");
  assert_true_regexp("ab+", "abbbb", "abbbb");
  assert_true_regexp("ab+?", "abbbb", "ab");
  assert_false_regexp("ab+bc", "abc");
  assert_false_regexp("ab+bc", "abq");
  assert_true_regexp("a+b+c", "aabbabc", "abc");
  assert_false_regexp("ab?bc", "abbbbc");
  assert_true_regexp("ab?c", "abc", "abc");
  assert_true_regexp("ab*?", "abbb", "a");
  assert_true_regexp("ab?c", "ac", "ac");
  assert_true_regexp("ab??", "ab", "a");
  assert_true_regexp("a(b|x)c", "abc", "abc");
  assert_true_regexp("a(b|x)c", "axc", "axc");
  assert_true_regexp("a(b|.)c", "axc", "axc");
  assert_true_regexp("a(b|x|y)c", "ayc", "ayc");
  assert_true_regexp("(a+|b)*", "ab", "ab");
  assert_true_regexp("a|b|c|d|e", "e", "e");
  assert_true_regexp("(a|b|c|d|e)f", "ef", "ef");
  assert_true_regexp(".b{2}", "abb", "abb");
  assert_true_regexp(".b{2,3}", "abbb", "abbb");
  assert_true_regexp(".b{2,3}?", "abbb", "abb");
  assert_true_regexp("ab{2,3}c", "abbbc", "abbbc");
  assert_true_regexp("ab{2,3}?c", "abbbc", "abbbc");
  assert_true_regexp(".b{2,3}cccc", "abbbcccc", "abbbcccc");
  assert_true_regexp(".b{2,3}?cccc", "abbbcccc", "bbbcccc");
  assert_true_regexp("a.b{2,3}cccc", "aabbbcccc", "aabbbcccc");
  assert_true_regexp("ab{2,3}c", "abbbc", "abbbc");
  assert_true_regexp("ab{2,3}?c", "abbbc", "abbbc");
  assert_true_regexp("ab{0,1}?c", "abc", "abc");
  assert_true_regexp("a{0,1}?bc", "abc", "abc");
  assert_true_regexp("a{0,1}bc", "bbc", "bc");
  assert_true_regexp("a{0,1}?bc", "abc", "bc");
  assert_true_regexp("aa{0,1}?bc", "abc", "abc");
  assert_true_regexp("aa{0,1}?bc", "abc", "abc");
  assert_true_regexp("aa{0,1}bc", "abc", "abc");
  assert_true_regexp("ab{1}c", "abc", "abc");
  assert_true_regexp("ab{1,2}c", "abbc", "abbc");
  assert_true_regexp("ab{1,}c", "abbbc", "abbbc");
  assert_false_regexp("ab{1,}b", "ab");
  assert_false_regexp("ab{1}c", "abbc");
  assert_true_regexp("ab{0,}c", "ac", "ac");
  assert_true_regexp("ab{1,1}c", "abc", "abc");
  assert_true_regexp("ab{0,}c", "abbbc", "abbbc");
  assert_true_regexp("ab{,3}c", "abbbc", "abbbc");
  assert_false_regexp("ab{,2}c", "abbbc");
  assert_false_regexp("ab{4,5}bc", "abbbbc");
  assert_true_regexp("ab{0,1}", "abbbbb", "ab");
  assert_true_regexp("ab{0,2}", "abbbbb", "abb");
  assert_true_regexp("ab{0,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{0,4}", "abbbbb", "abbbb");
  assert_true_regexp("ab{1,1}", "abbbbb", "ab");
  assert_true_regexp("ab{1,2}", "abbbbb", "abb");
  assert_true_regexp("ab{1,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{2,2}", "abbbbb", "abb");
  assert_true_regexp("ab{2,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{1,3}?", "abbbbb", "ab");
  assert_true_regexp("ab{0,1}?", "abbbbb", "a");
  assert_true_regexp("ab{0,2}?", "abbbbb", "a");
  assert_true_regexp("ab{0,3}?", "abbbbb", "a");
  assert_true_regexp("ab{0,4}?", "abbbbb", "a");
  assert_true_regexp("ab{1,1}?", "abbbbb", "ab");
  assert_true_regexp("ab{1,2}?", "abbbbb", "ab");
  assert_true_regexp("ab{1,3}?", "abbbbb", "ab");
  assert_true_regexp("ab{2,2}?", "abbbbb", "abb");
  assert_true_regexp("ab{2,3}?", "abbbbb", "abb");
  assert_true_regexp(".(abc){0,1}", "xabcabcabcabc", "xabc");
  assert_true_regexp(".(abc){0,2}", "xabcabcabcabc", "xabcabc");
  assert_true_regexp("x{1,2}abcd", "xxxxabcd", "xxabcd");
  assert_true_regexp("x{1,2}abcd", "xxxxabcd", "xxabcd");
  assert_true_regexp("ab{.*}", "ab{c}", "ab{c}");
  assert_true_regexp(".(aa){1,2}", "aaaaaaaaaa", "aaaaa");
  assert_true_regexp("a.(bc.){2}", "aabcabca", "aabcabca");
  assert_true_regexp("(ab{1,2}c){1,3}", "abbcabc", "abbcabc");
  assert_true_regexp("ab(c|cc){1,3}d", "abccccccd", "abccccccd");
  assert_true_regexp("a[bx]c", "abc", "abc");
  assert_true_regexp("a[bx]c", "axc", "axc");
  assert_true_regexp("a[0-9]*b", "ab", "ab");
  assert_true_regexp("a[0-9]*b", "a0123456789b", "a0123456789b");
  assert_true_regexp("[0-9a-f]+", "0123456789abcdef", "0123456789abcdef");
  assert_true_regexp("[0-9a-f]+", "xyz0123456789xyz", "0123456789");
  assert_true_regexp("a[\\s\\S]b", "a b", "a b");
  assert_true_regexp("a[\\d\\D]b", "a1b", "a1b");
  assert_false_regexp("[x-z]+", "abc");
  assert_true_regexp("a[-]?c", "ac", "ac");
  assert_true_regexp("a[-b]", "a-", "a-");
  assert_true_regexp("a[-b]", "ab", "ab");
  assert_true_regexp("a[b-]", "a-", "a-");
  assert_true_regexp("a[b-]", "ab", "ab");
  assert_true_regexp("[a-c-e]", "b", "b");
  assert_true_regexp("[a-c-e]", "-", "-");
  assert_false_regexp("[a-c-e]", "d");
  assert_regexp_syntax_error("[b-a]");
  assert_regexp_syntax_error("(abc");
  assert_regexp_syntax_error("abc)");
  assert_regexp_syntax_error("a[]b");
  assert_true_regexp("a[\\-b]", "a-", "a-");
  assert_true_regexp("a[\\-b]", "ab", "ab");
  assert_true_regexp("a]", "a]", "a]");
  assert_true_regexp("a[]]b", "a]b", "a]b");
  assert_true_regexp("a[\\]]b", "a]b", "a]b");
  assert_true_regexp("a[^bc]d", "aed", "aed");
  assert_false_regexp("a[^bc]d", "abd");
  assert_true_regexp("a[^-b]c", "adc", "adc");
  assert_false_regexp("a[^-b]c", "a-c");
  assert_false_regexp("a[^]b]c", "a]c");
  assert_true_regexp("a[^]b]c", "adc", "adc");
  assert_true_regexp("[^ab]*", "cde", "cde");
  assert_regexp_syntax_error(")(");
  assert_true_regexp("a\\sb", "a b", "a b");
  assert_true_regexp("a\\sb", "a\tb", "a\tb");
  assert_true_regexp("a\\sb", "a\rb", "a\rb");
  assert_true_regexp("a\\sb", "a\nb", "a\nb");
  assert_true_regexp("a\\sb", "a\vb", "a\vb");
  assert_true_regexp("a\\sb", "a\fb", "a\fb");
  assert_false_regexp("a\\Sb", "a b");
  assert_false_regexp("a\\Sb", "a\tb");
  assert_false_regexp("a\\Sb", "a\rb");
  assert_false_regexp("a\\Sb", "a\nb");
  assert_false_regexp("a\\Sb", "a\vb");
  assert_false_regexp("a\\Sb", "a\fb");
  assert_true_regexp("\\n\\r\\t\\f\\a", "\n\r\t\f\a", "\n\r\t\f\a");
  assert_true_regexp("[\\n][\\r][\\t][\\f][\\a]", "\n\r\t\f\a", "\n\r\t\f\a");
  assert_true_regexp("\\x01\\x02\\x03", "\x01\x02\x03", "\x01\x02\x03");
  assert_true_regexp("[\\x01-\\x03]+", "\x01\x02\x03", "\x01\x02\x03");
  assert_false_regexp("[\\x00-\\x02]+", "\x03\x04\x05");
  assert_true_regexp("[\\x5D]", "]", "]");
  assert_true_regexp("[\\0x5A-\\x5D]", "\x5B", "\x5B");
  assert_true_regexp("[\\x5D-\\x5F]", "\x5E", "\x5E");
  assert_true_regexp("[\\x5C-\\x5F]", "\x5E", "\x5E");
  assert_true_regexp("[\\x5D-\\x5F]", "\x5E", "\x5E");
  assert_true_regexp("a\\wc", "abc", "abc");
  assert_true_regexp("a\\wc", "a_c", "a_c");
  assert_true_regexp("a\\wc", "a0c", "a0c");
  assert_false_regexp("a\\wc", "a*c");
  assert_true_regexp("\\w+", "--ab_cd0123--", "ab_cd0123");
  assert_true_regexp("[\\w]+", "--ab_cd0123--", "ab_cd0123");
  assert_true_regexp("\\D+", "1234abc5678", "abc");
  assert_true_regexp("[\\d]+", "0123456789", "0123456789");
  assert_true_regexp("[\\D]+", "1234abc5678", "abc");
  assert_true_regexp("[\\da-fA-F]+", "123abc", "123abc");
  assert_false_regexp("^(ab|cd)e", "abcde");
  assert_true_regexp("(abc|)ef", "abcdef", "ef");
  assert_true_regexp("(abc|)ef", "abcef", "abcef");
  assert_true_regexp("\\babc", "abc", "abc");
  assert_true_regexp("abc\\b", "abc", "abc");
  assert_false_regexp("\\babc", "1abc");
  assert_false_regexp("abc\\b", "abc1");
  assert_true_regexp("abc\\s\\b", "abc x", "abc ");
  assert_false_regexp("abc\\s\\b", "abc  ");
  assert_true_regexp("\\babc\\b", " abc ", "abc");
  assert_true_regexp("\\b\\w\\w\\w\\b", " abc ", "abc");
  assert_true_regexp("\\w\\w\\w\\b", "abcd", "bcd");
  assert_true_regexp("\\b\\w\\w\\w", "abcd", "abc");
  assert_false_regexp("\\b\\w\\w\\w\\b", "abcd");
  assert_false_regexp("\\Babc", "abc");
  assert_false_regexp("abc\\B", "abc");
  assert_true_regexp("\\Babc", "1abc", "abc");
  assert_true_regexp("abc\\B", "abc1", "abc");
  assert_false_regexp("abc\\s\\B", "abc x");
  assert_true_regexp("abc\\s\\B", "abc  ", "abc ");
  assert_true_regexp("\\w\\w\\w\\B", "abcd", "abc");
  assert_true_regexp("\\B\\w\\w\\w", "abcd", "bcd");
  assert_false_regexp("\\B\\w\\w\\w\\B", "abcd");

  // This is allowed in most regexp engines but in order to keep the
  // grammar free of shift/reduce conflicts I've decided not supporting
  // it. Users can use the (abc|) form instead.
  assert_regexp_syntax_error("(|abc)ef");

  assert_true_regexp("((a)(b)c)(d)", "abcd", "abcd");
  assert_true_regexp("(a|b)c*d", "abcd", "bcd");
  assert_true_regexp("(ab|ab*)bc", "abc", "abc");
  assert_true_regexp("a([bc]*)c*", "abc", "abc");
  assert_true_regexp("a([bc]*)c*", "ac", "ac");
  assert_true_regexp("a([bc]*)c*", "a", "a");
  assert_true_regexp("a([bc]*)(c*d)", "abcd", "abcd");
  assert_true_regexp("a([bc]+)(c*d)", "abcd", "abcd");
  assert_true_regexp("a([bc]*)(c+d)", "abcd", "abcd");
  assert_true_regexp("a[bcd]*dcdcde", "adcdcde", "adcdcde");
  assert_false_regexp("a[bcd]+dcdcde", "adcdcde");
  assert_true_regexp("\\((.*), (.*)\\)", "(a, b)", "(a, b)");
  assert_true_regexp("abc|123$", "abcx", "abc");
  assert_false_regexp("abc|123$", "123x");
  assert_true_regexp("abc|^123", "123", "123");
  assert_false_regexp("abc|^123", "x123");
  assert_true_regexp("^abc$", "abc", "abc");
  assert_false_regexp("^abc$", "abcc");
  assert_true_regexp("^abc", "abcc", "abc");
  assert_false_regexp("^abc$", "aabc");
  assert_false_regexp("abc^", "abc");
  assert_false_regexp("ab^c", "abc");
  assert_false_regexp("a^bcdef", "abcdef")
  assert_true_regexp("abc$", "aabc", "abc");
  assert_false_regexp("$abc", "abc");
  assert_true_regexp("(a|a$)bcd", "abcd", "abcd");
  assert_false_regexp("(a$|a$)bcd", "abcd");
  assert_false_regexp("(abc$|ab$)", "abcd");
  assert_true_regexp("^a(bc+|b[eh])g|.h$", "abhg", "abhg");
  assert_true_regexp("(bc+d$|ef*g.|h?i(j|k))", "effgz", "effgz");
  assert_true_regexp("(bc+d$|ef*g.|h?i(j|k))", "ij", "ij");
  assert_false_regexp("(bc+d$|ef*g.|h?i(j|k))", "effg");
  assert_false_regexp("(bc+d$|ef*g.|h?i(j|k))", "bcdd");
  assert_true_regexp("(bc+d$|ef*g.|h?i(j|k))", "reffgz", "effgz");

  // Test case for issue #324
  assert_true_regexp("whatever|   x.   x", "   xy   x", "   xy   x");

  // test case for issue #503, \x without two following hex-digits
  assert_regexp_syntax_error("\\x0");
  assert_regexp_syntax_error("\\x");

  assert_regexp_syntax_error("x{0,0}");
  assert_regexp_syntax_error("x{0}");

  assert_regexp_syntax_error("\\xxy");

  // Test case for issue #682
  assert_true_regexp("(a|\\b)[a]{1,}", "aaaa", "aaaa");

  assert_error(
      "rule test { strings: $a = /a\\/ condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = /[a\\/ condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = /MZ.{300,}t/ \
        condition: !a == 317 }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = /MZ.{300,}?t/ \
        condition: !a == 314 }",
      PE32_FILE);
}


static void test_entrypoint()
{
  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 6a 2a 58 c3 } \
        condition: $a at entrypoint }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at entrypoint }",
      ELF32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at entrypoint }",
      ELF64_FILE);

  assert_false_rule(
      "rule test { condition: entrypoint >= 0 }",
      NULL);
}


static void test_filesize()
{
  char rule[80];

  snprintf(
      rule,
      sizeof(rule),
      "rule test { condition: filesize == %zd }",
      sizeof(PE32_FILE));

  assert_true_rule_blob(
      rule,
      PE32_FILE);
}


static void test_comments()
{
  assert_true_rule(
      "rule test {\n\
         condition:\n\
             //  this is a comment\n\
             /*** this is a comment ***/\n\
             /* /* /*\n\
                 this is a comment\n\
             */\n\
             true\n\
      }",
      NULL);
}

static void test_matches_operator()
{
  assert_true_rule(
      "rule test { condition: \"foo\" matches /foo/ }",
      NULL);

  assert_false_rule(
      "rule test { condition: \"foo\" matches /bar/ }",
      NULL);

  assert_true_rule(
      "rule test { condition: \"FoO\" matches /fOo/i }",
      NULL);

  assert_true_rule(
      "rule test { condition: \"xxFoOxx\" matches /fOo/i }",
      NULL);

  assert_false_rule(
      "rule test { condition: \"xxFoOxx\" matches /^fOo/i }",
      NULL);

  assert_false_rule(
      "rule test { condition: \"xxFoOxx\" matches /fOo$/i }",
      NULL);

  assert_true_rule(
      "rule test { condition: \"foo\" matches /^foo$/i }",
      NULL);

  assert_true_rule(
      "rule test { condition: \"foo\\nbar\" matches /foo.*bar/s }",
      NULL);

  assert_false_rule(
      "rule test { condition: \"foo\\nbar\" matches /foo.*bar/ }",
      NULL);
}


static void test_global_rules()
{
  assert_true_rule(
      "global private rule global_rule { \
        condition: \
          true \
      } \
      rule test { \
        condition: true \
      }",
      NULL);

  assert_false_rule(
      "global private rule global_rule { \
        condition: \
          false \
      } \
      rule test { \
        condition: true \
      }",
      NULL);
}


static void test_modules()
{
  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.constants.one + 1 == tests.constants.two \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.constants.foo == \"foo\" \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.constants.empty == \"\"  \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.empty() == \"\"  \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.struct_array[1].i == 1  \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.struct_array[0].i == 1 or true \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.integer_array[0] == 0 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.integer_array[1] == 1 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.integer_array[256] == 256 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.string_array[0] == \"foo\" \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.string_array[2] == \"baz\" \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.string_dict[\"foo\"] == \"foo\" \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.string_dict[\"bar\"] == \"bar\" \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.isum(1,2) == 3 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.isum(1,2,3) == 6 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.fsum(1.0,2.0) == 3.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.fsum(1.0,2.0,3.0) == 6.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.foobar(1) == tests.foobar(1) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.foobar(1) != tests.foobar(2) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
       rule test { \
        condition: tests.length(\"dummy\") == 5 \
      }",
      NULL);


  assert_false_rule(
      "import \"tests\" \
      rule test { condition: tests.struct_array[0].i == 1  \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { condition: tests.isum(1,1) == 3 \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { condition: tests.fsum(1.0,1.0) == 3.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo/,\"foo\") == 3 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo/,\"bar\") == -1\
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo.bar/i,\"FOO\\nBAR\") == -1\
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo.bar/is,\"FOO\\nBAR\") == 7\
      }",
      NULL);

  assert_error(
      "import \"\\x00\"",
      ERROR_INVALID_MODULE_NAME);

  assert_error(
      "import \"\"",
      ERROR_INVALID_MODULE_NAME);
}

#if defined(HASH_MODULE)
static void test_hash_module()
{
  uint8_t blob[] = {0x61, 0x62, 0x63, 0x64, 0x65};

  assert_true_rule_blob(
      "import \"hash\" \
       rule test { \
        condition: \
          hash.md5(0, filesize) == \
            \"ab56b4d92b40713acc5af89985d4b786\" \
            and \
          hash.md5(1, filesize) == \
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\" \
            and \
          hash.sha1(0, filesize) == \
            \"03de6c570bfe24bfc328ccd7ca46b76eadaf4334\" \
            and \
          hash.sha1(1, filesize) == \
            \"a302d65ae4d9e768a1538d53605f203fd8e2d6e2\" \
            and \
          hash.sha256(0, filesize) == \
            \"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c\" \
            and \
          hash.sha256(1, filesize) == \
            \"aaaaf2863e043b9df604158ad5c16ff1adaf3fd7e9fcea5dcb322b6762b3b59a\" \
      }",
      blob);

  // Test hash caching mechanism

  assert_true_rule_blob(
      "import \"hash\" \
       rule test { \
        condition: \
          hash.md5(0, filesize) == \
            \"ab56b4d92b40713acc5af89985d4b786\" \
            and \
          hash.md5(1, filesize) == \
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\" \
            and \
          hash.md5(0, filesize) == \
            \"ab56b4d92b40713acc5af89985d4b786\" \
            and \
          hash.md5(1, filesize) == \
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\" \
      }",
      blob);
}
#endif


void test_integer_functions()
{
  assert_true_rule(
      "rule test { condition: uint8(0) == 0xAA}",
      "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint16(0) == 0xBBAA}",
      "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint32(0) == 0xDDCCBBAA}",
      "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint8be(0) == 0xAA}",
      "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint16be(0) == 0xAABB}",
      "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint32be(0) == 0xAABBCCDD}",
      "\xaa\xbb\xcc\xdd");
}


void test_file_descriptor()
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

#if defined(_WIN32) || defined(__CYGWIN__)
  HANDLE fd = CreateFile("tests/data/true.yar", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (fd == INVALID_HANDLE_VALUE)
  {
    fputs("CreateFile failed", stderr);
    exit(1);
  }
#else
  int fd = open("tests/data/true.yar", O_RDONLY);
  if (fd < 0)
  {
    perror("open");
    exit(EXIT_FAILURE);
  }
#endif
  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_add_fd(compiler, fd, NULL, NULL) != 0) {
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

#if defined(_WIN32) || defined(__CYGWIN__)
  CloseHandle(fd);
#else
  close(fd);
#endif

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

  if (compiler)
  {
    yr_compiler_destroy(compiler);
  }
  if (rules)
  {
    yr_rules_destroy(rules);
  }

  return;
}

void test_max_string_per_rules()
{
  uint32_t new_max_strings_per_rule = 1;
  uint32_t old_max_strings_per_rule;

  yr_get_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &old_max_strings_per_rule);

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &new_max_strings_per_rule);

  assert_error(
      "rule test { \
         strings: \
           $ = \"uno\" \
           $ = \"dos\" \
         condition: \
           all of them }",
      ERROR_TOO_MANY_STRINGS);

  new_max_strings_per_rule = 2;

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &new_max_strings_per_rule);

  assert_error(
      "rule test { \
         strings: \
           $ = \"uno\" \
           $ = \"dos\" \
         condition: \
           all of them }",
      ERROR_SUCCESS);

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &old_max_strings_per_rule);
}


void test_save_load_rules()
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;


  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_add_string(compiler, "rule test {condition: true}", NULL) != 0)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_string");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);

  if (yr_rules_save(rules, "test-rules.yarc") != ERROR_SUCCESS)
  {
    yr_rules_destroy(rules);
    perror("yr_rules_save");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  if (yr_rules_load("test-rules.yarc", &rules) != ERROR_SUCCESS)
  {
    perror("yr_rules_load");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);
  return;
}


int main(int argc, char** argv)
{
  yr_initialize();

  test_boolean_operators();
  test_comparison_operators();
  test_arithmetic_operators();
  test_bitwise_operators();
  test_matches_operator();
  test_syntax();
  test_anonymous_strings();
  test_strings();
  test_wildcard_strings();
  test_hex_strings();
  test_count();
  test_at();
  test_in();
  test_offset();
  test_length();
  test_of();
  test_for();
  test_re();
  test_filesize();
  // test_compile_file();
  // test_compile_files();
  // test_include_files();
  // test_externals();
  // test_callback();
  // test_compare();
  test_comments();
  test_modules();
  test_integer_functions();
  // test_string_io();
  test_entrypoint();
  test_global_rules();

  #if defined(HASH_MODULE)
  test_hash_module();
  #endif

  test_file_descriptor();

  test_max_string_per_rules();
  test_save_load_rules();

  yr_finalize();

  return 0;
}
