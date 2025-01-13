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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <yara.h>

#if !defined(_WIN32) && !defined(__CYGWIN__)
#include <sys/wait.h>
#endif

#include "blob.h"
#include "util.h"

static void test_boolean_operators()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule("rule test { condition: not false }", NULL);

  assert_false_rule("rule test { condition: not true }", NULL);

  assert_false_rule("rule test { condition: not (false or true) }", NULL);

  assert_false_rule("rule test { condition: not (true or false) }", NULL);

  assert_true_rule("rule test { condition: not (false and true) }", NULL);

  assert_true_rule("rule test { condition: not (true and false) }", NULL);

  assert_true_rule("rule test { condition: not (true and false) }", NULL);

  assert_true_rule("rule test { condition: true }", NULL);

  assert_true_rule("rule test { condition: true or false }", NULL);

  assert_true_rule("rule test { condition: true and true }", NULL);

  assert_true_rule("rule test { condition: 0x1 and 0x2}", NULL);

  assert_false_rule("rule test { condition: false }", NULL);

  assert_false_rule("rule test { condition: true and false }", NULL);

  assert_false_rule("rule test { condition: false or false }", NULL);

  assert_true_rule("rule test { condition: not var_false }", NULL);

  assert_true_rule("rule test { condition: var_true }", NULL);

  assert_false_rule("rule test { condition: var_false }", NULL);

  assert_false_rule("rule test { condition: not var_true }", NULL);

  assert_false_rule(
      "import \"tests\" rule test { condition: not tests.undefined.i }", NULL);

  assert_false_rule(
      "import \"tests\" rule test { condition: tests.undefined.i }", NULL);

  assert_false_rule(
      "import \"tests\" rule test { condition: tests.undefined.i and true }",
      NULL);

  assert_false_rule(
      "import \"tests\" rule test { condition: true and tests.undefined.i }",
      NULL);

  assert_true_rule(
      "import \"tests\" rule test { condition: tests.undefined.i or true }",
      NULL);

  assert_true_rule(
      "import \"tests\" rule test { condition: true or tests.undefined.i }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not (tests.undefined.i and true) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not (true and tests.undefined.i) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not tests.string_array[4] contains \"foo\" \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not tests.string_dict[\"undefined\"] matches /foo/ \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not tests.undefined.i \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          not (tests.undefined.i) \
      }",
      NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_comparison_operators()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule("rule test { condition: 2 > 1 }", NULL);

  assert_true_rule("rule test { condition: 1 < 2 }", NULL);

  assert_true_rule("rule test { condition: 2 >= 1 }", NULL);

  assert_true_rule("rule test { condition: 1 <= 1 }", NULL);

  assert_true_rule("rule test { condition: 1 == 1 }", NULL);

  assert_true_rule("rule test { condition: 1.5 == 1.5}", NULL);

  assert_true_rule("rule test { condition: 1.0 == 1}", NULL);

  assert_true_rule("rule test { condition: 1.5 >= 1.0}", NULL);

  assert_true_rule("rule test { condition: 1.0 != 1.000000000000001 }", NULL);

  assert_true_rule("rule test { condition: 1.0 < 1.000000000000001 }", NULL);

  assert_false_rule("rule test { condition: 1.0 >= 1.000000000000001 }", NULL);

  assert_true_rule("rule test { condition: 1.000000000000001 > 1 }", NULL);

  assert_false_rule("rule test { condition: 1.000000000000001 <= 1 }", NULL);

  assert_true_rule("rule test { condition: 1.0 == 1.0000000000000001 }", NULL);

  assert_true_rule("rule test { condition: 1.0 >= 1.0000000000000001 }", NULL);

  assert_true_rule("rule test { condition: 1.5 >= 1}", NULL);

  assert_true_rule("rule test { condition: 1.0 >= 1}", NULL);

  assert_true_rule("rule test { condition: 0.5 < 1}", NULL);

  assert_true_rule("rule test { condition: 0.5 <= 1}", NULL);

  assert_true_rule("rule test { condition: 1.0 <= 1}", NULL);

  assert_true_rule("rule test { condition: \"abc\" == \"abc\"}", NULL);

  assert_true_rule("rule test { condition: \"abc\" <= \"abc\"}", NULL);

  assert_true_rule("rule test { condition: \"abc\" >= \"abc\"}", NULL);

  assert_true_rule("rule test { condition: \"ab\" < \"abc\"}", NULL);

  assert_true_rule("rule test { condition: \"abc\" > \"ab\"}", NULL);

  assert_true_rule("rule test { condition: \"abc\" < \"abd\"}", NULL);

  assert_true_rule("rule test { condition: \"abd\" > \"abc\"}", NULL);

  assert_false_rule("rule test { condition: 1 != 1}", NULL);

  assert_false_rule("rule test { condition: 1 != 1.0}", NULL);

  assert_false_rule("rule test { condition: 2 > 3}", NULL);

  assert_false_rule("rule test { condition: 2.1 < 2}", NULL);

  assert_false_rule("rule test { condition: \"abc\" != \"abc\"}", NULL);

  assert_false_rule("rule test { condition: \"abc\" > \"abc\"}", NULL);

  assert_false_rule("rule test { condition: \"abc\" < \"abc\"}", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_arithmetic_operators()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }", NULL);

  assert_true_rule("rule test { condition: 5 % 2 == 1 }", NULL);

  assert_true_rule("rule test { condition: 1.5 + 1.5 == 3}", NULL);

  assert_true_rule("rule test { condition: 3 \\ 2 == 1}", NULL);

  assert_true_rule("rule test { condition: 3.0 \\ 2 == 1.5}", NULL);

  assert_true_rule("rule test { condition: 1 + -1 == 0}", NULL);

  assert_true_rule("rule test { condition: -1 + -1 == -2}", NULL);

  assert_true_rule("rule test { condition: 4 --2 * 2 == 8}", NULL);

  assert_true_rule("rule test { condition: -1.0 * 1 == -1.0}", NULL);

  assert_true_rule("rule test { condition: 1-1 == 0}", NULL);

  assert_true_rule("rule test { condition: -2.0-3.0 == -5}", NULL);

  assert_true_rule("rule test { condition: --1 == 1}", NULL);

  assert_true_rule("rule test { condition: 1--1 == 2}", NULL);

  assert_true_rule("rule test { condition: 2 * -2 == -4}", NULL);

  assert_true_rule("rule test { condition: -4 * 2 == -8}", NULL);

  assert_true_rule("rule test { condition: -4 * -4 == 16}", NULL);

  assert_true_rule("rule test { condition: -0x01 == -1}", NULL);

  assert_true_rule("rule test { condition: 0o10 == 8 }", NULL);

  assert_true_rule("rule test { condition: 0o100 == 64 }", NULL);

  assert_true_rule("rule test { condition: 0o755 == 493 }", NULL);

  // Test cases for issue #1631.
  assert_true_rule("rule test { condition: var_one*3 == 3}", NULL);
  assert_true_rule("rule test { condition: var_zero*3 == 0}", NULL);

  // TODO: This should return ERROR_INTEGER_OVERFLOW, but right now it returns
  // ERROR_SYNTAX_ERROR because after the lexer aborts with
  // ERROR_INTEGER_OVERFLOW the parser finds an unexpected end fails with error:
  // unexpected $end.
  assert_error(
      "rule test { condition: 9223372036854775808 > 0 }", ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { condition: 9007199254740992KB > 0 }", ERROR_SYNTAX_ERROR);

  assert_error(  // integer too long
      "rule test { condition: 8796093022208MB > 0 }",
      ERROR_SYNTAX_ERROR);

  assert_error(  // integer too long
      "rule test { condition: 0x8000000000000000 > 0 }",
      ERROR_SYNTAX_ERROR);

  assert_error(  // integer too long
      "rule test { condition: 0o1000000000000000000000 > 0 }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { condition: 0x7FFFFFFFFFFFFFFF + 1 > 0 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: 9223372036854775807 + 1 > 0 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: -9223372036854775807 - 2 > 0 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: -2 + -9223372036854775807 > 0 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: 1 - -9223372036854775807 > 0 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: 0x4000000000000000 * 2 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: 4611686018427387904 * 2 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: 4611686018427387904 * -2 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: -4611686018427387904 * 2 }",
      ERROR_INTEGER_OVERFLOW);

  assert_error(
      "rule test { condition: -4611686018427387904 * -2 }",
      ERROR_INTEGER_OVERFLOW);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_bitwise_operators()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule("rule test { condition: 0x55 | 0xAA == 0xFF }", NULL);

  assert_true_rule(
      "rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }",
      NULL);

  assert_true_rule("rule test { condition: ~0x55 & 0xFF == 0xAA }", NULL);

  assert_true_rule("rule test { condition: 8 >> 2 == 2 }", NULL);

  assert_true_rule("rule test { condition: 1 << 3 == 8 }", NULL);

  assert_true_rule("rule test { condition: 1 << 64 == 0 }", NULL);

  assert_true_rule("rule test { condition: 1 >> 64 == 0 }", NULL);

  assert_error("rule test { condition: 1 << -1 == 0 }", ERROR_INVALID_OPERAND);

  assert_error("rule test { condition: 1 >> -1 == 0 }", ERROR_INVALID_OPERAND);

  assert_true_rule("rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }", NULL);

  assert_false_rule(
      "rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }", NULL);

  assert_false_rule("rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_string_operators()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" contains \"bar\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" contains \"foo\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" contains \"baz\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" icontains \"BAR\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" icontains \"BaR\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"FooBarBaz\" icontains \"bar\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"FooBarBaz\" icontains \"baz\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"FooBarBaz\" icontains \"FOO\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" contains \"foo\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" contains \"baz\" }", NULL);

  assert_false_rule(
      "rule test { condition: \"foobarbaz\" contains \"baq\" }", NULL);

  assert_false_rule("rule test { condition: \"foo\" contains \"foob\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" startswith \"foo\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" istartswith \"Foo\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"FooBarBaz\" istartswith \"fOO\" }", NULL);

  assert_false_rule(
      "rule test { condition: \"foobarbaz\" startswith \"fob\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" endswith \"baz\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" iendswith \"baZ\" }", NULL);

  assert_true_rule(
      "rule test { condition: \"foobarbaz\" iendswith \"BaZ\" }", NULL);

  assert_false_rule(
      "rule test { condition: \"foobarbaz\" endswith \"ba\" }", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_syntax()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_error(
      "rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }",
      ERROR_DUPLICATED_STRING_IDENTIFIER);

  assert_error(
      "rule test { strings: $a = /a.c/ xor condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = /abc/ xor condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = {01 02 ?? 03 04} xor condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = {01 02 0? 03 04} xor condition: $a }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = {01 02 03 04} xor condition: $a }",
      ERROR_SYNTAX_ERROR);

  // Test case for issue #1295
  assert_error("rule test rule test", ERROR_DUPLICATED_IDENTIFIER);

  assert_error(
      "rule test { strings: $a = \"a\" condition: -1 of them }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: 0 + -1 of them }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: for -1 of them: ($) }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: for 0 + -1 of them: ($) }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: \"foo\" of them }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: for \"foo\" of them: ($) }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: /foo/ of them }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: for /foo/ of them: ($) }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: for 3.14159 of them: ($) }",
      ERROR_INVALID_VALUE);

  assert_error(
      "rule test { strings: $a = \"a\" condition: true }",
      ERROR_UNREFERENCED_STRING);

  // String identifiers prefixed with '_' are allowed to be unreferenced.
  // Any unreferenced string must be searched for anywhere.
  assert_string_capture(
      "rule test { strings: $a = \"AXS\" $_b = \"ERS\" condition: $a }",
      "AXSERS",
      "ERS");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_anonymous_strings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $ = \"a\" $ = \"b\" condition: all of them }",
      "ab");

  // Anonymous strings must be referenced.
  assert_error(
      "rule test { strings: $ = \"a\" condition: true }",
      ERROR_UNREFERENCED_STRING);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_warnings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
      $b = \"WXSMTS\" \
    condition: \
      2 of them at 0 \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
      $b = \"WXSMTS\" \
    condition: \
      all of them at 0 \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      0 of them \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      for 0 of ($a*): ($) \
    }");

  assert_no_warnings("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      none of them \
    }");

  assert_no_warnings("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      for none of ($a*): ($) \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      1 + -1 of them \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      2 of them \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      2 of ($a) \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      2 of ($a*) \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      2 of ($a*) in (0..10) \
    }");

  assert_warning("rule a { \
    condition: \
      true \
    } \
    rule b { \
      condition: \
        2 of (a) \
    }");

  assert_warning("rule a { \
    condition: \
      true \
    } \
    rule b { \
      condition: \
        2 of (a*) \
    }");

  assert_warning("rule test { \
    strings: \
      $a = \"AXSERS\" \
    condition: \
      2 of ($a*) at 0\
    }");

  assert_error(
      "rule test { \
      strings: \
        $a = \"AXSERS\" \
      condition: \
        1 of them at \"x\"\
    }",
      ERROR_INVALID_VALUE);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_strings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  char* str = TEXT_1024_BYTES "---- abc ---- xyz";
  uint8_t blob[] = TEXT_1024_BYTES "---- a\0b\0c\0 -\0-\0-\0-\0x\0y\0z\0";

  assert_true_rule("rule test { strings: $a = \"a\" condition: $a }", str);

  assert_true_rule("rule test { strings: $a = \"ab\" condition: $a }", str);

  assert_true_rule("rule test { strings: $a = \"abc\" condition: $a }", str);

  assert_true_rule("rule test { strings: $a = \"xyz\" condition: $a }", str);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" nocase fullword condition: $a }", str);

  assert_true_rule(
      "rule test { strings: $a = \"aBc\" nocase  condition: $a }", str);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }", str);

  assert_false_rule(
      "rule test { strings: $a = \"a\" fullword condition: $a }", str);

  assert_false_rule(
      "rule test { strings: $a = \"ab\" fullword condition: $a }", str);

  assert_false_rule(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }", str);

  assert_true_rule_blob(
      "rule test { strings: $a = \"a\" wide condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"a\" wide ascii condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"ab\" wide condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"ab\" wide ascii condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide nocase fullword condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"aBc\" wide nocase condition: $a }", blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"aBc\" wide ascii nocase condition: $a }",
      blob);

  assert_true_rule_blob(
      "rule test { strings: $a = \"---xyz\" wide nocase condition: $a }", blob);

  assert_true_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      TEXT_1024_BYTES "abc");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      TEXT_1024_BYTES "xabcx");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      TEXT_1024_BYTES "xabc");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" fullword condition: $a }",
      TEXT_1024_BYTES "abcx");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abc\" wide condition: $a }",
      TEXT_1024_BYTES "a\1b\0c\0d\0e\0f\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abcdef\" wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0d\0e\0f\1");

  assert_false_rule(
      "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
      TEXT_1024_BYTES "abcx");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
      TEXT_1024_BYTES "a\0abc");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      TEXT_1024_BYTES "x\0a\0b\0c\0x\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"ab\" wide fullword condition: $a }",
      TEXT_1024_BYTES "x\0a\0b\0");

  assert_false_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      TEXT_1024_BYTES "x\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
      TEXT_1024_BYTES "x\001a\0b\0c\0");

  assert_true_rule(
      "rule test { strings: $a = \"\\t\\r\\n\\\"\\\\\" condition: $a }",
      TEXT_1024_BYTES "\t\r\n\"\\");

  assert_true_rule(
      "rule test {\n\
         strings:\n\
             $a = \"abcdef\"\n\
             $b = \"cdef\"\n\
             $c = \"ef\"\n\
         condition:\n\
             all of them\n\
       }",
      TEXT_1024_BYTES "abcdef");

  assert_true_rule(
      "rule test {\n\
         strings:\n\
             $a = \"foo\"\n\
             $b = \"bar\"\n\
             $c = \"baz\"\n\
         condition:\n\
             all of them in (0..10)\n\
       }",
      "foobarbaz" TEXT_1024_BYTES);

  // https://github.com/VirusTotal/yara/issues/1695
  assert_false_rule(
      "rule test {\n\
         strings:\n\
             $a = \"AXS\"\n\
             $b = \"ERS\"\n\
         condition:\n\
             none of them in (0..10)\n\
       }",
      "AXSERS" TEXT_1024_BYTES);

  // https://github.com/VirusTotal/yara/issues/1757
  assert_false_rule(
      "rule test {\n\
         strings:\n\
             $a = \"foo\"\n\
             $b = \"foo\"\n\
         condition:\n\
             none of them in (0..1)\n\
       }",
      "foo");

  // https://github.com/VirusTotal/yara/issues/1660
  assert_false_rule(
      "rule test {\n\
         strings:\n\
             $a = \"foo\"\n\
             $b = \"bar\"\n\
             $c = \"baz\"\n\
         condition:\n\
             all of them in (0..1)\n\
       }",
      TEXT_1024_BYTES);

  assert_true_rule(
      "rule test {\n\
         strings:\n\
             $a = \"foo\"\n\
         condition:\n\
             #a == 3 and #a in (0..10) == 2\n\
       }",
      "foofoo" TEXT_1024_BYTES "foo");

  // xor by itself will match the plaintext version of the string too.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor\n\
      condition:\n\
        #a == 256\n\
    }",
      "tests/data/xor.out");

  // Make sure the combination of xor and ascii behaves the same as just xor.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor ascii\n\
      condition:\n\
        #a == 256\n\
    }",
      "tests/data/xor.out");

  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor(1-0x10)\n\
      condition:\n\
        #a == 16\n\
    }",
      "tests/data/xor.out");

  // We should have no matches here because we are not generating the ascii
  // string, just the wide one, and the test data contains no wide strings.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor wide\n\
      condition:\n\
        #a == 0\n\
    }",
      "tests/data/xor.out");

  // xor by itself is equivalent to xor(0-255).
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor wide\n\
      condition:\n\
        #a == 256\n\
    }",
      "tests/data/xorwide.out");

  // This DOES NOT look for the plaintext wide version by itself.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor(1-16) wide\n\
      condition:\n\
        #a == 16\n\
    }",
      "tests/data/xorwide.out");

  // Check the location of the match to make sure we match on the correct one.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor(1) wide\n\
      condition:\n\
        #a == 1 and @a == 0x2f\n\
    }",
      "tests/data/xorwide.out");

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor(300)\n\
      condition:\n\
        $a\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor(200-10)\n\
      condition:\n\
        $a\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = {00 11 22 33} xor\n\
      condition:\n\
        $a\n\
    }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = /foo(bar|baz)/ xor\n\
      condition:\n\
        $a\n\
    }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" xor xor\n\
      condition:\n\
        $a\n\
    }",
      ERROR_DUPLICATED_MODIFIER);

  // We should have no matches here because we are not generating the wide
  // string, just the ascii one, and the test data contains no ascii strings.
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor ascii\n\
      condition:\n\
        #a == 0\n\
    }",
      "tests/data/xorwide.out");

  // This should match 512 times because we are looking for the wide and ascii
  // versions in plaintext and doing xor(0-255) (implicitly)
  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" xor wide ascii\n\
      condition:\n\
        #a == 512\n\
    }",
      "tests/data/xorwideandascii.out");

  assert_true_rule_file(
      "rule test {\n\
      strings:\n\
        $a = \"This program cannot\" wide ascii\n\
      condition:\n\
        #a == 2\n\
    }",
      "tests/data/xorwideandascii.out");

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" xor nocase\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_true_rule(
      "rule test { \
        strings:\
          $a = \"AXS\" private\
      condition:\
        all of them\
      }",
      TEXT_1024_BYTES "AXS");

  assert_true_rule(
      "rule test { \
        strings:\
          $a = { 45 52 53 } private\
      condition:\
        all of them\
      }",
      TEXT_1024_BYTES "ERS");

  assert_true_rule(
      "rule test { \
        strings:\
          $a = /AXS[0-9]{4}ERS[0-9]{4}/ private\
      condition:\
        all of them\
      }",
      TEXT_1024_BYTES "AXS1111ERS2222");

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64 nocase\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64 xor\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64 fullword\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64(\"AXS\")\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64wide(\"ERS\")\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  // Specifying different alphabets is an error.
  assert_error(
      "rule test {\n\
      strings:\n\
        $a = \"ab\" base64 base64wide(\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ,.\")\n\
      condition:\n\
        true\n\
    }",
      ERROR_INVALID_MODIFIER);

  // Be specific about the offsets in these tests to make sure we are matching
  // the correct strings. Also be specific about the length because we want to
  // make sure the match is not the entire base64 string, but just the
  // substrings which are not dependent upon leading or trailing bytes.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64\n\
        condition:\n\
          #a == 6 and\n\
          @a[1] == 0x53 and\n\
          !a[1] == 25 and\n\
          @a[2] == 0x70 and\n\
          !a[2] == 25 and\n\
          @a[3] == 0xa2 and\n\
          !a[3] == 24 and\n\
          @a[4] == 0xbd and\n\
          !a[4] == 24 and\n\
          @a[5] == 0xef and\n\
          !a[5] == 25 and\n\
          @a[6] == 0x109 and\n\
          !a[6] == 25\n\
      }",
      "tests/data/base64");

  // This is identical to "base64" alone, but test it to make sure we don't
  // accidentally include the plaintext in the base64 search.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 ascii\n\
        condition:\n\
          #a == 6 and\n\
          @a[1] == 0x53 and\n\
          !a[1] == 25 and\n\
          @a[2] == 0x70 and\n\
          !a[2] == 25 and\n\
          @a[3] == 0xa2 and\n\
          !a[3] == 24 and\n\
          @a[4] == 0xbd and\n\
          !a[4] == 24 and\n\
          @a[5] == 0xef and\n\
          !a[5] == 25 and\n\
          @a[6] == 0x109 and\n\
          !a[6] == 25\n\
      }",
      "tests/data/base64");

  // Make sure the wide modifier is applied BEFORE the base64 and we do NOT
  // include the wide plaintext string.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 wide\n\
        condition:\n\
          #a == 6 and\n\
          @a[1] == 0x1b5 and\n\
          !a[1] == 50 and\n\
          @a[2] == 0x1ea and\n\
          !a[2] == 50 and\n\
          @a[3] == 0x248 and\n\
          !a[3] == 50 and\n\
          @a[4] == 0x27b and\n\
          !a[4] == 50 and\n\
          @a[5] == 0x2db and\n\
          !a[5] == 50 and\n\
          @a[6] == 0x311 and\n\
          !a[6] == 50\n\
      }",
      "tests/data/base64");

  // Make sure that both wide and ascii are base64 encoded. We can skip the
  // verbose length and offset checks, since the previous tests cover that.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 wide ascii\n\
        condition:\n\
          #a == 12\n\
      }",
      "tests/data/base64");

  // Make sure that the two strings are generated when one ascii byte is
  // base64 encoded. When stripped, third base64 encoded is null.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"a\" base64\n\
          $b = \"a\" base64wide\n\
        condition:\n\
          @a[58] == 0x6ac and\n\
          @a[59] == 0x6b9 and\n\
          @b[15] == 0x6f7 and\n\
          @b[16] == 0x711\n\
      }",
      "tests/data/base64");

  // In the future, assert false if character classes are generated instead
  // of stripping the leading and trailing characters
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"Dhis program cannow\" base64\n\
        condition:\n\
          #a == 2 and\n\
          @a[1] == 0xa2 and\n\
          @a[2] == 0xbd\n\
      }",
      "tests/data/base64");

  // This checks for the ascii string in base64 form then widened.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64wide\n\
        condition:\n\
          #a == 3 and\n\
          @a[1] == 0x379 and\n\
          !a[1] == 50 and\n\
          @a[2] == 0x3b6 and\n\
          !a[2] == 48 and\n\
          @a[3] == 0x3f1 and\n\
          !a[3] == 50\n\
      }",
      "tests/data/base64");

  // Logically identical to the test above but include it to make sure we don't
  // accidentally include the plaintext in the future.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64wide ascii\n\
        condition:\n\
          #a == 3 and\n\
          @a[1] == 0x379 and\n\
          !a[1] == 50 and\n\
          @a[2] == 0x3b6 and\n\
          !a[2] == 48 and\n\
          @a[3] == 0x3f1 and\n\
          !a[3] == 50\n\
      }",
      "tests/data/base64");

  // Make sure the wide string is base64wide encoded.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64wide wide\n\
        condition:\n\
          #a == 3 and\n\
          @a[1] == 0x458 and\n\
          !a[1] == 100 and\n\
          @a[2] == 0x4c5 and\n\
          !a[2] == 100 and\n\
          @a[3] == 0x530 and\n\
          !a[3] == 100\n\
      }",
      "tests/data/base64");

  // Make sure both ascii and wide strings are base64wide encoded properly.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64wide wide ascii\n\
        condition:\n\
          #a == 6 and\n\
          @a[1] == 0x379 and\n\
          !a[1] == 50 and\n\
          @a[2] == 0x3b6 and\n\
          !a[2] == 48 and\n\
          @a[3] == 0x3f1 and\n\
          !a[3] == 50 and\n\
          @a[4] == 0x458 and\n\
          !a[4] == 100 and\n\
          @a[5] == 0x4c5 and\n\
          !a[5] == 100 and\n\
          @a[6] == 0x530 and\n\
          !a[6] == 100\n\
      }",
      "tests/data/base64");

  // Make sure base64 and base64wide together work.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 base64wide\n\
        condition:\n\
          #a == 9 and\n\
          @a[1] == 0x53 and\n\
          !a[1] == 25 and\n\
          @a[2] == 0x70 and\n\
          !a[2] == 25 and\n\
          @a[3] == 0xa2 and\n\
          !a[3] == 24 and\n\
          @a[4] == 0xbd and\n\
          !a[4] == 24 and\n\
          @a[5] == 0xef and\n\
          !a[5] == 25 and\n\
          @a[6] == 0x109 and\n\
          !a[6] == 25 and\n\
          @a[7] == 0x379 and\n\
          !a[7] == 50 and\n\
          @a[8] == 0x3b6 and\n\
          !a[8] == 48 and\n\
          @a[9] == 0x3f1 and\n\
          !a[9] == 50\n\
      }",
      "tests/data/base64");

  // Identical to the test above but useful to make sure we don't accidentally
  // include the ascii plaintext in the future.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 base64wide ascii\n\
        condition:\n\
          #a == 9\n\
      }",
      "tests/data/base64");

  // Making sure we don't accidentally include the wide plaintext in the future.
  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64 base64wide wide\n\
        condition:\n\
          #a == 9\n\
      }",
      "tests/data/base64");

  assert_true_rule_file(
      "rule test {\n\
        strings:\n\
          $a = \"This program cannot\" base64(\"!@#$\%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu\")\n\
        condition:\n\
          #a == 3 and\n\
          @a[1] == 0x619 and\n\
          !a[1] == 25 and\n\
          @a[2] == 0x638 and\n\
          !a[2] == 24 and\n\
          @a[3] == 0x656 and\n\
          !a[3] == 25\n\
      }",
      "tests/data/base64");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_wildcard_strings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule_blob(
      "rule test {\n\
         strings:\n\
             $s1 = \"abc\"\n\
             $s2 = \"xyz\"\n\
         condition:\n\
             for all of ($*) : ($)\n\
      }",
      TEXT_1024_BYTES "---- abc ---- A\x00"
                      "B\x00"
                      "C\x00 ---- xyz");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_hex_strings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

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

  assert_true_rule_blob(
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
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = {\n 31 32 [-] 38 39 \n\r} \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 } private \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [1] 34 35 [2] 38 39 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test {\
         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 } \
         condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 33 } \
        condition: !a == 3}",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 34 } \
        condition: !a == 4}",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 34 } \
        condition: !a == 4 }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 38 39 } \
        condition: all of them }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [-] 32 33 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 ~32 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 ~33 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { ( 31 32 ~32 34 35 | 31 32 ~33 34 35 ) } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 ~?2 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 ~?3 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 ~4? 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 ~3? 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { ( 31 32 ~3? 34 35 | 31 32 ~?2 34 35 ) } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 35 36 [-] 31 32 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [2-] 34 35 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 33 34 [0-2] 36 37 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-1] 34 35 [0-2] 36 37 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31 32 [0-3] 37 38 } \
        condition: $a }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [1] 33 34 } \
        condition: $a }",
      TEXT_1024_BYTES "12\n34");

  assert_true_rule(
      "rule test { \
        strings: $a = {31 32 [3-6] 32} \
        condition: !a == 6 }",
      TEXT_1024_BYTES "12111222");

  assert_true_rule(
      "rule test { \
        strings: $a = {31 [0-3] (32|33)} \
        condition: !a == 2 }",
      "122222222" TEXT_1024_BYTES);

  assert_true_rule(
      "rule test { \
        strings: $a = { 30 31 32 [0-5] 38 39 } \
        condition: $a }",
      "0123456789");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-5] 38 39 30 } \
        condition: $a }",
      "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 } \
        condition: $a }",
      "1244");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 } \
        condition: $a }",
      "12344");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 [2-3] 34 } \
        condition: $a }",
      "123440004");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31[-][8-][-]30 } \
        condition: $a }",
      "1234567890");

  assert_false_rule(
      "rule test { \
        strings: $a = { 31[-][9-][-]30 } \
        condition: $a }",
      "1234567890");

  // Test case for https://github.com/VirusTotal/yara/issues/2065
  uint8_t ISSUE_2065[] = {0x81, 0xEC, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00,
                          0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00,
                          0x00, 0x00, 0x44, 0x55, 0x66, 0x77};

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 81 EC 38 01 [4-25] B8 ?? ?? ?? ?? [20-21] 44 55 66 77  } \
        condition: $a }",
      ISSUE_2065);

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

  assert_error(
      "rule test { \
        strings: $a = { 01 02 ~ } \
        condition: $a ",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 ~0 11 } \
        condition: $a ",
      ERROR_INVALID_HEX_STRING);

  assert_error(
      "rule test { \
        strings: $a = { 01 ~?? 11 } \
        condition: $a ",
      ERROR_INVALID_HEX_STRING);

  /* TODO: tests.py:551 ff. */

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_count()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: #a == 2 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" private condition: #a == 2 }",
      TEXT_1024_BYTES "mississippi");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_at()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { \
        strings: $a = \"miss\" \
        condition: any of them at 0}",
      "mississippi");

  assert_true_rule(
      "rule test { \
        strings: $a = \"ssi\" \
        condition: $a at (1024+2) and $a at (1024+5) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { \
        strings: $a = \"ssi\" private \
        condition: $a at (1024+2) and $a at (1024+5) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { \
        strings: $a = \"mis\" \
        condition: $a at (1024+(~0xFF & 0xFF)) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 00 00 00 00 ?? 74 65 78 74 } \
        condition: $a at 308}",
      PE32_FILE);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_in()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 6a 2a 58 c3 } \
        condition: $a in (entrypoint .. entrypoint + 1) }",
      PE32_FILE);

  assert_true_rule_blob(
      "rule test { \
        strings: $a = { 6a 2a 58 c3 } private \
        condition: $a in (entrypoint .. entrypoint + 1) }",
      PE32_FILE);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_offset()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a == (1024+2) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" private condition: @a == (1024+2) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a == @a[1] }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" condition: @a[2] == (1024+5) }",
      TEXT_1024_BYTES "mississippi");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_length()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*?ssi/ private condition: !a == 5 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*ssi/ condition: !a == 8 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } condition: !a == "
      "11}",
      TEXT_1024_BYTES "mississippi");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_rule_of()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_match_count(
      "rule a { condition: true } rule b { condition: 1 of (a) }", NULL, 2);

  // https://github.com/VirusTotal/yara/issues/1695
  assert_match_count(
      "rule a { condition: false } rule b { condition: none of (a) }", NULL, 1);

  assert_match_count(
      "rule a1 { condition: true } "
      "rule a2 { condition: true } "
      "rule b { condition: 2 of (a*) }",
      NULL,
      3);

  assert_match_count(
      "rule a1 { condition: true } "
      "rule a2 { condition: false } "
      "rule b { condition: 50% of (a*) }",
      NULL,
      2);

  assert_error("rule a { condition: all of (b*) }", ERROR_UNDEFINED_IDENTIFIER);

  assert_error(
      "rule a0 { condition: true } "
      "rule b { condition: 1 of (a*) } "
      "rule a1 { condition: true } ",
      ERROR_IDENTIFIER_MATCHES_WILDCARD);

  // Make sure repeating the rule set works
  assert_match_count(
      "rule a { condition: true } "
      "rule b { condition: 1 of (a*) } "
      "rule c { condition: 1 of (a*) }",
      NULL,
      3);

  // This will compile but is false for the same reason that
  // "rule x { condition: x }" is compiles but is false.
  assert_false_rule("rule a { condition: 1 of (a*) }", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_of()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: any of them }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: none of them }",
      TEXT_1024_BYTES "AXSERS");

  // https://github.com/VirusTotal/yara/issues/1695
  assert_false_rule(
      "rule test { strings: $a = \"dummy1\" $b = \"dummy2\" $c = \"ssi\" "
      "condition: none of them }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" private $c = \"oops\" "
      "condition: 1 of them }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\" "
      "condition: 2 of them }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\" "
      "condition: any of ($a*, $b*) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\" "
      "condition: none of ($a*, $b*) }",
      TEXT_1024_BYTES "AXSERS");

  // https://github.com/VirusTotal/yara/issues/1695
  assert_false_rule(
      "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy2\" $b2 = \"ssi\" "
      "condition: none of ($a*, $b*) }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule_blob(
      "rule test { \
         strings: \
           $ = /abc/ \
           $ = /def/ \
           $ = /ghi/ \
         condition: \
           for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )\
       }",
      TEXT_1024_BYTES "abc\000def\000ghi");

  assert_false_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mis\" \
          $c = \"oops\" \
        condition: \
          all of them \
      }",
      TEXT_1024_BYTES "mississippi");

  assert_error("rule test { condition: all of ($a*) }", ERROR_UNDEFINED_STRING);

  assert_error("rule test { condition: all of them }", ERROR_UNDEFINED_STRING);

  assert_error(
      "rule test { strings: $a = \"AXS\" condition: 101% of them }",
      ERROR_INVALID_PERCENTAGE);

  assert_error(
      "rule test { strings: $a = \"ERS\" condition: 0% of them }",
      ERROR_INVALID_PERCENTAGE);

  assert_true_rule(
      "rule test { \
        strings: \
          $a1 = \"dummy\" \
          $a2 = \"issi\" \
        condition: \
          50% of them \
      }",
      "mississippi");

  // This is equivalent to "50% of them" because 1050%50 == 50
  assert_true_rule(
      "rule test { \
        strings: \
          $a1 = \"miss\" \
          $a2 = \"issi\" \
        condition: \
          1050%100% of them \
      }",
      "mississippi");

  assert_true_rule(
      "rule test { \
        strings: \
          $a1 = \"miss\" \
          $a2 = \"issi\" \
        condition: \
          100% of them \
      }",
      "mississippi");

  assert_true_rule(
      "import \"tests\" \
       rule test { \
         strings: \
           $a1 = \"miss\" \
           $a2 = \"issi\" \
         condition: \
           (25*tests.constants.two)% of them \
       }",
      "mississippi");

  // tests.integer_array[5] is undefined, so the following rule must evaluate
  // to false.
  assert_false_rule(
      "import \"tests\" \
       rule test { \
         strings: \
           $a1 = \"miss\" \
           $a2 = \"issi\" \
         condition: \
           tests.integer_array[5]% of them \
       }",
      "mississippi");

  // If one of the bounds can not be determined statically it isn't an error.
  assert_true_rule(
      "rule test { \
      strings: \
        $a = \"AXSERS\" \
      condition: \
        true or any of them in (0..filesize-100) \
    }",
      TEXT_1024_BYTES);

  // Lower bound can not be negative, if it can be determined statically.
  assert_error(
      "rule test { \
        strings: \
          $a = \"AXSERS\" \
        condition: \
          $a in (-1..10) \
      }",
      ERROR_INVALID_VALUE);

  // Make sure that an undefined range boundary returns an undefined value,
  // which translates to false.
  assert_false_rule(
      "import \"tests\" \
        rule test { \
		      strings: \
			      $a = \"missi\" \
		      condition: \
			      any of them in (0..tests.undefined.i) \
	    }",
      "mississippi");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_for()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
        condition: \
          for all i in (1..#a) : (@a[i] >= (1024+2) and @a[i] <= (1024+5)) \
      }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
          $b = \"mi\" \
        condition: \
          for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j])) \
      }",
      TEXT_1024_BYTES "mississippi");

  assert_false_rule(
      "rule test { \
        strings: \
          $a = \"ssi\" \
        condition: \
          for all i in (1..#a) : (@a[i] == (1024+5)) \
      }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule(
      "rule test { \
        condition: \
          for any i in (1, 2, 3) : (i <= 1) \
      }",
      NULL);

  assert_true_rule(
      "rule test { \
        condition: \
          for all i in (1, 2, 3) : (i >= 1) \
      }",
      NULL);

  assert_false_rule(
      "rule test { \
        condition: \
          for all i in (1, 0) : (i != 1) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any item in tests.struct_array : ( \
            item.i == 1 \
          ) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for 0 item in tests.struct_array : ( \
            item.i == 100 \
          ) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any item in tests.integer_array : ( \
            item == 2 \
          ) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any item in tests.string_array : ( \
            item == \"bar\" \
          ) \
      }",
      NULL);

  assert_true_rule(
      "rule test { \
        condition: \
          for all i in (3,5,4) : ( \
            i >= 3 and i <= 5 \
          ) \
      }",
      NULL);

  assert_true_rule(
      "rule test { \
        condition: \
          for all i in (3..5) : ( \
            i >= 3 and i <= 5 \
          ) \
      }",
      NULL);

  assert_true_rule(
      "rule test { \
        condition: \
          for 2 i in (5..10) : ( \
            i == 6 or i == 7 \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any k,v in tests.empty_struct_dict : ( \
            true \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for all i in (1..tests.undefined.i) : ( \
            true \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for all i in (tests.undefined.i..10) : ( \
            true \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for all i in (1..tests.undefined.i) : ( \
            false \
          ) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any k,v in tests.struct_dict : ( \
            k == \"foo\" and v.s == \"foo\" and v.i == 1 \
          ) \
      }",
      NULL);

  assert_error(
      "import \"tests\" \
      rule test { \
        condition: \
          for any k,v in tests.integer_array : ( false ) \
      }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "import \"tests\" \
      rule test { \
        condition: \
          for any a,b,c in tests.struct_dict : ( false ) \
      }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "import \"tests\" \
      rule test { \
        condition: \
          for any i in tests.struct_dict : ( false ) \
      }",
      ERROR_SYNTAX_ERROR);

  assert_error(
      "import \"tests\" \
      rule test { \
        condition: \
          for any i in tests.integer_array : ( undefined_ident ) \
      }",
      ERROR_UNDEFINED_IDENTIFIER);

  assert_error(
      "import \"tests\" \
      rule test { \
        condition: \
          for any i in tests.integer_array : ( i == \"foo\" ) \
      }",
      ERROR_WRONG_TYPE);

  assert_false_rule(
      "rule test { \
        condition: \
          for any i in (0,1): ( \
            for any j in (0,1): ( \
              for any k in (0,1): ( \
                for any l in (0,1): (\
                  false \
                ) \
              ) \
            ) \
        ) \
      }",
      NULL);

  // Lower bound must be less than upper bound, if it can be determined
  // statically.
  assert_error(
      "rule test { \
        condition: \
          for any i in (10..1): (i) \
      }",
      ERROR_INVALID_VALUE);

  // Test case for https://github.com/VirusTotal/yara/issues/1729
  assert_true_rule(
      "rule test { \
        strings: \
          $a = \"abcde\" \
        condition: \
          for any n in (1..10) : ( n of ($a*) ) \
      }",
      "abcde");

  assert_true_rule(
      "rule test { \
        condition: \
          for all i in (\"a\", \"b\") : (i == \"a\" or i == \"b\") \
      }",
      NULL);

  assert_error(
      "rule test { \
        condition: \
          for any i in (\"a\"): (i == 0) \
      }",
      ERROR_WRONG_TYPE);

  assert_error(
      "rule test { \
        condition: \
          for any i in (\"a\", 0): (i == 0) \
      }",
      ERROR_WRONG_TYPE);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_re()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { strings: $a = /ssi/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssi(s|p)/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssim*/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ssa?/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /Miss/ nocase condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /(M|N)iss/ nocase condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /[M-N]iss/ nocase condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ppi\\tmi/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /ppi\\.mi/ condition: $a }",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_true_rule(
      "rule test { strings: $a = /^mississippi/ fullword condition: $a }",
      "mississippi\tmississippi.mississippi\nmississippi" TEXT_1024_BYTES);

  assert_true_rule(
      "rule test { strings: $a = /mississippi.*mississippi$/s condition: $a}",
      TEXT_1024_BYTES "mississippi\tmississippi.mississippi\nmississippi");

  assert_false_rule(
      "rule test { strings: $a = /^ssi/ condition: $a }",
      TEXT_1024_BYTES "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /ssi$/ condition: $a }",
      TEXT_1024_BYTES "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /ssissi/ fullword condition: $a }",
      TEXT_1024_BYTES "mississippi");

  assert_false_rule(
      "rule test { strings: $a = /^[isp]+/ condition: $a }",
      TEXT_1024_BYTES "mississippi");

  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 6 }",
      TEXT_1024_BYTES "a\0x\0b\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 8 }",
      TEXT_1024_BYTES "a\0x\0x\0b\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      TEXT_1024_BYTES "\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      TEXT_1024_BYTES "\ta\0b\0c\0");

  assert_false_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      TEXT_1024_BYTES "x\0a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /\\babc/ wide condition: $a }",
      TEXT_1024_BYTES "x\ta\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0\t");

  assert_false_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0x\0");

  assert_true_rule_blob(
      "rule test { strings: $a = /abc\\b/ wide condition: $a }",
      TEXT_1024_BYTES "a\0b\0c\0b\t");

  assert_false_rule(
      "rule test { strings: $a = /\\b/ wide condition: $a }",
      TEXT_1024_BYTES "abc");

  assert_true_rule(
      "rule test { condition: \"avb\" matches /a\\vb/ }",
      TEXT_1024_BYTES "rule test { condition: \"avb\" matches /a\\vb/ }");

  assert_false_rule(
      "rule test { condition: \"ab\" matches /a\\vb/ }",
      TEXT_1024_BYTES "rule test { condition: \"ab\" matches /a\\vb/ }");

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
  assert_true_regexp("a|b", "a", "a");
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
  assert_true_regexp("ab{2, 3}c", "abbbc", "abbbc");
  assert_true_regexp("ab{2 ,3}c", "abbbc", "abbbc");
  assert_true_regexp("ab{2  ,  3}c", "abbbc", "abbbc");
  assert_true_regexp("ab{0,1}?c", "abc", "abc");
  assert_true_regexp("a{0,1}?bc", "abc", "abc");
  assert_true_regexp("a{0,1}bc", "bbc", "bc");
  assert_true_regexp("a{0,1}?bc", "abc", "bc");
  assert_true_regexp("a{,0}", "a", "");
  assert_true_regexp("a{,0}", "x", "");
  assert_true_regexp("aa{0,1}?bc", "abc", "abc");
  assert_true_regexp("aa{0,1}?bc", "abc", "abc");
  assert_true_regexp("aa{0,1}bc", "abc", "abc");
  assert_true_regexp("ab{1}c", "abc", "abc");
  assert_true_regexp("ab{1,2}c", "abbc", "abbc");
  assert_false_regexp("ab{1,2}c", "abbbc");
  assert_true_regexp("ab{1,}c", "abbbc", "abbbc");
  assert_false_regexp("ab{1,}b", "ab");
  assert_false_regexp("ab{1}c", "abbc");
  assert_false_regexp("ab{1}c", "ac");
  assert_true_regexp("ab{0,}c", "ac", "ac");
  assert_true_regexp("ab{1,1}c", "abc", "abc");
  assert_true_regexp("ab{0,}c", "abbbc", "abbbc");
  assert_true_regexp("ab{,3}c", "abbbc", "abbbc");
  assert_false_regexp("ab{,2}c", "abbbc");
  assert_false_regexp("ab{4,5}bc", "abbbbc");
  assert_false_regexp("ab{3}c", "abbbbc");  // Issue #817
  assert_false_regexp("ab{4}c", "abbbbbc");
  assert_false_regexp("ab{5}c", "abbbbbbc");
  assert_true_regexp("ab{0,1}", "abbbbb", "ab");
  assert_true_regexp("ab{0,2}", "abbbbb", "abb");
  assert_true_regexp("ab{0,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{0,4}", "abbbbb", "abbbb");
  assert_true_regexp("ab{1,1}", "abbbbb", "ab");
  assert_true_regexp("ab{1,2}", "abbbbb", "abb");
  assert_true_regexp("ab{1,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{2,2}", "abbbbb", "abb");
  assert_true_regexp("ab{2,3}", "abbbbb", "abbb");
  assert_true_regexp("ab{2,4}", "abbbbc", "abbbb");
  assert_true_regexp("ab{3,4}", "abbb", "abbb");
  assert_true_regexp("ab{3,5}", "abbbbb", "abbbbb");
  assert_false_regexp("ab{3,4}c", "abbbbbc");
  assert_false_regexp("ab{3,4}c", "abbc");
  assert_false_regexp("ab{3,5}c", "abbbbbbc");
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
  assert_true_regexp("(a{2,3}b){2,3}", "aabaaabaab", "aabaaabaab");
  assert_true_regexp("(a{2,3}?b){2,3}?", "aabaaabaab", "aabaaab");
  assert_false_regexp("(a{4,5}b){4,5}", "aaaabaaaabaaaaab");
  assert_true_regexp(
      "(a{4,5}b){4,5}", "aaaabaaaabaaaaabaaaaab", "aaaabaaaabaaaaabaaaaab");
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
  assert_true_regexp("[a-c-e]+", "abc", "abc");
  assert_true_regexp("[*-_]+", "ABC", "ABC");
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
  assert_true_regexp("[a-z]-b", "c-b-c", "c-b");  // Issue #1690
  assert_true_regexp("a[]-]b", "a]b", "a]b");
  assert_true_regexp("a[]-]b", "a-b", "a-b");
  assert_true_regexp("[\\.-z]*", "...abc", "...abc");
  assert_true_regexp("[\\.-]*", "...abc", "...");
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
  assert_true_regexp("a[\\s]*b", "a \t\r\n\v\fb", "a \t\r\n\v\fb");
  assert_true_regexp("a[^\\S]*b", "a \t\r\n\v\fb", "a \t\r\n\v\fb");
  assert_false_regexp("a\\Sb", "a b");
  assert_false_regexp("a\\Sb", "a\tb");
  assert_false_regexp("a\\Sb", "a\rb");
  assert_false_regexp("a\\Sb", "a\nb");
  assert_false_regexp("a\\Sb", "a\vb");
  assert_false_regexp("a\\Sb", "a\fb");
  assert_true_regexp("foo([^\\s]*)", "foobar\n", "foobar");
  assert_true_regexp("foo([^\\s]*)", "foobar\r\n", "foobar");
  assert_true_regexp("\\n\\r\\t\\f\\a", "\n\r\t\f\a", "\n\r\t\f\a");
  assert_true_regexp("[\\n][\\r][\\t][\\f][\\a]", "\n\r\t\f\a", "\n\r\t\f\a");
  assert_true_regexp("\\x01\\x02\\x03", "\x01\x02\x03", "\x01\x02\x03");
  assert_true_regexp("[\\x01-\\x03]+", "\x01\x02\x03", "\x01\x02\x03");
  assert_false_regexp("[\\x00-\\x02]+", "\x03\x04\x05");
  assert_true_regexp("[\\x5D]", "]", "]");
  assert_true_regexp("[\\x5A-\\x5D]", "\x5B", "\x5B");
  assert_false_regexp("[\\x5A-\\x5D]", "\x4F");
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
  assert_true_regexp("(abc|)", "foo", "");
  assert_true_regexp("\\babc", "abc", "abc");
  assert_true_regexp("abc\\b", "abc", "abc");
  assert_true_regexp("\\b", "abc", "");
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
  assert_false_regexp("a^bcdef", "abcdef");
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
  assert_true_regexp("abcx{0,0}", "abcx", "abc");
  assert_true_regexp("abcx{0}", "abcx", "abc");

  // Test case for issue #324
  assert_true_regexp("whatever|   x.   x", "   xy   x", "   xy   x");

  // Test case for issue #503, \x without two following hex-digits
  assert_regexp_syntax_error("\\x0");
  assert_regexp_syntax_error("\\x");

  assert_regexp_syntax_error("\\xxy");

  // Test case for issue #682
  assert_true_regexp("(a|\\b)[a]{1,}", "aaaa", "aaaa");

  // Test cases for issue #1018
  assert_true_regexp(
      "(ba{4}){4,10}",
      "baaaabaaaabaaaabaaaabaaaa",
      "baaaabaaaabaaaabaaaabaaaa");

  assert_true_regexp(
      "(ba{2}a{2}){5,10}",
      "baaaabaaaabaaaabaaaabaaaa",
      "baaaabaaaabaaaabaaaabaaaa");

  assert_true_regexp(
      "(ba{3}){4,10}", "baaabaaabaaabaaabaaa", "baaabaaabaaabaaabaaa");

  assert_true_regexp(
      "(ba{4}){5,10}",
      "baaaabaaaabaaaabaaaabaaaa",
      "baaaabaaaabaaaabaaaabaaaa");

  assert_false_regexp("(ba{4}){4,10}", "baaaabaaaabaaaa");

  // Test for integer overflow in repeat interval
  assert_regexp_syntax_error("a{2977952116}");

  assert_error(
      "rule test { strings: $a = /a\\/ condition: $a }", ERROR_SYNTAX_ERROR);

  assert_error(
      "rule test { strings: $a = /[a\\/ condition: $a }", ERROR_SYNTAX_ERROR);

  // Test case for issue #996
  assert_error("rule test {strings:$=/.{,}? /", ERROR_SYNTAX_ERROR);

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

  assert_false_rule(
      "rule test { strings: $a = /abc[^d]/ nocase condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_false_rule(
      "rule test { strings: $a = /abc[^d]/ condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_false_rule(
      "rule test { strings: $a = /abc[^D]/ nocase condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /abc[^D]/ condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /abc[^f]/ nocase condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /abc[^f]/ condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /abc[^F]/ nocase condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /abc[^F]/ condition: $a }",
      TEXT_1024_BYTES "abcd");

  assert_true_rule(
      "rule test { strings: $a = /[*-_]+/ nocase condition: !a == 3 }", "abc");

  assert_true_rule(
      "rule test { strings: $a = /([$&#*-_!().])+/ nocase condition: !a == 6 }",
      "ABCabc");

  // Test case for issue #1006
  assert_false_rule_blob(
      "rule test { strings: $a = \" cmd.exe \" nocase wide condition: $a }",
      ISSUE_1006);

  // Test case for issue #1117
  assert_true_rule_blob(
      "rule test { strings: $a =/abc([^\"\\\\])*\"/ nocase condition: $a }",
      TEXT_1024_BYTES "abc\xE0\x22");

  // Test case for issue #1933
  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1}1/ ascii wide condition: $a }",
      "a\0b\0\x31\0");

  // Test case for issue #1933
  assert_true_rule_blob(
      "rule test { strings: $a = /a.{1}1/ ascii wide condition: $a }", "ab1\0");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_entrypoint()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

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

  assert_false_rule("rule test { condition: entrypoint >= 0 }", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_filesize()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  char rule[80];

  snprintf(
      rule,
      sizeof(rule),
      "rule test { condition: filesize == %zd }",
      sizeof(PE32_FILE));

  assert_true_rule_blob(rule, PE32_FILE);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_comments()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

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

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 [-] // Inline comment\n\r \
          38 39 } \
        condition: !a == 9 }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 } \
        condition: !a == 9 }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 } \
                 $b = { 31 32 /* Inline comment */ [-] 35 36 } \
        condition: (!a == 9) and (!b == 6) }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline comment with *asterisks* */ [-] 38 39 } \
        condition: !a == 9}",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { 31 32 /* Inline multi-line\n\r \
                                 comment */ [-] 38 39 } \
        condition: !a == 9 }",
      TEXT_1024_BYTES "1234567890");

  assert_true_rule(
      "rule test { \
        strings: $a = { /*Some*/ 31 /*interleaved*/ [-] /*comments*/ 38 39 } \
        condition: !a == 9 }",
      "1234567890" TEXT_1024_BYTES);

  // Test case for https://github.com/VirusTotal/yara/issues/1819
  assert_true_rule(
      "rule test { \
        // single line comment with brace }\n\r \
        strings: \
          $a = \"foo\" ascii \
        condition: \
          $a \
      }",
      "foo");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_matches_operator()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule("rule test { condition: \"foo\" matches /foo/ }", NULL);

  assert_false_rule("rule test { condition: \"foo\" matches /bar/ }", NULL);

  assert_true_rule("rule test { condition: \"FoO\" matches /fOo/i }", NULL);

  assert_true_rule("rule test { condition: \"xxFoOxx\" matches /fOo/i }", NULL);

  assert_false_rule(
      "rule test { condition: \"xxFoOxx\" matches /^fOo/i }", NULL);

  assert_false_rule(
      "rule test { condition: \"xxFoOxx\" matches /fOo$/i }", NULL);

  assert_true_rule("rule test { condition: \"foo\" matches /^foo$/i }", NULL);

  assert_true_rule(
      "rule test { condition: \"foo\\nbar\" matches /foo.*bar/s }", NULL);

  assert_false_rule(
      "rule test { condition: \"foo\\nbar\" matches /foo.*bar/ }", NULL);

  assert_true_rule("rule test { condition: \"\" matches /foo|/ }", NULL);

  assert_true_rule("rule test { condition: \"\" matches /a||b/ }", NULL);

  assert_false_rule("rule test { condition: \"\" matches /foobar/ }", NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_global_rules()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

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

  assert_false_rule(
      "global private rule global_rule { \
        strings: \
          $a = \"foo\" \
        condition: \
          $a \
      } \
      rule test { \
       strings: \
          $a = \"bar\" \
        condition: \
          $a \
      }",
      "bar");

  assert_true_rule(
      "global private rule global_rule { \
        strings: \
          $a = \"foo\" \
        condition: \
          $a \
      } \
      rule test { \
       strings: \
          $a = \"bar\" \
        condition: \
          $a \
      }",
      "foobar");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_modules()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

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
      rule test { condition: tests.match(/foo/,\"bar\") == -1 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo.bar/i,\"FOO\\nBAR\") == -1 \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { condition: tests.match(/foo.bar/is,\"FOO\\nBAR\") == 7 \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any k,v in tests.empty_struct_array[0].struct_dict: ( \
            v.unused == \"foo\" \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any item in tests.empty_struct_array[0].struct_array: ( \
            item.unused == \"foo\" \
          ) \
      }",
      NULL);

  assert_true_rule(
      "import \"tests\" \
      rule test { \
        condition: \
          for any item1 in tests.struct_array: ( \
            item1.i == 1 and \
            for any item2 in tests.struct_array: ( \
              item2.i == item1.i \
            ) \
          ) \
      }",
      NULL);

  assert_error("import \"\\x00\"", ERROR_INVALID_MODULE_NAME);

  assert_error("import \"\"", ERROR_INVALID_MODULE_NAME);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_time_module()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "import \"time\" \
        rule test { condition: time.now() > 0 }",
      NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

#if defined(HASH_MODULE)
static void test_hash_module()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  uint8_t blob[] = {
      0x61, 0x62, 0x63, 0x64, 0x65};  // abcde without trailing zero

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
            and \
          hash.crc32(0, filesize) == 0x8587d865 \
            and \
          hash.checksum32(0, filesize) == 0x1ef \
      }",
      blob);

  assert_true_rule(
      "import \"hash\" \
       rule test { \
        condition: \
          hash.md5(\"TEST STRING\") == \
            \"2d7d687432758a8eeeca7b7e5d518e7f\" \
            and \
          hash.sha1(\"TEST STRING\") == \
            \"d39d009c05797a93a79720952e99c7054a24e7c4\" \
            and \
          hash.sha256(\"TEST STRING\") == \
            \"fb6ca29024bd42f1894620ffa45fd976217e72d988b04ee02bb4793ab9d0c862\" \
            and \
          hash.crc32(\"TEST STRING\") == 0x51f9be31 \
            and \
          hash.checksum32(\"TEST STRING\") == 0x337 \
      }",
      NULL);

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

  uint8_t multi_block_blob[] = TEXT_1024_BYTES TEXT_1024_BYTES;

  assert_true_rule_blob(
      "import \"hash\" \
       rule test { \
        condition: \
          hash.md5(768, 8) == \
            \"9edc35bab4510f115d0974fc3597d444\" /*    exact 1st block boundary - overlap */ \
            and \
          hash.md5(1024, 8) == \
            \"2b607f2bcdf01d2cc5484230c89f5e18\" /*    exact 1st block boundary */ \
            and \
          hash.md5(764, 8) == \
            \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap */ \
            and \
          hash.md5(764, 8) == \
            \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap; cache */ \
            and \
          hash.md5(1020, 8) == \
            \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary */ \
            and \
          hash.md5(1020, 8) == \
            \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary; cache */ \
            and \
          hash.md5(0, filesize) == \
            \"578848bccbd8294394864707e7f581e3\" \
            and \
          hash.md5(1, filesize) == \
            \"633e48db55a5b477f9eeafad0ebbe108\" \
            and \
          hash.sha1(0, filesize) == \
            \"0170d3bfb54b5ba2fc12df571ffb000fcb2a379d\" \
            and \
          hash.sha1(1, filesize) == \
            \"89d614c846abe670f998ef02c4f5277ab76c0b4d\" \
            and \
          hash.sha256(0, filesize) == \
            \"ebc7a22f28028552576eeef3c17182a7d635ddaefbc94fc6d85f099289fdf8a5\" \
            and \
          hash.sha256(1, filesize) == \
            \"9c19006ade01c93f42949723f4ec8b1158e07fa43fd946f03e84a1ce25baa2c1\" \
            and \
          hash.crc32(0, filesize) == 0x2b11af72 \
            and \
          hash.crc32(\"TEST STRING\") == 0x51f9be31 \
      }",
      multi_block_blob);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}
#endif

void test_integer_functions()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule(
      "rule test { condition: uint8(1024) == 0xAA}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint16(1024) == 0xBBAA}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint32(1024) == 0xDDCCBBAA}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint8be(1024) == 0xAA}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint16be(1024) == 0xAABB}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  assert_true_rule(
      "rule test { condition: uint32be(1024) == 0xAABBCCDD}",
      TEXT_1024_BYTES "\xaa\xbb\xcc\xdd");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_include_files()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  char rule[4096];
  snprintf(
      rule,
      sizeof(rule),
      "include \"%s/tests/data/baz.yar\" rule t { condition: baz }",
      top_srcdir);
  assert_true_rule(rule, NULL);

  snprintf(
      rule,
      sizeof(rule),
      "include \"%s/tests/data/foo.yar\" rule t { condition: foo }",
      top_srcdir);
  assert_true_rule(rule, NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_tags()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_true_rule("rule test : tag1 { condition: true}", NULL);

  assert_true_rule("rule test : tag1 tag2 { condition: true}", NULL);

  assert_error(
      "rule test : tag1 tag1 { condition: true}",
      ERROR_DUPLICATED_TAG_IDENTIFIER);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

#if !defined(_WIN32) || defined(__CYGWIN__)

#define spawn(cmd, rest...)                                     \
  do                                                            \
  {                                                             \
    if ((pid = fork()) == 0)                                    \
    {                                                           \
      execl(cmd, cmd, rest, NULL);                              \
      fprintf(stderr, "execl: %s: %s\n", cmd, strerror(errno)); \
      exit(1);                                                  \
    }                                                           \
    if (pid <= 0)                                               \
    {                                                           \
      perror("fork");                                           \
      abort();                                                  \
    }                                                           \
    sleep(1);                                                   \
    if (waitpid(pid, NULL, WNOHANG) != 0)                       \
    {                                                           \
      fprintf(stderr, "%s did not live long enough\n", cmd);    \
      abort();                                                  \
    }                                                           \
  } while (0)

void test_process_scan()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  int pid;
  int status = 0;
  YR_RULES* rules;
  int rc;
  int fd;
  char* tf;
  char buf[16384];
  size_t written;

  struct COUNTERS counters;

  if (compile_rule(
          "\
    rule should_match {\
      strings:\
        $a = { 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 }\
      condition:\
        all of them\
    } \
    rule should_not_match { \
      condition: \
        filesize < 100000000 \
    }",
          &rules) != ERROR_SUCCESS)
  {
    perror("compile_rule");
    exit(EXIT_FAILURE);
  }

  spawn("/bin/sh", "-c", "VAR='Hello, world!'; sleep 10; true");

  counters.rules_matching = 0;
  counters.rules_not_matching = 0;
  rc = yr_rules_scan_proc(rules, pid, 0, count, &counters, 0);

  switch (rc)
  {
  case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
    fprintf(stderr, "Could not attach to process, ignoring this error\n");
    return;
  }

  kill(pid, SIGALRM);

  assert(rc == ERROR_SUCCESS);

  assert(waitpid(pid, &status, 0) >= 0);
  assert(status == SIGALRM);

  assert(counters.rules_matching == 1);
  assert(counters.rules_not_matching == 1);

  tf = strdup("./map-XXXXXX");
  fd = mkstemp(tf);
  assert(fd >= 0);

  // check for string in file that gets mapped by a process
  bzero(buf, sizeof(buf));
  sprintf(buf, "Hello, world!");
  written = write(fd, buf, sizeof(buf));

  assert(written == sizeof(buf));
  lseek(fd, 0, SEEK_SET);

  spawn("tests/mapper", "open", tf);

  counters.rules_matching = 0;
  rc = yr_rules_scan_proc(rules, pid, 0, count, &counters, 0);
  kill(pid, SIGALRM);

  fprintf(stderr, "scan: %d\n", rc);
  assert(rc == ERROR_SUCCESS);

  assert(waitpid(pid, &status, 0) >= 0);
  assert(status == SIGALRM);

  assert(counters.rules_matching == 1);

  // check for string in blank mapping after process has overwritten
  // the mapping.
  bzero(buf, sizeof(buf));
  written = write(fd, buf, sizeof(buf));

  assert(written == sizeof(buf));

  spawn("./tests/mapper", "patch", tf);

  counters.rules_matching = 0;
  rc = yr_rules_scan_proc(rules, pid, 0, count, &counters, 0);
  kill(pid, SIGALRM);

  fprintf(stderr, "scan: %d\n", rc);
  assert(rc == ERROR_SUCCESS);

  assert(waitpid(pid, &status, 0) >= 0);
  assert(status == SIGALRM);

  assert(counters.rules_matching == 1);

  close(fd);
  unlink(tf);
  free(tf);
  yr_rules_destroy(rules);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}
#endif

void test_invalid_escape_sequences_warnings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_warning_strict_escape(
      "rule test { strings: $a = /ab\\cdef/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = /ab\\ def/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = /ab\\;def/ condition: $a }");
  assert_no_warnings("rule test { strings: $a = /ab\\*def/ condition: $a }");
  assert_no_warnings("rule test { strings: $a = /abcdef/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = /ab\\cdef/ condition: $a }");
  assert_no_warnings("rule test { strings: $a = /abcdef/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = "
      "/\\\\WINDOWS\\\\system32\\\\\\victim\\.exe\\.exe/ condition: $a }");
  assert_no_warnings(
      "rule test { strings: $a = "
      "/\\\\WINDOWS\\\\system32\\\\victim\\.exe\\.exe/ condition: $a }");
  assert_warning_strict_escape("rule test { strings: $a = "
                               "/AppData\\\\Roaming\\\\[0-9]{9,12}"
                               "\\VMwareCplLauncher\\.exe/ condition: $a }");
  assert_no_warnings("rule test { strings: $a = "
                     "/AppData\\\\Roaming\\\\[0-9]{9,12}"
                     "\\\\VMwareCplLauncher\\.exe/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = /ab[\\000-\\343]/ condition: $a }");
  assert_no_warnings(
      "rule test { strings: $a = /ab[\\x00-\\x43]/ condition: $a }");
  assert_warning_strict_escape(
      "rule test { strings: $a = "
      "/C:\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\AzireVPN\\\\token\\.txt/ "
      "condition: $a }");
  assert_no_warnings(
      "rule test { strings: $a = "
      "/C:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\AzireVPN\\\\token\\.txt/"
      " condition: $a }");
  assert_warning_strict_escape(
      "rule test { condition: \"avb\" matches /a\\vb/ }");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_performance_warnings()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  assert_warning("rule test { \
        strings: $a = { 01 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 01 ?? } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 01 ?? ?? } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 01 ?? ?? 02 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 01 ?? ?2 03 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 01 ?? 02 1? } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 68 ?? 00 ?? 00 68 ?? 00 ?? 00} \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { (61 62 63 64 ?? | 65 ?? ?? 00 00 66)} \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 1? 2? 3? } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 1? 2? 3? 04 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 1? ?? 03 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 00 01 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 01 00 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 00 00 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 00 00 00 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 00 00 01 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { 00 00 00 00 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 00 00 00 01 } \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = { FF FF FF FF } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 00 00 01 02 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 00 01 02 03 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 01 02 03 04 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 01 02 03 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 20 01 02 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = { 01 02 } \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = \"foo\" wide \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = \"MZ\" \
        condition: $a }");

  assert_no_warnings("rule test { \
        strings: $a = \"ZZ\" \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = \"                    \" xor(0x20) \
        condition: $a }");

  // This will eventually xor with 0x41 and should cause a warning.
  assert_warning("rule test { \
        strings: $a = \"AAAAAAAAAAAAAAAAAAAA\" xor \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = /abcd.*efgh/ \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = /abcd.+efgh/ \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = /abcd.{1,}efgh/ \
        condition: $a }");

  assert_warning("rule test { \
        strings: $a = /abcd.{10,}efgh/ \
        condition: $a }");

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

static void test_meta()
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() {\n", __FUNCTION__);

  // Make sure that multiple metadata with the same identifier are allowed.
  // This was not intentionally designed like that, but users are alreay
  // relying on this.
  assert_true_rule(
      "rule test { \
         meta: \
           foo = \"foo\" \
           foo = 1 \
           foo = false \
         condition:\
           true \
      }",
      NULL);

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

void test_defined()
{
  assert_true_rule("rule t { condition: defined 1 }", NULL);
  assert_false_rule("rule t { condition: defined true and false }", NULL);
  assert_true_rule("rule t { condition: defined (true and false) }", NULL);

  assert_true_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined ( \
            for any x in (0..10) : ( \
              pe.number_of_resources == 0 \
            ) \
          ) \
      }",
      NULL);

  assert_false_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined pe.number_of_resources \
      }",
      NULL);

  assert_true_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          not defined pe.number_of_resources \
      }",
      NULL);

  assert_false_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined not pe.number_of_resources \
      }",
      NULL);

  assert_false_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined pe.number_of_resources and pe.number_of_resources == 0 \
      }",
      NULL);

  assert_true_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined (pe.number_of_resources and pe.number_of_resources == 0) \
      }",
      NULL);

  assert_true_rule(
      "import \"pe\" \
      rule t { \
        condition: \
          defined \"foo\" contains \"f\" \
      }",
      NULL);

  // Test FOUND_IN and FOUND_AT propagates undefined values
  assert_true_rule(
      "import \"pe\" \
      rule t { \
        strings: \
            $a = \"abc\" \
        condition: \
          not defined ($a in (0..pe.number_of_resources)) and \
          not defined ($a in (pe.number_of_resources..5)) and \
          not defined ($a at pe.number_of_resources) \
      }",
      NULL);

  // Test that operations that would trigger a SIGFPE are detected and
  // returns undefined
  assert_true_rule(
      "rule t { \
        strings: \
          $a = /aaa/ \
        condition: \
          (not defined (1 \\ #a)) and \
          (not defined (1 % #a)) and \
          (not defined ((#a + -0x7FFFFFFFFFFFFFFF - 1) \\ -1)) and \
          (not defined ((#a + -0x7FFFFFFFFFFFFFFF - 1) % -1)) \
      }",
      NULL);
}

static void test_pass(int pass)
{
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { \n", __FUNCTION__);

  switch (pass)
  {
  case 1:
    // Come here to test with default libyara iterator which creates a single
    // block.
    matches_blob_uses_default_iterator = 1;
    break;
  case 2:
    // Come here to test with test libyara iterator which is:
    // Like default libyara iterator, plus records block stats.
    matches_blob_uses_default_iterator = 0;
    break;
  case 3:
    // Come here to test with test libyara iterator which is:
    // Like default libyara iterator, plus records block stats, plus splits
    // into multiple blocks:
    matches_blob_uses_default_iterator = 0;
    // "Actually, a single block will contain the whole file's content in most
    // cases, but you can't rely on that while writing your code. For very big
    // files YARA could eventually split the file into two or more blocks, and
    // your module should be prepared to handle that." [1]
    // [1]
    // https://yara.readthedocs.io/en/stable/writingmodules.html#accessing-the-scanned-data
    yr_test_mem_block_size = 1024;
    yr_test_mem_block_size_overlap = 256;
    assert(yr_test_mem_block_size_overlap <= yr_test_mem_block_size);
    break;
  }

  YR_DEBUG_FPRINTF(
      1,
      stderr,
      "- // pass %d: run all rule tests: using %s iterator "
      "split data into blocks of max %" PRId64 " bytes "
      "(0 means single / unlimited block size; default) "
      "with %" PRId64 " bytes overlapping the previous block\n",
      pass,
      pass == 1 ? "default" : "test",
      yr_test_mem_block_size,
      yr_test_mem_block_size_overlap);

  yr_test_count_get_block = 0;

  test_boolean_operators();
  test_comparison_operators();
  test_arithmetic_operators();
  test_bitwise_operators();
  test_string_operators();
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
  test_rule_of();
  test_for();
  test_re();
  test_filesize();
  test_include_files();
  // test_compile_file();
  // test_compile_files();

  // test_externals();
  // test_callback();
  // test_compare();
  test_comments();
  test_modules();
  test_integer_functions();
  // test_string_io();
  test_entrypoint();
  test_global_rules();
  test_tags();
  test_meta();
  test_warnings();

#if !defined(USE_NO_PROC) && !defined(_WIN32) && !defined(__CYGWIN__)
  test_process_scan();
#endif

#if defined(HASH_MODULE)
  test_hash_module();
#endif

  test_time_module();
  test_invalid_escape_sequences_warnings();
  test_performance_warnings();
  test_defined();

  if (pass >= 2)
  {
    YR_DEBUG_FPRINTF(
        1,
        stderr,
        "- // pass %d: yr_test_count_get_block=%" PRId64
        " is the number of times the above tests got a "
        "first or next block via the test iterator\n",
        pass,
        yr_test_count_get_block);
  }

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);
}

int main(int argc, char** argv)
{
  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { \n", __FUNCTION__);

  init_top_srcdir();
  yr_initialize();

  assert_true_expr(strlen(TEXT_1024_BYTES) == 1024);

  for (int i = 1; i <= 3; i++)
  {
    printf("--- PASS %d ---\n", i);
    test_pass(i);
  }

  yr_finalize();

  YR_DEBUG_FPRINTF(1, stderr, "} // %s()\n", __FUNCTION__);

  return 0;
}
