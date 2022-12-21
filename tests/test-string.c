#include <stdio.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"1234\") == 1234 \
      }",
      NULL);

  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"-1\") == -1 \
      }",
      NULL);

  // Leading spaces and + are allowed.
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\" +1\") == 1 \
      }",
      NULL);

  // Strings can be prefixed with 0x and will be interpreted as hexadecimal.
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"0x10\") == 16 \
      }",
      NULL);

  // Strings prefixed with 0 will be interpreted as octal.
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"010\") == 8 \
      }",
      NULL);

  // Strings that are only partially converted are still fine.
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"10A20\") == 10 \
      }",
      NULL);

  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"10\", 8) == 8 \
      }",
      NULL);

  // Base 0 is a special case that tries to interpret the string by prefix, or
  // default to decimal. We aren't doing anything special to get this, it is
  // part of strtoll by default.
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.to_int(\"010\", 0) == 8 and \
          string.to_int(\"0x10\", 0) == 16 and \
          string.to_int(\"10\", 0) == 10 \
      }",
      NULL);

  // Test undefined cases:
  // - on invalid base value
  // - on underflow or underflow
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          not defined string.to_int(\"1\", -1) and \
          not defined string.to_int(\"1\", 1) and \
          not defined string.to_int(\"1\", 37) \
      }",
      NULL);
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          not defined string.to_int(\"9223372036854775808\") \
      }",
      NULL);
  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          not defined string.to_int(\"-9223372036854775809\") \
      }",
      NULL);

  assert_true_rule(
      "import \"string\" \
      rule test { \
        condition: \
          string.length(\"AXS\\x00ERS\") == 7 \
      }",
      NULL);

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
