#include <stdio.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.min(0, 1) == 0 \
      }",
      "A");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.max(0, 1) == 1 \
      }",
      "A");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_number(1 == 1) \
      }",
      "A");

  assert_false_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_number(1 > 2) \
      }",
      "A");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.abs(-1) == 1 \
      }",
      "A");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        strings: \
          $a = \"A\" \
          $b = \"B\" \
        condition: \
          math.abs(@a - @b) == 1 \
      }",
      "AB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.count(0x41, 0, 3) == 2 \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.count(0x41, 4, 10) == 1  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.count(0x41, 10, 3)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.count(0x41, 0, -3)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.count(-1)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.count(0x41) == 2 \
      }",
      "ABAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.percentage(0x41) > 0.39 and math.percentage(0x41) < 0.41 \
      }",
      "ABAB");  // Blob matching includes terminating zero byte

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.percentage(0x41, 0, 4) == 0.5 \
      }",
      "ABABCDEF");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.percentage(0x41, 0, 0) \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.percentage(0x41, 10, 3)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.percentage(0x41, 0, -3)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          not defined math.percentage(-1)  \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.mode() == 0x41 \
      }",
      "ABABA");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.mode() == 0x41 \
      }",
      "ABAB");

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.mode(2, 3) == 0x41 \
      }",
      "CCABACC");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.entropy(\"AAAAA\") == 0.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.entropy(\"\") == 0.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.entropy(\"AABB\") == 1.0 \
      }",
      NULL);

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.entropy(2, 3) == 0.0 \
      }",
      "CCAAACC");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.deviation(\"AAAAA\", 0.0) == 65.0 \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.deviation(\"ABAB\", 65.0) == 0.5 \
      }",
      NULL);

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.deviation(2, 4, 65.0) == 0.5 \
      }",
      "ABABABAB");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.mean(\"ABCABC\") == 66.0 \
      }",
      NULL);

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.mean(0, 3) == 66.0 \
      }",
      "ABCABC");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.serial_correlation(\"BCA\") == -0.5 \
      }",
      NULL);

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.serial_correlation(1, 3) == -0.5 \
      }",
      "ABCABC");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.in_range(2.0, 1.0, 3.0) \
      }",
      NULL);

  assert_false_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.in_range(6.0, 1.0, 3.0) \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.monte_carlo_pi(\"ABCDEF123456987\") < 0.3 \
      }",
      NULL);

  assert_true_rule_blob(
      "import \"math\" \
      rule test { \
        condition: \
          math.monte_carlo_pi(3, 15) < 0.3 \
      }",
      "123ABCDEF123456987DE");

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(1234) == \"1234\" \
      }",
      NULL);

  // We use signed integers by default if no base is specified.
  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(-1) == \"-1\" \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(32, 16) == \"20\" \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(32, 8) == \"40\" \
      }",
      NULL);

  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(32, 10) == \"32\" \
      }",
      NULL);

  // Base 10 is always a signed integer, all other bases are unsigned.
  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          math.to_string(-1, 10) == \"-1\" and \
          math.to_string(-1, 16) == \"ffffffffffffffff\" and \
          math.to_string(-1, 8) == \"1777777777777777777777\" \
      }",
      NULL);

  // Passing a base that is not 10, 8 or 16 will result in UNDEFINED.
  assert_true_rule(
      "import \"math\" \
      rule test { \
        condition: \
          not defined(math.to_string(32, 9)) \
      }",
      NULL);

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
