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

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
