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
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(0x41, 0, 3) == 2 \
      }",
      "AABAAB");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(0x41) == 2 \
      }",
      "ABAB");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(\"AA\", 0, 10) == 4 \
      }",
      "AAAAA");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(\"ABC\", 0, 10) == 2 \
      }",
      "ABCDABCDABCD");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(\"ABC\") == 3 \
      }",
      "ABCDABCDABCD");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.count(\"AA\") == 4 \
      }",
      "AAAAA");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.percentage(0x41) > 0.39 and stats.percentage(0x41) < 0.41 \
      }",
      "ABAB"); // Blob matching includes terminating zero byte

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.percentage(0x41, 0, 4) == 0.5 \
      }",
      "ABABCDEF");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.mode() == 0x41 \
      }",
      "ABABA");

  assert_true_rule_blob(
      "import \"stats\" \
      rule test { \
        condition: \
          stats.mode(2, 3) == 0x41 \
      }",
      "CCABACC");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
