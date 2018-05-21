#include <yara.h>
#include <stdio.h>
#include "util.h"

int main(int argc, char** argv)
{
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

  yr_finalize();
  return 0;
}
