#include <stdio.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, __FILE__);

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

  YR_DEBUG_FPRINTF(1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, __FILE__);

  return result;
}
