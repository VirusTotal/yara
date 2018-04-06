#include <yara.h>
#include "util.h"
#include "blob.h"

int main(int argc, char** argv)
{
  yr_initialize();

  assert_true_rule_blob(
      "import \"xordiff\" rule test { condition: xordiff.match(9, \"All human beings are born free\") }",
      XORDIFF_FILE);

  assert_true_rule_blob(
      "import \"xordiff\" rule test { condition: xordiff.match(9, \"endowed with reason and conscience\") }",
      XORDIFF_FILE);

  assert_true_rule_blob(
      "import \"xordiff\" rule test { condition: xordiff.match(9, \"spirit of brotherhood\") }",
      XORDIFF_FILE);

  yr_finalize();
}
