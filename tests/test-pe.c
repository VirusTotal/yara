#include <yara.h>
#include "util.h"

int main(int argc, char** argv)
{
  yr_initialize();

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny");

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-51ff");

  assert_false_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-5200");

  yr_finalize();
  return 0;
}
