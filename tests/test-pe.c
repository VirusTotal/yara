#include <yara.h>
#include "util.h"

int main(int argc, char** argv)
{
  yr_initialize();

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny.exe");

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-51ff.exe");

  assert_false_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-5200.exe");

  yr_finalize();
  return 0;
}
