#include <yara.h>
#include <config.h>
#include <stdio.h>
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

  assert_true_rule_file("import \"pe\" rule test { condition: pe.checksum == 0xA8DC }",
      "tests/data/tiny");

  assert_true_rule_file("import \"pe\" rule test { condition: pe.checksum == pe.calculate_checksum() }",
      "tests/data/tiny");

  assert_false_rule_file("import \"pe\" rule test { condition: pe.checksum == pe.calculate_checksum() }",
      "tests/data/tiny-idata-51ff");

  yr_finalize();
  return 0;
}
