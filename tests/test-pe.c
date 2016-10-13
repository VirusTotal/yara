#include <yara.h>
#include <config.h>
#include <stdio.h>
#include "util.h"

int main(int argc, char** argv)
{
#if (defined(HAVE_ENDIAN_H) && BYTE_ORDER == LITTLE_ENDIAN) || defined(_MSC)
  yr_initialize();

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny");

  assert_true_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-51ff");

  assert_false_rule_file("import \"pe\" rule test { condition: pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\") }",
      "tests/data/tiny-idata-5200");

  yr_finalize();
#else
  puts("Not testing pe module on big-endian architectures ... yet");
  exit(77);
#endif
  return 0;
}
