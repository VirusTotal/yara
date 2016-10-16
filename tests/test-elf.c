#include <yara.h>
#include "util.h"
#include "blob.h"

int main(int argc, char** argv)
{
  yr_initialize();

  assert_true_rule_blob("import \"elf\" rule test { condition: elf.type }", ELF32_FILE);
  assert_true_rule_blob("import \"elf\" rule test { condition: elf.type }", ELF64_FILE);

  assert_true_rule_blob("import \"elf\" rule test { condition: elf.machine == elf.EM_386 }", ELF32_FILE)
  assert_true_rule_blob("import \"elf\" rule test { condition: elf.machine == elf.EM_X86_64 }", ELF64_FILE)

  assert_true_rule_blob(
      "import \"elf\" rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at elf.entry_point }",
      ELF32_FILE);

  assert_true_rule_blob(
      "import \"elf\" rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at elf.entry_point }",
      ELF64_FILE);

  yr_finalize();
  return 0;
}
