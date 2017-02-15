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

  assert_true_rule_blob("import \"elf\" rule test { \
    condition: elf.sections[2].name == \".comment\" }", ELF64_FILE);

  assert_true_rule_blob("import \"elf\" rule test { \
    condition: elf.machine == elf.EM_MIPS }", ELF32_MIPS_FILE);

  assert_true_rule_blob("import \"elf\" rule test { \
    condition: elf.number_of_sections == 11 and \
    elf.number_of_segments == 3 }", ELF32_MIPS_FILE);

  assert_true_rule_blob("import \"elf\" rule test { \
    condition: for any i in (0..elf.number_of_sections): ( \
    elf.sections[i].type == elf.SHT_PROGBITS and \
    elf.sections[i].name == \".text\")}", ELF32_MIPS_FILE);

  assert_true_rule_blob("import \"elf\" rule test { \
    condition: for any i in (0..elf.number_of_segments): ( \
    elf.segments[i].type == elf.PT_LOAD and \
    elf.segments[i].virtual_address == 0x00400000 and \
    elf.segments[i].file_size == 0xe0)}", ELF32_MIPS_FILE);

  yr_finalize();
  return 0;
}
