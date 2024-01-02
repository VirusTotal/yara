#include <yara.h>

#include "blob.h"
#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();

  assert_true_rule_blob(
      "import \"elf\" rule test { condition: elf.type }", ELF32_FILE);

  assert_true_rule_blob(
      "import \"elf\" rule test { condition: elf.type }", ELF64_FILE);

  assert_true_rule_blob(
      "import \"elf\" rule test { condition: elf.machine == elf.EM_386 }",
      ELF32_FILE)

      assert_true_rule_blob(
          "import \"elf\" rule test { condition: elf.machine == elf.EM_X86_64 "
          "}",
          ELF64_FILE)

          assert_true_rule_blob(
              "import \"elf\" \
      rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at elf.entry_point \
      }",
              ELF32_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        strings: $a = { b8 01 00 00 00 bb 2a } \
        condition: $a at elf.entry_point \
      }",
      ELF64_FILE);

  assert_true_rule_blob(
      "import \"elf\" rule test { condition: elf.entry_point == 0xa0 }",
      ELF32_NOSECTIONS);

  assert_true_rule_blob(
      "import \"elf\" rule test { condition: elf.entry_point == 0x1a0 }",
      ELF32_SHAREDOBJ);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: elf.sections[2].name == \".comment\" \
      }",
      ELF64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: elf.machine == elf.EM_MIPS \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.number_of_sections == 35 and elf.number_of_segments == 10 \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.number_of_sections): ( \
            elf.sections[i].type == elf.SHT_PROGBITS and  \
            elf.sections[i].address == 0x400600 and \
            elf.sections[i].name == \".text\") \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
        rule test { \
          condition: \
            for any i in (0..elf.number_of_segments): ( \
            elf.segments[i].type == elf.PT_LOAD and \
            elf.segments[i].virtual_address == 0x00400000 and \
            elf.segments[i].file_size == 0x95c)\
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.dynamic_section_entries == 19 and \
          elf.symtab_entries == 80 \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.symtab_entries): ( \
            elf.symtab[i].shndx == 9 and \
            elf.symtab[i].value == 0x400650 and \
            elf.symtab[i].name == \"_start_c\") \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.symtab[68].name == \"_start_c\" and \
          elf.symtab[68].type == elf.STT_FUNC and \
          elf.symtab[68].bind == elf.STB_GLOBAL and \
          elf.symtab[68].value == 0x400650 and \
          elf.symtab[68].size == 56 \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.dynsym_entries): ( \
            elf.dynsym[i].shndx == 11 and \
            elf.dynsym[i].value == 0x400910 and \
            elf.dynsym[i].name == \"_fini\") \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.dynsym[9].name == \"__RLD_MAP\" and \
          elf.dynsym[9].type == elf.STT_OBJECT and \
          elf.dynsym[9].bind == elf.STB_GLOBAL and \
          elf.dynsym[9].value == 0x411000 and \
          elf.dynsym[9].size == 0 \
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.dynamic[4].type == elf.DT_STRTAB and \
          elf.dynamic[4].val == 0x400484\
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.dynamic_section_entries): ( \
            elf.dynamic[i].type == 0x70000006 and \
            elf.dynamic[i].val == 0x400000)\
      }",
      ELF32_MIPS_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: elf.machine == elf.EM_X86_64 \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.number_of_sections == 22 and \
          elf.number_of_segments == 7 \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.number_of_sections): ( \
            elf.sections[i].type == elf.SHT_PROGBITS and \
            elf.sections[i].address == 0x601000 and \
            elf.sections[i].name == \".got.plt\") \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
         condition: \
            for any i in (0..elf.number_of_segments): ( \
              elf.segments[i].type == elf.PT_LOAD and \
              elf.segments[i].virtual_address == 0x600e78 and \
              elf.segments[i].file_size == 0x1b0) \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
         condition: \
            elf.dynamic_section_entries == 18 and \
            elf.symtab_entries == 48  \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.symtab_entries): ( \
            elf.symtab[i].shndx == 8 and \
            elf.symtab[i].value == 0x400400 and \
            elf.symtab[i].name == \"main\") \
     }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.symtab[20].name == \"__JCR_LIST__\" and \
          elf.symtab[20].type == elf.STT_OBJECT and \
          elf.symtab[20].bind == elf.STB_LOCAL and \
          elf.symtab[20].value == 0x600e88 and \
          elf.symtab[20].size == 0 \
      }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.dynamic[13].type == elf.DT_PLTGOT and \
          elf.dynamic[13].val == 0x601000 \
     }",
      ELF_x64_FILE);

  assert_true_rule_blob(
      "import \"elf\" \
      rule test { \
        condition: \
          for any i in (0..elf.dynamic_section_entries): ( \
            elf.dynamic[i].type == elf.DT_JMPREL and \
            elf.dynamic[i].val == 0x4003c0) \
      }",
      ELF_x64_FILE);

  assert_true_rule_file(
      "import \"elf\" \
      rule test { \
        condition: \
          elf.telfhash() == \
            \"T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA\" \
      }",
      "tests/data/elf_with_imports");


  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
