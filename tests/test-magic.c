#include <stdlib.h>
#include <unistd.h>
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
      "import \"magic\" rule test { condition: \
      magic.type() contains \"ELF\" }",
      ELF32_FILE);

  assert_true_rule_blob(
      "import \"magic\" rule test { condition: \
      ( magic.type() contains \"MS-DOS executable\" or \
        magic.type() contains \"PE32+ executable\" ) and                                                      \
      ( magic.mime_type() == \"application/x-dosexec\" or \
        magic.mime_type() == \"application/vnd.microsoft.portable-executable\" ) }",
      PE32_FILE);

  // Test case for https://github.com/VirusTotal/yara/issues/1663
  assert_true_rule_blob(
      "import \"magic\" rule test { condition: \
      magic.type() contains \"Mach-O\" and \
      (magic.mime_type() == \"application/x-mach-binary\" or magic.mime_type() == \"application/octet-stream\") and \
      magic.type() contains \"Mach-O\"}",
      MACHO_X86_FILE);

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
