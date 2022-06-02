#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();

  assert_true_rule_file(
      "import \"lnk\" \
      rule is_lnk { \
        condition: \
          lnk.is_lnk \
      }",
      "tests/data/standard-lnk");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_target_id_list { \
        condition: \
          lnk.link_flags & lnk.HasLinkTargetIDList \
      }",
      "tests/data/standard-lnk");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_info { \
        condition: \
          lnk.link_flags & lnk.HasLinkInfo \
      }",
      "tests/data/standard-lnk");
	  
  assert_false_rule_file(
      "import \"lnk\" \
      rule has_name { \
        condition: \
          lnk.link_flags & lnk.HasName \
      }",
      "tests/data/standard-lnk");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule file_attribute_archive { \
        condition: \
          lnk.file_attributes_flags & lnk.FILE_ATTRIBUTE_ARCHIVE \
      }",
      "tests/data/standard-lnk");
	  
  assert_false_rule_file(
      "import \"lnk\" \
      rule file_attribute_readonly { \
        condition: \
          lnk.file_attributes_flags & lnk.FILE_ATTRIBUTE_READONLY \
      }",
      "tests/data/standard-lnk");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule no_hotkey { \
        condition: \
          not lnk.has_hotkey and not defined lnk.hotkey \
      }",
      "tests/data/standard-lnk");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
