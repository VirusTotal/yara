#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
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
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule creation_time { \
        condition: \
          lnk.creation_time == 1221247637 \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_target_id_list { \
        condition: \
          lnk.link_flags & lnk.HasLinkTargetIDList \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_info { \
        condition: \
          lnk.link_flags & lnk.HasLinkInfo \
      }",
      "tests/data/lnk-standard");
	  
  assert_false_rule_file(
      "import \"lnk\" \
      rule has_name { \
        condition: \
          lnk.link_flags & lnk.HasName \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule file_attribute_archive { \
        condition: \
          lnk.file_attributes_flags & lnk.FILE_ATTRIBUTE_ARCHIVE \
      }",
      "tests/data/lnk-standard");
	  
  assert_false_rule_file(
      "import \"lnk\" \
      rule file_attribute_readonly { \
        condition: \
          lnk.file_attributes_flags & lnk.FILE_ATTRIBUTE_READONLY \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule no_hotkey { \
        condition: \
          not lnk.has_hotkey and not defined lnk.hotkey \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule item_id_list_size { \
        condition: \
          lnk.item_id_list_size == 0xBD \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule number_of_item_ids { \
        condition: \
          lnk.number_of_item_ids == 4 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule item_id_first_element { \
        condition: \
          lnk.item_id_list[0].size == 0x12 and lnk.item_id_list[0].data == \"\\x1fP\\xe0O\\xd0 \\xea:i\\x10\\xa2\\xd8\\x08\\x00+00\\x9d\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule item_id_first_element { \
        condition: \
          lnk.item_id_list[3].size == 0x46 and lnk.item_id_list[3].data == \"2\\x00\\x00\\x00\\x00\\x00,9i\\xa3 \\x00a.txt\\x004\\x00\\x07\\x00\\x04\\x00\\xef\\xbe,9i\\xa3,9i\\xa3&\\x00\\x00\\x00-n\\x00\\x00\\x00\\x00\\x96\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00a\\x00.\\x00t\\x00x\\x00t\\x00\\x00\\x00\\x14\\x00\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule link_info_size { \
        condition: \
          lnk.link_info.size == 0x3C \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule link_info_header_size { \
        condition: \
          lnk.link_info.header_size == 0x1C \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule link_info_flags { \
        condition: \
          lnk.link_info.flags == 0x01 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule volume_id_offset { \
        condition: \
          lnk.link_info.volume_id_offset == 0x1C \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule local_base_path_offset { \
        condition: \
          lnk.link_info.local_base_path_offset == 0x2D \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule common_network_relative_link_offset { \
        condition: \
          lnk.link_info.common_network_relative_link_offset == 0 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule common_path_suffix_offset { \
        condition: \
          lnk.link_info.common_path_suffix_offset == 0x3B \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule volume_id_size { \
        condition: \
          lnk.link_info.volume_id.size == 17 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule drive_type { \
        condition: \
          lnk.link_info.volume_id.drive_type & lnk.DRIVE_FIXED \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule drive_serial_number { \
        condition: \
          lnk.link_info.volume_id.drive_serial_number == 0x307A8A81 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule volume_label_offset { \
        condition: \
          lnk.link_info.volume_id.volume_label_offset == 0x10 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule volume_id_data { \
        condition: \
          lnk.link_info.volume_id.data == \"\\x00\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule local_base_path { \
        condition: \
          lnk.link_info.local_base_path == \"C:\\\\test\\\\a.txt\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule common_path_suffix { \
        condition: \
          lnk.link_info.common_path_suffix == \"\\x00\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule relative_path { \
        condition: \
          lnk.relative_path == \".\\x00\\\\\\x00a\\x00.\\x00t\\x00x\\x00t\\x00\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule working_dir { \
        condition: \
          lnk.working_dir == \"C\\x00:\\x00\\\\\\x00t\\x00e\\x00s\\x00t\\x00\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule tracker_data_block_size { \
        condition: \
          lnk.tracker_data.block_size == 0x60 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule tracker_data_block_signature { \
        condition: \
          lnk.tracker_data.block_signature == 0xA0000003 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule machine_id { \
        condition: \
          lnk.tracker_data.machine_id == \"chris-xps\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule droid_volume_identifier { \
        condition: \
          lnk.tracker_data.droid_volume_identifier == \"\\x40\\x78\\xC7\\x94\\x47\\xFA\\xC7\\x46\\xB3\\x56\\x5C\\x2D\\xC6\\xB6\\xD1\\x15\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule droid_file_identifier { \
        condition: \
          lnk.tracker_data.droid_file_identifier == \"\\xEC\\x46\\xCD\\x7B\\x22\\x7F\\xDD\\x11\\x94\\x99\\x00\\x13\\x72\\x16\\x87\\x4A\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule droid_birth_volume_identifier { \
        condition: \
          lnk.tracker_data.droid_birth_volume_identifier == \"\\x40\\x78\\xC7\\x94\\x47\\xFA\\xC7\\x46\\xB3\\x56\\x5C\\x2D\\xC6\\xB6\\xD1\\x15\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule droid_birth_file_identifier { \
        condition: \
          lnk.tracker_data.droid_birth_file_identifier == \"\\xEC\\x46\\xCD\\x7B\\x22\\x7F\\xDD\\x11\\x94\\x99\\x00\\x13\\x72\\x16\\x87\\x4A\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule net_name { \
        condition: \
          lnk.link_info.common_network_relative_link.net_name == \"\\\\\\\\localhost\\\\c$\\\\Users\\\\yarac\\\\Documents\\\\testing\" \
      }",
      "tests/data/lnk-network");

  assert_true_rule_file(
      "import \"lnk\" \
      rule device_name { \
        condition: \
          lnk.link_info.common_network_relative_link.device_name == \"Z:\" \
      }",
      "tests/data/lnk-network");

  // VolumeID has been set from 0x11 to an impossibly large value 0xFFFFFFFF
  assert_true_rule_file(
      "import \"lnk\" \
      rule malformed_lnk { \
        condition: \
          lnk.is_malformed \
      }",
      "tests/data/lnk-malformed");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
