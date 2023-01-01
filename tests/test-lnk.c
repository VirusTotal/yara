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
          lnk.creation_time == 1221251237 \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_target_id_list { \
        condition: \
          lnk.link_flags & lnk.HAS_LINK_TARGET_ID_LIST \
      }",
      "tests/data/lnk-standard");
	  
  assert_true_rule_file(
      "import \"lnk\" \
      rule has_link_info { \
        condition: \
          lnk.link_flags & lnk.HAS_LINK_INFO \
      }",
      "tests/data/lnk-standard");
	  
  assert_false_rule_file(
      "import \"lnk\" \
      rule has_name { \
        condition: \
          lnk.link_flags & lnk.HAS_NAME \
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
      rule show_command { \
        condition: \
          lnk.show_command == lnk.SW_SHOWNORMAL \
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
          lnk.link_target_id_list.item_id_list_size == 0xBD \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule number_of_item_ids { \
        condition: \
          lnk.link_target_id_list.number_of_item_ids == 4 \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule item_id_first_element { \
        condition: \
          lnk.link_target_id_list.item_id_list[0].size == 0x12 and lnk.link_target_id_list.item_id_list[0].data == \"\\x1fP\\xe0O\\xd0 \\xea:i\\x10\\xa2\\xd8\\x08\\x00+00\\x9d\" \
      }",
      "tests/data/lnk-standard");

  assert_true_rule_file(
      "import \"lnk\" \
      rule item_id_first_element { \
        condition: \
          lnk.link_target_id_list.item_id_list[3].size == 0x46 and lnk.link_target_id_list.item_id_list[3].data == \"2\\x00\\x00\\x00\\x00\\x00,9i\\xa3 \\x00a.txt\\x004\\x00\\x07\\x00\\x04\\x00\\xef\\xbe,9i\\xa3,9i\\xa3&\\x00\\x00\\x00-n\\x00\\x00\\x00\\x00\\x96\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00a\\x00.\\x00t\\x00x\\x00t\\x00\\x00\\x00\\x14\\x00\" \
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
          lnk.link_info.flags & lnk.VOLUME_ID_AND_LOCAL_BASE_PATH \
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
      rule has_volume_id { \
        condition: \
          lnk.link_info.has_volume_id \
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
      rule has_tracker_data { \
        condition: \
          lnk.has_tracker_data \
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
      rule common_network_relative_link_flags { \
        condition: \
          lnk.link_info.common_network_relative_link.flags & lnk.VALID_NET_TYPE \
      }",
      "tests/data/lnk-network");

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

  assert_true_rule_file(
      "import \"lnk\" \
      rule overlay_lnk { \
        condition: \
          lnk.has_overlay and lnk.overlay_offset == 0x1CB \
      }",
      "tests/data/lnk-overlay");

  assert_true_rule_file(
      "import \"lnk\" \
      rule has_console_data { \
        condition: \
          lnk.has_console_data \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule number_of_history_buffers { \
        condition: \
          lnk.console_data.number_of_history_buffers == 4 \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule color_table { \
        condition: \
          lnk.console_data.color_table[15] == 0x00ffffff \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule has_environment_variable_data { \
        condition: \
          lnk.has_environment_variable_data \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule environment_variable_data_ansi { \
        condition: \
          lnk.environment_variable_data.target_ansi == \"%SystemRoot%\\\\sysWOW64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\" \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule has_special_folder_data { \
        condition: \
          lnk.has_special_folder_data \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule special_folder_data { \
        condition: \
          lnk.special_folder_data.special_folder_id == 36 and lnk.special_folder_data.offset == 105 \
      }",
      "tests/data/lnk-extradata-1");

  assert_true_rule_file(
      "import \"lnk\" \
      rule icon_environment_data_target_ansi { \
        condition: \
          lnk.icon_environment_data.target_ansi == \"%ProgramFiles%\\\\PeaZip\\\\res\\\\icons\\\\peazip_new.icl\" \
      }",
      "tests/data/lnk-extradata-2");

  assert_true_rule_file(
      "import \"lnk\" \
      rule has_icon_environment_data { \
        condition: \
          lnk.has_icon_environment_data \
      }",
      "tests/data/lnk-extradata-2");

  assert_true_rule_file(
      "import \"lnk\" \
      rule has_known_folder_data { \
        condition: \
          lnk.has_known_folder_data \
      }",
      "tests/data/lnk-extradata-2");

  assert_true_rule_file(
      "import \"lnk\" \
      rule known_folder_offset { \
        condition: \
          lnk.known_folder_data.offset == 177 \
      }",
      "tests/data/lnk-extradata-2");

  assert_true_rule_file(
      "import \"lnk\" \
      rule known_folder_id { \
        condition: \
          lnk.known_folder_data.known_folder_id[15] == 142 \
      }",
      "tests/data/lnk-extradata-2");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
