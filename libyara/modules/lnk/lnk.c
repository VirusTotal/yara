#include <wchar.h>
#include <yara/endian.h>
#include <yara/lnk.h>
#include <yara/lnk_utils.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME lnk

begin_declarations
  declare_integer("HAS_LINK_TARGET_ID_LIST");
  declare_integer("HAS_LINK_INFO");
  declare_integer("HAS_NAME");
  declare_integer("HAS_RELATIVE_PATH");
  declare_integer("HAS_WORKING_DIR");
  declare_integer("HAS_ARGUMENTS");
  declare_integer("HAS_ICON_LOCATION");
  declare_integer("IS_UNICODE");
  declare_integer("FORCE_NO_LINK_INFO");
  declare_integer("HAS_EXP_STRING");
  declare_integer("RUN_IN_SEPARATE_PROCESS");
  declare_integer("UNUSED_1");
  declare_integer("HAS_DARWIN_ID");
  declare_integer("RUN_AS_USER");
  declare_integer("HAS_EXP_ICON");
  declare_integer("NO_PIDL_ALIAS");
  declare_integer("UNUSED_2");
  declare_integer("RUN_WITH_SHIM_LAYER");
  declare_integer("FORCE_NO_LINK_TRACK");
  declare_integer("ENABLE_TARGET_METADATA");
  declare_integer("DISABLE_LINK_PATH_TRACKING");
  declare_integer("DISABLE_KNOWN_FOLDER_TRACKING");
  declare_integer("DISABLE_KNOWN_FOLDER_ALIAS");
  declare_integer("ALLOW_LINK_TO_LINK");
  declare_integer("UNALIAS_ON_SAVE");
  declare_integer("PREFER_ENVIRONMENT_PATH");
  declare_integer("KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET");

  declare_integer("FILE_ATTRIBUTE_READONLY");
  declare_integer("FILE_ATTRIBUTE_HIDDEN");
  declare_integer("FILE_ATTRIBUTE_SYSTEM");
  declare_integer("RESERVED_1");
  declare_integer("FILE_ATTRIBUTE_DIRECTORY");
  declare_integer("FILE_ATTRIBUTE_ARCHIVE");
  declare_integer("RESERVED_2");
  declare_integer("FILE_ATTRIBUTE_NORMAL");
  declare_integer("FILE_ATTRIBUTE_TEMPORARY");
  declare_integer("FILE_ATTRIBUTE_SPARSE_FILE");
  declare_integer("FILE_ATTRIBUTE_REPARSE_POINT");
  declare_integer("FILE_ATTRIBUTE_COMPRESSED");
  declare_integer("FILE_ATTRIBUTE_OFFLINE");
  declare_integer("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
  declare_integer("FILE_ATTRIBUTE_ENCRYPTED");

  declare_integer("SW_SHOWNORMAL");
  declare_integer("SW_SHOWMAXIMIZED");
  declare_integer("SW_SHOWMINNOACTIVE");

  declare_integer("HOTKEYF_SHIFT");
  declare_integer("HOTKEYF_CONTROL");
  declare_integer("HOTKEYF_ALT");

  declare_integer("VOLUME_ID_AND_LOCAL_BASE_PATH");
  declare_integer("COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX");

  declare_integer("DRIVE_UNKNOWN");
  declare_integer("DRIVE_NO_ROOT_DIR");
  declare_integer("DRIVE_REMOVABLE");
  declare_integer("DRIVE_FIXED");
  declare_integer("DRIVE_REMOTE");
  declare_integer("DRIVE_CDROM");
  declare_integer("DRIVE_RAMDISK");

  declare_integer("VALID_DEVICE");
  declare_integer("VALID_NET_TYPE");

  declare_integer("WNNC_NET_AVID");
  declare_integer("WNNC_NET_DOCUSPACE");
  declare_integer("WNNC_NET_MANGOSOFT");
  declare_integer("WNNC_NET_SERNET");
  declare_integer("WNNC_NET_RIVERFRONT1");
  declare_integer("WNNC_NET_RIVERFRONT2");
  declare_integer("WNNC_NET_DECORB");
  declare_integer("WNNC_NET_PROTSTOR");
  declare_integer("WNNC_NET_FJ_REDIR");
  declare_integer("WNNC_NET_DISTINCT");
  declare_integer("WNNC_NET_TWINS");
  declare_integer("WNNC_NET_RDR2SAMPLE");
  declare_integer("WNNC_NET_CSC");
  declare_integer("WNNC_NET_3IN1");
  declare_integer("WNNC_NET_EXTENDNET");
  declare_integer("WNNC_NET_STAC");
  declare_integer("WNNC_NET_FOXBAT");
  declare_integer("WNNC_NET_YAHOO");
  declare_integer("WNNC_NET_EXIFS");
  declare_integer("WNNC_NET_DAV");
  declare_integer("WNNC_NET_KNOWARE");
  declare_integer("WNNC_NET_OBJECT_DIRE");
  declare_integer("WNNC_NET_MASFAX");
  declare_integer("WNNC_NET_HOB_NFS");
  declare_integer("WNNC_NET_SHIVA");
  declare_integer("WNNC_NET_IBMAL");
  declare_integer("WNNC_NET_LOCK");
  declare_integer("WNNC_NET_TERMSRV");
  declare_integer("WNNC_NET_SRT");
  declare_integer("WNNC_NET_QUINCY");
  declare_integer("WNNC_NET_OPENAFS");
  declare_integer("WNNC_NET_AVID1");
  declare_integer("WNNC_NET_DFS");
  declare_integer("WNNC_NET_KWNP");
  declare_integer("WNNC_NET_ZENWORKS");
  declare_integer("WNNC_NET_DRIVEONWEB");
  declare_integer("WNNC_NET_VMWARE");
  declare_integer("WNNC_NET_RSFX");
  declare_integer("WNNC_NET_MFILES");
  declare_integer("WNNC_NET_MS_NFS");
  declare_integer("WNNC_NET_GOOGLE");

  declare_integer("FOREGROUND_BLUE");
  declare_integer("FOREGROUND_GREEN");
  declare_integer("FOREGROUND_RED");
  declare_integer("FOREGROUND_INTENSITY");
  declare_integer("BACKGROUND_BLUE");
  declare_integer("BACKGROUND_GREEN");
  declare_integer("BACKGROUND_RED");
  declare_integer("BACKGROUND_INTENSITY");

  declare_integer("FF_DONTCARE");
  declare_integer("FF_ROMAN");
  declare_integer("FF_SWISS");
  declare_integer("FF_MODERN");
  declare_integer("FF_SCRIPT");
  declare_integer("FF_DECORATIVE");

  declare_integer("TMPF_NONE");
  declare_integer("TMPF_FIXED_PITCH");
  declare_integer("TMPF_VECTOR");
  declare_integer("TMPF_TRUETYPE");
  declare_integer("TMPF_DEVICE");

  declare_integer("is_lnk");
  declare_integer("creation_time");
  declare_integer("access_time");
  declare_integer("write_time");
  declare_integer("file_size");
  declare_integer("link_flags");
  declare_integer("file_attributes_flags");
  declare_integer("icon_index");
  declare_integer("show_command");
  declare_integer("hotkey_flags");

  declare_string("hotkey");
  declare_integer("hotkey_modifier_flags");
  declare_integer("has_hotkey");

  begin_struct("link_target_id_list");
    begin_struct_array("item_id_list");
      declare_integer("size");
      declare_string("data");
    end_struct_array("item_id_list");

    declare_integer("number_of_item_ids");
    declare_integer("item_id_list_size");
  end_struct("link_target_id_list");

  begin_struct("link_info");
    declare_integer("size");
    declare_integer("header_size");
    declare_integer("flags");
    declare_integer("volume_id_offset");
    declare_integer("local_base_path_offset");
    declare_integer("common_network_relative_link_offset");
    declare_integer("common_path_suffix_offset");
    declare_integer("local_base_path_offset_unicode");
    declare_integer("common_path_suffix_offset_unicode");

    declare_integer("has_volume_id");

    begin_struct("volume_id");
      declare_integer("size");
      declare_integer("drive_type");
      declare_integer("drive_serial_number");
      declare_integer("volume_label_offset");
      declare_integer("volume_label_offset_unicode");
      declare_string("data");
    end_struct("volume_id");

    declare_string("local_base_path");

    declare_integer("has_common_network_relative_link");

    begin_struct("common_network_relative_link");
      declare_integer("size");
      declare_integer("flags");
      declare_integer("net_name_offset");
      declare_integer("device_name_offset");
      declare_integer("network_provider_type");
      declare_integer("net_name_offset_unicode");
      declare_integer("device_name_offset_unicode");
      declare_string("net_name");
      declare_string("device_name");
      declare_string("net_name_unicode");
      declare_string("device_name_unicode");
    end_struct("common_network_relative_link");

    declare_string("common_path_suffix");
    declare_string("local_base_path_unicode");
    declare_string("common_path_suffix_unicode");
  end_struct("link_info");

  declare_string("name_string");
  declare_string("relative_path");
  declare_string("working_dir");
  declare_string("command_line_arguments");
  declare_string("icon_location");

  declare_integer("has_console_data");

  begin_struct("console_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("fill_attributes");
    declare_integer("popup_fill_attributes");
    declare_integer("screen_buffer_size_x");
    declare_integer("screen_buffer_size_y");
    declare_integer("window_size_x");
    declare_integer("window_size_y");
    declare_integer("window_origin_x");
    declare_integer("window_origin_y");
    declare_integer("font_size");
    declare_integer("font_family");
    declare_integer("font_weight");
    declare_string("face_name");
    declare_integer("cursor_size");
    declare_integer("full_screen");
    declare_integer("quick_edit");
    declare_integer("insert_mode");
    declare_integer("auto_position");
    declare_integer("history_buffer_size");
    declare_integer("number_of_history_buffers");
    declare_integer("history_no_dup");
    declare_integer_array("color_table");
  end_struct("console_data");

  declare_integer("has_console_fe_data");

  begin_struct("console_fe_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("code_page");
  end_struct("console_fe_data");

  declare_integer("has_darwin_data");

  begin_struct("darwin_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("darwin_data_ansi");
    declare_string("darwin_data_unicode");
  end_struct("darwin_data");

  declare_integer("has_environment_variable_data");

  begin_struct("environment_variable_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("target_ansi");
    declare_string("target_unicode");
  end_struct("environment_variable_data");

  declare_integer("has_icon_environment_data");

  begin_struct("icon_environment_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("target_ansi");
    declare_string("target_unicode");
  end_struct("icon_environment_data");

  declare_integer("has_known_folder_data");

  begin_struct("known_folder_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("offset");
    declare_integer_array("known_folder_id");
  end_struct("known_folder_data");

  declare_integer("has_property_store_data");

  begin_struct("property_store_data");
    declare_integer("block_size");
    declare_integer("block_signature");
  end_struct("property_store_data");

  declare_integer("has_shim_data");

  begin_struct("shim_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("layer_name");
  end_struct("shim_data");

  declare_integer("has_special_folder_data");

  begin_struct("special_folder_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("special_folder_id");
    declare_integer("offset");
  end_struct("special_folder_data");

  declare_integer("has_tracker_data");

  begin_struct("tracker_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("machine_id");
    declare_string("droid_volume_identifier");
    declare_string("droid_file_identifier");
    declare_string("droid_birth_volume_identifier");
    declare_string("droid_birth_file_identifier");
  end_struct("tracker_data");

  declare_integer("has_vista_and_above_id_list_data");

  begin_struct("vista_and_above_id_list_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("number_of_item_ids");

    begin_struct_array("item_id_list");
      declare_integer("size");
      declare_string("data");
    end_struct_array("item_id_list");
  end_struct("vista_and_above_id_list_data");

  declare_integer("has_overlay");
  declare_integer("overlay_offset");

  declare_integer("is_malformed");
end_declarations

uint32_t parse_id_list(
    const uint8_t* id_list_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    bool extra_data)
{
  uint16_t item_id_size;
  uint32_t num_item_ids = 0;
  const uint8_t* item_id_data_ptr;

  // Get the first ItemIDSize
  if (block_data_size_remaining < sizeof(item_id_size))
  {
    return 0;
  }
  memcpy(&item_id_size, id_list_ptr, sizeof(item_id_size));
  block_data_size_remaining -= sizeof(item_id_size);

  while (item_id_size != 0)
  {
    // Subtract 2 to not include it
    if (extra_data)
    {
      yr_set_integer(
          item_id_size - 2,
          module_object,
          "vista_and_above_id_list_data.item_id_list[%i].size",
          num_item_ids);
    }
    else
    {
      yr_set_integer(
          item_id_size - 2,
          module_object,
          "link_target_id_list.item_id_list[%i].size",
          num_item_ids);
    }

    // Get pointer to the ItemID Data
    item_id_data_ptr = id_list_ptr + sizeof(item_id_size);

    if (block_data_size_remaining < item_id_size - sizeof(item_id_size))
    {
      return 0;
    }

    if (extra_data)
    {
      yr_set_sized_string(
          (const char*) item_id_data_ptr,
          item_id_size - sizeof(item_id_size),
          module_object,
          "vista_and_above_id_list_data.item_id_list[%i].data",
          num_item_ids);
    }
    else
    {
      yr_set_sized_string(
          (const char*) item_id_data_ptr,
          item_id_size - sizeof(item_id_size),
          module_object,
          "link_target_id_list.item_id_list[%i].data",
          num_item_ids);
    }
    block_data_size_remaining -= item_id_size - sizeof(item_id_size);

    num_item_ids += 1;
    id_list_ptr += item_id_size;

    // Get the next ItemIDSize (or 0x0000 if we've reached TerminalID)
    if (block_data_size_remaining < sizeof(item_id_size))
    {
      return 0;
    }
    memcpy(&item_id_size, id_list_ptr, sizeof(item_id_size));
    block_data_size_remaining -= sizeof(item_id_size);
  }

  if (extra_data)
  {
    yr_set_integer(
        num_item_ids,
        module_object,
        "vista_and_above_id_list_data.number_of_item_ids");
  }
  else
  {
    yr_set_integer(
        num_item_ids, module_object, "link_target_id_list.number_of_item_ids");
  }

  return 1;
}

uint32_t parse_link_target_id_list(
    const uint8_t* link_target_id_list_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining)
{
  uint16_t id_list_size;

  // First, get the IDListSize
  if (block_data_size_remaining < sizeof(id_list_size))
  {
    return 0;
  }
  memcpy(&id_list_size, link_target_id_list_ptr, sizeof(id_list_size));
  block_data_size_remaining -= sizeof(id_list_size);

  yr_set_integer(
      id_list_size, module_object, "link_target_id_list.item_id_list_size");

  // Get pointer to start of IDList
  link_target_id_list_ptr += sizeof(id_list_size);

  if (!parse_id_list(
          link_target_id_list_ptr,
          module_object,
          block_data_size_remaining,
          false))
  {
    return 0;
  }

  // Return the size of the whole section to compute where the next one starts
  return id_list_size + 2;
}

uint32_t parse_volume_id(
    const uint8_t* volume_id_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining)
{
  volume_id_t volume_id;
  uint32_t size_of_data;
  uint32_t volume_label_offset_unicode;
  char* volume_id_data=NULL;
  uint32_t total_data_read = 0;

  if (block_data_size_remaining < sizeof(volume_id_t))
  {
    return 0;
  }

  memcpy(&volume_id, (volume_id_t*) volume_id_ptr, sizeof(volume_id_t));

  yr_set_integer(
      volume_id.volume_id_size, module_object, "link_info.volume_id.size");
  yr_set_integer(
      volume_id.drive_type, module_object, "link_info.volume_id.drive_type");
  yr_set_integer(
      volume_id.drive_serial_number,
      module_object,
      "link_info.volume_id.drive_serial_number");
  yr_set_integer(
      volume_id.volume_label_offset,
      module_object,
      "link_info.volume_id.volume_label_offset");

  // To work out the size of the data, we need to subtract the size of
  // the whole structure from the VolumeIDSize. However, this structure
  // size is variable based on if the unicode offset is present.
  size_of_data = volume_id.volume_id_size - volume_id.volume_label_offset;

  volume_id_ptr += sizeof(volume_id_t);
  block_data_size_remaining -= sizeof(volume_id_t);
  total_data_read += sizeof(volume_id_t);

  if (volume_id.volume_label_offset == 0x14)
  {
    if (block_data_size_remaining < sizeof(volume_label_offset_unicode))
    {
      return 0;
    }

    memcpy(
        &volume_label_offset_unicode,
        volume_id_ptr,
        sizeof(volume_label_offset_unicode));
    yr_set_integer(
        volume_label_offset_unicode,
        module_object,
        "link_info.volume_id.volume_label_offset_unicode");
    volume_id_ptr += sizeof(volume_label_offset_unicode);
    block_data_size_remaining -= sizeof(volume_label_offset_unicode);
    total_data_read += sizeof(volume_label_offset_unicode);

    // Compensate for extra entry in the structure
    // Todo: Extra checks if this size makes sense?
    size_of_data = volume_id.volume_id_size - volume_label_offset_unicode;
  }

  if (block_data_size_remaining < size_of_data)
  {
    return 0;
  }

  if (size_of_data > 256) {
    return 0;
  }

  volume_id_data = yr_malloc(size_of_data);

  memcpy(volume_id_data, volume_id_ptr, size_of_data);
  yr_set_sized_string(
      volume_id_data, size_of_data, module_object, "link_info.volume_id.data");

  volume_id_ptr += size_of_data;
  block_data_size_remaining -= size_of_data;
  total_data_read += size_of_data;

  if (volume_id_data) {
    yr_free(volume_id_data);
  }

  return total_data_read;
}

uint32_t parse_common_network_relative_link(
    const uint8_t* common_network_relative_link_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining)
{
  common_network_relative_link_t common_network_relative_link;
  uint32_t net_name_offset_unicode = 0;
  uint32_t device_name_offset_unicode = 0;
  char* net_name=NULL;
  char* device_name=NULL;
  wchar_t* net_name_unicode=NULL;
  wchar_t* device_name_unicode=NULL;
  uint32_t net_name_len;
  uint32_t device_name_len;
  uint32_t net_name_unicode_len;
  uint32_t device_name_unicode_len;

  if (block_data_size_remaining < sizeof(common_network_relative_link_t))
  {
    return 0;
  }

  memcpy(
      &common_network_relative_link,
      (common_network_relative_link_t*) common_network_relative_link_ptr,
      sizeof(common_network_relative_link_t));

  yr_set_integer(
      common_network_relative_link.common_network_relative_link_size,
      module_object,
      "link_info.common_network_relative_link.size");
  yr_set_integer(
      common_network_relative_link.common_network_relative_link_flags,
      module_object,
      "link_info.common_network_relative_link.flags");
  yr_set_integer(
      common_network_relative_link.net_name_offset,
      module_object,
      "link_info.common_network_relative_link.net_name_offset");
  yr_set_integer(
      common_network_relative_link.device_name_offset,
      module_object,
      "link_info.common_network_relative_link.device_name_offset");
  yr_set_integer(
      common_network_relative_link.network_provider_type,
      module_object,
      "link_info.common_network_relative_link.network_provider_type");

  common_network_relative_link_ptr += sizeof(common_network_relative_link_t);
  block_data_size_remaining -= sizeof(common_network_relative_link_t);

  if (common_network_relative_link.net_name_offset > 0x14)
  {
    if (block_data_size_remaining < sizeof(net_name_offset_unicode))
    {
      return 0;
    }

    memcpy(
        &net_name_offset_unicode,
        common_network_relative_link_ptr,
        sizeof(net_name_offset_unicode));
    yr_set_integer(
        net_name_offset_unicode,
        module_object,
        "link_info.common_network_relative_link.net_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(net_name_offset_unicode);
    block_data_size_remaining -= sizeof(net_name_offset_unicode);

    if (block_data_size_remaining < sizeof(device_name_offset_unicode))
    {
      return 0;
    }

    memcpy(
        &device_name_offset_unicode,
        common_network_relative_link_ptr,
        sizeof(device_name_offset_unicode));
    yr_set_integer(
        device_name_offset_unicode,
        module_object,
        "link_info.common_network_relative_link.device_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(device_name_offset_unicode);
    block_data_size_remaining -= sizeof(device_name_offset_unicode);

    // Parse unicode strings
    net_name_unicode_len = wcslen(
        (const wchar_t*) common_network_relative_link_ptr);

    if (block_data_size_remaining < net_name_unicode_len * 2)
    {
      return 0;
    }

    if (net_name_unicode_len > 260) {
      return 0;
    }

    net_name_unicode = yr_malloc(net_name_unicode_len * 2);

    memcpy(
        net_name_unicode,
        common_network_relative_link_ptr,
        net_name_unicode_len * 2);

    yr_set_sized_string(
        (char*) net_name_unicode,
        net_name_unicode_len,
        module_object,
        "link_info.common_network_relative_link.net_name_unicode");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += (net_name_unicode_len * 2) + 1;
    block_data_size_remaining -= (net_name_unicode_len * 2) + 1;

    device_name_unicode_len = wcslen(
        (const wchar_t*) common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_unicode_len * 2)
    {
      return 0;
    }

    if (device_name_unicode_len > 260) {
      return 0;
    }

    device_name_unicode = yr_malloc(device_name_unicode_len * 2);

    memcpy(
        device_name_unicode,
        common_network_relative_link_ptr,
        device_name_unicode_len * 2);

    yr_set_sized_string(
        (char*) device_name_unicode,
        device_name_unicode_len,
        module_object,
        "link_info.common_network_relative_link.device_name_unicode");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += (device_name_unicode_len * 2) + 1;
    block_data_size_remaining -= (device_name_unicode_len * 2) + 1;
  }

  // Otherwise parse ASCII strings
  else
  {
    net_name_len = strlen((const char*) common_network_relative_link_ptr);

    if (block_data_size_remaining < net_name_len)
    {
      return 0;
    }

    if (net_name_len > 260) {
      return 0;
    }

    net_name = yr_malloc(net_name_len);

    memcpy(net_name, common_network_relative_link_ptr, net_name_len);

    yr_set_sized_string(
        net_name,
        net_name_len,
        module_object,
        "link_info.common_network_relative_link.net_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += net_name_len + 1;
    block_data_size_remaining -= net_name_len + 1;

    device_name_len = strlen((const char*) common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_len)
    {
      return 0;
    }

    if (device_name_len > 260) {
      return 0;
    }

    device_name = yr_malloc(device_name_len);

    memcpy(device_name, common_network_relative_link_ptr, device_name_len);

    yr_set_sized_string(
        device_name,
        device_name_len,
        module_object,
        "link_info.common_network_relative_link.device_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += device_name_len + 1;
    block_data_size_remaining -= device_name_len + 1;
  }

  if (net_name) {
    yr_free(net_name);
  }

  if (device_name) {
    yr_free(device_name);
  }

  if (net_name_unicode) {
    yr_free(net_name_unicode);
  }

  if (device_name_unicode) {
    yr_free(device_name_unicode);
  }

  return common_network_relative_link.common_network_relative_link_size;
}

uint32_t parse_link_info(
    const uint8_t* link_info_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining)
{
  link_info_fixed_header_t* link_info_fixed_header;
  uint32_t local_base_path_offset_unicode = 0;
  uint32_t common_path_suffix_offset_unicode = 0;
  char* local_base_path=NULL;
  char* common_path_suffix=NULL;
  wchar_t* local_base_path_unicode=NULL;
  wchar_t* common_path_suffix_unicode=NULL;
  uint32_t local_base_path_len;
  uint32_t common_path_suffix_len;
  uint32_t local_base_path_unicode_len;
  uint32_t common_path_suffix_unicode_len;
  uint32_t volume_id_size;
  uint32_t common_network_relative_link_size;

  if (block_data_size_remaining < sizeof(link_info_fixed_header_t))
  {
    return 0;
  }
  link_info_fixed_header = (link_info_fixed_header_t*) link_info_ptr;

  yr_set_integer(
      link_info_fixed_header->link_info_size, module_object, "link_info.size");
  yr_set_integer(
      link_info_fixed_header->link_info_header_size,
      module_object,
      "link_info.header_size");
  yr_set_integer(
      link_info_fixed_header->link_info_flags,
      module_object,
      "link_info.flags");
  yr_set_integer(
      link_info_fixed_header->volume_id_offset,
      module_object,
      "link_info.volume_id_offset");
  yr_set_integer(
      link_info_fixed_header->local_base_path_offset,
      module_object,
      "link_info.local_base_path_offset");
  yr_set_integer(
      link_info_fixed_header->common_network_relative_link_offset,
      module_object,
      "link_info.common_network_relative_link_offset");
  yr_set_integer(
      link_info_fixed_header->common_path_suffix_offset,
      module_object,
      "link_info.common_path_suffix_offset");

  link_info_ptr += sizeof(link_info_fixed_header_t);
  block_data_size_remaining -= sizeof(link_info_fixed_header_t);

  // if VOLUME_ID_AND_LOCAL_BASE_PATH flag:
  //   VolumeID and LocalBasePath present
  //   VolumeIDOffset and LocalBasePathOffset specify offsets
  //   if LinkInfoHeaderSize > 0x24:
  //     LocalBasePathUnicode present (specified by offset value)
  // else
  //   VolumeID, LocalBasePath, and LocalBasePathUnicode fields are not present
  //   VolumeIDOffset and LocalBasePathOffset are 0
  //   if LinkInfoHeaderSize > 0x24:
  //     LocalBasePathOffsetUnicode is 0

  if (link_info_fixed_header->link_info_flags & VOLUME_ID_AND_LOCAL_BASE_PATH)
  {
    if (link_info_fixed_header->link_info_header_size >= 0x24)
    {
      if (block_data_size_remaining < sizeof(local_base_path_offset_unicode))
      {
        return 0;
      }

      memcpy(
          &local_base_path_offset_unicode,
          link_info_ptr,
          sizeof(local_base_path_offset_unicode));
      yr_set_integer(
          local_base_path_offset_unicode,
          module_object,
          "link_info.local_base_path_offset_unicode");
      link_info_ptr += sizeof(local_base_path_offset_unicode);
      block_data_size_remaining -= sizeof(local_base_path_offset_unicode);
    }

    if (link_info_fixed_header->volume_id_offset)
    {
      yr_set_integer(1, module_object, "link_info.has_volume_id");

      volume_id_size = parse_volume_id(
          link_info_ptr, module_object, block_data_size_remaining);

      if (volume_id_size == 0)
      {
        return 0;
      }

      if (block_data_size_remaining < volume_id_size)
      {
        return 0;
      }

      link_info_ptr += volume_id_size;
      block_data_size_remaining -= volume_id_size;
    }

    else
    {
      yr_set_integer(0, module_object, "link_info.has_volume_id");
    }

    // Handle LocalBasePath
    if (link_info_fixed_header->local_base_path_offset)
    {
      local_base_path_len = strlen((const char*) link_info_ptr);

      if (local_base_path_len > 256) {
        return 0;
      }

      if (block_data_size_remaining < local_base_path_len)
      {
        return 0;
      }

      local_base_path = (char*)yr_malloc(local_base_path_len);

      memcpy(local_base_path, link_info_ptr, local_base_path_len);
      yr_set_sized_string(
          local_base_path,
          local_base_path_len,
          module_object,
          "link_info.local_base_path");

      // Add 1 to deal with null terminator
      link_info_ptr += local_base_path_len + 1;
      block_data_size_remaining -= local_base_path_len + 1;
    }
  }

  if (link_info_fixed_header->link_info_header_size >= 0x24)
  {
    if (block_data_size_remaining < sizeof(common_path_suffix_offset_unicode))
    {
      return 0;
    }

    memcpy(
        &common_path_suffix_offset_unicode,
        link_info_ptr,
        sizeof(common_path_suffix_offset_unicode));
    yr_set_integer(
        common_path_suffix_offset_unicode,
        module_object,
        "link_info.common_path_suffix_offset_unicode");
    link_info_ptr += sizeof(common_path_suffix_offset_unicode);
    block_data_size_remaining -= sizeof(common_path_suffix_offset_unicode);
  }

  if (link_info_fixed_header->link_info_flags &
      COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX)
  {
    if (link_info_fixed_header->common_network_relative_link_offset)
    {
      common_network_relative_link_size = parse_common_network_relative_link(
          link_info_ptr, module_object, block_data_size_remaining);

      if (common_network_relative_link_size == 0)
      {
        return 0;
      }

      if (block_data_size_remaining < common_network_relative_link_size)
      {
        return 0;
      }

      link_info_ptr += common_network_relative_link_size;
      block_data_size_remaining -= common_network_relative_link_size;
    }
  }

  // Handle CommonPathSuffix
  if (link_info_fixed_header->common_path_suffix_offset)
  {
    if (block_data_size_remaining < 1)
    {
      return 0;
    }

    // Have to deal with this possibly being an empty string
    if (memcmp(link_info_ptr, "\x00", 1) == 0)
    {
      yr_set_sized_string(
          "\x00", 1, module_object, "link_info.common_path_suffix");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else
    {
      common_path_suffix_len = strlen((const char*) link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_len)
      {
        return 0;
      }

      if (common_path_suffix_len > 256) {
        return 0;
      }

      common_path_suffix = yr_malloc(common_path_suffix_len);

      memcpy(common_path_suffix, link_info_ptr, common_path_suffix_len);

      yr_set_sized_string(
          common_path_suffix,
          common_path_suffix_len,
          module_object,
          "link_info.common_path_suffix");

      // Add 1 to deal with null terminator
      link_info_ptr += common_path_suffix_len + 1;
      block_data_size_remaining -= common_path_suffix_len + 1;
    }
  }

  // TODO: These unicode functions will need some careful testing
  // Need some samples to test against
  if (local_base_path_offset_unicode)
  {
    local_base_path_unicode_len = wcslen((const wchar_t*) link_info_ptr);

    if (block_data_size_remaining < local_base_path_unicode_len * 2)
    {
      return 0;
    }

    if (local_base_path_unicode_len > 256) {
      return 0;
    }

    local_base_path_unicode = yr_malloc(local_base_path_unicode_len * 2);

    memcpy(
        local_base_path_unicode,
        link_info_ptr,
        local_base_path_unicode_len * 2);

    yr_set_sized_string(
        (char*) local_base_path_unicode,
        local_base_path_unicode_len,
        module_object,
        "link_info.local_base_path_unicode");

    // Add 1 to deal with null terminator
    link_info_ptr += (local_base_path_unicode_len * 2) + 1;
    block_data_size_remaining -= (local_base_path_unicode_len * 2) + 1;
  }

  if (common_path_suffix_offset_unicode)
  {
    if (block_data_size_remaining < 1)
    {
      return 0;
    }

    // Have to deal with this possibly being an empty string
    if (memcmp(link_info_ptr, "\x00", 1) == 0)
    {
      yr_set_sized_string(
          "\x00", 1, module_object, "link_info.common_path_suffix_unicode");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else
    {
      common_path_suffix_unicode_len = wcslen((const wchar_t*) link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_unicode_len * 2)
      {
        return 0;
      }

      if (common_path_suffix_unicode_len > 256) {
        return 0;
      }

      common_path_suffix_unicode = yr_malloc(common_path_suffix_unicode_len * 2);

      memcpy(
          common_path_suffix_unicode,
          link_info_ptr,
          common_path_suffix_unicode_len * 2);

      yr_set_sized_string(
          (char*) common_path_suffix_unicode,
          common_path_suffix_unicode_len,
          module_object,
          "link_info.common_path_suffix_unicode");

      // Add 1 to deal with null terminator
      link_info_ptr += (common_path_suffix_unicode_len * 2) + 1;
      block_data_size_remaining -= (common_path_suffix_unicode_len * 2) + 1;
    }
  }

  if (local_base_path){
    yr_free(local_base_path);
  }

  if (common_path_suffix){
    yr_free(common_path_suffix);
  }

  if (local_base_path_unicode) {
    yr_free(local_base_path_unicode);
  }

  if (common_path_suffix_unicode) {
    yr_free(common_path_suffix_unicode);
  }

  return (int) link_info_fixed_header->link_info_size;
}

uint32_t parse_string_data(
    const uint8_t* string_data_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    const char* name,
    bool is_unicode)
{
  uint16_t count_characters;
  uint32_t string_size;

  // CountCharacters only returns the number of characters in the string, but
  // not information on whether the string is unicode vs. another type of
  // string. The IS_UNICODE flag will tell us if the StringData values are
  // unicode, and if it is not set, we'll assume it is ascii (although it can be
  // whatever is the default codepage from where the LNK is generated)

  if (block_data_size_remaining < sizeof(count_characters))
  {
    return 0;
  }

  memcpy(&count_characters, string_data_ptr, sizeof(count_characters));
  string_data_ptr += sizeof(count_characters);
  block_data_size_remaining -= sizeof(count_characters);

  if (is_unicode)
  {
    if (block_data_size_remaining < count_characters * 2)
    {
      return 0;
    }

    string_size = count_characters * 2;
  }

  else
  {
    string_size = count_characters;
  }

  // Do these extra comparisons due to "format not a string literal and no
  // format arguments" error on compilation
  if (strcmp(name, "name_string") == 0)
  {
    yr_set_sized_string(
        (char*) string_data_ptr, string_size, module_object, "name_string");
  }

  else if (strcmp(name, "relative_path") == 0)
  {
    yr_set_sized_string(
        (char*) string_data_ptr, string_size, module_object, "relative_path");
  }

  else if (strcmp(name, "working_dir") == 0)
  {
    yr_set_sized_string(
        (char*) string_data_ptr, string_size, module_object, "working_dir");
  }

  else if (strcmp(name, "command_line_arguments") == 0)
  {
    yr_set_sized_string(
        (char*) string_data_ptr,
        string_size,
        module_object,
        "command_line_arguments");
  }

  else if (strcmp(name, "icon_location") == 0)
  {
    yr_set_sized_string(
        (char*) string_data_ptr, string_size, module_object, "icon_location");
  }

  else
  {
    return 0;
  }

  return string_size + sizeof(count_characters);
}

uint32_t parse_console_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  console_data_block_t console_data_block;
  int i;

  if (block_data_size_remaining < sizeof(console_data_block_t))
  {
    return 0;
  }

  memcpy(
      &console_data_block,
      (console_data_block_t*) extra_block_ptr,
      sizeof(console_data_block_t));

  yr_set_integer(extra_data_block_size, module_object, "console_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "console_data.block_signature");
  yr_set_integer(
      console_data_block.fill_attributes,
      module_object,
      "console_data.fill_attributes");
  yr_set_integer(
      console_data_block.popup_fill_attributes,
      module_object,
      "console_data.popup_fill_attributes");
  yr_set_integer(
      console_data_block.screen_buffer_size_x,
      module_object,
      "console_data.screen_buffer_size_x");
  yr_set_integer(
      console_data_block.screen_buffer_size_y,
      module_object,
      "console_data.screen_buffer_size_y");
  yr_set_integer(
      console_data_block.window_size_x,
      module_object,
      "console_data.window_size_x");
  yr_set_integer(
      console_data_block.window_size_y,
      module_object,
      "console_data.window_size_y");
  yr_set_integer(
      console_data_block.window_origin_x,
      module_object,
      "console_data.window_origin_x");
  yr_set_integer(
      console_data_block.window_origin_y,
      module_object,
      "console_data.window_origin_y");
  yr_set_integer(
      console_data_block.font_size, module_object, "console_data.font_size");
  yr_set_integer(
      console_data_block.font_family,
      module_object,
      "console_data.font_family");
  yr_set_integer(
      console_data_block.font_weight,
      module_object,
      "console_data.font_weight");
  yr_set_sized_string(
      (char*) console_data_block.face_name,
      wcslen((wchar_t*) console_data_block.face_name),
      module_object,
      "console_data.face_name");
  yr_set_integer(
      console_data_block.cursor_size,
      module_object,
      "console_data.cursor_size");
  yr_set_integer(
      console_data_block.full_screen,
      module_object,
      "console_data.full_screen");
  yr_set_integer(
      console_data_block.quick_edit, module_object, "console_data.quick_edit");
  yr_set_integer(
      console_data_block.insert_mode,
      module_object,
      "console_data.insert_mode");
  yr_set_integer(
      console_data_block.auto_position,
      module_object,
      "console_data.auto_position");
  yr_set_integer(
      console_data_block.history_buffer_size,
      module_object,
      "console_data.history_buffer_size");
  yr_set_integer(
      console_data_block.number_of_history_buffers,
      module_object,
      "console_data.number_of_history_buffers");
  yr_set_integer(
      console_data_block.history_no_dup,
      module_object,
      "console_data.history_no_dup");

  for (i = 0; i < 16; i++)
  {
    yr_set_integer(
        console_data_block.color_table[i],
        module_object,
        "console_data.color_table[%i]",
        i);
  }

  return 1;
}

uint32_t parse_console_fe_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  console_fe_data_block_t console_fe_data;

  if (block_data_size_remaining < sizeof(console_fe_data_block_t))
  {
    return 0;
  }

  memcpy(
      &console_fe_data,
      (console_fe_data_block_t*) extra_block_ptr,
      sizeof(console_fe_data_block_t));

  yr_set_integer(
      extra_data_block_size, module_object, "console_fe_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "console_fe_data.block_signature");
  yr_set_integer(
      console_fe_data.code_page, module_object, "console_fe_data.code_page");

  return 1;
}

uint32_t parse_darwin_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  darwin_data_block_t darwin_data;

  if (block_data_size_remaining < sizeof(darwin_data_block_t))
  {
    return 0;
  }

  memcpy(
      &darwin_data,
      (darwin_data_block_t*) extra_block_ptr,
      sizeof(darwin_data_block_t));

  yr_set_integer(extra_data_block_size, module_object, "darwin_data.block_size");
  yr_set_integer(
      extra_data_block_signature, module_object, "darwin_data.block_signature");
  yr_set_string(
      darwin_data.darwin_data_ansi,
      module_object,
      "darwin_data.darwin_data_ansi");
  yr_set_sized_string(
      (char*) darwin_data.darwin_data_unicode,
      wcslen((wchar_t*) darwin_data.darwin_data_unicode) * 2,
      module_object,
      "darwin_data.darwin_data_unicode");

  return 1;
}

uint32_t parse_environment_variable_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  environment_variable_data_block_t environment_variable_data;

  if (block_data_size_remaining < sizeof(environment_variable_data_block_t))
  {
    return 0;
  }

  memcpy(
      &environment_variable_data,
      (environment_variable_data_block_t*) extra_block_ptr,
      sizeof(environment_variable_data_block_t));

  yr_set_integer(
      extra_data_block_size,
      module_object,
      "environment_variable_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "environment_variable_data.block_signature");
  yr_set_string(
      environment_variable_data.target_ansi,
      module_object,
      "environment_variable_data.target_ansi");
  yr_set_sized_string(
      (char*) environment_variable_data.target_unicode,
      wcslen((wchar_t*) environment_variable_data.target_unicode) * 2,
      module_object,
      "environment_variable_data.target_unicode");

  return 1;
}

uint32_t parse_icon_environment_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  icon_environment_data_block_t icon_environment_data;

  if (block_data_size_remaining < sizeof(icon_environment_data_block_t))
  {
    return 0;
  }

  memcpy(
      &icon_environment_data,
      (icon_environment_data_block_t*) extra_block_ptr,
      sizeof(icon_environment_data_block_t));

  yr_set_integer(
      extra_data_block_size, module_object, "icon_environment_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "icon_environment_data.block_signature");
  yr_set_string(
      icon_environment_data.target_ansi,
      module_object,
      "icon_environment_data.target_ansi");
  yr_set_sized_string(
      (char*) icon_environment_data.target_unicode,
      wcslen((wchar_t*) icon_environment_data.target_unicode) * 2,
      module_object,
      "icon_environment_data.target_unicode");

  return 1;
}

uint32_t parse_known_folder_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  known_folder_data_block_t known_folder_data;
  int i;

  if (block_data_size_remaining < sizeof(known_folder_data_block_t))
  {
    return 0;
  }

  memcpy(
      &known_folder_data,
      (known_folder_data_block_t*) extra_block_ptr,
      sizeof(known_folder_data_block_t));

  yr_set_integer(
      extra_data_block_size, module_object, "known_folder_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "known_folder_data.block_signature");
  yr_set_integer(
      known_folder_data.offset, module_object, "known_folder_data.offset");

  for (i = 0; i < 16; i++)
  {
    yr_set_integer(
        known_folder_data.known_folder_id[i],
        module_object,
        "known_folder_data.known_folder_id[%i]",
        i);
  }

  return 1;
}

uint32_t parse_property_store_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  yr_set_integer(
      extra_data_block_size, module_object, "property_store_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "property_store_data.block_signature");

  // TODO: implement parsing the rest of the structure
  // https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-PROPSTORE/%5bMS-PROPSTORE%5d.pdf

  return 1;
}

uint32_t parse_shim_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  wchar_t* layer_name;

  if (block_data_size_remaining < extra_data_block_size -
                                      sizeof(extra_data_block_size) -
                                      sizeof(extra_data_block_signature))
  {
    return 0;
  }

  layer_name = (wchar_t*) extra_block_ptr;

  yr_set_integer(extra_data_block_size, module_object, "shim_data.block_size");
  yr_set_integer(
      extra_data_block_signature, module_object, "shim_data.block_signature");
  yr_set_sized_string(
      (char*) layer_name,
      extra_data_block_size - sizeof(extra_data_block_size) -
          sizeof(extra_data_block_signature),
      module_object,
      "shim_data.layer_name");

  return 1;
}

uint32_t parse_special_folder_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  special_folder_data_block_t special_folder_data;

  if (block_data_size_remaining < sizeof(special_folder_data_block_t))
  {
    return 0;
  }

  memcpy(
      &special_folder_data,
      (special_folder_data_block_t*) extra_block_ptr,
      sizeof(special_folder_data_block_t));

  yr_set_integer(
      extra_data_block_size, module_object, "special_folder_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "special_folder_data.block_signature");
  yr_set_integer(
      special_folder_data.special_folder_id,
      module_object,
      "special_folder_data.special_folder_id");
  yr_set_integer(
      special_folder_data.offset, module_object, "special_folder_data.offset");

  return 1;
}

uint32_t parse_tracker_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  tracker_data_block_t tracker_data_block;

  if (block_data_size_remaining < sizeof(tracker_data_block_t))
  {
    return 0;
  }

  memcpy(
      &tracker_data_block,
      (tracker_data_block_t*) extra_block_ptr,
      sizeof(tracker_data_block_t));

  yr_set_integer(extra_data_block_size, module_object, "tracker_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "tracker_data.block_signature");
  yr_set_string(
      tracker_data_block.machine_id, module_object, "tracker_data.machine_id");
  yr_set_sized_string(
      (char*) tracker_data_block.droid_volume_identifier,
      sizeof(tracker_data_block.droid_volume_identifier),
      module_object,
      "tracker_data.droid_volume_identifier");
  yr_set_sized_string(
      (char*) tracker_data_block.droid_file_identifier,
      sizeof(tracker_data_block.droid_file_identifier),
      module_object,
      "tracker_data.droid_file_identifier");
  yr_set_sized_string(
      (char*) tracker_data_block.droid_birth_volume_identifier,
      sizeof(tracker_data_block.droid_birth_volume_identifier),
      module_object,
      "tracker_data.droid_birth_volume_identifier");
  yr_set_sized_string(
      (char*) tracker_data_block.droid_birth_file_identifier,
      sizeof(tracker_data_block.droid_birth_file_identifier),
      module_object,
      "tracker_data.droid_birth_file_identifier");

  return 1;
}

uint32_t parse_vista_and_above_id_list_data_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{
  if (block_data_size_remaining < extra_data_block_size -
                                      sizeof(extra_data_block_size) -
                                      sizeof(extra_data_block_signature))
  {
    return 0;
  }

  yr_set_integer(
      extra_data_block_size,
      module_object,
      "vista_and_above_id_list_data.block_size");
  yr_set_integer(
      extra_data_block_signature,
      module_object,
      "vista_and_above_id_list_data.block_signature");
  if (!parse_id_list(
          extra_block_ptr, module_object, block_data_size_remaining, true))
  {
    return 0;
  }

  return 1;
}

uint32_t parse_extra_block(
    const uint8_t* extra_block_ptr,
    YR_OBJECT* module_object,
    uint32_t block_data_size_remaining,
    uint32_t extra_data_block_size,
    uint32_t extra_data_block_signature)
{

  switch (extra_data_block_signature)
  {
  case CONSOLE_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_console_data");

    if (extra_data_block_size == CONSOLE_DATA_BLOCK_SIZE &&
        parse_console_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case CONSOLE_FE_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_console_fe_data");

    if (extra_data_block_size == CONSOLE_FE_DATA_BLOCK_SIZE &&
        parse_console_fe_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case DARWIN_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_darwin_data");

    if (extra_data_block_size == DARWIN_DATA_BLOCK_SIZE &&
        parse_darwin_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case ENVIRONMENT_VARIABLE_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_environment_variable_data");

    if (extra_data_block_size == ENVIRONMENT_VARIABLE_DATA_BLOCK_SIZE &&
        parse_environment_variable_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case ICON_ENVIRONMENT_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_icon_environment_data");

    if (extra_data_block_size == ICON_ENVIRONMENT_DATA_BLOCK_SIZE &&
        parse_icon_environment_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case KNOWN_FOLDER_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_known_folder_data");

    if (extra_data_block_size == KNOWN_FOLDER_DATA_BLOCK_SIZE &&
        parse_known_folder_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case PROPERTY_STORE_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_property_store_data");

    if (extra_data_block_size >= PROPERTY_STORE_DATA_BLOCK_MIN_SIZE &&
        parse_property_store_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case SHIM_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_shim_data");

    if (extra_data_block_size >= SHIM_DATA_BLOCK_MIN_SIZE &&
        parse_shim_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case SPECIAL_FOLDER_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_special_folder_data");

    if (extra_data_block_size == SPECIAL_FOLDER_DATA_BLOCK_SIZE &&
        parse_special_folder_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case TRACKER_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_tracker_data");

    if (extra_data_block_size == TRACKER_DATA_BLOCK_SIZE &&
        parse_tracker_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  case VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK_SIGNATURE:

    yr_set_integer(1, module_object, "has_vista_and_above_id_list_data");

    if (extra_data_block_size >= VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK_MIN_SIZE &&
        parse_vista_and_above_id_list_data_block(
            extra_block_ptr,
            module_object,
            block_data_size_remaining,
            extra_data_block_size,
            extra_data_block_signature))
    {
      return 1;
    }
    break;

  default:
    return 0;
  }

  return 0;
}

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  shell_link_header_t* lnk_header;
  yr_set_integer(0, module_object, "is_lnk");

  yr_set_integer(HAS_LINK_TARGET_ID_LIST, module_object, "HAS_LINK_TARGET_ID_LIST");
  yr_set_integer(HAS_LINK_INFO, module_object, "HAS_LINK_INFO");
  yr_set_integer(HAS_NAME, module_object, "HAS_NAME");
  yr_set_integer(HAS_RELATIVE_PATH, module_object, "HAS_RELATIVE_PATH");
  yr_set_integer(HAS_WORKING_DIR, module_object, "HAS_WORKING_DIR");
  yr_set_integer(HAS_ARGUMENTS, module_object, "HAS_ARGUMENTS");
  yr_set_integer(HAS_ICON_LOCATION, module_object, "HAS_ICON_LOCATION");
  yr_set_integer(IS_UNICODE, module_object, "IS_UNICODE");
  yr_set_integer(FORCE_NO_LINK_INFO, module_object, "FORCE_NO_LINK_INFO");
  yr_set_integer(HAS_EXP_STRING, module_object, "HAS_EXP_STRING");
  yr_set_integer(RUN_IN_SEPARATE_PROCESS, module_object, "RUN_IN_SEPARATE_PROCESS");
  yr_set_integer(UNUSED_1, module_object, "UNUSED_1");
  yr_set_integer(HAS_DARWIN_ID, module_object, "HAS_DARWIN_ID");
  yr_set_integer(RUN_AS_USER, module_object, "RUN_AS_USER");
  yr_set_integer(HAS_EXP_ICON, module_object, "HAS_EXP_ICON");
  yr_set_integer(NO_PIDL_ALIAS, module_object, "NO_PIDL_ALIAS");
  yr_set_integer(UNUSED_2, module_object, "UNUSED_2");
  yr_set_integer(RUN_WITH_SHIM_LAYER, module_object, "RUN_WITH_SHIM_LAYER");
  yr_set_integer(FORCE_NO_LINK_TRACK, module_object, "FORCE_NO_LINK_TRACK");
  yr_set_integer(ENABLE_TARGET_METADATA, module_object, "ENABLE_TARGET_METADATA");
  yr_set_integer(
      DISABLE_LINK_PATH_TRACKING, module_object, "DISABLE_LINK_PATH_TRACKING");
  yr_set_integer(
      DISABLE_KNOWN_FOLDER_TRACKING, module_object, "DISABLE_KNOWN_FOLDER_TRACKING");
  yr_set_integer(
      DISABLE_KNOWN_FOLDER_ALIAS, module_object, "DISABLE_KNOWN_FOLDER_ALIAS");
  yr_set_integer(ALLOW_LINK_TO_LINK, module_object, "ALLOW_LINK_TO_LINK");
  yr_set_integer(UNALIAS_ON_SAVE, module_object, "UNALIAS_ON_SAVE");
  yr_set_integer(PREFER_ENVIRONMENT_PATH, module_object, "PREFER_ENVIRONMENT_PATH");
  yr_set_integer(
      KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET,
      module_object,
      "KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET");

  yr_set_integer(
      FILE_ATTRIBUTE_READONLY, module_object, "FILE_ATTRIBUTE_READONLY");
  yr_set_integer(FILE_ATTRIBUTE_HIDDEN, module_object, "FILE_ATTRIBUTE_HIDDEN");
  yr_set_integer(FILE_ATTRIBUTE_SYSTEM, module_object, "FILE_ATTRIBUTE_SYSTEM");
  yr_set_integer(RESERVED_1, module_object, "RESERVED_1");
  yr_set_integer(
      FILE_ATTRIBUTE_DIRECTORY, module_object, "FILE_ATTRIBUTE_DIRECTORY");
  yr_set_integer(FILE_ATTRIBUTE_ARCHIVE, module_object, "FILE_ATTRIBUTE_ARCHIVE");
  yr_set_integer(RESERVED_2, module_object, "RESERVED_2");
  yr_set_integer(FILE_ATTRIBUTE_NORMAL, module_object, "FILE_ATTRIBUTE_NORMAL");
  yr_set_integer(
      FILE_ATTRIBUTE_TEMPORARY, module_object, "FILE_ATTRIBUTE_TEMPORARY");
  yr_set_integer(
      FILE_ATTRIBUTE_SPARSE_FILE, module_object, "FILE_ATTRIBUTE_SPARSE_FILE");
  yr_set_integer(
      FILE_ATTRIBUTE_REPARSE_POINT,
      module_object,
      "FILE_ATTRIBUTE_REPARSE_POINT");
  yr_set_integer(
      FILE_ATTRIBUTE_COMPRESSED, module_object, "FILE_ATTRIBUTE_COMPRESSED");
  yr_set_integer(FILE_ATTRIBUTE_OFFLINE, module_object, "FILE_ATTRIBUTE_OFFLINE");
  yr_set_integer(
      FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
      module_object,
      "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
  yr_set_integer(
      FILE_ATTRIBUTE_ENCRYPTED, module_object, "FILE_ATTRIBUTE_ENCRYPTED");

  yr_set_integer(SW_SHOWNORMAL, module_object, "SW_SHOWNORMAL");
  yr_set_integer(SW_SHOWMAXIMIZED, module_object, "SW_SHOWMAXIMIZED");
  yr_set_integer(SW_SHOWMINNOACTIVE, module_object, "SW_SHOWMINNOACTIVE");

  yr_set_integer(HOTKEYF_SHIFT, module_object, "HOTKEYF_SHIFT");
  yr_set_integer(HOTKEYF_CONTROL, module_object, "HOTKEYF_CONTROL");
  yr_set_integer(HOTKEYF_ALT, module_object, "HOTKEYF_ALT");

  yr_set_integer(
      VOLUME_ID_AND_LOCAL_BASE_PATH, module_object, "VOLUME_ID_AND_LOCAL_BASE_PATH");
  yr_set_integer(
      COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX,
      module_object,
      "COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX");

  yr_set_integer(DRIVE_UNKNOWN, module_object, "DRIVE_UNKNOWN");
  yr_set_integer(DRIVE_NO_ROOT_DIR, module_object, "DRIVE_NO_ROOT_DIR");
  yr_set_integer(DRIVE_REMOVABLE, module_object, "DRIVE_REMOVABLE");
  yr_set_integer(DRIVE_FIXED, module_object, "DRIVE_FIXED");
  yr_set_integer(DRIVE_REMOTE, module_object, "DRIVE_REMOTE");
  yr_set_integer(DRIVE_CDROM, module_object, "DRIVE_CDROM");
  yr_set_integer(DRIVE_RAMDISK, module_object, "DRIVE_RAMDISK");

  yr_set_integer(VALID_DEVICE, module_object, "VALID_DEVICE");
  yr_set_integer(VALID_NET_TYPE, module_object, "VALID_NET_TYPE");

  yr_set_integer(WNNC_NET_AVID, module_object, "WNNC_NET_AVID");
  yr_set_integer(WNNC_NET_DOCUSPACE, module_object, "WNNC_NET_DOCUSPACE");
  yr_set_integer(WNNC_NET_MANGOSOFT, module_object, "WNNC_NET_MANGOSOFT");
  yr_set_integer(WNNC_NET_SERNET, module_object, "WNNC_NET_SERNET");
  yr_set_integer(WNNC_NET_RIVERFRONT1, module_object, "WNNC_NET_RIVERFRONT1");
  yr_set_integer(WNNC_NET_RIVERFRONT2, module_object, "WNNC_NET_RIVERFRONT2");
  yr_set_integer(WNNC_NET_DECORB, module_object, "WNNC_NET_DECORB");
  yr_set_integer(WNNC_NET_PROTSTOR, module_object, "WNNC_NET_PROTSTOR");
  yr_set_integer(WNNC_NET_FJ_REDIR, module_object, "WNNC_NET_FJ_REDIR");
  yr_set_integer(WNNC_NET_DISTINCT, module_object, "WNNC_NET_DISTINCT");
  yr_set_integer(WNNC_NET_TWINS, module_object, "WNNC_NET_TWINS");
  yr_set_integer(WNNC_NET_RDR2SAMPLE, module_object, "WNNC_NET_RDR2SAMPLE");
  yr_set_integer(WNNC_NET_CSC, module_object, "WNNC_NET_CSC");
  yr_set_integer(WNNC_NET_3IN1, module_object, "WNNC_NET_3IN1");
  yr_set_integer(WNNC_NET_EXTENDNET, module_object, "WNNC_NET_EXTENDNET");
  yr_set_integer(WNNC_NET_STAC, module_object, "WNNC_NET_STAC");
  yr_set_integer(WNNC_NET_FOXBAT, module_object, "WNNC_NET_FOXBAT");
  yr_set_integer(WNNC_NET_YAHOO, module_object, "WNNC_NET_YAHOO");
  yr_set_integer(WNNC_NET_EXIFS, module_object, "WNNC_NET_EXIFS");
  yr_set_integer(WNNC_NET_DAV, module_object, "WNNC_NET_DAV");
  yr_set_integer(WNNC_NET_KNOWARE, module_object, "WNNC_NET_KNOWARE");
  yr_set_integer(WNNC_NET_OBJECT_DIRE, module_object, "WNNC_NET_OBJECT_DIRE");
  yr_set_integer(WNNC_NET_MASFAX, module_object, "WNNC_NET_MASFAX");
  yr_set_integer(WNNC_NET_HOB_NFS, module_object, "WNNC_NET_HOB_NFS");
  yr_set_integer(WNNC_NET_SHIVA, module_object, "WNNC_NET_SHIVA");
  yr_set_integer(WNNC_NET_IBMAL, module_object, "WNNC_NET_IBMAL");
  yr_set_integer(WNNC_NET_LOCK, module_object, "WNNC_NET_LOCK");
  yr_set_integer(WNNC_NET_TERMSRV, module_object, "WNNC_NET_TERMSRV");
  yr_set_integer(WNNC_NET_SRT, module_object, "WNNC_NET_SRT");
  yr_set_integer(WNNC_NET_QUINCY, module_object, "WNNC_NET_QUINCY");
  yr_set_integer(WNNC_NET_OPENAFS, module_object, "WNNC_NET_OPENAFS");
  yr_set_integer(WNNC_NET_AVID1, module_object, "WNNC_NET_AVID1");
  yr_set_integer(WNNC_NET_DFS, module_object, "WNNC_NET_DFS");
  yr_set_integer(WNNC_NET_KWNP, module_object, "WNNC_NET_KWNP");
  yr_set_integer(WNNC_NET_ZENWORKS, module_object, "WNNC_NET_ZENWORKS");
  yr_set_integer(WNNC_NET_DRIVEONWEB, module_object, "WNNC_NET_DRIVEONWEB");
  yr_set_integer(WNNC_NET_VMWARE, module_object, "WNNC_NET_VMWARE");
  yr_set_integer(WNNC_NET_RSFX, module_object, "WNNC_NET_RSFX");
  yr_set_integer(WNNC_NET_MFILES, module_object, "WNNC_NET_MFILES");
  yr_set_integer(WNNC_NET_MS_NFS, module_object, "WNNC_NET_MS_NFS");
  yr_set_integer(WNNC_NET_GOOGLE, module_object, "WNNC_NET_GOOGLE");

  yr_set_integer(FOREGROUND_BLUE, module_object, "FOREGROUND_BLUE");
  yr_set_integer(FOREGROUND_GREEN, module_object, "FOREGROUND_GREEN");
  yr_set_integer(FOREGROUND_RED, module_object, "FOREGROUND_RED");
  yr_set_integer(FOREGROUND_INTENSITY, module_object, "FOREGROUND_INTENSITY");
  yr_set_integer(BACKGROUND_BLUE, module_object, "BACKGROUND_BLUE");
  yr_set_integer(BACKGROUND_GREEN, module_object, "BACKGROUND_GREEN");
  yr_set_integer(BACKGROUND_RED, module_object, "BACKGROUND_RED");
  yr_set_integer(BACKGROUND_INTENSITY, module_object, "BACKGROUND_INTENSITY");

  yr_set_integer(FF_DONTCARE, module_object, "FF_DONTCARE");
  yr_set_integer(FF_ROMAN, module_object, "FF_ROMAN");
  yr_set_integer(FF_SWISS, module_object, "FF_SWISS");
  yr_set_integer(FF_MODERN, module_object, "FF_MODERN");
  yr_set_integer(FF_SCRIPT, module_object, "FF_SCRIPT");
  yr_set_integer(FF_DECORATIVE, module_object, "FF_DECORATIVE");

  yr_set_integer(TMPF_NONE, module_object, "TMPF_NONE");
  yr_set_integer(TMPF_FIXED_PITCH, module_object, "TMPF_FIXED_PITCH");
  yr_set_integer(TMPF_VECTOR, module_object, "TMPF_VECTOR");
  yr_set_integer(TMPF_TRUETYPE, module_object, "TMPF_TRUETYPE");
  yr_set_integer(TMPF_DEVICE, module_object, "TMPF_DEVICE");

  const uint8_t* block_data;
  uint32_t block_data_size_remaining;
  char* hotkey_str;
  const uint8_t* current_location;
  uint32_t id_list_size;
  uint32_t link_info_size;
  uint32_t string_data_size;
  uint32_t extra_data_block_size;
  uint32_t extra_data_block_signature;

  block = first_memory_block(context);
  block_data = block->fetch_data(block);

  // Keep track the amount of space in the current block we have left
  // to prevent any issues when dereferencing pointers
  block_data_size_remaining = (int) block->size;

  // Don't try to parse a file unless it is the minimum size an LNK can be
  // based on fixed length headers it has (described in shell_link_header_t)
  if (block_data != NULL &&
      block_data_size_remaining >= sizeof(shell_link_header_t))
  {
    // Validate LNK header
    lnk_header = (shell_link_header_t*) block_data;
    if (lnk_header->header_size == HEADER_SIZE &&
        lnk_header->clsid[0] == LINK_CLSID_0 &&
        lnk_header->clsid[1] == LINK_CLSID_1 &&
        lnk_header->clsid[2] == LINK_CLSID_2 &&
        lnk_header->clsid[3] == LINK_CLSID_3)
    {
      yr_set_integer(1, module_object, "is_lnk");

      // Convert timestamps from Windows TIMESTAMP to Unix timestamp
      yr_set_integer(
          convertWindowsTimeToUnixTime(lnk_header->creation_time),
          module_object,
          "creation_time");

      yr_set_integer(
          convertWindowsTimeToUnixTime(lnk_header->access_time),
          module_object,
          "access_time");

      yr_set_integer(
          convertWindowsTimeToUnixTime(lnk_header->write_time),
          module_object,
          "write_time");

      yr_set_integer(lnk_header->file_size, module_object, "file_size");
      yr_set_integer(lnk_header->link_flags, module_object, "link_flags");
      yr_set_integer(
          lnk_header->file_attributes_flags,
          module_object,
          "file_attributes_flags");
      yr_set_integer(lnk_header->icon_index, module_object, "icon_index");
      yr_set_integer(lnk_header->show_command, module_object, "show_command");
      yr_set_integer(lnk_header->hotkey_flags, module_object, "hotkey_flags");

      // Hotkey handling code
      if (lnk_header->hotkey_flags & 0xFF)
      {
        hotkey_str = get_hotkey_char(lnk_header->hotkey_flags & 0xFF);

        if (hotkey_str)
        {
          yr_set_string(hotkey_str, module_object, "hotkey");
        }

        yr_set_integer(1, module_object, "has_hotkey");
      }

      else
      {
        yr_set_integer(0, module_object, "has_hotkey");
      }

      yr_set_integer(
          (lnk_header->hotkey_flags >> 8),
          module_object,
          "hotkey_modifier_flags");

      // Set pointer of current location to be after the LNK fixed header
      current_location = block_data + sizeof(shell_link_header_t);
      block_data_size_remaining -= sizeof(shell_link_header_t);

      // Optional parsing of LinkTargetIDList
      if (lnk_header->link_flags & HAS_LINK_TARGET_ID_LIST)
      {
        id_list_size = parse_link_target_id_list(
            current_location, module_object, block_data_size_remaining);

        if (id_list_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < id_list_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += id_list_size;
        block_data_size_remaining -= id_list_size;
      }

      if (lnk_header->link_flags & HAS_LINK_INFO)
      {
        link_info_size = parse_link_info(
            current_location, module_object, block_data_size_remaining);

        if (link_info_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < link_info_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += link_info_size;
        block_data_size_remaining -= link_info_size;
      }

      // NAME_STRING
      if (lnk_header->link_flags & HAS_NAME)
      {
        string_data_size = parse_string_data(
            current_location,
            module_object,
            block_data_size_remaining,
            "name_string",
            lnk_header->link_flags & IS_UNICODE);

        if (string_data_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < string_data_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // RELATIVE_PATH
      if (lnk_header->link_flags & HAS_RELATIVE_PATH)
      {
        string_data_size = parse_string_data(
            current_location,
            module_object,
            block_data_size_remaining,
            "relative_path",
            lnk_header->link_flags & IS_UNICODE);

        if (string_data_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < string_data_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // WORKING_DIR
      if (lnk_header->link_flags & HAS_WORKING_DIR)
      {
        string_data_size = parse_string_data(
            current_location,
            module_object,
            block_data_size_remaining,
            "working_dir",
            lnk_header->link_flags & IS_UNICODE);

        if (string_data_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < string_data_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // COMMAND_LINK_ARGUMENTS
      if (lnk_header->link_flags & HAS_ARGUMENTS)
      {
        string_data_size = parse_string_data(
            current_location,
            module_object,
            block_data_size_remaining,
            "command_line_arguments",
            lnk_header->link_flags & IS_UNICODE);

        if (string_data_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < string_data_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // ICON_LOCATION
      if (lnk_header->link_flags & HAS_ICON_LOCATION)
      {
        string_data_size = parse_string_data(
            current_location,
            module_object,
            block_data_size_remaining,
            "icon_location",
            lnk_header->link_flags & IS_UNICODE);

        if (string_data_size == 0)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        if (block_data_size_remaining < string_data_size)
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      yr_set_integer(0, module_object, "has_console_data");
      yr_set_integer(0, module_object, "has_console_fe_data");
      yr_set_integer(0, module_object, "has_darwin_data");
      yr_set_integer(0, module_object, "has_environment_variable_data");
      yr_set_integer(0, module_object, "has_icon_environment_data");
      yr_set_integer(0, module_object, "has_known_folder_data");
      yr_set_integer(0, module_object, "has_property_store_data");
      yr_set_integer(0, module_object, "has_shim_data");
      yr_set_integer(0, module_object, "has_special_folder_data");
      yr_set_integer(0, module_object, "has_tracker_data");
      yr_set_integer(0, module_object, "has_vista_and_above_id_list_data");

      // Parse ExtraData
      if (block_data_size_remaining > 0)
      {
        if (block_data_size_remaining < sizeof(extra_data_block_size))
        {
          yr_set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        memcpy(
            &extra_data_block_size,
            current_location,
            sizeof(extra_data_block_size));
        current_location += sizeof(extra_data_block_size);

        // The TerminalBlock must be less than 0x04, so iterate until we find it
        // (or run out of space)
        while (extra_data_block_size >= 0x04)
        {
          // Only do this in the loop so we don't overshoot the end of the block
          block_data_size_remaining -= sizeof(extra_data_block_size);

          if (block_data_size_remaining < sizeof(extra_data_block_signature))
          {
            yr_set_integer(1, module_object, "is_malformed");
            return ERROR_SUCCESS;
          }

          memcpy(
              &extra_data_block_signature,
              current_location,
              sizeof(extra_data_block_signature));
          current_location += sizeof(extra_data_block_signature);
          block_data_size_remaining -= sizeof(extra_data_block_signature);

          if (!parse_extra_block(
                  current_location,
                  module_object,
                  block_data_size_remaining,
                  extra_data_block_size,
                  extra_data_block_signature))
          {
            break;
          }

          // Don't add/take away the block size + signature, as those have
          // already been dealt with
          current_location += extra_data_block_size -
                              sizeof(extra_data_block_size) -
                              sizeof(extra_data_block_signature);
          block_data_size_remaining -= extra_data_block_size -
                                       sizeof(extra_data_block_size) -
                                       sizeof(extra_data_block_signature);

          if (block_data_size_remaining < sizeof(extra_data_block_size))
          {
            yr_set_integer(1, module_object, "is_malformed");
            return ERROR_SUCCESS;
          }

          memcpy(
              &extra_data_block_size,
              current_location,
              sizeof(extra_data_block_size));
          current_location += sizeof(extra_data_block_size);
        }

        // Finally, take away size of the TerminalBlock
        block_data_size_remaining -= 4;
      }

      if (block_data_size_remaining > 0)
      {
        yr_set_integer(1, module_object, "has_overlay");
        yr_set_integer(
            block->size - block_data_size_remaining,
            module_object,
            "overlay_offset");
      }

      else
      {
        yr_set_integer(0, module_object, "has_overlay");
      }

      // If all parsing successful, say that the LNK isn't malformed
      yr_set_integer(0, module_object, "is_malformed");
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
