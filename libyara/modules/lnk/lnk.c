#include <yara/modules.h>
#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/lnk.h>
#include <yara/lnk_utils.h>
#include <wchar.h>

#define MODULE_NAME lnk

begin_declarations
  declare_integer("HasLinkTargetIDList");
  declare_integer("HasLinkInfo");
  declare_integer("HasName");
  declare_integer("HasRelativePath");
  declare_integer("HasWorkingDir");
  declare_integer("HasArguments");
  declare_integer("HasIconLocation");
  declare_integer("IsUnicode");
  declare_integer("ForceNoLinkInfo");
  declare_integer("HasExpString");
  declare_integer("RunInSeparateProcess");
  declare_integer("Unused1");
  declare_integer("HasDarwinID");
  declare_integer("RunAsUser");
  declare_integer("HasExpIcon");
  declare_integer("NoPidlAlias");
  declare_integer("Unused2");
  declare_integer("RunWithShimLayer");
  declare_integer("ForceNoLinkTrack");
  declare_integer("EnableTargetMetadata");
  declare_integer("DisableLinkPathTracking");
  declare_integer("DisableKnownFolderTracking");
  declare_integer("DisableKnownFolderAlias");
  declare_integer("AllowLinkToLink");
  declare_integer("UnaliasOnSave");
  declare_integer("PreferEnvironmentPath");
  declare_integer("KeepLocalIDListForUNCTarget");
  
  declare_integer("FILE_ATTRIBUTE_READONLY");
  declare_integer("FILE_ATTRIBUTE_HIDDEN");
  declare_integer("FILE_ATTRIBUTE_SYSTEM");
  declare_integer("Reserved1");
  declare_integer("FILE_ATTRIBUTE_DIRECTORY");
  declare_integer("FILE_ATTRIBUTE_ARCHIVE");
  declare_integer("Reserved2");
  declare_integer("FILE_ATTRIBUTE_NORMAL");
  declare_integer("FILE_ATTRIBUTE_TEMPORARY");
  declare_integer("FILE_ATTRIBUTE_SPARSE_FILE");
  declare_integer("FILE_ATTRIBUTE_REPARSE_POINT");
  declare_integer("FILE_ATTRIBUTE_COMPRESSED");
  declare_integer("FILE_ATTRIBUTE_OFFLINE");
  declare_integer("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
  declare_integer("FILE_ATTRIBUTE_ENCRYPTED");
  
  declare_integer("HOTKEYF_SHIFT");
  declare_integer("HOTKEYF_CONTROL");
  declare_integer("HOTKEYF_ALT");

  declare_integer("VolumeIDAndLocalBasePath");
  declare_integer("CommonNetworkRelativeLinkAndPathSuffix");

  declare_integer("DRIVE_UNKNOWN");
  declare_integer("DRIVE_NO_ROOT_DIR");
  declare_integer("DRIVE_REMOVABLE");
  declare_integer("DRIVE_FIXED");
  declare_integer("DRIVE_REMOTE");
  declare_integer("DRIVE_CDROM");
  declare_integer("DRIVE_RAMDISK");

  declare_integer("ValidDevice");
  declare_integer("ValidNetType");
  
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

    begin_struct("volume_id");
      declare_integer("size");
      declare_integer("drive_type");
      declare_integer("drive_serial_number");
      declare_integer("volume_label_offset");
      declare_integer("volume_label_offset_unicode");
      declare_string("data");
    end_struct("volume_id");

    declare_string("local_base_path");

    begin_struct("common_network_relative_link");
      declare_integer("common_network_relative_link_size");
      declare_integer("common_network_relative_link_flags");
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

  begin_struct("console_fed_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("code_page");
  end_struct("console_fed_data");

  begin_struct("darwin_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("darwin_data_ansi");
    declare_string("darwin_data_unicode");
  end_struct("darwin_data");

  begin_struct("environment_variable_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("target_ansi");
    declare_string("target_unicode");
  end_struct("environment_variable_data");

  begin_struct("icon_environment_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("target_ansi");
    declare_string("target_unicode");
  end_struct("icon_environment_data");

  begin_struct("known_folder_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("offset");
    declare_integer_array("known_folder_id");
  end_struct("known_folder_data");

  begin_struct("property_store_data");
    declare_integer("block_size");
    declare_integer("block_signature");
  end_struct("property_store_data");

  begin_struct("shim_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("layer_name");
  end_struct("shim_data");

  begin_struct("special_folder_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_integer("special_folder_id");
    declare_integer("offset");
  end_struct("special_folder_data");

  begin_struct("tracker_data");
    declare_integer("block_size");
    declare_integer("block_signature");
    declare_string("machine_id");
    declare_string("droid_volume_identifier");
    declare_string("droid_file_identifier");
    declare_string("droid_birth_volume_identifier");
    declare_string("droid_birth_file_identifier");
  end_struct("tracker_data");

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

unsigned int parse_id_list(const uint8_t * id_list_ptr, YR_OBJECT* module_object, int block_data_size_remaining, bool extra_data) {
  uint16_t item_id_size;
  unsigned int num_item_ids = 0;
  const uint8_t* item_id_data_ptr;
  
  // Get the first ItemIDSize
  if (block_data_size_remaining < sizeof(item_id_size)) {
    return 0;
  }
  memcpy(&item_id_size, id_list_ptr, sizeof(item_id_size));
  block_data_size_remaining -= sizeof(item_id_size);

  while (item_id_size != 0) {
    // Subtract 2 to not include it
    if (extra_data) {
      set_integer(item_id_size - 2, module_object, "vista_and_above_id_list_data.item_id_list[%i].size", num_item_ids);
    }
    else {
      set_integer(item_id_size - 2, module_object, "link_target_id_list.item_id_list[%i].size", num_item_ids);
    }
    
    // Get pointer to the ItemID Data
    item_id_data_ptr = id_list_ptr + sizeof(item_id_size);

    if (block_data_size_remaining < item_id_size-sizeof(item_id_size)) {
      return 0;
    }

    if (extra_data) {
      set_sized_string((const char *)item_id_data_ptr, item_id_size-sizeof(item_id_size), module_object, "vista_and_above_id_list_data.item_id_list[%i].data", num_item_ids);
    }
    else {
      set_sized_string((const char *)item_id_data_ptr, item_id_size-sizeof(item_id_size), module_object, "link_target_id_list.item_id_list[%i].data", num_item_ids);
    }
    block_data_size_remaining -= item_id_size-sizeof(item_id_size);

    num_item_ids += 1;
    id_list_ptr += item_id_size;

    // Get the next ItemIDSize (or 0x0000 if we've reached TerminalID)
    if (block_data_size_remaining < sizeof(item_id_size)) {
      return 0;
    }
    memcpy(&item_id_size, id_list_ptr, sizeof(item_id_size));
    block_data_size_remaining -= sizeof(item_id_size);
  }

  if (extra_data) {
    set_integer(num_item_ids, module_object, "vista_and_above_id_list_data.number_of_item_ids");
  }
  else {
    set_integer(num_item_ids, module_object, "link_target_id_list.number_of_item_ids");
  }

  return 1;
}

unsigned int parse_link_target_id_list(const uint8_t * link_target_id_list_ptr, YR_OBJECT* module_object, int block_data_size_remaining) {
  uint16_t id_list_size;

  // First, get the IDListSize
  if (block_data_size_remaining < sizeof(id_list_size)) {
    return 0;
  }
  memcpy(&id_list_size, link_target_id_list_ptr, sizeof(id_list_size));
  block_data_size_remaining -= sizeof(id_list_size);

  set_integer(id_list_size, module_object, "link_target_id_list.item_id_list_size");

  // Get pointer to start of IDList
  link_target_id_list_ptr += sizeof(id_list_size);

  if (!parse_id_list(link_target_id_list_ptr, module_object, block_data_size_remaining, false)) {
    return 0;
  }

  // Return the size of the whole section to compute where the next one starts
  return id_list_size + 2;
}

unsigned int parse_volume_id(const uint8_t * volume_id_ptr, YR_OBJECT* module_object, int block_data_size_remaining) {
  volume_id_t volume_id;
  unsigned int size_of_data;
  uint32_t volume_label_offset_unicode;
  char volume_id_data[256];
  unsigned int total_data_read=0;
  
  if (block_data_size_remaining < sizeof(volume_id_t)) {
    return 0;
  }

  memcpy(&volume_id, (volume_id_t*)volume_id_ptr, sizeof(volume_id_t));

  set_integer(volume_id.volume_id_size, module_object, "link_info.volume_id.size");
  set_integer(volume_id.drive_type, module_object, "link_info.volume_id.drive_type");
  set_integer(volume_id.drive_serial_number, module_object, "link_info.volume_id.drive_serial_number");
  set_integer(volume_id.volume_label_offset, module_object, "link_info.volume_id.volume_label_offset");

  // To work out the size of the data, we need to subtract the size of
  // the whole structure from the VolumeIDSize. However, this structure 
  // size is variable based on if the unicode offset is present.
  size_of_data = volume_id.volume_id_size - volume_id.volume_label_offset;

  volume_id_ptr += sizeof(volume_id_t);
  block_data_size_remaining -= sizeof(volume_id_t);
  total_data_read += sizeof(volume_id_t);

  if (volume_id.volume_label_offset == 0x14) {

    if (block_data_size_remaining < sizeof(volume_label_offset_unicode)) {
      return 0;
    }

    memcpy(&volume_label_offset_unicode, volume_id_ptr, sizeof(volume_label_offset_unicode));
    set_integer(volume_label_offset_unicode, module_object, "link_info.volume_id.volume_label_offset_unicode");
    volume_id_ptr += sizeof(volume_label_offset_unicode);
    block_data_size_remaining -= sizeof(volume_label_offset_unicode);
    total_data_read += sizeof(volume_label_offset_unicode);

    // Compensate for extra entry in the structure
    size_of_data = volume_id.volume_id_size - volume_label_offset_unicode;
  }

  if (block_data_size_remaining < size_of_data) {
    return 0;
  }

  memcpy(volume_id_data, volume_id_ptr, size_of_data);
  set_sized_string(volume_id_data, size_of_data, module_object, "link_info.volume_id.data");

  volume_id_ptr += size_of_data;
  block_data_size_remaining -= size_of_data;
  total_data_read += size_of_data;

  return total_data_read;
}

unsigned int parse_common_network_relative_link(const uint8_t * common_network_relative_link_ptr, YR_OBJECT* module_object, int block_data_size_remaining) {
  common_network_relative_link_t common_network_relative_link;
  uint32_t net_name_offset_unicode=0;
  uint32_t device_name_offset_unicode=0;
  char net_name[260];
  char device_name[260];
  wchar_t net_name_unicode[260];
  wchar_t device_name_unicode[260];
  unsigned int net_name_len;
  unsigned int device_name_len;
  unsigned int net_name_unicode_len;
  unsigned int device_name_unicode_len;
  
  if (block_data_size_remaining < sizeof(common_network_relative_link_t)) {
    return 0;
  }

  memcpy(&common_network_relative_link, (common_network_relative_link_t*)common_network_relative_link_ptr, sizeof(common_network_relative_link_t));
  
  set_integer(common_network_relative_link.common_network_relative_link_size, module_object, "link_info.common_network_relative_link.size");
  set_integer(common_network_relative_link.common_network_relative_link_flags, module_object, "link_info.common_network_relative_link.flags");
  set_integer(common_network_relative_link.net_name_offset, module_object, "link_info.common_network_relative_link.net_name_offset");
  set_integer(common_network_relative_link.device_name_offset, module_object, "link_info.common_network_relative_link.device_name_offset");
  set_integer(common_network_relative_link.network_provider_type, module_object, "link_info.common_network_relative_link.network_provider_type");

  common_network_relative_link_ptr += sizeof(common_network_relative_link_t);
  block_data_size_remaining -= sizeof(common_network_relative_link_t);

  if (common_network_relative_link.net_name_offset > 0x14) {

    if (block_data_size_remaining < sizeof(net_name_offset_unicode)) {
      return 0;
    }

    memcpy(&net_name_offset_unicode, common_network_relative_link_ptr, sizeof(net_name_offset_unicode));
    set_integer(net_name_offset_unicode, module_object, "link_info.common_network_relative_link.net_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(net_name_offset_unicode);
    block_data_size_remaining -= sizeof(net_name_offset_unicode);

    if (block_data_size_remaining < sizeof(device_name_offset_unicode)) {
      return 0;
    }

    memcpy(&device_name_offset_unicode, common_network_relative_link_ptr, sizeof(device_name_offset_unicode));
    set_integer(device_name_offset_unicode, module_object, "link_info.common_network_relative_link.device_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(device_name_offset_unicode);
    block_data_size_remaining -= sizeof(device_name_offset_unicode);

    // Parse unicode strings
    net_name_unicode_len = wcslen((const wchar_t *)common_network_relative_link_ptr);

    if (block_data_size_remaining < net_name_unicode_len*2) {
      return 0;
    }

    memcpy(&net_name_unicode, common_network_relative_link_ptr, net_name_unicode_len*2);

    set_sized_string((char*)net_name_unicode, net_name_unicode_len, module_object, "link_info.common_network_relative_link.net_name_unicode");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += (net_name_unicode_len * 2) + 1;
    block_data_size_remaining -= (net_name_unicode_len * 2) + 1;

    device_name_unicode_len = wcslen((const wchar_t *)common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_unicode_len*2) {
      return 0;
    }
    
    memcpy(&device_name_unicode, common_network_relative_link_ptr, device_name_unicode_len*2);

    set_sized_string((char*)device_name_unicode, device_name_unicode_len, module_object, "link_info.common_network_relative_link.device_name_unicode");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += (device_name_unicode_len * 2) + 1;
    block_data_size_remaining -= (device_name_unicode_len * 2) + 1;
  }

  // Otherwise parse ASCII strings
  else {
    net_name_len = strlen((const char *)common_network_relative_link_ptr);

    if (block_data_size_remaining < net_name_len) {
      return 0;
    }

    memcpy(&net_name, common_network_relative_link_ptr, net_name_len);

    set_sized_string(net_name, net_name_len, module_object, "link_info.common_network_relative_link.net_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += net_name_len + 1;
    block_data_size_remaining -= net_name_len + 1;

    device_name_len = strlen((const char *)common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_len) {
      return 0;
    }
    
    memcpy(&device_name, common_network_relative_link_ptr, device_name_len);

    set_sized_string(device_name, device_name_len, module_object, "link_info.common_network_relative_link.device_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += device_name_len + 1;
    block_data_size_remaining -= device_name_len + 1;
  }

  return common_network_relative_link.common_network_relative_link_size;
}

unsigned int parse_link_info(const uint8_t * link_info_ptr, YR_OBJECT* module_object, int block_data_size_remaining) {
  
  link_info_fixed_header_t* link_info_fixed_header;
  uint32_t local_base_path_offset_unicode=0;
  uint32_t common_path_suffix_offset_unicode=0;
  char local_base_path[256];
  char common_path_suffix[256];
  wchar_t local_base_path_unicode[256];
  wchar_t common_path_suffix_unicode[256];
  unsigned int local_base_path_len;
  unsigned int common_path_suffix_len;
  unsigned int local_base_path_unicode_len;
  unsigned int common_path_suffix_unicode_len;
  unsigned int volume_id_size;
  unsigned int common_network_relative_link_size;

  if (block_data_size_remaining < sizeof(link_info_fixed_header_t)) {
    return 0;
  }
  link_info_fixed_header = (link_info_fixed_header_t*) link_info_ptr;

  set_integer(link_info_fixed_header->link_info_size, module_object, "link_info.size");
  set_integer(link_info_fixed_header->link_info_header_size, module_object, "link_info.header_size");
  set_integer(link_info_fixed_header->link_info_flags, module_object, "link_info.flags");
  set_integer(link_info_fixed_header->volume_id_offset, module_object, "link_info.volume_id_offset");
  set_integer(link_info_fixed_header->local_base_path_offset, module_object, "link_info.local_base_path_offset");
  set_integer(link_info_fixed_header->common_network_relative_link_offset, module_object, "link_info.common_network_relative_link_offset");
  set_integer(link_info_fixed_header->common_path_suffix_offset, module_object, "link_info.common_path_suffix_offset");

  link_info_ptr += sizeof(link_info_fixed_header_t);
  block_data_size_remaining -= sizeof(link_info_fixed_header_t);

  // if VolumeIDAndLocalBasePath flag:
  //   VolumeID and LocalBasePath present
  //   VolumeIDOffset and LocalBasePathOffset specify offsets
  //   if LinkInfoHeaderSize > 0x24:
  //     LocalBasePathUnicode present (specified by offset value)
  // else
  //   VolumeID, LocalBasePath, and LocalBasePathUnicode fields are not present
  //   VolumeIDOffset and LocalBasePathOffset are 0
  //   if LinkInfoHeaderSize > 0x24:
  //     LocalBasePathOffsetUnicode is 0

  if (link_info_fixed_header->link_info_flags & VolumeIDAndLocalBasePath) {

    if (link_info_fixed_header->link_info_header_size >= 0x24) {

      if (block_data_size_remaining < sizeof(local_base_path_offset_unicode)) {
        return 0;
      }

      memcpy(&local_base_path_offset_unicode, link_info_ptr, sizeof(local_base_path_offset_unicode));
      set_integer(local_base_path_offset_unicode, module_object, "link_info.local_base_path_offset_unicode");
      link_info_ptr += sizeof(local_base_path_offset_unicode);
      block_data_size_remaining -= sizeof(local_base_path_offset_unicode);
    }

    if (link_info_fixed_header->volume_id_offset) {

      volume_id_size = parse_volume_id(link_info_ptr, module_object, block_data_size_remaining);

      if (volume_id_size == 0) {
        return 0;
      }

      link_info_ptr += volume_id_size;
      block_data_size_remaining -= volume_id_size;
    }

    // Handle LocalBasePath
    if (link_info_fixed_header->local_base_path_offset) {

      local_base_path_len = strlen((const char *)link_info_ptr);

      if (block_data_size_remaining < local_base_path_len) {
        return 0;
      }

      memcpy(&local_base_path, link_info_ptr, local_base_path_len);
      set_sized_string(local_base_path, local_base_path_len, module_object, "link_info.local_base_path");

      // Add 1 to deal with null terminator
      link_info_ptr += local_base_path_len + 1;
      block_data_size_remaining -= local_base_path_len + 1;
    }
  }

  if (link_info_fixed_header->link_info_header_size >= 0x24) {

    if (block_data_size_remaining < sizeof(common_path_suffix_offset_unicode)) {
      return 0;
    }

    memcpy(&common_path_suffix_offset_unicode, link_info_ptr, sizeof(common_path_suffix_offset_unicode));
    set_integer(common_path_suffix_offset_unicode, module_object, "link_info.common_path_suffix_offset_unicode");
    link_info_ptr += sizeof(common_path_suffix_offset_unicode);
    block_data_size_remaining -= sizeof(common_path_suffix_offset_unicode);
  }

  if (link_info_fixed_header->link_info_flags & CommonNetworkRelativeLinkAndPathSuffix) {
    if (link_info_fixed_header->common_network_relative_link_offset) {
      common_network_relative_link_size = parse_common_network_relative_link(link_info_ptr, module_object, block_data_size_remaining);

      if (common_network_relative_link_size == 0) {
        return 0;
      }

      link_info_ptr += common_network_relative_link_size;
      block_data_size_remaining -= common_network_relative_link_size;
    }
  }

  // Handle CommonPathSuffix
  if (link_info_fixed_header->common_path_suffix_offset) {

    if (block_data_size_remaining < 1) {
      return 0;
    }

    // Have to deal with this possibly being an empty string
    if (memcmp(link_info_ptr, "\x00", 1) == 0) {
      set_sized_string("\x00", 1, module_object, "link_info.common_path_suffix");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else {
      common_path_suffix_len = strlen((const char *)link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_len) {
        return 0;
      }

      memcpy(&common_path_suffix, link_info_ptr, common_path_suffix_len);

      set_sized_string(common_path_suffix, common_path_suffix_len, module_object, "link_info.common_path_suffix");

      // Add 1 to deal with null terminator
      link_info_ptr += common_path_suffix_len + 1;
      block_data_size_remaining -= common_path_suffix_len + 1;
    }
  }

  // TODO: These unicode functions will need some careful testing
  if (local_base_path_offset_unicode) {

    local_base_path_unicode_len = wcslen((const wchar_t *)link_info_ptr);

    if (block_data_size_remaining < local_base_path_unicode_len*2) {
        return 0;
      }
    
    memcpy(&local_base_path_unicode, link_info_ptr, local_base_path_unicode_len*2);

    set_sized_string((char*)local_base_path_unicode, local_base_path_unicode_len, module_object, "link_info.local_base_path_unicode");

    // Add 1 to deal with null terminator
    link_info_ptr += (local_base_path_unicode_len * 2) + 1;
    block_data_size_remaining -= (local_base_path_unicode_len * 2) + 1;
  }

  if (common_path_suffix_offset_unicode) {

    if (block_data_size_remaining < 1) {
      return 0;
    }

    // Have to deal with this possibly being an empty string
    if (memcmp(link_info_ptr, "\x00", 1) == 0) {
      set_sized_string("\x00", 1, module_object, "link_info.common_path_suffix_unicode");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else {
      common_path_suffix_unicode_len = wcslen((const wchar_t *)link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_unicode_len*2) {
        return 0;
      }

      memcpy(&common_path_suffix_unicode, link_info_ptr, common_path_suffix_unicode_len*2);
  
      set_sized_string((char*)common_path_suffix_unicode, common_path_suffix_unicode_len, module_object, "link_info.common_path_suffix_unicode");
  
      // Add 1 to deal with null terminator
      link_info_ptr += (common_path_suffix_unicode_len * 2) + 1;
      block_data_size_remaining -= (common_path_suffix_unicode_len * 2) + 1;
    }
  }

  return (int)link_info_fixed_header->link_info_size;
}

unsigned int parse_string_data(const uint8_t * string_data_ptr, YR_OBJECT* module_object, int block_data_size_remaining, const char* name, bool is_unicode) {
  uint16_t count_characters;
  unsigned int string_size;

  // CountCharacters only returns the number of characters in the string, but not information
  // on whether the string is unicode vs. another type of string. The IsUnicode flag will tell
  // us if the StringData values are unicode, and if it is not set, we'll assume it is ascii
  // (although it can be whatever is the default codepage from where the LNK is generated)

  if (block_data_size_remaining < sizeof(count_characters)) {
    return 0;
  }

  memcpy(&count_characters, string_data_ptr, sizeof(count_characters));
  string_data_ptr += sizeof(count_characters);
  block_data_size_remaining -= sizeof(count_characters);

  if (is_unicode) {
    if (block_data_size_remaining < count_characters * 2) {
      return 0;
    }

    string_size = count_characters * 2;
  }

  else {
    string_size = count_characters;
  }

  // Do these extra comparisons due to "format not a string literal and no format arguments" 
  // error on compilation
  if (strcmp(name, "name_string") == 0){
    set_sized_string((char *)string_data_ptr, string_size, module_object, "name_string");
  }

  else if (strcmp(name, "relative_path") == 0){
    set_sized_string((char *)string_data_ptr, string_size, module_object, "relative_path");
  }

  else if (strcmp(name, "working_dir") == 0){
    set_sized_string((char *)string_data_ptr, string_size, module_object, "working_dir");
  }

  else if (strcmp(name, "command_line_arguments") == 0){
    set_sized_string((char *)string_data_ptr, string_size, module_object, "command_line_arguments");
  }

  else if (strcmp(name, "icon_location") == 0){
    set_sized_string((char *)string_data_ptr, string_size, module_object, "icon_location");
  }

  else {
    return 0;
  }

  return string_size + sizeof(count_characters);
}

unsigned int parse_console_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  console_data_block_t console_data_block;
  int i;

  if (block_data_size_remaining < sizeof(console_data_block_t)) {
    return 0;
  }

  memcpy(&console_data_block, (console_data_block_t*)extra_block_ptr, sizeof(console_data_block_t));

  set_integer(extra_data_block_size, module_object, "console_data.block_size");
  set_integer(extra_data_block_signature, module_object, "console_data.block_signature");
  set_integer(console_data_block.fill_attributes, module_object, "console_data.fill_attributes");
  set_integer(console_data_block.popup_fill_attributes, module_object, "console_data.popup_fill_attributes");
  set_integer(console_data_block.screen_buffer_size_x, module_object, "console_data.screen_buffer_size_x");
  set_integer(console_data_block.screen_buffer_size_y, module_object, "console_data.screen_buffer_size_y");
  set_integer(console_data_block.window_size_x, module_object, "console_data.window_size_x");
  set_integer(console_data_block.window_size_y, module_object, "console_data.window_size_y");
  set_integer(console_data_block.window_origin_x, module_object, "console_data.window_origin_x");
  set_integer(console_data_block.window_origin_y, module_object, "console_data.window_origin_y");
  set_integer(console_data_block.font_size, module_object, "console_data.font_size");
  set_integer(console_data_block.font_family, module_object, "console_data.font_family");
  set_integer(console_data_block.font_weight, module_object, "console_data.font_weight");
  set_sized_string((char *)console_data_block.face_name, sizeof(console_data_block.face_name), module_object, "console_data.face_name");
  set_integer(console_data_block.cursor_size, module_object, "console_data.cursor_size");
  set_integer(console_data_block.full_screen, module_object, "console_data.full_screen");
  set_integer(console_data_block.quick_edit, module_object, "console_data.quick_edit");
  set_integer(console_data_block.insert_mode, module_object, "console_data.insert_mode");
  set_integer(console_data_block.auto_position, module_object, "console_data.auto_position");
  set_integer(console_data_block.history_buffer_size, module_object, "console_data.history_buffer_size");
  set_integer(console_data_block.number_of_history_buffers, module_object, "console_data.number_of_history_buffers");
  set_integer(console_data_block.history_no_dup, module_object, "console_data.history_no_dup");

  for (i=0; i<16; i++) {
    set_integer(console_data_block.color_table[i], module_object, "console_data.color_table[%i]", i);
  }

  return 1;
}

unsigned int parse_console_fed_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  console_fed_data_block_t console_fed_data;

  if (block_data_size_remaining < sizeof(console_fed_data_block_t)) {
    return 0;
  }

  memcpy(&console_fed_data, (console_fed_data_block_t*)extra_block_ptr, sizeof(console_fed_data_block_t));

  set_integer(extra_data_block_size, module_object, "console_fed_data.block_size");
  set_integer(extra_data_block_signature, module_object, "console_fed_data.block_signature");
  set_integer(console_fed_data.code_page, module_object, "console_fed_data.code_page");

  return 1;
}

unsigned int parse_darwin_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  darwin_data_block_t darwin_data;

  if (block_data_size_remaining < sizeof(darwin_data_block_t)) {
    return 0;
  }

  memcpy(&darwin_data, (darwin_data_block_t*)extra_block_ptr, sizeof(darwin_data_block_t));

  set_integer(extra_data_block_size, module_object, "darwin_data.block_size");
  set_integer(extra_data_block_signature, module_object, "darwin_data.block_signature");
  set_string(darwin_data.darwin_data_ansi, module_object, "darwin_data.darwin_data_ansi");
  set_sized_string((char *)darwin_data.darwin_data_unicode, wcslen(darwin_data.darwin_data_unicode)*2, module_object, "darwin_data.darwin_data_unicode");

  return 1;
}

unsigned int parse_environment_variable_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  environment_variable_data_block_t environment_variable_data;

  if (block_data_size_remaining < sizeof(environment_variable_data_block_t)) {
    return 0;
  }

  memcpy(&environment_variable_data, (environment_variable_data_block_t*)extra_block_ptr, sizeof(environment_variable_data_block_t));

  set_integer(extra_data_block_size, module_object, "environment_variable_data.block_size");
  set_integer(extra_data_block_signature, module_object, "environment_variable_data.block_signature");
  set_string(environment_variable_data.target_ansi, module_object, "environment_variable_data.target_ansi");
  set_sized_string((char *)environment_variable_data.target_unicode, wcslen(environment_variable_data.target_unicode)*2, module_object, "environment_variable_data.target_unicode");

  return 1;
}

unsigned int parse_icon_environment_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  icon_environment_data_block_t icon_environment_data;

  if (block_data_size_remaining < sizeof(icon_environment_data_block_t)) {
    return 0;
  }

  memcpy(&icon_environment_data, (icon_environment_data_block_t*)extra_block_ptr, sizeof(icon_environment_data_block_t));

  set_integer(extra_data_block_size, module_object, "icon_environment_data.block_size");
  set_integer(extra_data_block_signature, module_object, "icon_environment_data.block_signature");
  set_string(icon_environment_data.target_ansi, module_object, "icon_environment_data.target_ansi");
  set_sized_string((char *)icon_environment_data.target_unicode, wcslen(icon_environment_data.target_unicode)*2, module_object, "icon_environment_data.target_unicode");

  return 1;
}

unsigned int parse_known_folder_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  known_folder_data_block_t known_folder_data;
  int i;

  if (block_data_size_remaining < sizeof(known_folder_data_block_t)) {
    return 0;
  }

  memcpy(&known_folder_data, (known_folder_data_block_t*)extra_block_ptr, sizeof(known_folder_data_block_t));

  set_integer(extra_data_block_size, module_object, "known_folder_data.block_size");
  set_integer(extra_data_block_signature, module_object, "known_folder_data.block_signature");
  set_integer(known_folder_data.offset, module_object, "known_folder_data.offset");

  for (i=0; i<16; i++) {
    set_integer(known_folder_data.known_folder_id[i], module_object, "known_folder_data.known_folder_id[%i]", i);
  }

  return 1;
}

unsigned int parse_property_store_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {

  set_integer(extra_data_block_size, module_object, "property_store_data.block_size");
  set_integer(extra_data_block_signature, module_object, "property_store_data.block_signature");

  return 1;
}

unsigned int parse_shim_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  wchar_t * layer_name;
  
  if (block_data_size_remaining < extra_data_block_size - sizeof(extra_data_block_size) - sizeof(extra_data_block_signature)) {
    return 0;
  }

  layer_name = (wchar_t*) extra_block_ptr;

  set_integer(extra_data_block_size, module_object, "shim_data.block_size");
  set_integer(extra_data_block_signature, module_object, "shim_data.block_signature");
  set_sized_string((char *)layer_name, extra_data_block_size - sizeof(extra_data_block_size) - sizeof(extra_data_block_signature), module_object, "shim_data.layer_name");

  return 1;
}

unsigned int parse_special_folder_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  special_folder_data_block_t special_folder_data;

  if (block_data_size_remaining < sizeof(special_folder_data_block_t)) {
    return 0;
  }

  memcpy(&special_folder_data, (special_folder_data_block_t*)extra_block_ptr, sizeof(special_folder_data_block_t));

  set_integer(extra_data_block_size, module_object, "special_folder_data.block_size");
  set_integer(extra_data_block_signature, module_object, "special_folder_data.block_signature");
  set_integer(special_folder_data.special_folder_id, module_object, "special_folder_data.special_folder_id");
  set_integer(special_folder_data.offset, module_object, "special_folder_data.offset");

  return 1;
}

unsigned int parse_tracker_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  tracker_data_block_t tracker_data_block;

  if (block_data_size_remaining < sizeof(tracker_data_block_t)) {
    return 0;
  }

  memcpy(&tracker_data_block, (tracker_data_block_t*)extra_block_ptr, sizeof(tracker_data_block_t));

  set_integer(extra_data_block_size, module_object, "tracker_data.block_size");
  set_integer(extra_data_block_signature, module_object, "tracker_data.block_signature");
  set_string(tracker_data_block.machine_id, module_object, "tracker_data.machine_id");
  set_sized_string((char *)tracker_data_block.droid_volume_identifier, sizeof(tracker_data_block.droid_volume_identifier), module_object, "tracker_data.droid_volume_identifier");
  set_sized_string((char *)tracker_data_block.droid_file_identifier, sizeof(tracker_data_block.droid_file_identifier), module_object, "tracker_data.droid_file_identifier");
  set_sized_string((char *)tracker_data_block.droid_birth_volume_identifier, sizeof(tracker_data_block.droid_birth_volume_identifier), module_object, "tracker_data.droid_birth_volume_identifier");
  set_sized_string((char *)tracker_data_block.droid_birth_file_identifier, sizeof(tracker_data_block.droid_birth_file_identifier), module_object, "tracker_data.droid_birth_file_identifier");

  return 1;
}

unsigned int parse_vista_and_above_id_list_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  
  if (block_data_size_remaining < extra_data_block_size - sizeof(extra_data_block_size) - sizeof(extra_data_block_signature)) {
    return 0;
  }

  set_integer(extra_data_block_size, module_object, "vista_and_above_id_list_data.block_size");
  set_integer(extra_data_block_signature, module_object, "vista_and_above_id_list_data.block_signature");
  if (!parse_id_list(extra_block_ptr, module_object, block_data_size_remaining, true)) {
    return 0;
  }

  return 1;
}

unsigned int parse_extra_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, int block_data_size_remaining, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  // Ignore PropertyStore for now
  // Docs: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-PROPSTORE/%5bMS-PROPSTORE%5d.pdf

  switch(extra_data_block_signature) {
    case ConsoleDataBlockSignature:
      if (extra_data_block_size == ConsoleDataBlockSize && 
          parse_console_data_block(extra_block_ptr, 
                                   module_object, 
                                   block_data_size_remaining,
                                   extra_data_block_size,
                                   extra_data_block_signature)) {
            return 1;
          }
      break;

    case ConsoleFEDataBlockSignature:
      if (extra_data_block_size == ConsoleFEDataBlockSize && 
          parse_console_fed_data_block(extra_block_ptr, 
                                       module_object, 
                                       block_data_size_remaining,
                                       extra_data_block_size,
                                       extra_data_block_signature)) {
            return 1;
          }
      break;

    case DarwinDataBlockSignature:
      if (extra_data_block_size == DarwinDataBlockSize && 
          parse_darwin_data_block(extra_block_ptr, 
                                  module_object, 
                                  block_data_size_remaining,
                                  extra_data_block_size,
                                  extra_data_block_signature)) {
            return 1;
          }
      break;

    case EnvironmentVariableDataBlockSignature:
      if (extra_data_block_size == EnvironmentVariableDataBlockSize && 
          parse_environment_variable_data_block(extra_block_ptr, 
                                                module_object, 
                                                block_data_size_remaining,
                                                extra_data_block_size,
                                                extra_data_block_signature)) {
            return 1;
          }
      break;

    case IconEnvironmentDataBlockSignature:
      if (extra_data_block_size == IconEnvironmentDataBlockSize && 
          parse_icon_environment_data_block(extra_block_ptr, 
                                         module_object, 
                                         block_data_size_remaining,
                                         extra_data_block_size,
                                         extra_data_block_signature)) {
            return 1;
          }
      break;

    case KnownFolderDataBlockSignature:
      if (extra_data_block_size == KnownFolderDataBlockSize && 
          parse_known_folder_data_block(extra_block_ptr, 
                                        module_object, 
                                        block_data_size_remaining,
                                        extra_data_block_size,
                                        extra_data_block_signature)) {
            return 1;
          }
      break;

    case PropertyStoreDataBlockSignature:
      if (extra_data_block_size >= PropertyStoreDataBlockMinSize && 
          parse_property_store_data_block(extra_block_ptr, 
                                          module_object, 
                                          block_data_size_remaining,
                                          extra_data_block_size,
                                          extra_data_block_signature)) {
            return 1;
          }
      break;

    case ShimDataBlockSignature:
      if (extra_data_block_size >= ShimDataBlockMinSize && 
          parse_shim_data_block(extra_block_ptr, 
                                module_object, 
                                block_data_size_remaining,
                                extra_data_block_size,
                                extra_data_block_signature)) {
            return 1;
          }
      break;

    case SpecialFolderDataBlockSignature:
      if (extra_data_block_size == SpecialFolderDataBlockSize && 
          parse_special_folder_data_block(extra_block_ptr, 
                                          module_object, 
                                          block_data_size_remaining,
                                          extra_data_block_size,
                                          extra_data_block_signature)) {
            return 1;
          }
      break;

    case TrackerDataBlockSignature:
      if (extra_data_block_size == TrackerDataBlockSize && 
          parse_tracker_data_block(extra_block_ptr, 
                                   module_object, 
                                   block_data_size_remaining,
                                   extra_data_block_size,
                                   extra_data_block_signature)) {
            return 1;
          }
      break;

    case VistaAndAboveIDListDataBlockSignature:
      if (extra_data_block_size >= VistaAndAboveIDListDataBlockMinSize && 
          parse_vista_and_above_id_list_data_block(extra_block_ptr, 
                                                   module_object, 
                                                   block_data_size_remaining,
                                                   extra_data_block_size,
                                                   extra_data_block_signature)) {
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
  set_integer(0, module_object, "is_lnk");
  
  set_integer(HasLinkTargetIDList, module_object, "HasLinkTargetIDList");
  set_integer(HasLinkInfo, module_object, "HasLinkInfo");
  set_integer(HasName, module_object, "HasName");
  set_integer(HasRelativePath, module_object, "HasRelativePath");
  set_integer(HasWorkingDir, module_object, "HasWorkingDir");
  set_integer(HasArguments, module_object, "HasArguments");
  set_integer(HasIconLocation, module_object, "HasIconLocation");
  set_integer(IsUnicode, module_object, "IsUnicode");
  set_integer(ForceNoLinkInfo, module_object, "ForceNoLinkInfo");
  set_integer(HasExpString, module_object, "HasExpString");
  set_integer(RunInSeparateProcess, module_object, "RunInSeparateProcess");
  set_integer(Unused1, module_object, "Unused1");
  set_integer(HasDarwinID, module_object, "HasDarwinID");
  set_integer(RunAsUser, module_object, "RunAsUser");
  set_integer(HasExpIcon, module_object, "HasExpIcon");
  set_integer(NoPidlAlias, module_object, "NoPidlAlias");
  set_integer(Unused2, module_object, "Unused2");
  set_integer(RunWithShimLayer, module_object, "RunWithShimLayer");
  set_integer(ForceNoLinkTrack, module_object, "ForceNoLinkTrack");
  set_integer(EnableTargetMetadata, module_object, "EnableTargetMetadata");
  set_integer(DisableLinkPathTracking, module_object, "DisableLinkPathTracking");
  set_integer(DisableKnownFolderTracking, module_object, "DisableKnownFolderTracking");
  set_integer(DisableKnownFolderAlias, module_object, "DisableKnownFolderAlias");
  set_integer(AllowLinkToLink, module_object, "AllowLinkToLink");
  set_integer(UnaliasOnSave, module_object, "UnaliasOnSave");
  set_integer(PreferEnvironmentPath, module_object, "PreferEnvironmentPath");
  set_integer(KeepLocalIDListForUNCTarget, module_object, "KeepLocalIDListForUNCTarget");
  
  set_integer(FILE_ATTRIBUTE_READONLY, module_object, "FILE_ATTRIBUTE_READONLY");
  set_integer(FILE_ATTRIBUTE_HIDDEN, module_object, "FILE_ATTRIBUTE_HIDDEN");
  set_integer(FILE_ATTRIBUTE_SYSTEM, module_object, "FILE_ATTRIBUTE_SYSTEM");
  set_integer(Reserved1, module_object, "Reserved1");
  set_integer(FILE_ATTRIBUTE_DIRECTORY, module_object, "FILE_ATTRIBUTE_DIRECTORY");
  set_integer(FILE_ATTRIBUTE_ARCHIVE, module_object, "FILE_ATTRIBUTE_ARCHIVE");
  set_integer(Reserved2, module_object, "Reserved2");
  set_integer(FILE_ATTRIBUTE_NORMAL, module_object, "FILE_ATTRIBUTE_NORMAL");
  set_integer(FILE_ATTRIBUTE_TEMPORARY, module_object, "FILE_ATTRIBUTE_TEMPORARY");
  set_integer(FILE_ATTRIBUTE_SPARSE_FILE, module_object, "FILE_ATTRIBUTE_SPARSE_FILE");
  set_integer(FILE_ATTRIBUTE_REPARSE_POINT, module_object, "FILE_ATTRIBUTE_REPARSE_POINT");
  set_integer(FILE_ATTRIBUTE_COMPRESSED, module_object, "FILE_ATTRIBUTE_COMPRESSED");
  set_integer(FILE_ATTRIBUTE_OFFLINE, module_object, "FILE_ATTRIBUTE_OFFLINE");
  set_integer(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, module_object, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
  set_integer(FILE_ATTRIBUTE_ENCRYPTED, module_object, "FILE_ATTRIBUTE_ENCRYPTED");
  
  set_integer(HOTKEYF_SHIFT, module_object, "HOTKEYF_SHIFT");
  set_integer(HOTKEYF_CONTROL, module_object, "HOTKEYF_CONTROL");
  set_integer(HOTKEYF_ALT, module_object, "HOTKEYF_ALT");

  set_integer(VolumeIDAndLocalBasePath, module_object, "VolumeIDAndLocalBasePath");
  set_integer(CommonNetworkRelativeLinkAndPathSuffix, module_object, "CommonNetworkRelativeLinkAndPathSuffix");

  set_integer(DRIVE_UNKNOWN, module_object, "DRIVE_UNKNOWN");
  set_integer(DRIVE_NO_ROOT_DIR, module_object, "DRIVE_NO_ROOT_DIR");
  set_integer(DRIVE_REMOVABLE, module_object, "DRIVE_REMOVABLE");
  set_integer(DRIVE_FIXED, module_object, "DRIVE_FIXED");
  set_integer(DRIVE_REMOTE, module_object, "DRIVE_REMOTE");
  set_integer(DRIVE_CDROM, module_object, "DRIVE_CDROM");
  set_integer(DRIVE_RAMDISK, module_object, "DRIVE_RAMDISK");

  set_integer(ValidDevice, module_object, "ValidDevice");
  set_integer(ValidNetType, module_object, "ValidNetType");
  
  set_integer(WNNC_NET_AVID, module_object, "WNNC_NET_AVID");
  set_integer(WNNC_NET_DOCUSPACE, module_object, "WNNC_NET_DOCUSPACE");
  set_integer(WNNC_NET_MANGOSOFT, module_object, "WNNC_NET_MANGOSOFT");
  set_integer(WNNC_NET_SERNET, module_object, "WNNC_NET_SERNET");
  set_integer(WNNC_NET_RIVERFRONT1, module_object, "WNNC_NET_RIVERFRONT1");
  set_integer(WNNC_NET_RIVERFRONT2, module_object, "WNNC_NET_RIVERFRONT2");
  set_integer(WNNC_NET_DECORB, module_object, "WNNC_NET_DECORB");
  set_integer(WNNC_NET_PROTSTOR, module_object, "WNNC_NET_PROTSTOR");
  set_integer(WNNC_NET_FJ_REDIR, module_object, "WNNC_NET_FJ_REDIR");
  set_integer(WNNC_NET_DISTINCT, module_object, "WNNC_NET_DISTINCT");
  set_integer(WNNC_NET_TWINS, module_object, "WNNC_NET_TWINS");
  set_integer(WNNC_NET_RDR2SAMPLE, module_object, "WNNC_NET_RDR2SAMPLE");
  set_integer(WNNC_NET_CSC, module_object, "WNNC_NET_CSC");
  set_integer(WNNC_NET_3IN1, module_object, "WNNC_NET_3IN1");
  set_integer(WNNC_NET_EXTENDNET, module_object, "WNNC_NET_EXTENDNET");
  set_integer(WNNC_NET_STAC, module_object, "WNNC_NET_STAC");
  set_integer(WNNC_NET_FOXBAT, module_object, "WNNC_NET_FOXBAT");
  set_integer(WNNC_NET_YAHOO, module_object, "WNNC_NET_YAHOO");
  set_integer(WNNC_NET_EXIFS, module_object, "WNNC_NET_EXIFS");
  set_integer(WNNC_NET_DAV, module_object, "WNNC_NET_DAV");
  set_integer(WNNC_NET_KNOWARE, module_object, "WNNC_NET_KNOWARE");
  set_integer(WNNC_NET_OBJECT_DIRE, module_object, "WNNC_NET_OBJECT_DIRE");
  set_integer(WNNC_NET_MASFAX, module_object, "WNNC_NET_MASFAX");
  set_integer(WNNC_NET_HOB_NFS, module_object, "WNNC_NET_HOB_NFS");
  set_integer(WNNC_NET_SHIVA, module_object, "WNNC_NET_SHIVA");
  set_integer(WNNC_NET_IBMAL, module_object, "WNNC_NET_IBMAL");
  set_integer(WNNC_NET_LOCK, module_object, "WNNC_NET_LOCK");
  set_integer(WNNC_NET_TERMSRV, module_object, "WNNC_NET_TERMSRV");
  set_integer(WNNC_NET_SRT, module_object, "WNNC_NET_SRT");
  set_integer(WNNC_NET_QUINCY, module_object, "WNNC_NET_QUINCY");
  set_integer(WNNC_NET_OPENAFS, module_object, "WNNC_NET_OPENAFS");
  set_integer(WNNC_NET_AVID1, module_object, "WNNC_NET_AVID1");
  set_integer(WNNC_NET_DFS, module_object, "WNNC_NET_DFS");
  set_integer(WNNC_NET_KWNP, module_object, "WNNC_NET_KWNP");
  set_integer(WNNC_NET_ZENWORKS, module_object, "WNNC_NET_ZENWORKS");
  set_integer(WNNC_NET_DRIVEONWEB, module_object, "WNNC_NET_DRIVEONWEB");
  set_integer(WNNC_NET_VMWARE, module_object, "WNNC_NET_VMWARE");
  set_integer(WNNC_NET_RSFX, module_object, "WNNC_NET_RSFX");
  set_integer(WNNC_NET_MFILES, module_object, "WNNC_NET_MFILES");
  set_integer(WNNC_NET_MS_NFS, module_object, "WNNC_NET_MS_NFS");
  set_integer(WNNC_NET_GOOGLE, module_object, "WNNC_NET_GOOGLE");

  const uint8_t* block_data;
  int block_data_size_remaining;
  char* hotkey_str;
  const uint8_t* current_location;
  unsigned int id_list_size;
  unsigned int link_info_size;
  unsigned int string_data_size;
  uint32_t extra_data_block_size;
  uint32_t extra_data_block_signature;

  block = first_memory_block(context);
  block_data = block->fetch_data(block);

  // Keep track the amount of space in the current block we have left
  // to prevent any issues when dereferencing pointers
  block_data_size_remaining = (int)block->size;

  // Don't try to parse a file unless it is the minimum size an LNK can be
  // based on fixed length headers it has (described in shell_link_header_t)
  if (block_data != NULL && block_data_size_remaining >= sizeof(shell_link_header_t))
  {
    // Validate LNK header
    lnk_header = (shell_link_header_t*) block_data;
    if (lnk_header->header_size == HEADER_SIZE &&
      lnk_header->clsid[0] == LINK_CLSID_0 &&
      lnk_header->clsid[1] == LINK_CLSID_1 &&
      lnk_header->clsid[2] == LINK_CLSID_2 &&
      lnk_header->clsid[3] == LINK_CLSID_3)
    {
      set_integer(1, module_object, "is_lnk");

      // Convert timestamps from Windows TIMESTAMP to Unix timestamp
      set_integer(
        convertWindowsTimeToUnixTime(lnk_header->creation_time),
        module_object,
        "creation_time");

      set_integer(
        convertWindowsTimeToUnixTime(lnk_header->access_time),
        module_object,
        "access_time");

      set_integer(
        convertWindowsTimeToUnixTime(lnk_header->write_time),
        module_object,
        "write_time");

      set_integer(lnk_header->file_size, module_object, "file_size");
      set_integer(lnk_header->link_flags, module_object, "link_flags");
      set_integer(lnk_header->file_attributes_flags, module_object, "file_attributes_flags");
      set_integer(lnk_header->icon_index, module_object, "icon_index");
      set_integer(lnk_header->show_command, module_object, "show_command");
      set_integer(lnk_header->hotkey_flags, module_object, "hotkey_flags");
      
      // Hotkey handling code
      if (lnk_header->hotkey_flags & 0xFF) {
          
          hotkey_str = get_hotkey_char(lnk_header->hotkey_flags & 0xFF);

          if (hotkey_str) {
            set_string(hotkey_str, module_object, "hotkey");
          }

          set_integer(1, module_object, "has_hotkey");   
      }
      
      else {
        set_integer(0, module_object, "has_hotkey");
      }
      
      set_integer((lnk_header->hotkey_flags >> 8), module_object, "hotkey_modifier_flags");

      // Set pointer of current location to be after the LNK fixed header
      current_location = block_data + sizeof(shell_link_header_t);
      block_data_size_remaining -= sizeof(shell_link_header_t);

      // Optional parsing of LinkTargetIDList
      if (lnk_header->link_flags & HasLinkTargetIDList) {

        id_list_size = parse_link_target_id_list(current_location, module_object, block_data_size_remaining);

        if (id_list_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += id_list_size;
        block_data_size_remaining -= id_list_size;
      }

      if (lnk_header->link_flags & HasLinkInfo) {
        link_info_size = parse_link_info(current_location, module_object, block_data_size_remaining);

        if (link_info_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += link_info_size;
        block_data_size_remaining -= link_info_size;
      }

      // NAME_STRING
      if (lnk_header->link_flags & HasName) {
        string_data_size = parse_string_data(current_location, module_object, block_data_size_remaining, "name_string", lnk_header->link_flags & IsUnicode);

        if (string_data_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // RELATIVE_PATH
      if (lnk_header->link_flags & HasRelativePath) {
        string_data_size = parse_string_data(current_location, module_object, block_data_size_remaining, "relative_path", lnk_header->link_flags & IsUnicode);

        if (string_data_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // WORKING_DIR
      if (lnk_header->link_flags & HasWorkingDir) {
        string_data_size = parse_string_data(current_location, module_object, block_data_size_remaining, "working_dir", lnk_header->link_flags & IsUnicode);

        if (string_data_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // COMMAND_LINK_ARGUMENTS
      if (lnk_header->link_flags & HasArguments) {
        string_data_size = parse_string_data(current_location, module_object, block_data_size_remaining, "command_line_arguments", lnk_header->link_flags & IsUnicode);

        if (string_data_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // ICON_LOCATION
      if (lnk_header->link_flags & HasIconLocation) {
        string_data_size = parse_string_data(current_location, module_object, block_data_size_remaining, "icon_location", lnk_header->link_flags & IsUnicode);

        if (string_data_size == 0) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // Parse ExtraData
      if (block_data_size_remaining > 0) {
        if (block_data_size_remaining < sizeof(extra_data_block_size)) {
          set_integer(1, module_object, "is_malformed");
          return ERROR_SUCCESS;
        }

        memcpy(&extra_data_block_size, current_location, sizeof(extra_data_block_size));
        current_location += sizeof(extra_data_block_size);

        // The TerminalBlock must be less than 0x04, so iterate until we find it (or run out of space)
        while (extra_data_block_size >= 0x04) {

          // Only do this in the loop so we don't overshoot the end of the block
          block_data_size_remaining -= sizeof(extra_data_block_size);

          if (block_data_size_remaining < sizeof(extra_data_block_signature)) {
            set_integer(1, module_object, "is_malformed");
            return ERROR_SUCCESS;
          }

          memcpy(&extra_data_block_signature, current_location, sizeof(extra_data_block_signature));
          current_location += sizeof(extra_data_block_signature);
          block_data_size_remaining -= sizeof(extra_data_block_signature);

          if (!parse_extra_block(current_location, 
               module_object, 
               block_data_size_remaining,
               extra_data_block_size, 
               extra_data_block_signature)
          ) {
            break;
          }

          // Don't add/take away the block size + signature, as those have already been dealt with
          current_location += extra_data_block_size - sizeof(extra_data_block_size) - sizeof(extra_data_block_signature);
          block_data_size_remaining -= extra_data_block_size - sizeof(extra_data_block_size) - sizeof(extra_data_block_signature);

          if (block_data_size_remaining < sizeof(extra_data_block_size)) {
            set_integer(1, module_object, "is_malformed");
            return ERROR_SUCCESS;
          }

          memcpy(&extra_data_block_size, current_location, sizeof(extra_data_block_size));
          current_location += sizeof(extra_data_block_size);
        }
        
        // Finally, take away size of the TerminalBlock
        block_data_size_remaining -= 4;
      }
    }
  }

  

  if (block_data_size_remaining > 0) {
    set_integer(1, module_object, "has_overlay");
    set_integer(block->size - block_data_size_remaining, module_object, "overlay_offset");
  }

  else {
    set_integer(0, module_object, "has_overlay");
  }

  // If all parsing successful, say that the LNK isn't malformed
  set_integer(0, module_object, "is_malformed");

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
