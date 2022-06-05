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

  declare_integer("DRIVE_UNKNOWN");
  declare_integer("DRIVE_NO_ROOT_DIR");
  declare_integer("DRIVE_REMOVABLE");
  declare_integer("DRIVE_FIXED");
  declare_integer("DRIVE_REMOTE");
  declare_integer("DRIVE_CDROM");
  declare_integer("DRIVE_RAMDISK");

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

  begin_struct_array("item_id_list");
    declare_integer("size");
    declare_string("data");
  end_struct_array("item_id_list");

  declare_integer("number_of_item_ids");
  declare_integer("item_id_list_size");

  declare_integer("link_info_size");
  declare_integer("link_info_header_size");
  declare_integer("link_info_flags");
  declare_integer("volume_id_offset");
  declare_integer("local_base_path_offset");
  declare_integer("common_network_relative_link_offset");
  declare_integer("common_path_suffix_offset");
  declare_integer("local_base_path_offset_unicode");
  declare_integer("common_path_suffix_offset_unicode");
  declare_integer("volume_id_size");
  declare_integer("drive_type");
  declare_integer("drive_serial_number");
  declare_integer("volume_label_offset");
  declare_integer("volume_label_offset_unicode");
  declare_string("volume_id_data");
  declare_string("local_base_path");
  declare_string("common_path_suffix");
  declare_string("local_base_path_unicode");
  declare_string("common_path_suffix_unicode");
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

  declare_string("name_string");
  declare_string("relative_path");
  declare_string("working_dir");
  declare_string("command_line_arguments");
  declare_string("icon_location");

  declare_string("machine_id");
  declare_string("droid_volume_identifier");
  declare_string("droid_file_identifier");
  declare_string("droid_birth_volume_identifier");
  declare_string("droid_birth_file_identifier");
end_declarations

unsigned int parse_link_target_id_list(const uint8_t * link_target_id_list_ptr, YR_OBJECT* module_object, size_t block_data_size_remaining) {
  uint16_t id_list_size;
  const uint8_t* id_list_ptr;
  unsigned int num_item_ids = 0;
  uint16_t item_id_size;
  const uint8_t* item_id_data_ptr;

  // First, get the IDListSize
  if (block_data_size_remaining < sizeof(id_list_size)) {
    return 0;
  }
  memcpy(&id_list_size, link_target_id_list_ptr, sizeof(id_list_size));
  block_data_size_remaining -= sizeof(id_list_size);

  set_integer(id_list_size, module_object, "item_id_list_size");

  // Get pointer to start of IDList
  id_list_ptr = link_target_id_list_ptr + sizeof(id_list_size);

  // Get the first ItemIDSize
  if (block_data_size_remaining < sizeof(item_id_size)) {
    return 0;
  }
  memcpy(&item_id_size, id_list_ptr, sizeof(item_id_size));
  block_data_size_remaining -= sizeof(item_id_size);

  while (item_id_size != 0) {
    // Subtract 2 to not include it
    set_integer(item_id_size - 2, module_object, "item_id_list[%i].size", num_item_ids);

    // Get pointer to the ItemID Data
    item_id_data_ptr = id_list_ptr + sizeof(item_id_size);

    if (block_data_size_remaining < item_id_size-sizeof(item_id_size)) {
      return 0;
    }
    set_sized_string((const char *)item_id_data_ptr, item_id_size-sizeof(item_id_size), module_object, "item_id_list[%i].data", num_item_ids);
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

  set_integer(num_item_ids, module_object, "number_of_item_ids");

  // Return the size of the whole section to compute where the next one starts
  return id_list_size + 2;
}

unsigned int parse_common_network_relative_link(const uint8_t * common_network_relative_link_ptr, YR_OBJECT* module_object, size_t block_data_size_remaining) {
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
  
  set_integer(common_network_relative_link.common_network_relative_link_size, module_object, "common_network_relative_link_size");
  set_integer(common_network_relative_link.common_network_relative_link_flags, module_object, "common_network_relative_link_flags");
  set_integer(common_network_relative_link.net_name_offset, module_object, "net_name_offset");
  set_integer(common_network_relative_link.device_name_offset, module_object, "device_name_offset");
  set_integer(common_network_relative_link.network_provider_type, module_object, "network_provider_type");

  common_network_relative_link_ptr += sizeof(common_network_relative_link_t);
  block_data_size_remaining -= sizeof(common_network_relative_link_t);

  if (common_network_relative_link.net_name_offset > 0x14) {

    if (block_data_size_remaining < sizeof(net_name_offset_unicode)) {
      return 0;
    }

    memcpy(&net_name_offset_unicode, common_network_relative_link_ptr, sizeof(net_name_offset_unicode));
    set_integer(net_name_offset_unicode, module_object, "net_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(net_name_offset_unicode);
    block_data_size_remaining -= sizeof(net_name_offset_unicode);

    if (block_data_size_remaining < sizeof(device_name_offset_unicode)) {
      return 0;
    }

    memcpy(&device_name_offset_unicode, common_network_relative_link_ptr, sizeof(device_name_offset_unicode));
    set_integer(device_name_offset_unicode, module_object, "device_name_offset_unicode");
    common_network_relative_link_ptr += sizeof(device_name_offset_unicode);
    block_data_size_remaining -= sizeof(device_name_offset_unicode);

    // Parse unicode strings
    net_name_unicode_len = wcslen((const wchar_t *)common_network_relative_link_ptr);

    if (block_data_size_remaining < net_name_unicode_len*2) {
      return 0;
    }

    memcpy(&net_name_unicode, common_network_relative_link_ptr, net_name_unicode_len*2);

    set_sized_string((char*)net_name_unicode, net_name_unicode_len, module_object, "net_name_unicode");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += (net_name_unicode_len * 2) + 1;
    block_data_size_remaining -= (net_name_unicode_len * 2) + 1;

    device_name_unicode_len = wcslen((const wchar_t *)common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_unicode_len*2) {
      return 0;
    }
    
    memcpy(&device_name_unicode, common_network_relative_link_ptr, device_name_unicode_len*2);

    set_sized_string((char*)device_name_unicode, device_name_unicode_len, module_object, "device_name_unicode");

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

    set_sized_string(net_name, net_name_len, module_object, "net_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += net_name_len + 1;
    block_data_size_remaining -= net_name_len + 1;

    device_name_len = strlen((const char *)common_network_relative_link_ptr);

    if (block_data_size_remaining < device_name_len) {
      return 0;
    }
    
    memcpy(&device_name, common_network_relative_link_ptr, device_name_len);

    set_sized_string(device_name, device_name_len, module_object, "device_name");

    // Add 1 to deal with null terminator
    common_network_relative_link_ptr += device_name_len + 1;
    block_data_size_remaining -= device_name_len + 1;
  }

  return common_network_relative_link.common_network_relative_link_size;
}

unsigned int parse_link_info(const uint8_t * link_info_ptr, YR_OBJECT* module_object, size_t block_data_size_remaining) {
  
  link_info_fixed_header_t* link_info_fixed_header;
  uint32_t local_base_path_offset_unicode=0;
  uint32_t common_path_suffix_offset_unicode=0;
  volume_id_t volume_id;
  uint32_t volume_label_offset_unicode;
  unsigned int size_of_data;
  char volume_id_data[256];
  char local_base_path[256];
  char common_path_suffix[256];
  wchar_t local_base_path_unicode[256];
  wchar_t common_path_suffix_unicode[256];
  unsigned int local_base_path_len;
  unsigned int common_path_suffix_len;
  unsigned int local_base_path_unicode_len;
  unsigned int common_path_suffix_unicode_len;
  unsigned int common_network_relative_link_size;

  if (block_data_size_remaining < sizeof(link_info_fixed_header_t)) {
    return 0;
  }
  link_info_fixed_header = (link_info_fixed_header_t*) link_info_ptr;

  set_integer(link_info_fixed_header->link_info_size, module_object, "link_info_size");
  set_integer(link_info_fixed_header->link_info_header_size, module_object, "link_info_header_size");
  set_integer(link_info_fixed_header->link_info_flags, module_object, "link_info_flags");
  set_integer(link_info_fixed_header->volume_id_offset, module_object, "volume_id_offset");
  set_integer(link_info_fixed_header->local_base_path_offset, module_object, "local_base_path_offset");
  set_integer(link_info_fixed_header->common_network_relative_link_offset, module_object, "common_network_relative_link_offset");
  set_integer(link_info_fixed_header->common_path_suffix_offset, module_object, "common_path_suffix_offset");

  link_info_ptr += sizeof(link_info_fixed_header_t);
  block_data_size_remaining -= sizeof(link_info_fixed_header_t);

  if (link_info_fixed_header->link_info_flags & VolumeIDAndLocalBasePath &&
      link_info_fixed_header->link_info_header_size >= 0x24) {

    if (block_data_size_remaining < sizeof(local_base_path_offset_unicode)) {
      return 0;
    }

    memcpy(&local_base_path_offset_unicode, link_info_ptr, sizeof(local_base_path_offset_unicode));
    set_integer(local_base_path_offset_unicode, module_object, "local_base_path_offset_unicode");
    link_info_ptr += sizeof(local_base_path_offset_unicode);
    block_data_size_remaining -= sizeof(local_base_path_offset_unicode);
  }

  if (link_info_fixed_header->link_info_header_size >= 0x24) {

    if (block_data_size_remaining < sizeof(common_path_suffix_offset_unicode)) {
      return 0;
    }

    memcpy(&common_path_suffix_offset_unicode, link_info_ptr, sizeof(common_path_suffix_offset_unicode));
    set_integer(common_path_suffix_offset_unicode, module_object, "common_path_suffix_offset_unicode");
    link_info_ptr += sizeof(common_path_suffix_offset_unicode);
    block_data_size_remaining -= sizeof(common_path_suffix_offset_unicode);
  }

  if (link_info_fixed_header->volume_id_offset) {

    if (block_data_size_remaining < sizeof(volume_id_t)) {
      return 0;
    }

    memcpy(&volume_id, (volume_id_t*)link_info_ptr, sizeof(volume_id_t));

    set_integer(volume_id.volume_id_size, module_object, "volume_id_size");
    set_integer(volume_id.drive_type, module_object, "drive_type");
    set_integer(volume_id.drive_serial_number, module_object, "drive_serial_number");
    set_integer(volume_id.volume_label_offset, module_object, "volume_label_offset");

    // To work out the size of the data, we need to subtract the size of
    // the whole structure from the VolumeIDSize. However, this structure 
    // size is variable based on if the unicode offset is present.
    size_of_data = volume_id.volume_id_size - volume_id.volume_label_offset;

    link_info_ptr += sizeof(volume_id_t);
    block_data_size_remaining -= sizeof(volume_id_t);

    if (volume_id.volume_label_offset == 0x14) {

      if (block_data_size_remaining < sizeof(volume_label_offset_unicode)) {
        return 0;
      }

      memcpy(&volume_label_offset_unicode, link_info_ptr, sizeof(volume_label_offset_unicode));
      set_integer(volume_label_offset_unicode, module_object, "volume_label_offset_unicode");
      link_info_ptr += sizeof(volume_label_offset_unicode);
      block_data_size_remaining -= sizeof(volume_label_offset_unicode);

      // Compensate for extra entry in the structure
      size_of_data = volume_id.volume_id_size - volume_label_offset_unicode;
    }

    if (block_data_size_remaining < size_of_data) {
      return 0;
    }

    memcpy(volume_id_data, link_info_ptr, size_of_data);
    set_sized_string(volume_id_data, size_of_data, module_object, "volume_id_data");

    link_info_ptr += size_of_data;
    block_data_size_remaining -= size_of_data;
  }

  // Handle LocalBasePath
  if (link_info_fixed_header->local_base_path_offset) {

    local_base_path_len = strlen((const char *)link_info_ptr);

    if (block_data_size_remaining < local_base_path_len) {
      return 0;
    }

    memcpy(&local_base_path, link_info_ptr, local_base_path_len);
    set_sized_string(local_base_path, local_base_path_len, module_object, "local_base_path");

    // Add 1 to deal with null terminator
    link_info_ptr += local_base_path_len + 1;
    block_data_size_remaining -= local_base_path_len + 1;
  }

  if (link_info_fixed_header->common_network_relative_link_offset) {
    common_network_relative_link_size = parse_common_network_relative_link(link_info_ptr, module_object, block_data_size_remaining);

    link_info_ptr += common_network_relative_link_size;
    block_data_size_remaining -= common_network_relative_link_size;
  }

  // Handle LocalBasePath
  if (link_info_fixed_header->common_path_suffix_offset) {

    if (block_data_size_remaining < 1) {
      return 0;
    }

    // Have to deal with this possibly being an empty string
    if (memcmp(link_info_ptr, "\x00", 1) == 0) {
      set_sized_string("\x00", 1, module_object, "common_path_suffix");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else {
      common_path_suffix_len = strlen((const char *)link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_len) {
        return 0;
      }

      memcpy(&common_path_suffix, link_info_ptr, common_path_suffix_len);

      set_sized_string(common_path_suffix, common_path_suffix_len, module_object, "common_path_suffix");

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

    set_sized_string((char*)local_base_path_unicode, local_base_path_unicode_len, module_object, "local_base_path_unicode");

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
      set_sized_string("\x00", 1, module_object, "common_path_suffix_unicode");
      link_info_ptr += 1;
      block_data_size_remaining -= 1;
    }

    else {
      common_path_suffix_unicode_len = wcslen((const wchar_t *)link_info_ptr);

      if (block_data_size_remaining < common_path_suffix_unicode_len*2) {
        return 0;
      }

      memcpy(&common_path_suffix_unicode, link_info_ptr, common_path_suffix_unicode_len*2);
  
      set_sized_string((char*)common_path_suffix_unicode, common_path_suffix_unicode_len, module_object, "common_path_suffix_unicode");
  
      // Add 1 to deal with null terminator
      link_info_ptr += (common_path_suffix_unicode_len * 2) + 1;
      block_data_size_remaining -= (common_path_suffix_unicode_len * 2) + 1;
    }
  }

  return (int)link_info_fixed_header->link_info_size;
}

unsigned int parse_string_data(const uint8_t * string_data_ptr, YR_OBJECT* module_object, const char* name) {
  uint16_t count_characters;

  // For the sake of this module we will assume the StringData is unicode. Technically,
  // it can be whatever the default code page is for the system the LNK was generated
  // on; but that would be much more complicated to parse at the time.
  // Frustratingly, the CountCharacters value doesn't return the absolute size of the
  // data, but rather that number of characters, so we'd have to "guess" either way.

  memcpy(&count_characters, string_data_ptr, sizeof(count_characters));
  string_data_ptr += sizeof(count_characters);

  // Do these extra comparisons due to "format not a string literal and no format arguments" 
  // error on compilation
  if (strcmp(name, "name_string") == 0){
    set_sized_string((char *)string_data_ptr, count_characters * 2, module_object, "name_string");
  }

  else if (strcmp(name, "relative_path") == 0){
    set_sized_string((char *)string_data_ptr, count_characters * 2, module_object, "relative_path");
  }

  else if (strcmp(name, "working_dir") == 0){
    set_sized_string((char *)string_data_ptr, count_characters * 2, module_object, "working_dir");
  }

  else if (strcmp(name, "command_line_arguments") == 0){
    set_sized_string((char *)string_data_ptr, count_characters * 2, module_object, "command_line_arguments");
  }

  else if (strcmp(name, "icon_location") == 0){
    set_sized_string((char *)string_data_ptr, count_characters * 2, module_object, "icon_location");
  }

  else {
    return 0;
  }

  return (count_characters * 2) + sizeof(count_characters);
}

void parse_tracker_data_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object) {
  tracker_data_block_t tracker_data_block;

  memcpy(&tracker_data_block, (tracker_data_block_t*)extra_block_ptr, sizeof(tracker_data_block_t));

  set_string(tracker_data_block.machine_id, module_object, "machine_id");
  set_sized_string((char *)tracker_data_block.droid_volume_identifier, sizeof(tracker_data_block.droid_volume_identifier), module_object, "droid_volume_identifier");
  set_sized_string((char *)tracker_data_block.droid_file_identifier, sizeof(tracker_data_block.droid_file_identifier), module_object, "droid_file_identifier");
  set_sized_string((char *)tracker_data_block.droid_birth_volume_identifier, sizeof(tracker_data_block.droid_birth_volume_identifier), module_object, "droid_birth_volume_identifier");
  set_sized_string((char *)tracker_data_block.droid_birth_file_identifier, sizeof(tracker_data_block.droid_birth_file_identifier), module_object, "droid_birth_file_identifier");
}

unsigned int parse_extra_block(const uint8_t * extra_block_ptr, YR_OBJECT* module_object, uint32_t extra_data_block_size, uint32_t extra_data_block_signature) {
  // Ignore PropertyStore for now
  // Docs: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-PROPSTORE/%5bMS-PROPSTORE%5d.pdf
  
  if (extra_data_block_size == TrackerDataBlockSize && extra_data_block_signature == TrackerDataBlockSignature) {
    parse_tracker_data_block(extra_block_ptr, module_object);
    return 1;
  }

  else {
    return 0;
  }
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

  set_integer(DRIVE_UNKNOWN, module_object, "DRIVE_UNKNOWN");
  set_integer(DRIVE_NO_ROOT_DIR, module_object, "DRIVE_NO_ROOT_DIR");
  set_integer(DRIVE_REMOVABLE, module_object, "DRIVE_REMOVABLE");
  set_integer(DRIVE_FIXED, module_object, "DRIVE_FIXED");
  set_integer(DRIVE_REMOTE, module_object, "DRIVE_REMOTE");
  set_integer(DRIVE_CDROM, module_object, "DRIVE_CDROM");
  set_integer(DRIVE_RAMDISK, module_object, "DRIVE_RAMDISK");

  const uint8_t* block_data;
  size_t block_data_size_remaining;
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
  // TODO: Make this an int value so it can have a negative value
  block_data_size_remaining = block->size;

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
          return ERROR_SUCCESS;
        }

        current_location += id_list_size;
        block_data_size_remaining -= id_list_size;
      }

      if (lnk_header->link_flags & HasLinkInfo) {
        link_info_size = parse_link_info(current_location, module_object, block_data_size_remaining);

        if (link_info_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += link_info_size;
        block_data_size_remaining -= link_info_size;
      }

      // NAME_STRING
      if (lnk_header->link_flags & HasName) {
        string_data_size = parse_string_data(current_location, module_object, "name_string");

        if (string_data_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // RELATIVE_PATH
      if (lnk_header->link_flags & HasRelativePath) {
        string_data_size = parse_string_data(current_location, module_object, "relative_path");

        if (string_data_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // WORKING_DIR
      if (lnk_header->link_flags & HasWorkingDir) {
        string_data_size = parse_string_data(current_location, module_object, "working_dir");

        if (string_data_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // COMMAND_LINK_ARGUMENTS
      if (lnk_header->link_flags & HasArguments) {
        string_data_size = parse_string_data(current_location, module_object, "command_line_arguments");

        if (string_data_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // ICON_LOCATION
      if (lnk_header->link_flags & HasIconLocation) {
        string_data_size = parse_string_data(current_location, module_object, "icon_location");

        if (string_data_size == 0) {
          return ERROR_SUCCESS;
        }

        current_location += string_data_size;
        block_data_size_remaining -= string_data_size;
      }

      // Parse ExtraData
      memcpy(&extra_data_block_size, current_location, sizeof(extra_data_block_size));
      current_location += sizeof(extra_data_block_size);

      // The TerminalBlock must be less than 0x04, so iterate until we find it (or run out of space)
      while (extra_data_block_size >= 0x04) {
        memcpy(&extra_data_block_signature, current_location, sizeof(extra_data_block_signature));
        current_location += sizeof(extra_data_block_signature);

        if (!parse_extra_block(current_location, 
             module_object, 
             extra_data_block_size, 
             extra_data_block_signature)
        ) {
          break;
        }

        current_location += extra_data_block_size;

        memcpy(&extra_data_block_size, current_location, sizeof(extra_data_block_size));
        current_location += sizeof(extra_data_block_size);
      }
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
