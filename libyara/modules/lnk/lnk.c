#include <yara/modules.h>
#include <yara/endian.h>
#include <yara/mem.h>

#define TICKS_PER_SECOND 10000000
#define EPOCH_DIFFERENCE 11644473600LL

#define MODULE_NAME lnk

uint64_t convertWindowsTimeToUnixTime(uint64_t input)
{
    // https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux
  long long int temp;
  temp = input / TICKS_PER_SECOND;  // convert from 100ns intervals to seconds;
  temp = temp - EPOCH_DIFFERENCE;   // subtract number of seconds between epochs
  return temp - 3600; // no idea why, but the conver function is always an hour off
}

#pragma pack(push, 4)

typedef struct _shell_link_header_t
{
  uint32_t header_size;
  uint32_t clsid[4];
  uint32_t link_flags;
  uint32_t file_attributes_flags;
  uint64_t creation_time;
  uint64_t access_time;
  uint64_t write_time;
  uint32_t file_size;
  uint32_t icon_index;
  uint32_t show_command;
  uint16_t hotkey_flags;
  uint16_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} shell_link_header_t;

typedef struct _link_info_fixed_header_t
{
  uint32_t link_info_size;
  uint32_t link_info_header_size;
  uint32_t link_info_flags;
  uint32_t volume_id_offset;
  uint32_t local_base_path_offset;
  uint32_t common_network_relative_link_offset;
  uint32_t common_path_suffix_offset;
} link_info_fixed_header_t;

#pragma pack(pop)

#define MIN_LNK_SIZE 76

#define HEADER_SIZE 0x0000004C
#define LINK_CLSID_0 0x00021401
#define LINK_CLSID_1 0x00000000
#define LINK_CLSID_2 0x000000C0
#define LINK_CLSID_3 0x46000000

#define LINK_INFO_FIXED_HEADER_LENGTH 28

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
end_declarations

#define HasLinkTargetIDList            0x00000001
#define HasLinkInfo                    0x00000002
#define HasName                        0x00000004
#define HasRelativePath                0x00000008
#define HasWorkingDir                  0x00000010
#define HasArguments                   0x00000020
#define HasIconLocation                0x00000040
#define IsUnicode                      0x00000080
#define ForceNoLinkInfo                0x00000100
#define HasExpString                   0x00000200
#define RunInSeparateProcess           0x00000400
#define Unused1                        0x00000800
#define HasDarwinID                    0x00001000
#define RunAsUser                      0x00002000
#define HasExpIcon                     0x00004000
#define NoPidlAlias                    0x00008000
#define Unused2                        0x00010000
#define RunWithShimLayer               0x00020000
#define ForceNoLinkTrack               0x00040000
#define EnableTargetMetadata           0x00080000
#define DisableLinkPathTracking        0x00100000
#define DisableKnownFolderTracking     0x00200000
#define DisableKnownFolderAlias        0x00400000
#define AllowLinkToLink                0x00800000
#define UnaliasOnSave                  0x01000000
#define PreferEnvironmentPath          0x02000000
#define KeepLocalIDListForUNCTarget    0x04000000

#define FILE_ATTRIBUTE_READONLY               0x00000001
#define FILE_ATTRIBUTE_HIDDEN                 0x00000002
#define FILE_ATTRIBUTE_SYSTEM                 0x00000004
#define Reserved1                             0x00000008
#define FILE_ATTRIBUTE_DIRECTORY              0x00000010
#define FILE_ATTRIBUTE_ARCHIVE                0x00000020
#define Reserved2                             0x00000040
#define FILE_ATTRIBUTE_NORMAL                 0x00000080
#define FILE_ATTRIBUTE_TEMPORARY              0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE            0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT          0x00000400
#define FILE_ATTRIBUTE_COMPRESSED             0x00000800
#define FILE_ATTRIBUTE_OFFLINE                0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED    0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED              0x00004000

#define HOTKEYF_SHIFT       0x01
#define HOTKEYF_CONTROL     0x02
#define HOTKEYF_ALT         0x04

char* get_hotkey_char(uint8_t key) {

  char key_str[64];
  key_str[0] = '\0';

  switch(key) {
    case 0x30:
      sprintf(key_str, "0");
      break;
      
    case 0x31:
      sprintf(key_str, "1");
      break;
      
    case 0x32:
      sprintf(key_str, "2");
      break;
      
    case 0x33:
      sprintf(key_str, "3");
      break;
      
    case 0x34:
      sprintf(key_str, "4");
      break;
      
    case 0x35:
      sprintf(key_str, "5");
      break;
      
    case 0x36:
      sprintf(key_str, "6");
      break;
      
    case 0x37:
      sprintf(key_str, "7");
      break;
      
    case 0x38:
      sprintf(key_str, "8");
      break;
      
    case 0x39:
      sprintf(key_str, "9");
      break;
      
    case 0x41:
      sprintf(key_str, "A");
      break;
      
    case 0x42:
      sprintf(key_str, "B");
      break;
      
    case 0x43:
      sprintf(key_str, "C");
      break;
      
    case 0x44:
      sprintf(key_str, "D");
      break;
      
    case 0x45:
      sprintf(key_str, "E");
      break;
      
    case 0x46:
      sprintf(key_str, "F");
      break;
      
    case 0x47:
      sprintf(key_str, "G");
      break;
      
    case 0x48:
      sprintf(key_str, "H");
      break;
      
    case 0x49:
      sprintf(key_str, "I");
      break;
      
    case 0x4A:
      sprintf(key_str, "J");
      break;
      
    case 0x4B:
      sprintf(key_str, "K");
      break;
      
    case 0x4C:
      sprintf(key_str, "L");
      break;
      
    case 0x4D:
      sprintf(key_str, "M");
      break;
      
    case 0x4E:
      sprintf(key_str, "N");
      break;
      
    case 0x4F:
      sprintf(key_str, "O");
      break;
      
    case 0x50:
      sprintf(key_str, "P");
      break;
      
    case 0x51:
      sprintf(key_str, "Q");
      break;
      
    case 0x52:
      sprintf(key_str, "R");
      break;
      
    case 0x53:
      sprintf(key_str, "S");
      break;
      
    case 0x54:
      sprintf(key_str, "T");
      break;
      
    case 0x55:
      sprintf(key_str, "U");
      break;
      
    case 0x56:
      sprintf(key_str, "V");
      break;
      
    case 0x57:
      sprintf(key_str, "W");
      break;
      
    case 0x58:
      sprintf(key_str, "X");
      break;
      
    case 0x59:
      sprintf(key_str, "Y");
      break;
      
    case 0x5A:
      sprintf(key_str, "Z");
      break;
      
    case 0x70:
      sprintf(key_str, "F1");
      break;
      
    case 0x71:
      sprintf(key_str, "F2");
      break;
      
    case 0x72:
      sprintf(key_str, "F3");
      break;
      
    case 0x73:
      sprintf(key_str, "F4");
      break;
      
    case 0x74:
      sprintf(key_str, "F5");
      break;
      
    case 0x75:
      sprintf(key_str, "F6");
      break;
      
    case 0x76:
      sprintf(key_str, "F7");
      break;
      
    case 0x77:
      sprintf(key_str, "F8");
      break;
      
    case 0x78:
      sprintf(key_str, "F9");
      break;
      
    case 0x79:
      sprintf(key_str, "F10");
      break;
      
    case 0x7A:
      sprintf(key_str, "F11");
      break;
      
    case 0x7B:
      sprintf(key_str, "F12");
      break;
      
    case 0x7C:
      sprintf(key_str, "F13");
      break;
      
    case 0x7D:
      sprintf(key_str, "F14");
      break;
      
    case 0x7E:
      sprintf(key_str, "F15");
      break;
      
    case 0x7F:
      sprintf(key_str, "F16");
      break;
      
    case 0x80:
      sprintf(key_str, "F17");
      break;
      
    case 0x81:
      sprintf(key_str, "F18");
      break;
      
    case 0x82:
      sprintf(key_str, "F19");
      break;
      
    case 0x83:
      sprintf(key_str, "F20");
      break;
      
    case 0x84:
      sprintf(key_str, "F21");
      break;
      
    case 0x85:
      sprintf(key_str, "F22");
      break;
      
    case 0x86:
      sprintf(key_str, "F23");
      break;
      
    case 0x87:
      sprintf(key_str, "F24");
      break;
      
    case 0x90:
      sprintf(key_str, "NUM LOCK");
      break;
      
    case 0x91:
      sprintf(key_str, "SCROLL LOCK");
      break;
  }

  return yr_strdup(key_str);
}

int parse_link_target_id_list(const uint8_t * link_target_id_list_ptr, YR_OBJECT* module_object) {
  uint16_t id_list_size;
  uint8_t * id_list;
  unsigned int num_item_ids = 0;
  uint16_t item_id_size;
  char * item_id_data;

  // First, get the IDListSize
  memcpy(&id_list_size, link_target_id_list_ptr, sizeof(id_list_size));

  set_integer(id_list_size, module_object, "item_id_list_size");

  // Using this size, allocate space for the IDList
  // (probably don't need to make a whole copy of this)
  id_list = (uint8_t*)yr_malloc(id_list_size);
  memcpy(id_list, link_target_id_list_ptr + sizeof(id_list_size), id_list_size);

  // Get the first ItemIDSize
  memcpy(&item_id_size, id_list, sizeof(item_id_size));

  while (item_id_size != 0) {
    // Subtract 2 to not include it
    set_integer(item_id_size - 2, module_object, "item_id_list[%i].size", num_item_ids);

    item_id_data = (char *)yr_malloc(item_id_size);
    memcpy(item_id_data, id_list + sizeof(item_id_size), item_id_size);

    set_sized_string(item_id_data, item_id_size-sizeof(item_id_size), module_object, "item_id_list[%i].data", num_item_ids);

    yr_free(item_id_data);

    num_item_ids += 1;
    id_list += item_id_size;

    memcpy(&item_id_size, id_list, sizeof(item_id_size));
  }

  set_integer(num_item_ids, module_object, "number_of_item_ids");

  // Return the size of the whole section to compute where the next one starts
  return id_list_size + 2;
}

int parse_link_info(const uint8_t * link_info_ptr, YR_OBJECT* module_object) {
  
  link_info_fixed_header_t* link_info_fixed_header;

  link_info_fixed_header = (link_info_fixed_header_t*) link_info_ptr;

  set_integer(link_info_fixed_header->link_info_size, module_object, "link_info_size");
  set_integer(link_info_fixed_header->link_info_header_size, module_object, "link_info_header_size");
  set_integer(link_info_fixed_header->link_info_flags, module_object, "link_info_flags");
  set_integer(link_info_fixed_header->volume_id_offset, module_object, "volume_id_offset");
  set_integer(link_info_fixed_header->local_base_path_offset, module_object, "local_base_path_offset");
  set_integer(link_info_fixed_header->common_network_relative_link_offset, module_object, "common_network_relative_link_offset");
  set_integer(link_info_fixed_header->common_path_suffix_offset, module_object, "common_path_suffix_offset");

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

  const uint8_t* block_data;
  char* hotkey_str;
  const uint8_t* current_location;
  unsigned int id_list_size;

  block = first_memory_block(context);
  block_data = block->fetch_data(block);

  if (block_data != NULL && block->size >= MIN_LNK_SIZE)
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
      current_location = block_data + MIN_LNK_SIZE;

      // Optional parsing of LinkTargetIDList
      if (lnk_header->link_flags & HasLinkTargetIDList) {
        
        id_list_size = parse_link_target_id_list(current_location, module_object);

        current_location += id_list_size;
      }

      if (lnk_header->link_flags & HasLinkInfo) {
        parse_link_info(current_location, module_object);
      }
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
