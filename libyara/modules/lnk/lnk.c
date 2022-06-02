#include <yara/modules.h>
#include <yara/endian.h>

#define TICKS_PER_SECOND 10000000
#define EPOCH_DIFFERENCE 11644473600LL

#define MODULE_NAME lnk

uint64_t convertWindowsTimeToUnixTime(uint64_t input)
{
    // https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux
  long long int temp;
  temp = input / TICKS_PER_SECOND;  // convert from 100ns intervals to seconds;
  temp = temp - EPOCH_DIFFERENCE;   // subtract number of seconds between epochs
  return temp;
}

typedef struct
{
  uint32_t dwLowDateTime;
  uint32_t dwHighDateTime;
} FILE_TIME; // give custom struct name to prevent any Windows clashes

#pragma pack(push, 4)

typedef struct _shell_link_header_t
{
  uint32_t header_size;
  uint32_t clsid[4];
  uint32_t link_flags;
  uint32_t file_attributes;
  FILE_TIME creation_time;
  FILE_TIME access_time;
  FILE_TIME write_time;
  uint32_t file_size;
  uint32_t icon_index;
  uint32_t show_command;
  uint16_t hotkey;
  uint16_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} shell_link_header_t;

typedef struct _link_flags_t
{
  int HasLinkTargetIDList;
} link_flags_t;

#pragma pack(pop)

#define HEADER_SIZE 0x0000004C
#define LINK_CLSID_0 0x00021401
#define LINK_CLSID_1 0x00000000
#define LINK_CLSID_2 0x000000C0
#define LINK_CLSID_3 0x46000000

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

  declare_integer("is_lnk");
  declare_integer("creation_time");
  declare_integer("access_time");
  declare_integer("write_time");
  declare_integer("file_size");
  declare_integer("link_flags");
  declare_integer("file_attributes");
  declare_integer("icon_index");
  declare_integer("show_command");
  declare_integer("hotkey");
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

uint64_t file_time_to_microseconds(FILE_TIME ft)
{
  // https://www.boost.org/doc/libs/1_41_0/boost/date_time/filetime_functions.hpp
  /* shift is difference between 1970-Jan-01 & 1601-Jan-01
   * in 100-nanosecond intervals */
  const uint64_t shift =
      116444736000000000ULL;  // (27111902 << 32) + 3577643008

  union
  {
    FILE_TIME as_file_time;
    uint64_t as_integer;  // 100-nanos since 1601-Jan-01
  } caster;
  caster.as_file_time = ft;

  caster.as_integer -= shift;  // filetime is now 100-nanos since 1970-Jan-01
  return (caster.as_integer / 10000000);  // truncate to microseconds
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

  const uint8_t* block_data;

  block = first_memory_block(context);
  block_data = block->fetch_data(block);

  if (block_data != NULL)
  {
    lnk_header = (shell_link_header_t*) block_data;
    if (lnk_header->header_size == HEADER_SIZE &&
        lnk_header->clsid[0] == LINK_CLSID_0 &&
        lnk_header->clsid[1] == LINK_CLSID_1 &&
        lnk_header->clsid[2] == LINK_CLSID_2 &&
        lnk_header->clsid[3] == LINK_CLSID_3)
    {
      set_integer(1, module_object, "is_lnk");

      set_integer(
          file_time_to_microseconds(lnk_header->creation_time),
          module_object,
          "creation_time");

      set_integer(
          file_time_to_microseconds(lnk_header->access_time),
          module_object,
          "access_time");

      set_integer(
          file_time_to_microseconds(lnk_header->write_time),
          module_object,
          "write_time");

      set_integer(lnk_header->file_size, module_object, "file_size");
      set_integer(lnk_header->link_flags, module_object, "link_flags");
      set_integer(lnk_header->file_attributes, module_object, "file_attributes");
      set_integer(lnk_header->icon_index, module_object, "icon_index");
      set_integer(lnk_header->show_command, module_object, "show_command");
      set_integer(lnk_header->hotkey, module_object, "hotkey");
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
