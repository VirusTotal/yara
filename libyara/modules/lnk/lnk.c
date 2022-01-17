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
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
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
