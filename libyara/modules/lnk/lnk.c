/*
Copyright (c) 2023. UpSight Security Inc. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/lnk.h>

#define MODULE_NAME lnk

#define IMPORT_STANDARD 1
#define IMPORT_DELAYED  2
#define IMPORT_ANY      (~0)

// {00021401-0000-0000-c000-000000000046}
static const GUID s_LINK_GUID = 
{ 0x00021401, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

//  TODO: 
//
// - Deal with the target id list - this is the 'how' the target of a link is
// activated which is certainly of interest since the args parameter is involved there
// The related 'Vista and above IDList' in the extra data list is equally relevant.
//
// - Parse the network link targets
// 
// - The many 'EXTRA DATA' parameters that define custom environment blocks, folder locations
// property data and activation shims that all are used to change how a link is resolved
// and activated with much room for fun and games to obscure to the casual observer.
//
// Less sure it matters too much.. but header resident file attributes/time stamps are 
// also not handled.

#pragma pack(push, 1)
typedef struct _LNK_HEADER {
  uint32_t  m_HeaderSize; // must be 4c;
  uint8_t m_Signature[16];  // must be s_LINK_GUID
  uint32_t  m_LinkFlags;
  uint32_t  m_FileAttributes;
  uint64_t  m_CreationTime;
  uint64_t  m_AccessTime;
  uint64_t  m_WriteTime;
  uint32_t  m_FileSize;
  uint32_t  m_IconIndex;
  uint32_t  m_ShowCommand;
  uint16_t  m_HotKey;
  uint16_t  m_Reserved1; // must be 0
  uint32_t  m_Reserved2; // must be 0
  uint32_t  m_Reserved3; // must be 0
} LNK_HEADER, *PLNK_HEADER;

//C_ASSERT( (sizeof(struct _LNK_HEADER) == 0x4c));

#define LINK_FLAG_HAS_TARGET_ID_LIST      0x0000001
#define LINK_FLAG_HAS_LINKINFO        0x0000002
#define LINK_FLAG_HAS_NAME        0x0000004
#define LINK_FLAG_HAS_RELATIVE_PATH      0x0000008
#define LINK_FLAG_HAS_WORKING_DIR      0x0000010
#define LINK_FLAG_HAS_ARGUMENTS        0x0000020 // the fun one!
#define LINK_FLAG_HAS_ICON_LOCATION      0x0000040 // another fun one!
#define LINK_FLAG_IS_UNICODE        0x0000080
#define LINK_FLAG_FORCE_NO_LINKINFO      0x0000100
#define LINK_FLAG_HAS_EXPAND_STRING      0x0000200
#define LINK_FLAG_RUN_IN_SEPARATE_PROCESS    0x0000400
#define LINK_FLAG_HAS_DARWIN_PROPS      0x0001000
#define LINK_FLAG_RUN_AS_USER        0x0002000
#define LINK_FLAG_HAS_EXPAND_ICON      0x0004000
#define LINK_FLAG_NO_PIDL_ALIAS        0x0008000
#define LINK_FLAG_RUN_WITH_SHIM        0x0020000
#define LINK_FLAG_NO_LINK_TRACK        0x0040000
#define LINK_FLAG_ENABLE_TARGET_METADATA    0x0080000
#define LINK_FLAG_DISABLE_LINK_PATH_TRACKING    0x0100000
#define LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING    0x0200000
#define LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS    0x0400000
#define LINK_FLAG_ALLOW_LINK_TO_LINK      0x0800000
#define LINK_FLAG_UNALIAS_ON_SAVE      0x1000000
#define LINK_FLAG_PREFER_ENVIRONMENT_PATH    0x2000000
#define LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET  0x4000000

#define FILE_ATTRIBUTE_READONLY        0x0001
#define FILE_ATTRIBUTE_HIDDEN        0x0002
#define FILE_ATTRIBUTE_SYSTEM        0x0004
#define FILE_ATTRIBUTE_DIRECTORY      0x0010
#define FILE_ATTRIBUTE_ARCHIVE        0x0020
#define FILE_ATTRIBUTE_NORMAL        0x0080
#define FILE_ATTRIBUTE_TEMPORARY      0x0100
#define FILE_ATTRIBUTE_SPARSE        0x0200
#define FILE_ATTRIBUTE_REPARSE        0x0400
#define FILE_ATTRIBUTE_COMPRESSED      0x0800
#define FILE_ATTRIBUTE_OFFLINE        0x1000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED    0x2000
#define FILE_ATTRIBUTE_ENCRYPTED      0x4000

// MS docs state 3 values "all others should be treated as SW_SHOWNORMAL" other sources cite 10-11 values
#define SW_HIDE 0 
#define SW_SHOWNORMAL 1 // ms documented
#define SW_SHOWMINIMIZED 2
#define SW_SHOWMAXIMIZED 3 // ms documented
#define SW_SHOWNOACTIVATE 4
#define SW_SHOW 5
#define SW_MINIMIZE 6
#define SW_SHOWMINNOACTIVE 7 // ms documented
#define SW_SHOWNA 8
#define SW_RESTORE 9
#define SW_SHOWDEFAULT 10
#define SW_FORCEMINIMIZE 11 // https://github.com/EricZimmerman/Lnk.git 
#define SW_NORMALNA 0xCC // Wine? https://github.com/EricZimmerman/Lnk.git

typedef struct _LINKINFO
{
  uint32_t m_LinkInfoSize;
  uint32_t m_LinkInfoHeaderSize;
  uint32_t m_LinkInfoFlags;
  uint32_t m_VolumeIdOffset;
  uint32_t m_LocalBasePathOffset;
  uint32_t m_CommonNetworkRelativePathOffset;
  uint32_t m_CommonPathSuffixOffset;
  uint32_t m_LocalBasePathOffsetUnicode; // optional - check size of header!
  uint32_t m_CommonPathSuffixOffsetUnicode; // optional - check size of header!
} LINKINFO, *PLINKINFO;

#define LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH        0x1
#define LINKINFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX  0x2

#pragma pack(pop)

typedef struct _LNK
{
  const uint8_t* data;
  size_t data_size;
} LNK;

begin_declarations
  declare_integer("is_lnk")

  declare_integer("LINK_FLAG_HAS_TARGET_ID_LIST")
  declare_integer("LINK_FLAG_HAS_LINKINFO")
  declare_integer("LINK_FLAG_HAS_NAME")
  declare_integer("LINK_FLAG_HAS_RELATIVE_PATH")
  declare_integer("LINK_FLAG_HAS_WORKING_DIR")
  declare_integer("LINK_FLAG_HAS_ARGUMENTS")
  declare_integer("LINK_FLAG_HAS_ICON_LOCATION")
  declare_integer("LINK_FLAG_IS_UNICODE")
  declare_integer("LINK_FLAG_FORCE_NO_LINKINFO")
  declare_integer("LINK_FLAG_HAS_EXPAND_STRING")
  declare_integer("LINK_FLAG_RUN_IN_SEPARATE_PROCESS")
  declare_integer("LINK_FLAG_HAS_DARWIN_PROPS")
  declare_integer("LINK_FLAG_RUN_AS_USER")
  declare_integer("LINK_FLAG_HAS_EXPAND_ICON")
  declare_integer("LINK_FLAG_NO_PIDL_ALIAS")
  declare_integer("LINK_FLAG_RUN_WITH_SHIM")
  declare_integer("LINK_FLAG_NO_LINK_TRACK")
  declare_integer("LINK_FLAG_ENABLE_TARGET_METADATA")
  declare_integer("LINK_FLAG_DISABLE_LINK_PATH_TRACKING")
  declare_integer("LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING")
  declare_integer("LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS")
  declare_integer("LINK_FLAG_ALLOW_LINK_TO_LINK")
  declare_integer("LINK_FLAG_UNALIAS_ON_SAVE")
  declare_integer("LINK_FLAG_PREFER_ENVIRONMENT_PATH")
  declare_integer("LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET")

  declare_integer("LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH")
  declare_integer("LINKINFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX")

  declare_integer("header_flags") 

  begin_struct("linkinfo")
    declare_integer("linkinfo_flags") 
    declare_string("link_target_local_base")
    declare_string("link_target_network_base")
    declare_string("link_target_suffix")
  end_struct("linkinfo")

  declare_string("link_name")
  declare_string("rel_path")
  declare_string("work_dir")
  declare_string("args")
  declare_string("icon_loc")
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

PLNK_HEADER lnk_get_header(const uint8_t* data, size_t data_size)
{
   PLNK_HEADER pHeader = NULL;
   if (data_size < sizeof(LNK_HEADER))
   {
      return NULL;
   }

   pHeader = (PLNK_HEADER)data; 
   if (yr_le32toh(pHeader->m_HeaderSize) != sizeof(LNK_HEADER))
   {
       return NULL;
   }

   const uint8_t *guid_offset = pHeader->m_Signature;
   GUID foundGuid;

   foundGuid.Data1 = yr_le32toh(*(uint32_t*) guid_offset);
   foundGuid.Data2 = yr_le16toh(*(uint16_t*) (guid_offset + 4));
   foundGuid.Data3 = yr_le16toh(*(uint16_t*) (guid_offset + 6));
   for (uint32_t i = 0; i < 8; i++)
   {
     foundGuid.Data4[i] = *(guid_offset + 8 + i);
   }
   if (memcmp(&foundGuid,&s_LINK_GUID,sizeof(GUID)) != 0)
   {
       return NULL;
   }
   return pHeader;
}

bool lnk_set_bounded_null_term_string(
  bool bUnicode,
  const uint8_t* data,
  size_t dataLen,
  void* module_object,
  const char* stringName)
{
  for (uint32_t i = 0; i < dataLen; i++)
  {
    if (bUnicode)
    {
      if (i+1 < dataLen)
      {
        if (data[i] == '\0' &&
          data[i+1] == '\0')
        {
          if (i)
          {
            yr_set_sized_string((const char*) data, i - 1, module_object, stringName);
          }
          return true;
        }
      }
      i++;
    }
    else
    {
      if (data[i] == '\0')
      {
        if (i)
        {
          yr_set_sized_string((const char *) data, i-1, module_object, stringName);
        }
        return true;
      }
    }
  }
  return false;
}

bool
lnk_set_string(
  bool bUnicode,
  const uint8_t* *data,
  size_t *dataLen,
  void* module_object,
  const char *stringName)
{
  if (*dataLen < sizeof(uint16_t))
  {
    return false;
  }
  uint16_t string_len = yr_le16toh(*(uint16_t *) (*data));
  *data += 2;
  *dataLen -= 2;
  if (bUnicode) // string_len is in _chars_ not storage size.
  {
    string_len *= 2; 
  }
  if (*dataLen < string_len)
  {
    return false;
  }
        
  yr_set_sized_string((const char *) * data, string_len, module_object, stringName);
  *data += string_len;
  *dataLen -= string_len;
  return true;
}

int module_load(
  YR_SCAN_CONTEXT* context,
  YR_OBJECT* module_object,
  void* module_data,
  size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  PLNK_HEADER pLnkHeader;
  const uint8_t* block_data = NULL;
  bool bUnicode = false;

  yr_set_integer(0, module_object, "is_lnk");

  // define flag constants
  yr_set_integer(LINK_FLAG_HAS_TARGET_ID_LIST, module_object, "LINK_FLAG_HAS_TARGET_ID_LIST");
  yr_set_integer(LINK_FLAG_HAS_LINKINFO, module_object, "LINK_FLAG_HAS_LINKINFO");
  yr_set_integer(LINK_FLAG_HAS_NAME, module_object, "LINK_FLAG_HAS_NAME");
  yr_set_integer(LINK_FLAG_HAS_RELATIVE_PATH, module_object, "LINK_FLAG_HAS_RELATIVE_PATH");
  yr_set_integer(LINK_FLAG_HAS_WORKING_DIR, module_object, "LINK_FLAG_HAS_WORKING_DIR");
  yr_set_integer(LINK_FLAG_HAS_ARGUMENTS, module_object, "LINK_FLAG_HAS_ARGUMENTS");
  yr_set_integer(LINK_FLAG_HAS_ICON_LOCATION, module_object, "LINK_FLAG_HAS_ICON_LOCATION");
  yr_set_integer(LINK_FLAG_IS_UNICODE, module_object, "LINK_FLAG_IS_UNICODE");
  yr_set_integer(LINK_FLAG_FORCE_NO_LINKINFO, module_object, "LINK_FLAG_FORCE_NO_LINKINFO");
  yr_set_integer(LINK_FLAG_HAS_EXPAND_STRING, module_object, "LINK_FLAG_HAS_EXPAND_STRING");
  yr_set_integer(LINK_FLAG_RUN_IN_SEPARATE_PROCESS, module_object, "LINK_FLAG_RUN_IN_SEPARATE_PROCESS");
  yr_set_integer(LINK_FLAG_HAS_DARWIN_PROPS, module_object, "LINK_FLAG_HAS_DARWIN_PROPS");
  yr_set_integer(LINK_FLAG_RUN_AS_USER, module_object, "LINK_FLAG_RUN_AS_USER");
  yr_set_integer(LINK_FLAG_HAS_EXPAND_ICON, module_object, "LINK_FLAG_HAS_EXPAND_ICON");
  yr_set_integer(LINK_FLAG_NO_PIDL_ALIAS, module_object, "LINK_FLAG_NO_PIDL_ALIAS");
  yr_set_integer(LINK_FLAG_RUN_WITH_SHIM, module_object, "LINK_FLAG_RUN_WITH_SHIM");
  yr_set_integer(LINK_FLAG_NO_LINK_TRACK, module_object, "LINK_FLAG_NO_LINK_TRACK");
  yr_set_integer(LINK_FLAG_ENABLE_TARGET_METADATA, module_object, "LINK_FLAG_ENABLE_TARGET_METADATA");
  yr_set_integer(LINK_FLAG_DISABLE_LINK_PATH_TRACKING, module_object, "LINK_FLAG_DISABLE_LINK_PATH_TRACKING");
  yr_set_integer(LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING, module_object, "LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING");
  yr_set_integer(LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS, module_object, "LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS");
  yr_set_integer(LINK_FLAG_ALLOW_LINK_TO_LINK, module_object, "LINK_FLAG_ALLOW_LINK_TO_LINK");
  yr_set_integer(LINK_FLAG_UNALIAS_ON_SAVE, module_object, "LINK_FLAG_UNALIAS_ON_SAVE");
  yr_set_integer(LINK_FLAG_PREFER_ENVIRONMENT_PATH, module_object, "LINK_FLAG_PREFER_ENVIRONMENT_PATH");
  yr_set_integer(LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET, module_object, "LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET");

  yr_set_integer(LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH, module_object, "LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH");
  yr_set_integer(LINKINFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX, module_object, "LINKINFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX");

  foreach_memory_block(iterator, block)
  {
    block_data = block->fetch_data(block);

    if (block_data == NULL)
    {
      continue;
    }

    pLnkHeader = lnk_get_header(block_data, block->size);

    if (pLnkHeader != NULL)
    {
      const uint8_t *data = block_data;
      size_t dataLen = block->size;
      uint32_t header_flags = 0;

      yr_set_integer(1, module_object, "is_lnk");
      header_flags  = yr_le32toh(pLnkHeader->m_LinkFlags);
      yr_set_integer(header_flags, module_object, "header_flags");
      if (header_flags & LINK_FLAG_IS_UNICODE) // string fields are wide-char
      {
         bUnicode = true; 
      }
      data += sizeof(LNK_HEADER);
      dataLen -= sizeof(LNK_HEADER);

      if (header_flags & LINK_FLAG_HAS_TARGET_ID_LIST)
      {
        uint16_t idListLen = 0;
        // min size of an ITEM_ID_LIST is the size of the list
        if (dataLen < sizeof(uint16_t))
        {
          goto error_return;
        }

        idListLen = yr_le16toh(*(uint16_t*) (data));
        data += 2;
        dataLen -= 2;

        if (dataLen < idListLen)
        {
          goto error_return;
        }
        data += idListLen;
        dataLen -= idListLen;
      }

      if (header_flags & LINK_FLAG_HAS_LINKINFO)
      {
        PLINKINFO pLinkInfo = NULL;
           uint32_t linkInfoHeaderSize = 0;
        uint32_t linkInfoLen = 0;
        uint32_t linkinfo_flags = 0;
        if (dataLen < (sizeof(uint32_t)))
        {
          goto error_return;
        }
        pLinkInfo = (PLINKINFO) data;
        linkInfoLen = yr_le32toh(pLinkInfo->m_LinkInfoSize);
        if (dataLen < linkInfoLen)
        {
          goto error_return;
        }
        linkInfoHeaderSize = yr_le32toh(pLinkInfo->m_LinkInfoHeaderSize);
        if (linkInfoLen < linkInfoHeaderSize)
        {
          goto error_return;
        }
        linkinfo_flags  = yr_le32toh(pLinkInfo->m_LinkInfoFlags);
        yr_set_integer(linkinfo_flags, module_data, "linkinfo.linkinfo_flags");

        // unicode wide
        if (linkInfoHeaderSize >= 0x24)
        {
          if (linkinfo_flags & LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH)
          {
            uint32_t baseOffset = yr_le32toh(pLinkInfo->m_LocalBasePathOffsetUnicode);
            if (baseOffset >= linkInfoLen)
            {
              goto error_return;
            }
            if (!lnk_set_bounded_null_term_string(true, data + baseOffset, linkInfoLen-baseOffset, module_object, "linkinfo.link_target_local_base"))
            {
              goto error_return;    
            }
          }
          uint32_t suffixOffset = yr_le32toh(pLinkInfo->m_CommonPathSuffixOffsetUnicode);
          if (suffixOffset >= linkInfoLen)
          {
             goto error_return;
          }
          if (!lnk_set_bounded_null_term_string(true, data + suffixOffset, linkInfoLen-suffixOffset, module_object, "linkinfo.link_target_suffix"))
          {
             goto error_return;
          }
        }
        else // code-page
        {
          if (linkinfo_flags & LINKINFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH)
          {
            uint32_t baseOffset = yr_le32toh( pLinkInfo->m_LocalBasePathOffset);
            if (baseOffset >= linkInfoLen)
            {
              goto error_return;
            }
            if (!lnk_set_bounded_null_term_string(false, data + baseOffset, linkInfoLen-baseOffset, module_object, "linkinfo.link_target_local_base"))
            {
               goto error_return;
            }
          }
          uint32_t suffixOffset = yr_le32toh(pLinkInfo->m_CommonPathSuffixOffset);
          if (suffixOffset >= linkInfoLen)
          {
            goto error_return;
          }
          if (!lnk_set_bounded_null_term_string(false, data + suffixOffset, linkInfoLen-suffixOffset, module_object, "linkinfo.link_target_suffix"))
          {
             goto error_return;
          }
        }
        if (linkinfo_flags & LINKINFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX)
        {
          // this is an entirely different sub-structure yet again.
        }

        data += linkInfoLen;
        dataLen -= linkInfoLen;
      }

      if (header_flags & LINK_FLAG_HAS_NAME)
      {
        if (!lnk_set_string(bUnicode, &data, &dataLen, module_object, "link_name"))
        {
          goto error_return; 
        }
      }
      if (header_flags & LINK_FLAG_HAS_RELATIVE_PATH)
      {
        if (!lnk_set_string(bUnicode, &data, &dataLen, module_object, "rel_path"))
        {
          goto error_return; 
        }
      }
      if (header_flags & LINK_FLAG_HAS_WORKING_DIR)
      {
        if (!lnk_set_string(bUnicode, &data, &dataLen, module_object, "work_dir"))
        {
          goto error_return; 
        }
      }
      if (header_flags & LINK_FLAG_HAS_ARGUMENTS)
      {
        if (!lnk_set_string(bUnicode, &data, &dataLen, module_object, "args"))
        {
          goto error_return; 
        }
      }
      if (header_flags & LINK_FLAG_HAS_ICON_LOCATION)
      {
        if (!lnk_set_string(bUnicode, &data, &dataLen, module_object, "icon_loc"))
        {
          goto error_return; 
        }
      }
    }
  }

error_return:
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  LNK* lnk = (LNK*) module_object->data;

  if (lnk == NULL)
  {
    return ERROR_SUCCESS;
  }

  yr_free(lnk);

  return ERROR_SUCCESS;
}
