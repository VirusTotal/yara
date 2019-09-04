/*
Copyright (c) 2014-2015. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>

#include <string.h>

#include <yara/endian.h>
#include <yara/utils.h>
#include <yara/strutils.h>
#include <yara/mem.h>
#include <yara/integers.h>
#include <yara/pe_utils.h>
#include <yara/pe.h>

#if HAVE_LIBCRYPTO
#include <openssl/asn1.h>
#endif

PIMAGE_NT_HEADERS32 pe_get_header(
    const uint8_t* data,
    size_t data_size)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;

  size_t headers_size = 0;

  if (data_size < sizeof(IMAGE_DOS_HEADER))
    return NULL;

  mz_header = (PIMAGE_DOS_HEADER) data;

  if (yr_le16toh(mz_header->e_magic) != IMAGE_DOS_SIGNATURE)
    return NULL;

  if (yr_le32toh(mz_header->e_lfanew) < 0)
    return NULL;

  headers_size = yr_le32toh(mz_header->e_lfanew) + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (data_size < headers_size)
    return NULL;

  pe_header = (PIMAGE_NT_HEADERS32) (data + yr_le32toh(mz_header->e_lfanew));

  if (yr_le32toh(pe_header->Signature) != IMAGE_NT_SIGNATURE)
    return NULL;

  if (data_size < headers_size + sizeof(IMAGE_OPTIONAL_HEADER32))
    return NULL;

  if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    headers_size += sizeof(IMAGE_OPTIONAL_HEADER64);
  else
    headers_size += sizeof(IMAGE_OPTIONAL_HEADER32);

  if (data_size < headers_size)
    return NULL;

  if (yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_UNKNOWN &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_AM33 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_AMD64 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_ARM &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_ARMNT &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_ARM64 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_EBC &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_I386 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_IA64 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_M32R &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_MIPS16 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_MIPSFPU &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_MIPSFPU16 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_POWERPC &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_POWERPCFP &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_R4000 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_SH3 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_SH3DSP &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_SH4 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_SH5 &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_THUMB &&
      yr_le16toh(pe_header->FileHeader.Machine) != IMAGE_FILE_MACHINE_WCEMIPSV2)
  {
    return NULL;
  }

  return pe_header;
}


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry)
{
  PIMAGE_DATA_DIRECTORY directory_start;
  uint8_t* optional_header_start;
  uint16_t optional_header_size;

  // We are specifically NOT checking NumberOfRvaAndSizes here because it can
  // lie. 7ff1bf680c80fd73c0b35084904848b3705480ddeb6d0eff62180bd14cd18570 has
  // NumberOfRvaAndSizes set to 11 when in fact there is a valid
  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR entry (which is more than 11). If we
  // are overly strict here and only parse entries which are less than
  // NumberOfRvaAndSizes we run the risk of missing otherwise perfectly valid
  // files. Instead of being strict we check to make sure the entry is within
  // the OptionalHeader, since SizeOfOptionalHeader includes the DataDirectory
  // array.

  // In case someone requests an entry which is, by definition, invalid.
  if (entry >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    return NULL;

  if (IS_64BITS_PE(pe))
  {
    optional_header_start = (uint8_t*) &pe->header64->OptionalHeader;
    optional_header_size = pe->header64->FileHeader.SizeOfOptionalHeader;
    directory_start = pe->header64->OptionalHeader.DataDirectory;
  }
  else
  {
    optional_header_start = (uint8_t*) &pe->header->OptionalHeader;
    optional_header_size = pe->header->FileHeader.SizeOfOptionalHeader;
    directory_start = pe->header->OptionalHeader.DataDirectory;
  }

  // Make sure the entry doesn't point outside of the OptionalHeader.
  if ((uint8_t*) (directory_start + entry) <= optional_header_start + optional_header_size)
  {
    if (IS_64BITS_PE(pe))
      return &pe->header64->OptionalHeader.DataDirectory[entry];
    else
      return &pe->header->OptionalHeader.DataDirectory[entry];
  }

  return NULL;
}


int64_t pe_rva_to_offset(
    PE* pe,
    uint64_t rva)
{
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe->header);

  DWORD lowest_section_rva = 0xffffffff;
  DWORD section_rva = 0;
  DWORD section_offset = 0;
  DWORD section_raw_size = 0;

  int64_t result;

  int i = 0;

  int alignment = 0;
  int rest = 0;

  while(i < yr_min(yr_le16toh(pe->header->FileHeader.NumberOfSections), MAX_PE_SECTIONS))
  {
    if (struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
    {
      if (lowest_section_rva > yr_le32toh(section->VirtualAddress))
      {
        lowest_section_rva = yr_le32toh(section->VirtualAddress);
      }

      if (rva >= yr_le32toh(section->VirtualAddress) &&
          section_rva <= yr_le32toh(section->VirtualAddress))
      {
        // Round section_offset
        //
        // Rounding everything less than 0x200 to 0 as discussed in
        // https://code.google.com/archive/p/corkami/wikis/PE.wiki#PointerToRawData
        // does not work for PE32_FILE from the test suite and for
        // some tinype samples where File Alignment = 4
        // (http://www.phreedom.org/research/tinype/).
        //
        // If FileAlignment is >= 0x200, it is apparently ignored (see
        // Ero Carreras's pefile.py, PE.adjust_FileAlignment).

        alignment = yr_min(yr_le32toh(OptionalHeader(pe, FileAlignment)), 0x200);

        section_rva = yr_le32toh(section->VirtualAddress);
        section_offset = yr_le32toh(section->PointerToRawData);
        section_raw_size = yr_le32toh(section->SizeOfRawData);

        if (alignment)
        {
          rest = section_offset % alignment;

          if (rest)
            section_offset -= rest;
        }
      }

      section++;
      i++;
    }
    else
    {
      return -1;
    }
  }

  // Everything before the first section seems to get mapped straight
  // relative to ImageBase.

  if (rva < lowest_section_rva)
  {
    section_rva = 0;
    section_offset = 0;
    section_raw_size = (DWORD) pe->data_size;
  }

  // Many sections, have a raw (on disk) size smaller than their in-memory size.
  // Check for rva's that map to this sparse space, and therefore have no valid
  // associated file offset.

  if ((rva - section_rva) >= section_raw_size)
    return -1;

  result = section_offset + (rva - section_rva);

  // Check that the offset fits within the file.
  if (result >= pe->data_size)
    return -1;

  return result;
}


#if !HAVE_TIMEGM
#if HAVE__MKGMTIME
#define timegm _mkgmtime
#else

#include <time.h>

static bool is_leap(
    unsigned int year)
{
  year += 1900;
  return (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0);
}


time_t timegm(
    struct tm *tm)
{
  static const unsigned ndays[2][12] = {
      {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
      {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};

  time_t res = 0;
  int i;

  for (i = 70; i < tm->tm_year; ++i)
    res += is_leap(i) ? 366 : 365;

  for (i = 0; i < tm->tm_mon; ++i)
    res += ndays[is_leap(tm->tm_year)][i];

  res += tm->tm_mday - 1;
  res *= 24;
  res += tm->tm_hour;
  res *= 60;
  res += tm->tm_min;
  res *= 60;
  res += tm->tm_sec;

  return res;
}

#endif // HAVE__MKGMTIME
#endif // !HAVE_TIMEGM

#if HAVE_LIBCRYPTO

// Taken from http://stackoverflow.com/questions/10975542/asn1-time-conversion
// and cleaned up. Also uses timegm(3) instead of mktime(3).

time_t ASN1_get_time_t(
  	ASN1_TIME* time)
{
  struct tm t;
  const char* str = (const char*) time->data;
  size_t i = 0;

  memset(&t, 0, sizeof(t));

  if (time->type == V_ASN1_UTCTIME) /* two digit year */
  {
    t.tm_year = (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');

    if (t.tm_year < 70)
      t.tm_year += 100;
  }
  else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
  {
    t.tm_year = (str[i++] - '0') * 1000;
    t.tm_year += (str[i++] - '0') * 100;
    t.tm_year += (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    t.tm_year -= 1900;
  }

  t.tm_mon = (str[i++] - '0') * 10;
  t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
  t.tm_mday = (str[i++] - '0') * 10;
  t.tm_mday += (str[i++] - '0');
  t.tm_hour = (str[i++] - '0') * 10;
  t.tm_hour += (str[i++] - '0');
  t.tm_min = (str[i++] - '0') * 10;
  t.tm_min += (str[i++] - '0');
  t.tm_sec = (str[i++] - '0') * 10;
  t.tm_sec += (str[i++] - '0');

  /* Note: we did not adjust the time based on time zone information */
  return timegm(&t);
}

#endif


// These ordinals are taken from pefile. If a lookup fails attempt to return
// "ordN" and if that fails, return NULL. The caller is responsible for freeing
// the returned string.

char *ord_lookup(
    char *dll,
    uint16_t ord)
{
  char name[64];
  name[0] = '\0';

  if (strncasecmp(dll, "WS2_32.dll", 10) == 0 ||
      strncasecmp(dll, "wsock32.dll", 11) == 0)
  {
    switch(ord) {
      case 1:
        sprintf(name, "accept");
        break;
      case 2:
        sprintf(name, "bind");
        break;
      case 3:
        sprintf(name, "closesocket");
        break;
      case 4:
        sprintf(name, "connect");
        break;
      case 5:
        sprintf(name, "getpeername");
        break;
      case 6:
        sprintf(name, "getsockname");
        break;
      case 7:
        sprintf(name, "getsockopt");
        break;
      case 8:
        sprintf(name, "htonl");
        break;
      case 9:
        sprintf(name, "htons");
        break;
      case 10:
        sprintf(name, "ioctlsocket");
        break;
      case 11:
        sprintf(name, "inet_addr");
        break;
      case 12:
        sprintf(name, "inet_ntoa");
        break;
      case 13:
        sprintf(name, "listen");
        break;
      case 14:
        sprintf(name, "ntohl");
        break;
      case 15:
        sprintf(name, "ntohs");
        break;
      case 16:
        sprintf(name, "recv");
        break;
      case 17:
        sprintf(name, "recvfrom");
        break;
      case 18:
        sprintf(name, "select");
        break;
      case 19:
        sprintf(name, "send");
        break;
      case 20:
        sprintf(name, "sendto");
        break;
      case 21:
        sprintf(name, "setsockopt");
        break;
      case 22:
        sprintf(name, "shutdown");
        break;
      case 23:
        sprintf(name, "socket");
        break;
      case 24:
        sprintf(name, "GetAddrInfoW");
        break;
      case 25:
        sprintf(name, "GetNameInfoW");
        break;
      case 26:
        sprintf(name, "WSApSetPostRoutine");
        break;
      case 27:
        sprintf(name, "FreeAddrInfoW");
        break;
      case 28:
        sprintf(name, "WPUCompleteOverlappedRequest");
        break;
      case 29:
        sprintf(name, "WSAAccept");
        break;
      case 30:
        sprintf(name, "WSAAddressToStringA");
        break;
      case 31:
        sprintf(name, "WSAAddressToStringW");
        break;
      case 32:
        sprintf(name, "WSACloseEvent");
        break;
      case 33:
        sprintf(name, "WSAConnect");
        break;
      case 34:
        sprintf(name, "WSACreateEvent");
        break;
      case 35:
        sprintf(name, "WSADuplicateSocketA");
        break;
      case 36:
        sprintf(name, "WSADuplicateSocketW");
        break;
      case 37:
        sprintf(name, "WSAEnumNameSpaceProvidersA");
        break;
      case 38:
        sprintf(name, "WSAEnumNameSpaceProvidersW");
        break;
      case 39:
        sprintf(name, "WSAEnumNetworkEvents");
        break;
      case 40:
        sprintf(name, "WSAEnumProtocolsA");
        break;
      case 41:
        sprintf(name, "WSAEnumProtocolsW");
        break;
      case 42:
        sprintf(name, "WSAEventSelect");
        break;
      case 43:
        sprintf(name, "WSAGetOverlappedResult");
        break;
      case 44:
        sprintf(name, "WSAGetQOSByName");
        break;
      case 45:
        sprintf(name, "WSAGetServiceClassInfoA");
        break;
      case 46:
        sprintf(name, "WSAGetServiceClassInfoW");
        break;
      case 47:
        sprintf(name, "WSAGetServiceClassNameByClassIdA");
        break;
      case 48:
        sprintf(name, "WSAGetServiceClassNameByClassIdW");
        break;
      case 49:
        sprintf(name, "WSAHtonl");
        break;
      case 50:
        sprintf(name, "WSAHtons");
        break;
      case 51:
        sprintf(name, "gethostbyaddr");
        break;
      case 52:
        sprintf(name, "gethostbyname");
        break;
      case 53:
        sprintf(name, "getprotobyname");
        break;
      case 54:
        sprintf(name, "getprotobynumber");
        break;
      case 55:
        sprintf(name, "getservbyname");
        break;
      case 56:
        sprintf(name, "getservbyport");
        break;
      case 57:
        sprintf(name, "gethostname");
        break;
      case 58:
        sprintf(name, "WSAInstallServiceClassA");
        break;
      case 59:
        sprintf(name, "WSAInstallServiceClassW");
        break;
      case 60:
        sprintf(name, "WSAIoctl");
        break;
      case 61:
        sprintf(name, "WSAJoinLeaf");
        break;
      case 62:
        sprintf(name, "WSALookupServiceBeginA");
        break;
      case 63:
        sprintf(name, "WSALookupServiceBeginW");
        break;
      case 64:
        sprintf(name, "WSALookupServiceEnd");
        break;
      case 65:
        sprintf(name, "WSALookupServiceNextA");
        break;
      case 66:
        sprintf(name, "WSALookupServiceNextW");
        break;
      case 67:
        sprintf(name, "WSANSPIoctl");
        break;
      case 68:
        sprintf(name, "WSANtohl");
        break;
      case 69:
        sprintf(name, "WSANtohs");
        break;
      case 70:
        sprintf(name, "WSAProviderConfigChange");
        break;
      case 71:
        sprintf(name, "WSARecv");
        break;
      case 72:
        sprintf(name, "WSARecvDisconnect");
        break;
      case 73:
        sprintf(name, "WSARecvFrom");
        break;
      case 74:
        sprintf(name, "WSARemoveServiceClass");
        break;
      case 75:
        sprintf(name, "WSAResetEvent");
        break;
      case 76:
        sprintf(name, "WSASend");
        break;
      case 77:
        sprintf(name, "WSASendDisconnect");
        break;
      case 78:
        sprintf(name, "WSASendTo");
        break;
      case 79:
        sprintf(name, "WSASetEvent");
        break;
      case 80:
        sprintf(name, "WSASetServiceA");
        break;
      case 81:
        sprintf(name, "WSASetServiceW");
        break;
      case 82:
        sprintf(name, "WSASocketA");
        break;
      case 83:
        sprintf(name, "WSASocketW");
        break;
      case 84:
        sprintf(name, "WSAStringToAddressA");
        break;
      case 85:
        sprintf(name, "WSAStringToAddressW");
        break;
      case 86:
        sprintf(name, "WSAWaitForMultipleEvents");
        break;
      case 87:
        sprintf(name, "WSCDeinstallProvider");
        break;
      case 88:
        sprintf(name, "WSCEnableNSProvider");
        break;
      case 89:
        sprintf(name, "WSCEnumProtocols");
        break;
      case 90:
        sprintf(name, "WSCGetProviderPath");
        break;
      case 91:
        sprintf(name, "WSCInstallNameSpace");
        break;
      case 92:
        sprintf(name, "WSCInstallProvider");
        break;
      case 93:
        sprintf(name, "WSCUnInstallNameSpace");
        break;
      case 94:
        sprintf(name, "WSCUpdateProvider");
        break;
      case 95:
        sprintf(name, "WSCWriteNameSpaceOrder");
        break;
      case 96:
        sprintf(name, "WSCWriteProviderOrder");
        break;
      case 97:
        sprintf(name, "freeaddrinfo");
        break;
      case 98:
        sprintf(name, "getaddrinfo");
        break;
      case 99:
        sprintf(name, "getnameinfo");
        break;
      case 101:
        sprintf(name, "WSAAsyncSelect");
        break;
      case 102:
        sprintf(name, "WSAAsyncGetHostByAddr");
        break;
      case 103:
        sprintf(name, "WSAAsyncGetHostByName");
        break;
      case 104:
        sprintf(name, "WSAAsyncGetProtoByNumber");
        break;
      case 105:
        sprintf(name, "WSAAsyncGetProtoByName");
        break;
      case 106:
        sprintf(name, "WSAAsyncGetServByPort");
        break;
      case 107:
        sprintf(name, "WSAAsyncGetServByName");
        break;
      case 108:
        sprintf(name, "WSACancelAsyncRequest");
        break;
      case 109:
        sprintf(name, "WSASetBlockingHook");
        break;
      case 110:
        sprintf(name, "WSAUnhookBlockingHook");
        break;
      case 111:
        sprintf(name, "WSAGetLastError");
        break;
      case 112:
        sprintf(name, "WSASetLastError");
        break;
      case 113:
        sprintf(name, "WSACancelBlockingCall");
        break;
      case 114:
        sprintf(name, "WSAIsBlocking");
        break;
      case 115:
        sprintf(name, "WSAStartup");
        break;
      case 116:
        sprintf(name, "WSACleanup");
        break;
      case 151:
        sprintf(name, "__WSAFDIsSet");
        break;
      case 500:
        sprintf(name, "WEP");
        break;
      default:
        break;
    }
  }
  else if (strncasecmp(dll, "oleaut32.dll", 12) == 0)
  {
    switch (ord) {
      case 2:
        sprintf(name, "SysAllocString");
        break;
      case 3:
        sprintf(name, "SysReAllocString");
        break;
      case 4:
        sprintf(name, "SysAllocStringLen");
        break;
      case 5:
        sprintf(name, "SysReAllocStringLen");
        break;
      case 6:
        sprintf(name, "SysFreeString");
        break;
      case 7:
        sprintf(name, "SysStringLen");
        break;
      case 8:
        sprintf(name, "VariantInit");
        break;
      case 9:
        sprintf(name, "VariantClear");
        break;
      case 10:
        sprintf(name, "VariantCopy");
        break;
      case 11:
        sprintf(name, "VariantCopyInd");
        break;
      case 12:
        sprintf(name, "VariantChangeType");
        break;
      case 13:
        sprintf(name, "VariantTimeToDosDateTime");
        break;
      case 14:
        sprintf(name, "DosDateTimeToVariantTime");
        break;
      case 15:
        sprintf(name, "SafeArrayCreate");
        break;
      case 16:
        sprintf(name, "SafeArrayDestroy");
        break;
      case 17:
        sprintf(name, "SafeArrayGetDim");
        break;
      case 18:
        sprintf(name, "SafeArrayGetElemsize");
        break;
      case 19:
        sprintf(name, "SafeArrayGetUBound");
        break;
      case 20:
        sprintf(name, "SafeArrayGetLBound");
        break;
      case 21:
        sprintf(name, "SafeArrayLock");
        break;
      case 22:
        sprintf(name, "SafeArrayUnlock");
        break;
      case 23:
        sprintf(name, "SafeArrayAccessData");
        break;
      case 24:
        sprintf(name, "SafeArrayUnaccessData");
        break;
      case 25:
        sprintf(name, "SafeArrayGetElement");
        break;
      case 26:
        sprintf(name, "SafeArrayPutElement");
        break;
      case 27:
        sprintf(name, "SafeArrayCopy");
        break;
      case 28:
        sprintf(name, "DispGetParam");
        break;
      case 29:
        sprintf(name, "DispGetIDsOfNames");
        break;
      case 30:
        sprintf(name, "DispInvoke");
        break;
      case 31:
        sprintf(name, "CreateDispTypeInfo");
        break;
      case 32:
        sprintf(name, "CreateStdDispatch");
        break;
      case 33:
        sprintf(name, "RegisterActiveObject");
        break;
      case 34:
        sprintf(name, "RevokeActiveObject");
        break;
      case 35:
        sprintf(name, "GetActiveObject");
        break;
      case 36:
        sprintf(name, "SafeArrayAllocDescriptor");
        break;
      case 37:
        sprintf(name, "SafeArrayAllocData");
        break;
      case 38:
        sprintf(name, "SafeArrayDestroyDescriptor");
        break;
      case 39:
        sprintf(name, "SafeArrayDestroyData");
        break;
      case 40:
        sprintf(name, "SafeArrayRedim");
        break;
      case 41:
        sprintf(name, "SafeArrayAllocDescriptorEx");
        break;
      case 42:
        sprintf(name, "SafeArrayCreateEx");
        break;
      case 43:
        sprintf(name, "SafeArrayCreateVectorEx");
        break;
      case 44:
        sprintf(name, "SafeArraySetRecordInfo");
        break;
      case 45:
        sprintf(name, "SafeArrayGetRecordInfo");
        break;
      case 46:
        sprintf(name, "VarParseNumFromStr");
        break;
      case 47:
        sprintf(name, "VarNumFromParseNum");
        break;
      case 48:
        sprintf(name, "VarI2FromUI1");
        break;
      case 49:
        sprintf(name, "VarI2FromI4");
        break;
      case 50:
        sprintf(name, "VarI2FromR4");
        break;
      case 51:
        sprintf(name, "VarI2FromR8");
        break;
      case 52:
        sprintf(name, "VarI2FromCy");
        break;
      case 53:
        sprintf(name, "VarI2FromDate");
        break;
      case 54:
        sprintf(name, "VarI2FromStr");
        break;
      case 55:
        sprintf(name, "VarI2FromDisp");
        break;
      case 56:
        sprintf(name, "VarI2FromBool");
        break;
      case 57:
        sprintf(name, "SafeArraySetIID");
        break;
      case 58:
        sprintf(name, "VarI4FromUI1");
        break;
      case 59:
        sprintf(name, "VarI4FromI2");
        break;
      case 60:
        sprintf(name, "VarI4FromR4");
        break;
      case 61:
        sprintf(name, "VarI4FromR8");
        break;
      case 62:
        sprintf(name, "VarI4FromCy");
        break;
      case 63:
        sprintf(name, "VarI4FromDate");
        break;
      case 64:
        sprintf(name, "VarI4FromStr");
        break;
      case 65:
        sprintf(name, "VarI4FromDisp");
        break;
      case 66:
        sprintf(name, "VarI4FromBool");
        break;
      case 67:
        sprintf(name, "SafeArrayGetIID");
        break;
      case 68:
        sprintf(name, "VarR4FromUI1");
        break;
      case 69:
        sprintf(name, "VarR4FromI2");
        break;
      case 70:
        sprintf(name, "VarR4FromI4");
        break;
      case 71:
        sprintf(name, "VarR4FromR8");
        break;
      case 72:
        sprintf(name, "VarR4FromCy");
        break;
      case 73:
        sprintf(name, "VarR4FromDate");
        break;
      case 74:
        sprintf(name, "VarR4FromStr");
        break;
      case 75:
        sprintf(name, "VarR4FromDisp");
        break;
      case 76:
        sprintf(name, "VarR4FromBool");
        break;
      case 77:
        sprintf(name, "SafeArrayGetVartype");
        break;
      case 78:
        sprintf(name, "VarR8FromUI1");
        break;
      case 79:
        sprintf(name, "VarR8FromI2");
        break;
      case 80:
        sprintf(name, "VarR8FromI4");
        break;
      case 81:
        sprintf(name, "VarR8FromR4");
        break;
      case 82:
        sprintf(name, "VarR8FromCy");
        break;
      case 83:
        sprintf(name, "VarR8FromDate");
        break;
      case 84:
        sprintf(name, "VarR8FromStr");
        break;
      case 85:
        sprintf(name, "VarR8FromDisp");
        break;
      case 86:
        sprintf(name, "VarR8FromBool");
        break;
      case 87:
        sprintf(name, "VarFormat");
        break;
      case 88:
        sprintf(name, "VarDateFromUI1");
        break;
      case 89:
        sprintf(name, "VarDateFromI2");
        break;
      case 90:
        sprintf(name, "VarDateFromI4");
        break;
      case 91:
        sprintf(name, "VarDateFromR4");
        break;
      case 92:
        sprintf(name, "VarDateFromR8");
        break;
      case 93:
        sprintf(name, "VarDateFromCy");
        break;
      case 94:
        sprintf(name, "VarDateFromStr");
        break;
      case 95:
        sprintf(name, "VarDateFromDisp");
        break;
      case 96:
        sprintf(name, "VarDateFromBool");
        break;
      case 97:
        sprintf(name, "VarFormatDateTime");
        break;
      case 98:
        sprintf(name, "VarCyFromUI1");
        break;
      case 99:
        sprintf(name, "VarCyFromI2");
        break;
      case 100:
        sprintf(name, "VarCyFromI4");
        break;
      case 101:
        sprintf(name, "VarCyFromR4");
        break;
      case 102:
        sprintf(name, "VarCyFromR8");
        break;
      case 103:
        sprintf(name, "VarCyFromDate");
        break;
      case 104:
        sprintf(name, "VarCyFromStr");
        break;
      case 105:
        sprintf(name, "VarCyFromDisp");
        break;
      case 106:
        sprintf(name, "VarCyFromBool");
        break;
      case 107:
        sprintf(name, "VarFormatNumber");
        break;
      case 108:
        sprintf(name, "VarBstrFromUI1");
        break;
      case 109:
        sprintf(name, "VarBstrFromI2");
        break;
      case 110:
        sprintf(name, "VarBstrFromI4");
        break;
      case 111:
        sprintf(name, "VarBstrFromR4");
        break;
      case 112:
        sprintf(name, "VarBstrFromR8");
        break;
      case 113:
        sprintf(name, "VarBstrFromCy");
        break;
      case 114:
        sprintf(name, "VarBstrFromDate");
        break;
      case 115:
        sprintf(name, "VarBstrFromDisp");
        break;
      case 116:
        sprintf(name, "VarBstrFromBool");
        break;
      case 117:
        sprintf(name, "VarFormatPercent");
        break;
      case 118:
        sprintf(name, "VarBoolFromUI1");
        break;
      case 119:
        sprintf(name, "VarBoolFromI2");
        break;
      case 120:
        sprintf(name, "VarBoolFromI4");
        break;
      case 121:
        sprintf(name, "VarBoolFromR4");
        break;
      case 122:
        sprintf(name, "VarBoolFromR8");
        break;
      case 123:
        sprintf(name, "VarBoolFromDate");
        break;
      case 124:
        sprintf(name, "VarBoolFromCy");
        break;
      case 125:
        sprintf(name, "VarBoolFromStr");
        break;
      case 126:
        sprintf(name, "VarBoolFromDisp");
        break;
      case 127:
        sprintf(name, "VarFormatCurrency");
        break;
      case 128:
        sprintf(name, "VarWeekdayName");
        break;
      case 129:
        sprintf(name, "VarMonthName");
        break;
      case 130:
        sprintf(name, "VarUI1FromI2");
        break;
      case 131:
        sprintf(name, "VarUI1FromI4");
        break;
      case 132:
        sprintf(name, "VarUI1FromR4");
        break;
      case 133:
        sprintf(name, "VarUI1FromR8");
        break;
      case 134:
        sprintf(name, "VarUI1FromCy");
        break;
      case 135:
        sprintf(name, "VarUI1FromDate");
        break;
      case 136:
        sprintf(name, "VarUI1FromStr");
        break;
      case 137:
        sprintf(name, "VarUI1FromDisp");
        break;
      case 138:
        sprintf(name, "VarUI1FromBool");
        break;
      case 139:
        sprintf(name, "VarFormatFromTokens");
        break;
      case 140:
        sprintf(name, "VarTokenizeFormatString");
        break;
      case 141:
        sprintf(name, "VarAdd");
        break;
      case 142:
        sprintf(name, "VarAnd");
        break;
      case 143:
        sprintf(name, "VarDiv");
        break;
      case 144:
        sprintf(name, "DllCanUnloadNow");
        break;
      case 145:
        sprintf(name, "DllGetClassObject");
        break;
      case 146:
        sprintf(name, "DispCallFunc");
        break;
      case 147:
        sprintf(name, "VariantChangeTypeEx");
        break;
      case 148:
        sprintf(name, "SafeArrayPtrOfIndex");
        break;
      case 149:
        sprintf(name, "SysStringByteLen");
        break;
      case 150:
        sprintf(name, "SysAllocStringByteLen");
        break;
      case 151:
        sprintf(name, "DllRegisterServer");
        break;
      case 152:
        sprintf(name, "VarEqv");
        break;
      case 153:
        sprintf(name, "VarIdiv");
        break;
      case 154:
        sprintf(name, "VarImp");
        break;
      case 155:
        sprintf(name, "VarMod");
        break;
      case 156:
        sprintf(name, "VarMul");
        break;
      case 157:
        sprintf(name, "VarOr");
        break;
      case 158:
        sprintf(name, "VarPow");
        break;
      case 159:
        sprintf(name, "VarSub");
        break;
      case 160:
        sprintf(name, "CreateTypeLib");
        break;
      case 161:
        sprintf(name, "LoadTypeLib");
        break;
      case 162:
        sprintf(name, "LoadRegTypeLib");
        break;
      case 163:
        sprintf(name, "RegisterTypeLib");
        break;
      case 164:
        sprintf(name, "QueryPathOfRegTypeLib");
        break;
      case 165:
        sprintf(name, "LHashValOfNameSys");
        break;
      case 166:
        sprintf(name, "LHashValOfNameSysA");
        break;
      case 167:
        sprintf(name, "VarXor");
        break;
      case 168:
        sprintf(name, "VarAbs");
        break;
      case 169:
        sprintf(name, "VarFix");
        break;
      case 170:
        sprintf(name, "OaBuildVersion");
        break;
      case 171:
        sprintf(name, "ClearCustData");
        break;
      case 172:
        sprintf(name, "VarInt");
        break;
      case 173:
        sprintf(name, "VarNeg");
        break;
      case 174:
        sprintf(name, "VarNot");
        break;
      case 175:
        sprintf(name, "VarRound");
        break;
      case 176:
        sprintf(name, "VarCmp");
        break;
      case 177:
        sprintf(name, "VarDecAdd");
        break;
      case 178:
        sprintf(name, "VarDecDiv");
        break;
      case 179:
        sprintf(name, "VarDecMul");
        break;
      case 180:
        sprintf(name, "CreateTypeLib2");
        break;
      case 181:
        sprintf(name, "VarDecSub");
        break;
      case 182:
        sprintf(name, "VarDecAbs");
        break;
      case 183:
        sprintf(name, "LoadTypeLibEx");
        break;
      case 184:
        sprintf(name, "SystemTimeToVariantTime");
        break;
      case 185:
        sprintf(name, "VariantTimeToSystemTime");
        break;
      case 186:
        sprintf(name, "UnRegisterTypeLib");
        break;
      case 187:
        sprintf(name, "VarDecFix");
        break;
      case 188:
        sprintf(name, "VarDecInt");
        break;
      case 189:
        sprintf(name, "VarDecNeg");
        break;
      case 190:
        sprintf(name, "VarDecFromUI1");
        break;
      case 191:
        sprintf(name, "VarDecFromI2");
        break;
      case 192:
        sprintf(name, "VarDecFromI4");
        break;
      case 193:
        sprintf(name, "VarDecFromR4");
        break;
      case 194:
        sprintf(name, "VarDecFromR8");
        break;
      case 195:
        sprintf(name, "VarDecFromDate");
        break;
      case 196:
        sprintf(name, "VarDecFromCy");
        break;
      case 197:
        sprintf(name, "VarDecFromStr");
        break;
      case 198:
        sprintf(name, "VarDecFromDisp");
        break;
      case 199:
        sprintf(name, "VarDecFromBool");
        break;
      case 200:
        sprintf(name, "GetErrorInfo");
        break;
      case 201:
        sprintf(name, "SetErrorInfo");
        break;
      case 202:
        sprintf(name, "CreateErrorInfo");
        break;
      case 203:
        sprintf(name, "VarDecRound");
        break;
      case 204:
        sprintf(name, "VarDecCmp");
        break;
      case 205:
        sprintf(name, "VarI2FromI1");
        break;
      case 206:
        sprintf(name, "VarI2FromUI2");
        break;
      case 207:
        sprintf(name, "VarI2FromUI4");
        break;
      case 208:
        sprintf(name, "VarI2FromDec");
        break;
      case 209:
        sprintf(name, "VarI4FromI1");
        break;
      case 210:
        sprintf(name, "VarI4FromUI2");
        break;
      case 211:
        sprintf(name, "VarI4FromUI4");
        break;
      case 212:
        sprintf(name, "VarI4FromDec");
        break;
      case 213:
        sprintf(name, "VarR4FromI1");
        break;
      case 214:
        sprintf(name, "VarR4FromUI2");
        break;
      case 215:
        sprintf(name, "VarR4FromUI4");
        break;
      case 216:
        sprintf(name, "VarR4FromDec");
        break;
      case 217:
        sprintf(name, "VarR8FromI1");
        break;
      case 218:
        sprintf(name, "VarR8FromUI2");
        break;
      case 219:
        sprintf(name, "VarR8FromUI4");
        break;
      case 220:
        sprintf(name, "VarR8FromDec");
        break;
      case 221:
        sprintf(name, "VarDateFromI1");
        break;
      case 222:
        sprintf(name, "VarDateFromUI2");
        break;
      case 223:
        sprintf(name, "VarDateFromUI4");
        break;
      case 224:
        sprintf(name, "VarDateFromDec");
        break;
      case 225:
        sprintf(name, "VarCyFromI1");
        break;
      case 226:
        sprintf(name, "VarCyFromUI2");
        break;
      case 227:
        sprintf(name, "VarCyFromUI4");
        break;
      case 228:
        sprintf(name, "VarCyFromDec");
        break;
      case 229:
        sprintf(name, "VarBstrFromI1");
        break;
      case 230:
        sprintf(name, "VarBstrFromUI2");
        break;
      case 231:
        sprintf(name, "VarBstrFromUI4");
        break;
      case 232:
        sprintf(name, "VarBstrFromDec");
        break;
      case 233:
        sprintf(name, "VarBoolFromI1");
        break;
      case 234:
        sprintf(name, "VarBoolFromUI2");
        break;
      case 235:
        sprintf(name, "VarBoolFromUI4");
        break;
      case 236:
        sprintf(name, "VarBoolFromDec");
        break;
      case 237:
        sprintf(name, "VarUI1FromI1");
        break;
      case 238:
        sprintf(name, "VarUI1FromUI2");
        break;
      case 239:
        sprintf(name, "VarUI1FromUI4");
        break;
      case 240:
        sprintf(name, "VarUI1FromDec");
        break;
      case 241:
        sprintf(name, "VarDecFromI1");
        break;
      case 242:
        sprintf(name, "VarDecFromUI2");
        break;
      case 243:
        sprintf(name, "VarDecFromUI4");
        break;
      case 244:
        sprintf(name, "VarI1FromUI1");
        break;
      case 245:
        sprintf(name, "VarI1FromI2");
        break;
      case 246:
        sprintf(name, "VarI1FromI4");
        break;
      case 247:
        sprintf(name, "VarI1FromR4");
        break;
      case 248:
        sprintf(name, "VarI1FromR8");
        break;
      case 249:
        sprintf(name, "VarI1FromDate");
        break;
      case 250:
        sprintf(name, "VarI1FromCy");
        break;
      case 251:
        sprintf(name, "VarI1FromStr");
        break;
      case 252:
        sprintf(name, "VarI1FromDisp");
        break;
      case 253:
        sprintf(name, "VarI1FromBool");
        break;
      case 254:
        sprintf(name, "VarI1FromUI2");
        break;
      case 255:
        sprintf(name, "VarI1FromUI4");
        break;
      case 256:
        sprintf(name, "VarI1FromDec");
        break;
      case 257:
        sprintf(name, "VarUI2FromUI1");
        break;
      case 258:
        sprintf(name, "VarUI2FromI2");
        break;
      case 259:
        sprintf(name, "VarUI2FromI4");
        break;
      case 260:
        sprintf(name, "VarUI2FromR4");
        break;
      case 261:
        sprintf(name, "VarUI2FromR8");
        break;
      case 262:
        sprintf(name, "VarUI2FromDate");
        break;
      case 263:
        sprintf(name, "VarUI2FromCy");
        break;
      case 264:
        sprintf(name, "VarUI2FromStr");
        break;
      case 265:
        sprintf(name, "VarUI2FromDisp");
        break;
      case 266:
        sprintf(name, "VarUI2FromBool");
        break;
      case 267:
        sprintf(name, "VarUI2FromI1");
        break;
      case 268:
        sprintf(name, "VarUI2FromUI4");
        break;
      case 269:
        sprintf(name, "VarUI2FromDec");
        break;
      case 270:
        sprintf(name, "VarUI4FromUI1");
        break;
      case 271:
        sprintf(name, "VarUI4FromI2");
        break;
      case 272:
        sprintf(name, "VarUI4FromI4");
        break;
      case 273:
        sprintf(name, "VarUI4FromR4");
        break;
      case 274:
        sprintf(name, "VarUI4FromR8");
        break;
      case 275:
        sprintf(name, "VarUI4FromDate");
        break;
      case 276:
        sprintf(name, "VarUI4FromCy");
        break;
      case 277:
        sprintf(name, "VarUI4FromStr");
        break;
      case 278:
        sprintf(name, "VarUI4FromDisp");
        break;
      case 279:
        sprintf(name, "VarUI4FromBool");
        break;
      case 280:
        sprintf(name, "VarUI4FromI1");
        break;
      case 281:
        sprintf(name, "VarUI4FromUI2");
        break;
      case 282:
        sprintf(name, "VarUI4FromDec");
        break;
      case 283:
        sprintf(name, "BSTR_UserSize");
        break;
      case 284:
        sprintf(name, "BSTR_UserMarshal");
        break;
      case 285:
        sprintf(name, "BSTR_UserUnmarshal");
        break;
      case 286:
        sprintf(name, "BSTR_UserFree");
        break;
      case 287:
        sprintf(name, "VARIANT_UserSize");
        break;
      case 288:
        sprintf(name, "VARIANT_UserMarshal");
        break;
      case 289:
        sprintf(name, "VARIANT_UserUnmarshal");
        break;
      case 290:
        sprintf(name, "VARIANT_UserFree");
        break;
      case 291:
        sprintf(name, "LPSAFEARRAY_UserSize");
        break;
      case 292:
        sprintf(name, "LPSAFEARRAY_UserMarshal");
        break;
      case 293:
        sprintf(name, "LPSAFEARRAY_UserUnmarshal");
        break;
      case 294:
        sprintf(name, "LPSAFEARRAY_UserFree");
        break;
      case 295:
        sprintf(name, "LPSAFEARRAY_Size");
        break;
      case 296:
        sprintf(name, "LPSAFEARRAY_Marshal");
        break;
      case 297:
        sprintf(name, "LPSAFEARRAY_Unmarshal");
        break;
      case 298:
        sprintf(name, "VarDecCmpR8");
        break;
      case 299:
        sprintf(name, "VarCyAdd");
        break;
      case 300:
        sprintf(name, "DllUnregisterServer");
        break;
      case 301:
        sprintf(name, "OACreateTypeLib2");
        break;
      case 303:
        sprintf(name, "VarCyMul");
        break;
      case 304:
        sprintf(name, "VarCyMulI4");
        break;
      case 305:
        sprintf(name, "VarCySub");
        break;
      case 306:
        sprintf(name, "VarCyAbs");
        break;
      case 307:
        sprintf(name, "VarCyFix");
        break;
      case 308:
        sprintf(name, "VarCyInt");
        break;
      case 309:
        sprintf(name, "VarCyNeg");
        break;
      case 310:
        sprintf(name, "VarCyRound");
        break;
      case 311:
        sprintf(name, "VarCyCmp");
        break;
      case 312:
        sprintf(name, "VarCyCmpR8");
        break;
      case 313:
        sprintf(name, "VarBstrCat");
        break;
      case 314:
        sprintf(name, "VarBstrCmp");
        break;
      case 315:
        sprintf(name, "VarR8Pow");
        break;
      case 316:
        sprintf(name, "VarR4CmpR8");
        break;
      case 317:
        sprintf(name, "VarR8Round");
        break;
      case 318:
        sprintf(name, "VarCat");
        break;
      case 319:
        sprintf(name, "VarDateFromUdateEx");
        break;
      case 322:
        sprintf(name, "GetRecordInfoFromGuids");
        break;
      case 323:
        sprintf(name, "GetRecordInfoFromTypeInfo");
        break;
      case 325:
        sprintf(name, "SetVarConversionLocaleSetting");
        break;
      case 326:
        sprintf(name, "GetVarConversionLocaleSetting");
        break;
      case 327:
        sprintf(name, "SetOaNoCache");
        break;
      case 329:
        sprintf(name, "VarCyMulI8");
        break;
      case 330:
        sprintf(name, "VarDateFromUdate");
        break;
      case 331:
        sprintf(name, "VarUdateFromDate");
        break;
      case 332:
        sprintf(name, "GetAltMonthNames");
        break;
      case 333:
        sprintf(name, "VarI8FromUI1");
        break;
      case 334:
        sprintf(name, "VarI8FromI2");
        break;
      case 335:
        sprintf(name, "VarI8FromR4");
        break;
      case 336:
        sprintf(name, "VarI8FromR8");
        break;
      case 337:
        sprintf(name, "VarI8FromCy");
        break;
      case 338:
        sprintf(name, "VarI8FromDate");
        break;
      case 339:
        sprintf(name, "VarI8FromStr");
        break;
      case 340:
        sprintf(name, "VarI8FromDisp");
        break;
      case 341:
        sprintf(name, "VarI8FromBool");
        break;
      case 342:
        sprintf(name, "VarI8FromI1");
        break;
      case 343:
        sprintf(name, "VarI8FromUI2");
        break;
      case 344:
        sprintf(name, "VarI8FromUI4");
        break;
      case 345:
        sprintf(name, "VarI8FromDec");
        break;
      case 346:
        sprintf(name, "VarI2FromI8");
        break;
      case 347:
        sprintf(name, "VarI2FromUI8");
        break;
      case 348:
        sprintf(name, "VarI4FromI8");
        break;
      case 349:
        sprintf(name, "VarI4FromUI8");
        break;
      case 360:
        sprintf(name, "VarR4FromI8");
        break;
      case 361:
        sprintf(name, "VarR4FromUI8");
        break;
      case 362:
        sprintf(name, "VarR8FromI8");
        break;
      case 363:
        sprintf(name, "VarR8FromUI8");
        break;
      case 364:
        sprintf(name, "VarDateFromI8");
        break;
      case 365:
        sprintf(name, "VarDateFromUI8");
        break;
      case 366:
        sprintf(name, "VarCyFromI8");
        break;
      case 367:
        sprintf(name, "VarCyFromUI8");
        break;
      case 368:
        sprintf(name, "VarBstrFromI8");
        break;
      case 369:
        sprintf(name, "VarBstrFromUI8");
        break;
      case 370:
        sprintf(name, "VarBoolFromI8");
        break;
      case 371:
        sprintf(name, "VarBoolFromUI8");
        break;
      case 372:
        sprintf(name, "VarUI1FromI8");
        break;
      case 373:
        sprintf(name, "VarUI1FromUI8");
        break;
      case 374:
        sprintf(name, "VarDecFromI8");
        break;
      case 375:
        sprintf(name, "VarDecFromUI8");
        break;
      case 376:
        sprintf(name, "VarI1FromI8");
        break;
      case 377:
        sprintf(name, "VarI1FromUI8");
        break;
      case 378:
        sprintf(name, "VarUI2FromI8");
        break;
      case 379:
        sprintf(name, "VarUI2FromUI8");
        break;
      case 401:
        sprintf(name, "OleLoadPictureEx");
        break;
      case 402:
        sprintf(name, "OleLoadPictureFileEx");
        break;
      case 411:
        sprintf(name, "SafeArrayCreateVector");
        break;
      case 412:
        sprintf(name, "SafeArrayCopyData");
        break;
      case 413:
        sprintf(name, "VectorFromBstr");
        break;
      case 414:
        sprintf(name, "BstrFromVector");
        break;
      case 415:
        sprintf(name, "OleIconToCursor");
        break;
      case 416:
        sprintf(name, "OleCreatePropertyFrameIndirect");
        break;
      case 417:
        sprintf(name, "OleCreatePropertyFrame");
        break;
      case 418:
        sprintf(name, "OleLoadPicture");
        break;
      case 419:
        sprintf(name, "OleCreatePictureIndirect");
        break;
      case 420:
        sprintf(name, "OleCreateFontIndirect");
        break;
      case 421:
        sprintf(name, "OleTranslateColor");
        break;
      case 422:
        sprintf(name, "OleLoadPictureFile");
        break;
      case 423:
        sprintf(name, "OleSavePictureFile");
        break;
      case 424:
        sprintf(name, "OleLoadPicturePath");
        break;
      case 425:
        sprintf(name, "VarUI4FromI8");
        break;
      case 426:
        sprintf(name, "VarUI4FromUI8");
        break;
      case 427:
        sprintf(name, "VarI8FromUI8");
        break;
      case 428:
        sprintf(name, "VarUI8FromI8");
        break;
      case 429:
        sprintf(name, "VarUI8FromUI1");
        break;
      case 430:
        sprintf(name, "VarUI8FromI2");
        break;
      case 431:
        sprintf(name, "VarUI8FromR4");
        break;
      case 432:
        sprintf(name, "VarUI8FromR8");
        break;
      case 433:
        sprintf(name, "VarUI8FromCy");
        break;
      case 434:
        sprintf(name, "VarUI8FromDate");
        break;
      case 435:
        sprintf(name, "VarUI8FromStr");
        break;
      case 436:
        sprintf(name, "VarUI8FromDisp");
        break;
      case 437:
        sprintf(name, "VarUI8FromBool");
        break;
      case 438:
        sprintf(name, "VarUI8FromI1");
        break;
      case 439:
        sprintf(name, "VarUI8FromUI2");
        break;
      case 440:
        sprintf(name, "VarUI8FromUI4");
        break;
      case 441:
        sprintf(name, "VarUI8FromDec");
        break;
      case 442:
        sprintf(name, "RegisterTypeLibForUser");
        break;
      case 443:
        sprintf(name, "UnRegisterTypeLibForUser");
        break;
      default:
        break;
    }
  }

  if (name[0] == '\0')
    sprintf(name, "ord%u", ord);

  return yr_strdup(name);
}
