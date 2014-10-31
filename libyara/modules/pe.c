/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>

#include <config.h>

#if defined(HAVE_LIBCRYPTO)
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/safestack.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#endif

#include <yara/pe.h>
#include <yara/modules.h>
#include <yara/mem.h>
#include <yara/strutils.h>


#define bigendian(n) \
    (((((uint32_t)(n) & 0xFF)) << 24) | \
     ((((uint32_t)(n) & 0xFF00)) << 8) | \
     ((((uint32_t)(n) & 0xFF0000)) >> 8) | \
     ((((uint32_t)(n) & 0xFF000000)) >> 24))


#define MODULE_NAME pe

#define RESOURCE_TYPE_CURSOR         1
#define RESOURCE_TYPE_BITMAP         2
#define RESOURCE_TYPE_ICON           3
#define RESOURCE_TYPE_MENU           4
#define RESOURCE_TYPE_DIALOG         5
#define RESOURCE_TYPE_STRING         6
#define RESOURCE_TYPE_FONTDIR        7
#define RESOURCE_TYPE_FONT           8
#define RESOURCE_TYPE_ACCELERATOR    9
#define RESOURCE_TYPE_RCDATA         10
#define RESOURCE_TYPE_MESSAGETABLE   11
#define RESOURCE_TYPE_VERSION        16
#define RESOURCE_TYPE_MANIFEST       24


#define RESOURCE_CALLBACK_CONTINUE   0
#define RESOURCE_CALLBACK_ABORT      1


#define RESOURCE_ITERATOR_FINISHED   0
#define RESOURCE_ITERATOR_ABORTED    1


#define MAX_PE_SECTIONS              96


#define IS_RESOURCE_SUBDIRECTORY(entry) \
    ((entry)->OffsetToData & 0x80000000)


#define RESOURCE_OFFSET(entry) \
    ((entry)->OffsetToData & 0x7FFFFFFF)


#define available_space(pe, pointer) \
    (pe->data + pe->data_size - (uint8_t*)(pointer))


#define fits_in_pe(pe, pointer, size) \
    ((uint8_t*)(pointer) + size <= pe->data + pe->data_size)


#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof(struct_type))


typedef int (*RESOURCE_CALLBACK_FUNC) ( \
     PIMAGE_RESOURCE_DATA_ENTRY rsrc_data, \
     int rsrc_type, \
     int rsrc_id, \
     int rsrc_language, \
     void* cb_data);


//
// Imports are stored in a linked list. Each node (IMPORTED_DLL) contains the
// name of the DLL and a pointer to another linked list of IMPORTED_FUNCTION
// structures containing the names of imported functions.
//

typedef struct _IMPORTED_DLL
{
  char *name;

  struct _IMPORTED_FUNCTION *functions;
  struct _IMPORTED_DLL *next;

} IMPORTED_DLL, *PIMPORTED_DLL;


typedef struct _IMPORTED_FUNCTION
{
  char *name;
  struct _IMPORTED_FUNCTION *next;

} IMPORTED_FUNCTION, *PIMPORTED_FUNCTION;


typedef struct _PE
{
  uint8_t* data;
  size_t data_size;

  PIMAGE_NT_HEADERS32 header;
  YR_OBJECT* object;
  IMPORTED_DLL* imported_dlls;

} PE;

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
    return NULL;

  return yr_strdup(name);
}


PIMAGE_NT_HEADERS32 pe_get_header(
    uint8_t* data,
    size_t data_size)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;

  size_t headers_size = 0;

  if (data_size < sizeof(IMAGE_DOS_HEADER))
    return NULL;

  mz_header = (PIMAGE_DOS_HEADER) data;

  if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  if (mz_header->e_lfanew < 0)
    return NULL;

  headers_size = mz_header->e_lfanew + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (data_size < headers_size)
    return NULL;

  pe_header = (PIMAGE_NT_HEADERS32) (data + mz_header->e_lfanew);

  headers_size += pe_header->FileHeader.SizeOfOptionalHeader;

  if (pe_header->Signature == IMAGE_NT_SIGNATURE &&
      (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ||
       pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
      data_size > headers_size)
  {
    return pe_header;
  }
  else
  {
    return NULL;
  }
}


// Parse the rich signature.
// http://www.ntcore.com/files/richsign.htm

void pe_parse_rich_signature(
    PE* pe)
{
  PIMAGE_DOS_HEADER mz_header;
  PIMAGE_NT_HEADERS32 pe_header;
  PRICH_SIGNATURE rich_signature;
  DWORD* rich_ptr;

  BYTE* raw_data = NULL;
  BYTE* clear_data = NULL;
  size_t headers_size = 0;
  size_t rich_len = 0;

  if (pe->data_size < sizeof(IMAGE_DOS_HEADER))
    return;

  mz_header = (PIMAGE_DOS_HEADER) pe->data;

  if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  if (mz_header->e_lfanew < 0)
    return;

  headers_size = mz_header->e_lfanew + \
                 sizeof(pe_header->Signature) + \
                 sizeof(IMAGE_FILE_HEADER);

  if (pe->data_size < headers_size)
    return;

  // From offset 0x80 until the start of the PE header should be the Rich
  // signature. The three key values must all be equal and the first dword
  // XORs to "DanS". Then walk the buffer looking for "Rich" which marks the
  // end. Technically the XOR key should be right after "Rich" but it's not
  // important.

  rich_signature = (PRICH_SIGNATURE) (pe->data + 0x80);

  if (rich_signature->key1 != rich_signature->key2 ||
      rich_signature->key2 != rich_signature->key3 ||
      (rich_signature->dans ^ rich_signature->key1) != RICH_DANS)
  {
    return;
  }

  for (rich_ptr = (DWORD*) rich_signature;
       rich_ptr <= (DWORD*) (pe->data + headers_size);
       rich_ptr++)
  {
    if (*rich_ptr == RICH_RICH)
    {
      // Multiple by 4 because we are counting in DWORDs.
      rich_len = (rich_ptr - (DWORD*) rich_signature) * 4;
      raw_data = (BYTE*) yr_malloc(rich_len);

      if (!raw_data)
        return;

      memcpy(raw_data, rich_signature, rich_len);

      set_integer(
          bigendian(rich_signature->dans), pe->object, "rich_signature.start");
      set_integer(
          bigendian(rich_signature->key1), pe->object, "rich_signature.key");

      break;
    }
  }

  // Walk the entire block and apply the XOR key.
  if (raw_data)
  {
    clear_data = (BYTE*) yr_malloc(rich_len);

    if (!clear_data)
    {
      yr_free(raw_data);
      return;
    }

    // Copy the entire block here to be XORed.
    memcpy(clear_data, raw_data, rich_len);

    for (rich_ptr = (DWORD*) clear_data;
         rich_ptr < (DWORD*) (clear_data + rich_len);
         rich_ptr++)
    {
      *rich_ptr ^= rich_signature->key1;
    }

    set_sized_string(
        (char*) raw_data, rich_len, pe->object, "rich_signature.raw_data");

    set_sized_string(
        (char*) clear_data, rich_len, pe->object, "rich_signature.clear_data");

    return;
  }

  return;
}


PIMAGE_DATA_DIRECTORY pe_get_directory_entry(
    PE* pe,
    int entry)
{
  PIMAGE_DATA_DIRECTORY result;

  if (pe->header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    result = &((PIMAGE_NT_HEADERS64) pe->header)->
        OptionalHeader.DataDirectory[entry];
  else
    result = &pe->header->OptionalHeader.DataDirectory[entry];

  return result;
}


uint64_t pe_rva_to_offset(
    PE* pe,
    uint64_t rva)
{
  PIMAGE_SECTION_HEADER section;
  DWORD section_rva;
  DWORD section_offset;

  int i = 0;

  section = IMAGE_FIRST_SECTION(pe->header);
  section_rva = 0;
  section_offset = 0;

  while(i < min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS))
  {
    if ((uint8_t*) section - \
        (uint8_t*) pe->data + sizeof(IMAGE_SECTION_HEADER) < pe->data_size)
    {
      if (rva >= section->VirtualAddress &&
          section_rva <= section->VirtualAddress)
      {
        section_rva = section->VirtualAddress;
        section_offset = section->PointerToRawData;
      }

      section++;
      i++;
    }
    else
    {
      return 0;
    }
  }

  return section_offset + (rva - section_rva);
}


int _pe_iterate_resources(
    PE* pe,
    PIMAGE_RESOURCE_DIRECTORY resource_dir,
    uint8_t* rsrc_data,
    int rsrc_tree_level,
    int* type,
    int* id,
    int* language,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  int result = RESOURCE_ITERATOR_FINISHED;

  // A few sanity checks to avoid corrupt files

  if (resource_dir->Characteristics != 0 ||
      resource_dir->NumberOfNamedEntries > 32768 ||
      resource_dir->NumberOfIdEntries > 32768)
  {
    return result;
  }

  int total_entries = resource_dir->NumberOfNamedEntries +
                      resource_dir->NumberOfIdEntries;

  PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;

  // The first directory entry is just after the resource directory,
  // by incrementing resource_dir we skip sizeof(resource_dir) bytes
  // and get a pointer to the end of the resource directory.

  entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (resource_dir + 1);

  for (int i = 0; i < total_entries; i++)
  {
    if (!struct_fits_in_pe(pe, entry, IMAGE_RESOURCE_DIRECTORY_ENTRY))
      break;

    switch(rsrc_tree_level)
    {
      case 0:
        *type = entry->Name;
        break;
      case 1:
        *id = entry->Name;
        break;
      case 2:
        *language = entry->Name;
        break;
    }

    if (IS_RESOURCE_SUBDIRECTORY(entry) && rsrc_tree_level < 2)
    {
      PIMAGE_RESOURCE_DIRECTORY directory = (PIMAGE_RESOURCE_DIRECTORY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

      if (struct_fits_in_pe(pe, directory, IMAGE_RESOURCE_DIRECTORY))
      {
        result = _pe_iterate_resources(
            pe,
            directory,
            rsrc_data,
            rsrc_tree_level + 1,
            type,
            id,
            language,
            callback,
            callback_data);

        if (result == RESOURCE_ITERATOR_ABORTED)
          return RESOURCE_ITERATOR_ABORTED;
      }
    }
    else
    {
      PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY) \
          (rsrc_data + RESOURCE_OFFSET(entry));

      if (struct_fits_in_pe(pe, data_entry, IMAGE_RESOURCE_DATA_ENTRY))
      {
        result = callback(
            data_entry,
            *type,
            *id,
            *language,
            callback_data);
      }

      if (result == RESOURCE_CALLBACK_ABORT)
        return RESOURCE_ITERATOR_ABORTED;
    }

    if (result == RESOURCE_ITERATOR_ABORTED)
      return result;

    entry++;
  }

  return RESOURCE_ITERATOR_FINISHED;
}


int pe_iterate_resources(
    PE* pe,
    RESOURCE_CALLBACK_FUNC callback,
    void* callback_data)
{
  uint64_t offset;

  int type = -1;
  int id = -1;
  int language = -1;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);

  if (directory->VirtualAddress != 0)
  {
    offset = pe_rva_to_offset(pe, directory->VirtualAddress);

    if (offset != 0 &&
        offset < pe->data_size)
    {
      _pe_iterate_resources(
          pe,
          (PIMAGE_RESOURCE_DIRECTORY) (pe->data + offset),
          pe->data + offset,
          0,
          &type,
          &id,
          &language,
          callback,
          callback_data);

      return 1;
    }
  }

  return 0;
}

#ifdef __cplusplus
#define typeof decltype
#endif

// Align offset to a 32-bit boundary and add it to a pointer

#define ADD_OFFSET(ptr, offset) \
    (typeof(ptr)) ((uint8_t*) (ptr) + ((offset + 3) & ~3))


int pe_find_version_info_cb(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    PE* pe)
{
  PVERSION_INFO version_info;
  PVERSION_INFO string_file_info;

  char key[64];
  char value[256];

  size_t version_info_offset;

  if (rsrc_type == RESOURCE_TYPE_VERSION)
  {
    version_info_offset = pe_rva_to_offset(pe, rsrc_data->OffsetToData);

    if (version_info_offset == 0)
      return RESOURCE_CALLBACK_CONTINUE;

    version_info = (PVERSION_INFO) (pe->data + version_info_offset);

    if (!struct_fits_in_pe(pe, version_info, VERSION_INFO))
      return RESOURCE_CALLBACK_CONTINUE;

    if (!fits_in_pe(pe, version_info, sizeof("VS_VERSION_INFO")))
      return RESOURCE_CALLBACK_CONTINUE;

    if (strcmp_w(version_info->Key, "VS_VERSION_INFO") != 0)
      return RESOURCE_CALLBACK_CONTINUE;

    string_file_info = ADD_OFFSET(version_info, sizeof(VERSION_INFO) + 86);

    if (!struct_fits_in_pe(pe, string_file_info, VERSION_INFO))
      return RESOURCE_CALLBACK_CONTINUE;

    if (!fits_in_pe(pe, string_file_info, sizeof("StringFileInfo")))
      return RESOURCE_CALLBACK_CONTINUE;

    while(strcmp_w(string_file_info->Key, "StringFileInfo") == 0)
    {
      PVERSION_INFO string_table = ADD_OFFSET(
          string_file_info,
          sizeof(VERSION_INFO) + 30);

      string_file_info = ADD_OFFSET(
          string_file_info,
          string_file_info->Length);

      while (string_table < string_file_info)
      {
        PVERSION_INFO string = ADD_OFFSET(
            string_table,
            sizeof(VERSION_INFO) + 2 * (strlen_w(string_table->Key) + 1));

        string_table = ADD_OFFSET(
            string_table,
            string_table->Length);

        while (string < string_table)
        {
          char* string_value = (char*) ADD_OFFSET(
              string,
              sizeof(VERSION_INFO) + 2 * (strlen_w(string->Key) + 1));

          strlcpy_w(key, string->Key, sizeof(key));
          strlcpy_w(value, string_value, sizeof(value));

          set_string(value, pe->object, "version_info[%s]", key);

          if (string->Length == 0)
            break;

          string = ADD_OFFSET(string, string->Length);
        }

        if (string_table->Length == 0)
          break;
      }
    }

    return RESOURCE_CALLBACK_ABORT;
  }

  return RESOURCE_CALLBACK_CONTINUE;
}


IMPORTED_FUNCTION* pe_parse_import_descriptor(
    PE* pe,
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor,
    char* dll_name)
{
  IMPORTED_FUNCTION* head = NULL;
  IMPORTED_FUNCTION* tail = NULL;

  uint64_t offset = pe_rva_to_offset(
      pe, import_descriptor->OriginalFirstThunk);

  if (offset == 0)
    return NULL;

  if (pe->header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
  {
    PIMAGE_THUNK_DATA64 thunks64 = (PIMAGE_THUNK_DATA64)(pe->data + offset);

    while (struct_fits_in_pe(pe, thunks64, IMAGE_THUNK_DATA64) &&
           thunks64->u1.Ordinal != 0)
    {
      char* name = NULL;

      if (!(thunks64->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, thunks64->u1.Function);

        if (offset != 0)
        {
          PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME) \
              (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char *) yr_strndup(
                (char*) import->Name, available_space(pe, import->Name));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, thunks64->u1.Ordinal & 0xFFFF);
      }

      if (name != NULL)
      {
        IMPORTED_FUNCTION* imported_func = (IMPORTED_FUNCTION*)
            yr_calloc(1, sizeof(IMPORTED_FUNCTION));

        imported_func->name = name;
        imported_func->next = NULL;

        if (head == NULL)
          head = imported_func;

        if (tail != NULL)
          tail->next = imported_func;

        tail = imported_func;
      }

      thunks64++;
    }
  }
  else
  {
    PIMAGE_THUNK_DATA32 thunks32 = (PIMAGE_THUNK_DATA32)(pe->data + offset);

    while (struct_fits_in_pe(pe, thunks32, IMAGE_THUNK_DATA32) &&
           thunks32->u1.Ordinal != 0)
    {
      char* name = NULL;

      if (!(thunks32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
      {
        // If imported by name
        offset = pe_rva_to_offset(pe, thunks32->u1.Function);

        if (offset != 0)
        {
          PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME) \
              (pe->data + offset);

          if (struct_fits_in_pe(pe, import, IMAGE_IMPORT_BY_NAME))
          {
            name = (char *) yr_strndup(
                (char*) import->Name, available_space(pe, import->Name));
          }
        }
      }
      else
      {
        // If imported by ordinal. Lookup the ordinal.
        name = ord_lookup(dll_name, thunks32->u1.Ordinal & 0xFFFF);
      }

      if (name != NULL)
      {
        IMPORTED_FUNCTION* imported_func = (IMPORTED_FUNCTION*)
            yr_calloc(1, sizeof(IMPORTED_FUNCTION));

        imported_func->name = name;
        imported_func->next = NULL;

        if (head == NULL)
          head = imported_func;

        if (tail != NULL)
          tail->next = imported_func;

        tail = imported_func;
      }

      thunks32++;
    }
  }

  return head;
}

//
// Walk the imports and collect relevant information. It is used in the
// "imports" function for comparison and in the "imphash" function for
// calculation.
//

IMPORTED_DLL* pe_parse_imports(
    PE* pe)
{
  IMPORTED_DLL* head = NULL;
  IMPORTED_DLL* tail = NULL;

  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

  if (directory->VirtualAddress == 0)
    return NULL;

  uint64_t offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset == 0)
    return NULL;

  PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR) \
      (pe->data + offset);

  while (struct_fits_in_pe(pe, imports, IMAGE_IMPORT_DESCRIPTOR) &&
         imports->Name != 0)
  {
    uint64_t offset = pe_rva_to_offset(pe, imports->Name);

    if (offset != 0 && offset < pe->data_size)
    {
      char* dll_name = yr_strndup(
          (char *) (pe->data + offset), pe->data_size - offset);

      IMPORTED_FUNCTION* functions = pe_parse_import_descriptor(
          pe, imports, dll_name);

      if (functions != NULL)
      {
        IMPORTED_DLL* imported_dll = (IMPORTED_DLL*) yr_calloc(
            1, sizeof(IMPORTED_DLL));

        if (imported_dll != NULL)
        {
          imported_dll->name = dll_name;
          imported_dll->functions = functions;
          imported_dll->next = NULL;

          if (head == NULL)
            head = imported_dll;

          if (tail != NULL)
            tail->next = imported_dll;

          tail = imported_dll;
        }
      }
    }

    imports++;
  }

  return head;
}

#if defined(HAVE_LIBCRYPTO)
//
// Taken from http://stackoverflow.com/questions/10975542/asn1-time-conversion
// and cleaned up. Also uses timegm(3) instead of mktime(3).
//
static time_t ASN1_GetTimeT(
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

void pe_parse_certificates(
  PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory;
  PWIN_CERTIFICATE win_cert;
  BIO *cert_bio = NULL;
  PKCS7 *p7;
  X509 *cert;
  int i, j, counter = 0;
  uintptr_t end;
  uint8_t *eod; // End of directory.
  char *p;
  const char *sig_alg;
  ASN1_INTEGER *serial;
  time_t date_time;
  STACK_OF(X509) *certs;

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
  // directory->VirtualAddress is a file offset. Don't call pe_rva_to_offset().
  if (directory->VirtualAddress == 0 ||
      directory->VirtualAddress + directory->Size > pe->data_size)
  {
    return;
  }

  // Store the end of directory, making comparisons easier.
  eod = pe->data + directory->VirtualAddress + directory->Size;

  win_cert = (PWIN_CERTIFICATE) (pe->data + directory->VirtualAddress);
  //
  // Walk the directory, pulling out certificates.
  //
  // Make sure WIN_CERTIFICATE fits within the directory.
  // Make sure the Length specified fits within directory too.
  //
  // Subtracting 8 because the docs say that the length is only for the
  // Certificate, but the next paragraph contradicts that. All the binaries
  // I've seen have the Length being the entire structure (Certificate
  // included).
  //
  while (struct_fits_in_pe(pe, win_cert, WIN_CERTIFICATE) &&
         (uint8_t *) win_cert + sizeof(WIN_CERTIFICATE) <= eod &&
         (uint8_t *) win_cert->Certificate + win_cert->Length - 8 <= eod)
  {
    // Don't support legacy revision for now.
    // Make sure type is PKCS#7 too.
    if (win_cert->Revision != WIN_CERT_REVISION_2_0 ||
        win_cert->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
    {
      end = (uintptr_t) ((uint8_t *) win_cert) + win_cert->Length;
      win_cert = (PWIN_CERTIFICATE) (end + (end % 8));
      continue;
    }

    cert_bio = BIO_new_mem_buf(win_cert->Certificate, win_cert->Length);
    if (!cert_bio)
      break;
    p7 = d2i_PKCS7_bio(cert_bio, NULL);
    certs = PKCS7_get0_signers(p7, NULL, 0);
    if (!certs)
      break;
    for (i = 0; i < sk_X509_num(certs); i++)
    {
      cert = sk_X509_value(certs, i);

      p = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
      if (!p)
        break;
      set_string(p, pe->object, "signatures[%i].issuer", counter);
      yr_free(p);

      p = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
      if (!p)
        break;
      set_string(p, pe->object, "signatures[%i].subject", counter);
      yr_free(p);

      // Versions are zero based, so add one.
      set_integer(X509_get_version(cert) + 1, pe->object, "signatures[%i].version", counter);

      sig_alg = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));
      set_string(sig_alg, pe->object, "signatures[%i].algorithm", counter);

      serial = X509_get_serialNumber(cert);
      if (serial->length > 0)
      {
        //
        // Convert serial number to "common" string format: 00:01:02:03:04...
        // The (length * 2) is for each of the bytes in the integer to convert
        // to hexlified format. The (length - 1) is for the colons. The extra
        // byte is for the NULL terminator.
        //
        p = (char *) yr_malloc((serial->length * 2) + (serial->length - 1) + 1);
        if (!p)
          break;
        for (j = 0; j < serial->length; j++)
        {
          // Don't put the colon on the last one.
          if (j < serial->length - 1)
            snprintf(p + 3 * j, 4, "%02x:", serial->data[j]);
          else
            snprintf(p + 3 * j, 3, "%02x", serial->data[j]);
        }
        set_string(p, pe->object, "signatures[%i].serial", counter);
        yr_free(p);
      }

      date_time = ASN1_GetTimeT(X509_get_notBefore(cert));
      set_integer(date_time, pe->object, "signatures[%i].not_before", counter);
      date_time = ASN1_GetTimeT(X509_get_notAfter(cert));
      set_integer(date_time, pe->object, "signatures[%i].not_after", counter);

      counter++;
    }
    end = (uintptr_t) ((uint8_t *) win_cert) + win_cert->Length;
    win_cert = (PWIN_CERTIFICATE) (end + (end % 8));

    BIO_set_close(cert_bio, BIO_CLOSE);
    BIO_free(cert_bio);
    cert_bio = NULL;
    sk_X509_free(certs);
  }

  // Decrement counter as it gets incremented one extra time erroneously.
  if (counter > 0)
    counter--;
  set_integer(counter, pe->object, "number_of_signatures");
  return;
}
#endif  // defined(HAVE_LIBCRYPTO)


void pe_parse_header(
    PE* pe,
    size_t base_address,
    int flags)
{
  PIMAGE_SECTION_HEADER section;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];

#define OptionalHeader(field) \
  (pe->header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? \
   ((PIMAGE_NT_HEADERS64) pe->header)->OptionalHeader.field : \
     pe->header->OptionalHeader.field)

  set_integer(
      pe->header->FileHeader.Machine,
      pe->object, "machine");

  set_integer(
      pe->header->FileHeader.NumberOfSections,
      pe->object, "number_of_sections");

  set_integer(
      pe->header->FileHeader.TimeDateStamp,
      pe->object, "timestamp");

  set_integer(
      pe->header->FileHeader.Characteristics,
      pe->object, "characteristics");

  set_integer(
      flags & SCAN_FLAGS_PROCESS_MEMORY ?
        base_address + OptionalHeader(AddressOfEntryPoint) :
        pe_rva_to_offset(pe, OptionalHeader(AddressOfEntryPoint)),
      pe->object, "entry_point");

  set_integer(
      OptionalHeader(ImageBase),
      pe->object, "image_base");

  set_integer(
      OptionalHeader(MajorLinkerVersion),
      pe->object, "linker_version.major");

  set_integer(
      OptionalHeader(MinorLinkerVersion),
      pe->object, "linker_version.minor");

  set_integer(
      OptionalHeader(MajorOperatingSystemVersion),
      pe->object, "os_version.major");

  set_integer(
      OptionalHeader(MinorOperatingSystemVersion),
      pe->object, "os_version.minor");

  set_integer(
      OptionalHeader(MajorImageVersion),
      pe->object, "image_version.major");

  set_integer(
      OptionalHeader(MinorImageVersion),
      pe->object, "image_version.minor");

  set_integer(
      OptionalHeader(MajorSubsystemVersion),
      pe->object, "subsystem_version.major");

  set_integer(
      OptionalHeader(MinorSubsystemVersion),
      pe->object, "subsystem_version.minor");

  set_integer(
      OptionalHeader(Subsystem),
      pe->object, "subsystem");

  pe_iterate_resources(
      pe,
      (RESOURCE_CALLBACK_FUNC) pe_find_version_info_cb,
      (void*) pe);

  section = IMAGE_FIRST_SECTION(pe->header);

  int scount = min(pe->header->FileHeader.NumberOfSections, MAX_PE_SECTIONS);

  for (int i = 0; i < scount; i++)
  {
    if (!struct_fits_in_pe(pe, section, IMAGE_SECTION_HEADER))
      break;

    strlcpy(section_name, (char*) section->Name, IMAGE_SIZEOF_SHORT_NAME + 1);

    set_string(
        section_name,
        pe->object, "sections[%i].name", i);

    set_integer(
        section->Characteristics,
        pe->object, "sections[%i].characteristics", i);

    set_integer(section->SizeOfRawData,
        pe->object, "sections[%i].raw_data_size", i);

    set_integer(section->PointerToRawData,
        pe->object, "sections[%i].raw_data_offset", i);

    set_integer(section->VirtualAddress,
        pe->object, "sections[%i].virtual_address", i);

    set_integer(
        section->Misc.VirtualSize,
        pe->object, "sections[%i].virtual_size", i);

    section++;
  }
}

define_function(section_index)
{
  YR_OBJECT* module = module();
  SIZED_STRING* sect;
  char* name = string_argument(1);

  int64_t n = get_integer(module, "number_of_sections");
  int64_t i;

  if (n == UNDEFINED)
    return_integer(UNDEFINED);

  for (i = 0; i < n; i++)
  {
    sect = get_string(module, "sections[%i].name", i);
    if (strcmp(name, sect->c_string) == 0)
      return_integer(i);
  }

  return_integer(UNDEFINED);
}


define_function(exports)
{
  char* function_name = string_argument(1);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  PIMAGE_DATA_DIRECTORY directory;
  PIMAGE_EXPORT_DIRECTORY exports;
  DWORD* names;

  char* name;
  int i;
  uint64_t offset;

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

  // If the PE doesn't export any functions, return FALSE

  if (directory->VirtualAddress == 0)
    return_integer(0);

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset == 0 ||
      offset >= pe->data_size)
    return_integer(0);

  exports = (PIMAGE_EXPORT_DIRECTORY)(pe->data + offset);

  offset = pe_rva_to_offset(pe, exports->AddressOfNames);

  if (offset == 0 ||
      offset + exports->NumberOfNames * sizeof(DWORD) > pe->data_size)
    return_integer(0);

  names = (DWORD*)(pe->data + offset);

  for (i = 0; i < exports->NumberOfNames; i++)
  {
    offset = pe_rva_to_offset(pe, names[i]);

    if (offset == 0 || offset >= pe->data_size)
      return_integer(0);

    name = (char*)(pe->data + offset);

    if (strncmp(name, function_name, pe->data_size - offset) == 0)
      return_integer(1);
  }

  return_integer(0);
}


#if defined(HAVE_LIBCRYPTO)

//
// Generate an import hash:
// https://www.mandiant.com/blog/tracking-malware-import-hashing/
// It is important to make duplicates of the strings as we don't want
// to alter the contents of the parsed import structures.
//

define_function(imphash)
{
  YR_OBJECT* module = module();
  IMPORTED_DLL* dll = NULL;
  IMPORTED_FUNCTION* func = NULL;

  MD5_CTX ctx;

  unsigned char digest[MD5_DIGEST_LENGTH];
  char digest_ascii[MD5_DIGEST_LENGTH * 2 + 1];
  int first = TRUE;

  PE* pe = (PE*) module->data;

  // If not a PE, return 0.

  if (!pe)
    return_string(UNDEFINED);

  MD5_Init(&ctx);

  dll = pe->imported_dlls;

  while (dll)
  {
    size_t dll_name_len;

    // If extension is 'ocx', 'sys' or 'dll', chop it.

    char* ext = strstr(dll->name, ".");

    if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||
                strncasecmp(ext, ".sys", 4) == 0 ||
                strncasecmp(ext, ".dll", 4) == 0))
    {
      dll_name_len = (ext - dll->name);
    }
    else
    {
      dll_name_len = strlen(dll->name);
    }

    // Allocate a new string to hold the dll name.

    char* dll_name = (char *) yr_malloc(dll_name_len + 1);
    strlcpy(dll_name, dll->name, dll_name_len + 1);

    func = dll->functions;

    while (func)
    {
      size_t final_name_len = dll_name_len + strlen(func->name) + 1;

      if (!first)
        final_name_len++;   // Additional byte to accommodate the extra comma

      char* final_name = (char*) yr_malloc(final_name_len + 1);

      if (final_name == NULL)
        break;

      sprintf(final_name, first ? "%s.%s": ",%s.%s", dll_name, func->name);

      // Lowercase the whole thing.

      for (int i = 0; i < final_name_len; i++)
        final_name[i] = tolower(final_name[i]);

      MD5_Update(&ctx, final_name, final_name_len);

      yr_free(final_name);

      func = func->next;
      first = FALSE;
    }

    yr_free(dll_name);
    dll = dll->next;
  }

  MD5_Final(digest, &ctx);

  // Transform the binary digest to ascii

  for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
  }

  digest_ascii[MD5_DIGEST_LENGTH * 2] = '\0';

  return_string(digest_ascii);
}


//
// Nothing fancy here. Just a sha256 of the clear data.
//

define_function(richhash)
{
  YR_OBJECT* parent = parent();
  SHA256_CTX ctx;

  unsigned char digest[SHA256_DIGEST_LENGTH];
  char digest_ascii[SHA256_DIGEST_LENGTH * 2 + 1];

  SIZED_STRING *clear_data = get_string(parent, "clear_data");

  if (!clear_data)
    return_string(UNDEFINED);

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, clear_data->c_string, clear_data->length);
  SHA256_Final(digest, &ctx);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
  }

  digest_ascii[SHA256_DIGEST_LENGTH * 2] = '\0';

  return_string(digest_ascii);
}

#endif  // defined(HAVE_LIBCRYPTO)


define_function(imports)
{
  char* dll_name = string_argument(1);
  char* function_name = string_argument(2);

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  IMPORTED_DLL* imported_dll = NULL;
  IMPORTED_FUNCTION* imported_func = NULL;

  if (!pe)
    return_integer(UNDEFINED);

  imported_dll = pe->imported_dlls;

  while (imported_dll != NULL)
  {
    if (strcasecmp(imported_dll->name, dll_name) == 0)
    {
      imported_func = imported_dll->functions;

      while (imported_func)
      {
        if (strcasecmp(imported_func->name, function_name) == 0)
          return_integer(1);

        imported_dll = imported_dll->next;
      }
    }
    imported_dll = imported_dll->next;
  }

  return_integer(0);
}


typedef struct _FIND_LANGUAGE_CB_DATA
{
  uint64_t locale;
  uint64_t mask;

  int found;

} FIND_LANGUAGE_CB_DATA;


int pe_find_language_cb(
    PIMAGE_RESOURCE_DATA_ENTRY rsrc_data,
    int rsrc_type,
    int rsrc_id,
    int rsrc_language,
    FIND_LANGUAGE_CB_DATA* cb_data)
{
  if ((rsrc_language & cb_data->mask) == cb_data->locale)
  {
    cb_data->found = TRUE;
    return RESOURCE_CALLBACK_ABORT;
  }

  return RESOURCE_CALLBACK_CONTINUE;
}


define_function(locale)
{
  FIND_LANGUAGE_CB_DATA cb_data;

  cb_data.locale = integer_argument(1);
  cb_data.mask = 0xFFFF;
  cb_data.found = FALSE;

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  if (pe_iterate_resources(pe,
          (RESOURCE_CALLBACK_FUNC) pe_find_language_cb,
          (void*) &cb_data))
  {
    return_integer(cb_data.found);
  }
  else
  {
    return_integer(UNDEFINED);
  }
}


define_function(language)
{
  FIND_LANGUAGE_CB_DATA cb_data;

  cb_data.locale = integer_argument(1);
  cb_data.mask = 0xFF;
  cb_data.found = FALSE;

  YR_OBJECT* module = module();
  PE* pe = (PE*) module->data;

  // If not a PE file, return UNDEFINED

  if (pe == NULL)
    return_integer(UNDEFINED);

  if (pe_iterate_resources(pe,
          (RESOURCE_CALLBACK_FUNC) pe_find_language_cb,
          (void*) &cb_data))
  {
    return_integer(cb_data.found);
  }
  else
  {
    return_integer(UNDEFINED);
  }
}


begin_declarations;

  declare_integer("MACHINE_I386");
  declare_integer("MACHINE_AMD64");

  declare_integer("SUBSYSTEM_UNKNOWN");
  declare_integer("SUBSYSTEM_NATIVE");
  declare_integer("SUBSYSTEM_WINDOWS_GUI");
  declare_integer("SUBSYSTEM_WINDOWS_CUI");
  declare_integer("SUBSYSTEM_OS2_CUI");
  declare_integer("SUBSYSTEM_POSIX_CUI");
  declare_integer("SUBSYSTEM_NATIVE_WINDOWS");

  declare_integer("RELOCS_STRIPPED");
  declare_integer("EXECUTABLE_IMAGE");
  declare_integer("LINE_NUMS_STRIPPED");
  declare_integer("LOCAL_SYMS_STRIPPED");
  declare_integer("AGGRESIVE_WS_TRIM");
  declare_integer("LARGE_ADDRESS_AWARE");
  declare_integer("BYTES_REVERSED_LO");
  declare_integer("32BIT_MACHINE");
  declare_integer("DEBUG_STRIPPED");
  declare_integer("REMOVABLE_RUN_FROM_SWAP");
  declare_integer("NET_RUN_FROM_SWAP");
  declare_integer("SYSTEM");
  declare_integer("DLL");
  declare_integer("UP_SYSTEM_ONLY");
  declare_integer("BYTES_REVERSED_HI");

  declare_integer("machine");
  declare_integer("number_of_sections");
  declare_integer("timestamp");
  declare_integer("characteristics");

  declare_integer("entry_point");
  declare_integer("image_base");

  declare_string_dictionary("version_info");

  begin_struct("linker_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("linker_version");

  begin_struct("os_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("os_version");

  begin_struct("image_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("image_version");

  begin_struct("subsystem_version");
    declare_integer("major");
    declare_integer("minor");
  end_struct("subsystem_version");

  declare_integer("subsystem");

  begin_struct_array("sections");
    declare_string("name");
    declare_integer("characteristics");
    declare_integer("virtual_address");
    declare_integer("virtual_size");
    declare_integer("raw_data_offset");
    declare_integer("raw_data_size");
  end_struct_array("sections");

  begin_struct("rich_signature");
    declare_integer("start");
    declare_integer("key");
    declare_string("raw_data");
    declare_string("clear_data");
    #if defined(HAVE_LIBCRYPTO)
    declare_function("hash", "", "s", richhash);
    #endif
  end_struct("rich_signature");

  #if defined(HAVE_LIBCRYPTO)
  declare_function("imphash", "", "s", imphash);
  #endif

  declare_function("section_index", "s", "i", section_index);
  declare_function("exports", "s", "i", exports);
  declare_function("imports", "ss", "i", imports);
  declare_function("locale", "i", "i", locale);
  declare_function("language", "i", "i", language);

  #if defined(HAVE_LIBCRYPTO)
  begin_struct_array("signatures");
    declare_string("issuer");
    declare_string("subject");
    declare_integer("version");
    declare_string("algorithm");
    declare_string("serial");
    declare_integer("not_before");
    declare_integer("not_after");
  end_struct_array("signatures");
  declare_integer("number_of_signatures");
  #endif

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  set_integer(
      IMAGE_FILE_MACHINE_I386, module_object,
      "MACHINE_I386");
  set_integer(
      IMAGE_FILE_MACHINE_AMD64, module_object,
      "MACHINE_AMD64");

  set_integer(
      IMAGE_SUBSYSTEM_UNKNOWN, module_object,
      "SUBSYSTEM_UNKNOWN");
  set_integer(
      IMAGE_SUBSYSTEM_NATIVE, module_object,
      "SUBSYSTEM_NATIVE");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_GUI, module_object,
      "SUBSYSTEM_WINDOWS_GUI");
  set_integer(
      IMAGE_SUBSYSTEM_WINDOWS_CUI, module_object,
      "SUBSYSTEM_WINDOWS_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_OS2_CUI, module_object,
      "SUBSYSTEM_OS2_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_POSIX_CUI, module_object,
      "SUBSYSTEM_POSIX_CUI");
  set_integer(
      IMAGE_SUBSYSTEM_NATIVE_WINDOWS, module_object,
      "SUBSYSTEM_NATIVE_WINDOWS");

  set_integer(
      IMAGE_FILE_RELOCS_STRIPPED, module_object,
      "RELOCS_STRIPPED");
  set_integer(
      IMAGE_FILE_EXECUTABLE_IMAGE, module_object,
      "EXECUTABLE_IMAGE");
  set_integer(
      IMAGE_FILE_LINE_NUMS_STRIPPED, module_object,
      "LINE_NUMS_STRIPPED");
  set_integer(
      IMAGE_FILE_LOCAL_SYMS_STRIPPED, module_object,
      "LOCAL_SYMS_STRIPPED");
  set_integer(
      IMAGE_FILE_AGGRESIVE_WS_TRIM, module_object,
      "AGGRESIVE_WS_TRIM");
  set_integer(
      IMAGE_FILE_LARGE_ADDRESS_AWARE, module_object,
      "LARGE_ADDRESS_AWARE");
  set_integer(
      IMAGE_FILE_BYTES_REVERSED_LO, module_object,
      "BYTES_REVERSED_LO");
  set_integer(
      IMAGE_FILE_32BIT_MACHINE, module_object,
      "32BIT_MACHINE");
  set_integer(
      IMAGE_FILE_DEBUG_STRIPPED, module_object,
      "DEBUG_STRIPPED");
  set_integer(
      IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, module_object,
      "REMOVABLE_RUN_FROM_SWAP");
  set_integer(
      IMAGE_FILE_NET_RUN_FROM_SWAP, module_object,
      "NET_RUN_FROM_SWAP");
  set_integer(
      IMAGE_FILE_SYSTEM, module_object,
      "SYSTEM");
  set_integer(
      IMAGE_FILE_DLL, module_object,
      "DLL");
  set_integer(
      IMAGE_FILE_UP_SYSTEM_ONLY, module_object,
      "UP_SYSTEM_ONLY");
  set_integer(
      IMAGE_FILE_BYTES_REVERSED_HI, module_object,
      "BYTES_REVERSED_HI");

  YR_MEMORY_BLOCK* block;

  foreach_memory_block(context, block)
  {
    PIMAGE_NT_HEADERS32 pe_header = pe_get_header(block->data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        PE* pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFICIENT_MEMORY;

        pe->data = block->data;
        pe->data_size = block->size;
        pe->header = pe_header;
        pe->object = module_object;

        module_object->data = pe;

        pe_parse_header(pe, block->base, context->flags);
        pe_parse_rich_signature(pe);
        #if defined(HAVE_LIBCRYPTO)
        pe_parse_certificates(pe);
        #endif

        pe->imported_dlls = pe_parse_imports(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  IMPORTED_DLL* dll = NULL;
  IMPORTED_DLL* next_dll = NULL;
  IMPORTED_FUNCTION* func = NULL;
  IMPORTED_FUNCTION* next_func = NULL;

  PE* pe = (PE *) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  dll = pe->imported_dlls;

  while (dll)
  {
    func = dll->functions;

    while (func)
    {
      next_func = func->next;
      yr_free(func);
      func = next_func;
    }

    next_dll = dll->next;
    yr_free(dll);
    dll = next_dll;
  }

  yr_free(pe);

  return ERROR_SUCCESS;
}
