/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

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

#ifndef YR_PE_H
#define YR_PE_H

#include <yara/endian.h>
#include <yara/types.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>

// PKCS7_SIGNER_INFO is defined by wincrypt.h, but it conflicts with a type
// defined in openssl/pkcs7.h which is used in pe.c. Let's undefine the macro.
#undef PKCS7_SIGNER_INFO

// These definitions are not present in older Windows headers.

#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#endif

#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#endif

#ifndef IMAGE_SUBSYSTEM_EFI_ROM_IMAGE
#define IMAGE_SUBSYSTEM_EFI_ROM_IMAGE 13
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_COPYRIGHT
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7  // (X86 usage)
#endif

#ifndef IMAGE_FILE_MACHINE_TARGET_HOST
#define IMAGE_FILE_MACHINE_TARGET_HOST 0x0001
#endif

#else

#include <stdlib.h>
#include <yara/integers.h>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint16_t WCHAR;
typedef int16_t SHORT;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;

#ifndef _MAC

#define IMAGE_DOS_SIGNATURE    0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE    0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE 0x454C      // LE
#define IMAGE_VXD_SIGNATURE    0x454C      // LE
#define IMAGE_NT_SIGNATURE     0x00004550  // PE00

#else

#define IMAGE_DOS_SIGNATURE    0x4D5A      // MZ
#define IMAGE_OS2_SIGNATURE    0x4E45      // NE
#define IMAGE_OS2_SIGNATURE_LE 0x4C45      // LE
#define IMAGE_NT_SIGNATURE     0x50450000  // PE00

#endif

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER
{                   // DOS .EXE header
  WORD e_magic;     // Magic number
  WORD e_cblp;      // Bytes on last page of file
  WORD e_cp;        // Pages in file
  WORD e_crlc;      // Relocations
  WORD e_cparhdr;   // Size of header in paragraphs
  WORD e_minalloc;  // Minimum extra paragraphs needed
  WORD e_maxalloc;  // Maximum extra paragraphs needed
  WORD e_ss;        // Initial (relative) SS value
  WORD e_sp;        // Initial SP value
  WORD e_csum;      // Checksum
  WORD e_ip;        // Initial IP value
  WORD e_cs;        // Initial (relative) CS value
  WORD e_lfarlc;    // File address of relocation table
  WORD e_ovno;      // Overlay number
  WORD e_res[4];    // Reserved words
  WORD e_oemid;     // OEM identifier (for e_oeminfo)
  WORD e_oeminfo;   // OEM information; e_oemid specific
  WORD e_res2[10];  // Reserved words
  LONG e_lfanew;    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER           20

// Relocation info stripped from file.
#define IMAGE_FILE_RELOCS_STRIPPED         0x0001
// File is executable (i.e. no unresolved external references).
#define IMAGE_FILE_EXECUTABLE_IMAGE        0x0002
// Line numbers stripped from file.
#define IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004
// Local symbols stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
// Aggressively trim working set
#define IMAGE_FILE_AGGRESIVE_WS_TRIM       0x0010
// App can handle >2gb addresses
#define IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020
// Bytes of machine word are reversed.
#define IMAGE_FILE_BYTES_REVERSED_LO       0x0080
// 32 bit word machine.
#define IMAGE_FILE_32BIT_MACHINE           0x0100
// Debugging info stripped from file in .DBG file
#define IMAGE_FILE_DEBUG_STRIPPED          0x0200
// If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
// If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800
// System File.
#define IMAGE_FILE_SYSTEM                  0x1000
// File is a DLL.s
#define IMAGE_FILE_DLL                     0x2000
// File should only be run on a UP machine
#define IMAGE_FILE_UP_SYSTEM_ONLY          0x4000
// Bytes of machine word are reversed.
#define IMAGE_FILE_BYTES_REVERSED_HI       0x8000

#define IMAGE_FILE_MACHINE_UNKNOWN       0x0000
#define IMAGE_FILE_MACHINE_AM33          0x01d3
#define IMAGE_FILE_MACHINE_AMD64         0x8664
#define IMAGE_FILE_MACHINE_ARM           0x01c0
#define IMAGE_FILE_MACHINE_ARMNT         0x01c4
#define IMAGE_FILE_MACHINE_ARM64         0xaa64
#define IMAGE_FILE_MACHINE_EBC           0x0ebc
#define IMAGE_FILE_MACHINE_I386          0x014c
#define IMAGE_FILE_MACHINE_IA64          0x0200
#define IMAGE_FILE_MACHINE_M32R          0x9041
#define IMAGE_FILE_MACHINE_MIPS16        0x0266
#define IMAGE_FILE_MACHINE_MIPSFPU       0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16     0x0466
#define IMAGE_FILE_MACHINE_POWERPC       0x01f0
#define IMAGE_FILE_MACHINE_POWERPCFP     0x01f1
#define IMAGE_FILE_MACHINE_R4000         0x0166
#define IMAGE_FILE_MACHINE_SH3           0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP        0x01a3
#define IMAGE_FILE_MACHINE_SH4           0x01a6
#define IMAGE_FILE_MACHINE_SH5           0x01a8
#define IMAGE_FILE_MACHINE_THUMB         0x01c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2     0x0169
// Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_TARGET_HOST   0x0001
// MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R3000         0x0162  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000        0x0168  // Alpha_AXP
#define IMAGE_FILE_MACHINE_ALPHA         0x0184  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH3E          0x01a4  // ALPHA64
#define IMAGE_FILE_MACHINE_ALPHA64       0x0284
#define IMAGE_FILE_MACHINE_AXP64         IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE       0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF           0x0CEF
#define IMAGE_FILE_MACHINE_CEE           0xC0EE

// Section characteristics
#define IMAGE_SCN_TYPE_NO_PAD            0x00000008
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_LNK_OTHER              0x00000100
#define IMAGE_SCN_LNK_INFO               0x00000200
#define IMAGE_SCN_LNK_REMOVE             0x00000800
#define IMAGE_SCN_LNK_COMDAT             0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC      0x00004000
#define IMAGE_SCN_GPREL                  0x00008000
#define IMAGE_SCN_MEM_FARDATA            0x00008000
#define IMAGE_SCN_MEM_PURGEABLE          0x00020000
#define IMAGE_SCN_MEM_16BIT              0x00020000
#define IMAGE_SCN_MEM_LOCKED             0x00040000
#define IMAGE_SCN_MEM_PRELOAD            0x00080000
#define IMAGE_SCN_ALIGN_1BYTES           0x00100000
#define IMAGE_SCN_ALIGN_2BYTES           0x00200000
#define IMAGE_SCN_ALIGN_4BYTES           0x00300000
#define IMAGE_SCN_ALIGN_8BYTES           0x00400000
#define IMAGE_SCN_ALIGN_16BYTES          0x00500000
#define IMAGE_SCN_ALIGN_32BYTES          0x00600000
#define IMAGE_SCN_ALIGN_64BYTES          0x00700000
#define IMAGE_SCN_ALIGN_128BYTES         0x00800000
#define IMAGE_SCN_ALIGN_256BYTES         0x00900000
#define IMAGE_SCN_ALIGN_512BYTES         0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES        0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES        0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES        0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES        0x00E00000
#define IMAGE_SCN_ALIGN_MASK             0x00F00000
#define IMAGE_SCN_LNK_NRELOC_OVFL        0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED         0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED          0x08000000
#define IMAGE_SCN_MEM_SHARED             0x10000000
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000
#define IMAGE_SCN_SCALE_INDEX            0x00000001

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY
{
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
#define IMAGE_DIRECTORY_ENTRY_TLS            9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER32
{
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC  0x107

typedef struct _IMAGE_NT_HEADERS32
{
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;

} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64
{
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;

} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is
// the same either way.

#define IMAGE_FIRST_SECTION(ntheader) \
  ((PIMAGE_SECTION_HEADER)(                                             \
      (BYTE*) ntheader + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + \
      yr_le16toh(((PIMAGE_NT_HEADERS32)(ntheader))                      \
                     ->FileHeader.SizeOfOptionalHeader)))

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN                  0
#define IMAGE_SUBSYSTEM_NATIVE                   1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI              2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI              3
#define IMAGE_SUBSYSTEM_OS2_CUI                  5
#define IMAGE_SUBSYSTEM_POSIX_CUI                7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS           8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION          10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       12
#define IMAGE_SUBSYSTEM_EFI_ROM_IMAGE            13
#define IMAGE_SUBSYSTEM_XBOX                     14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DllCharacteristics values

#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER          0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF              0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER
{
  BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
  union
  {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD NumberOfRelocations;
  WORD NumberOfLinenumbers;
  DWORD Characteristics;

} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

typedef struct _IMAGE_EXPORT_DIRECTORY
{
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
  union
  {
    DWORD Characteristics;
    DWORD OriginalFirstThunk;
  };
  DWORD TimeDateStamp;
  DWORD ForwarderChain;
  DWORD Name;
  DWORD FirstThunk;

} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME
{
  WORD Hint;
  BYTE Name[1];

} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA32
{
  union
  {
    DWORD ForwarderString;
    DWORD Function;
    DWORD Ordinal;
    DWORD AddressOfData;
  } u1;

} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000L

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
{
  DWORD TimeDateStamp;
  WORD OffsetModuleName;
  WORD NumberOfModuleForwarderRefs;
  // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF
{
  DWORD TimeDateStamp;
  WORD OffsetModuleName;
  WORD Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR
{
  union
  {
    DWORD AllAttributes;
    struct
    {
      DWORD RvaBased : 1;  // Delay load version 2
      DWORD ReservedAttributes : 31;
    } DUMMYSTRUCTNAME;
  } Attributes;

  // RVA to the name of the target library (NULL-terminate ASCII string)
  DWORD DllNameRVA;
  // RVA to the HMODULE caching location (PHMODULE)
  DWORD ModuleHandleRVA;
  // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
  DWORD ImportAddressTableRVA;
  // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
  DWORD ImportNameTableRVA;
  // RVA to an optional bound IAT
  DWORD BoundImportAddressTableRVA;
  // RVA to an optional unload info table
  DWORD UnloadInformationTableRVA;
  // 0 if not bound, otherwise, date/time of the target DLL
  DWORD TimeDateStamp;

} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64
{
  union
  {
    ULONGLONG ForwarderString;
    ULONGLONG Function;
    ULONGLONG Ordinal;
    ULONGLONG AddressOfData;
  } u1;

} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U
{
  WORD Length;
  WCHAR NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
{
  DWORD Name;
  DWORD OffsetToData;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
  DWORD OffsetToData;
  DWORD Size;
  DWORD CodePage;
  DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY
{
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  WORD NumberOfNamedEntries;
  WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

#define IMAGE_DEBUG_TYPE_FPO           3
#define IMAGE_DEBUG_TYPE_MISC          4
#define IMAGE_DEBUG_TYPE_EXCEPTION     5
#define IMAGE_DEBUG_TYPE_FIXUP         6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC   7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC 8
#define IMAGE_DEBUG_TYPE_BORLAND       9
#define IMAGE_DEBUG_TYPE_RESERVED10    10
#define IMAGE_DEBUG_TYPE_CLSID         11
#define IMAGE_DEBUG_TYPE_VC_FEATURE    12
#define IMAGE_DEBUG_TYPE_POGO          13
#define IMAGE_DEBUG_TYPE_ILTCG         14
#define IMAGE_DEBUG_TYPE_MPX           15
#define IMAGE_DEBUG_TYPE_REPRO         16

typedef struct _IMAGE_DEBUG_DIRECTORY
{
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Type;
  DWORD SizeOfData;
  DWORD AddressOfRawData;
  DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

//
// Symbol format.
//

typedef struct _IMAGE_SYMBOL
{
  union
  {
    BYTE ShortName[8];
    struct
    {
      DWORD Short;  // if 0, use LongName
      DWORD Long;   // offset into string table
    } Name;
    DWORD LongName[2];  // PBYTE [2]
  } N;
  DWORD Value;
  SHORT SectionNumber;
  WORD Type;
  BYTE StorageClass;
  BYTE NumberOfAuxSymbols;
} IMAGE_SYMBOL, *PIMAGE_SYMBOL;

#define IMAGE_SIZEOF_SYMBOL 18

typedef struct _IMAGE_SYMBOL_EX
{
  union
  {
    BYTE ShortName[8];
    struct
    {
      DWORD Short;  // if 0, use LongName
      DWORD Long;   // offset into string table
    } Name;
    DWORD LongName[2];  // PBYTE  [2]
  } N;
  DWORD Value;
  LONG SectionNumber;
  WORD Type;
  BYTE StorageClass;
  BYTE NumberOfAuxSymbols;
} IMAGE_SYMBOL_EX, *PIMAGE_SYMBOL_EX;

//
// Section values.
//
// Symbols have a section number of the section in which they are
// defined. Otherwise, section numbers have the following meanings:
//

#define IMAGE_SYM_UNDEFINED      (SHORT) 0  // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE       (SHORT) - 1  // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG          (SHORT) - 2  // Symbol is a special debug item.
#define IMAGE_SYM_SECTION_MAX    0xFEFF  // Values 0xFF00-0xFFFF are special
#define IMAGE_SYM_SECTION_MAX_EX MAXLONG

//
// Type (fundamental) values.
//

#define IMAGE_SYM_TYPE_NULL   0x0000  // no type.
#define IMAGE_SYM_TYPE_VOID   0x0001  //
#define IMAGE_SYM_TYPE_CHAR   0x0002  // type character.
#define IMAGE_SYM_TYPE_SHORT  0x0003  // type short integer.
#define IMAGE_SYM_TYPE_INT    0x0004  //
#define IMAGE_SYM_TYPE_LONG   0x0005  //
#define IMAGE_SYM_TYPE_FLOAT  0x0006  //
#define IMAGE_SYM_TYPE_DOUBLE 0x0007  //
#define IMAGE_SYM_TYPE_STRUCT 0x0008  //
#define IMAGE_SYM_TYPE_UNION  0x0009  //
#define IMAGE_SYM_TYPE_ENUM   0x000A  // enumeration.
#define IMAGE_SYM_TYPE_MOE    0x000B  // member of enumeration.
#define IMAGE_SYM_TYPE_BYTE   0x000C  //
#define IMAGE_SYM_TYPE_WORD   0x000D  //
#define IMAGE_SYM_TYPE_UINT   0x000E  //
#define IMAGE_SYM_TYPE_DWORD  0x000F  //
#define IMAGE_SYM_TYPE_PCODE  0x8000  //
//
// Type (derived) values.
//

#define IMAGE_SYM_DTYPE_NULL             0  // no derived type.
#define IMAGE_SYM_DTYPE_POINTER          1  // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION         2  // function.
#define IMAGE_SYM_DTYPE_ARRAY            3  // array.

//
// Storage classes.
//
#define IMAGE_SYM_CLASS_END_OF_FUNCTION  (BYTE) - 1
#define IMAGE_SYM_CLASS_NULL             0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC        0x0001
#define IMAGE_SYM_CLASS_EXTERNAL         0x0002
#define IMAGE_SYM_CLASS_STATIC           0x0003
#define IMAGE_SYM_CLASS_REGISTER         0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF     0x0005
#define IMAGE_SYM_CLASS_LABEL            0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL  0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT 0x0008
#define IMAGE_SYM_CLASS_ARGUMENT         0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG       0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION  0x000B
#define IMAGE_SYM_CLASS_UNION_TAG        0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION  0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC 0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG         0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM   0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM   0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD        0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL 0x0044  //

#define IMAGE_SYM_CLASS_BLOCK         0x0064
#define IMAGE_SYM_CLASS_FUNCTION      0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT 0x0066
#define IMAGE_SYM_CLASS_FILE          0x0067
// new
#define IMAGE_SYM_CLASS_SECTION       0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL 0x0069

#define IMAGE_SYM_CLASS_CLR_TOKEN 0x006B

// type packing constants

#define N_BTMASK 0x000F
#define N_TMASK  0x0030
#define N_TMASK1 0x00C0
#define N_TMASK2 0x00F0
#define N_BTSHFT 4
#define N_TSHIFT 2
// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) &N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) &N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) &N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) &N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x)                                                            \
  ((x) == IMAGE_SYM_CLASS_STRUCT_TAG || (x) == IMAGE_SYM_CLASS_UNION_TAG || \
   (x) == IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x)                                                            \
  ((((x) & ~N_BTMASK) << N_TSHIFT) | (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT) | \
   ((x) &N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x) >> N_TSHIFT) & ~N_BTMASK) | ((x) &N_BTMASK))
#endif

#pragma pack(pop)

#endif  // _WIN32 || defined(__CYGWIN__)

#define CVINFO_PDB70_CVSIGNATURE 0x53445352  // "RSDS"
#define CVINFO_PDB20_CVSIGNATURE 0x3031424e  // "NB10"
#define CODEVIEW_SIGNATURE_MTOC  0x434f544d  // "MTOC"

#pragma pack(push, 1)

typedef struct _CV_HEADER
{
  DWORD dwSignature;
  DWORD dwOffset;
} CV_HEADER, *PCV_HEADER;

typedef struct _CV_INFO_PDB20
{
  CV_HEADER CvHeader;
  DWORD dwSignature;
  DWORD dwAge;
  BYTE PdbFileName[1];
} CV_INFO_PDB20, *PCV_INFO_PDB20;

typedef struct _CV_INFO_PDB70
{
  DWORD CvSignature;
  DWORD Signature[4];
  DWORD Age;
  BYTE PdbFileName[1];
} CV_INFO_PDB70, *PCV_INFO_PDB70;

typedef struct _MTOC_ENTRY
{
  DWORD Signature;
  BYTE uuid[16];
  BYTE PdbFileName[1];
} MTOC_ENTRY, *PMTOC_ENTRY;

typedef struct _VERSION_INFO
{
  WORD Length;
  WORD ValueLength;
  WORD Type;
  char Key[0];
} VERSION_INFO, *PVERSION_INFO;

#define MAX_PE_CERTS 16

#define WIN_CERT_REVISION_1_0 0x0100
#define WIN_CERT_REVISION_2_0 0x0200

#define WIN_CERT_TYPE_X509             0x0001
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_RESERVED_1       0x0003
#define WIN_CERT_TYPE_TS_STACK_SIGNED  0x0004

#define WIN_CERTIFICATE_HEADER_SIZE 8

typedef struct _WIN_CERTIFICATE
{
  DWORD Length;
  WORD Revision;
  WORD CertificateType;
  BYTE Certificate[0];
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;

#define SPC_NESTED_SIGNATURE_OBJID "1.3.6.1.4.1.311.2.4.1"

//
// Rich signature.
// http://www.ntcore.com/files/richsign.htm
//

#define RICH_VERSION_ID(id_version)      (id_version >> 16)
#define RICH_VERSION_VERSION(id_version) (id_version & 0xFFFF)
#define IMAGE_DEBUG_TYPE_UNKNOWN         0
#define IMAGE_DEBUG_TYPE_COFF            1
#define IMAGE_DEBUG_TYPE_CODEVIEW        2
#define IMAGE_DEBUG_TYPE_FPO             3
#define IMAGE_DEBUG_TYPE_MISC            4
#define IMAGE_DEBUG_TYPE_EXCEPTION       5
#define IMAGE_DEBUG_TYPE_FIXUP           6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC     7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC   8
#define IMAGE_DEBUG_TYPE_BORLAND         9
#define IMAGE_DEBUG_TYPE_RESERVED10      10
#define IMAGE_DEBUG_TYPE_CLSID           11
#define IMAGE_DEBUG_TYPE_VC_FEATURE      12
#define IMAGE_DEBUG_TYPE_POGO            13
#define IMAGE_DEBUG_TYPE_ILTCG           14
#define IMAGE_DEBUG_TYPE_MPX             15
#define IMAGE_DEBUG_TYPE_REPRO           16

typedef struct _RICH_VERSION_INFO
{
  DWORD id_version;  // tool id and version (use RICH_VERSION_ID and
                     // RICH_VERSION_VERSION macros)
  DWORD times;       // number of times this tool was used
} RICH_VERSION_INFO, *PRICH_VERSION_INFO;

typedef struct _RICH_SIGNATURE
{
  DWORD dans;
  DWORD key1;
  DWORD key2;
  DWORD key3;
  RICH_VERSION_INFO versions[0];
} RICH_SIGNATURE, *PRICH_SIGNATURE;

#define RICH_DANS 0x536e6144  // "DanS"
#define RICH_RICH 0x68636952  // "Rich"

#define PE_PAGE_SIZE   0x1000
#define PE_SECTOR_SIZE 0x0200

#pragma pack(pop)

#endif
