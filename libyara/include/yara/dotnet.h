#ifndef YR_DOTNET_H
#define YR_DOTNET_H

#include <yara/pe.h>

#pragma pack(push, 1)

//
// CLI header.
// ECMA-335 Section II.25.3.3
//
typedef struct _CLI_HEADER
{
  DWORD Size;  // Called "Cb" in documentation.
  WORD MajorRuntimeVersion;
  WORD MinorRuntimeVersion;
  IMAGE_DATA_DIRECTORY MetaData;
  DWORD Flags;
  DWORD EntryPointToken;
  IMAGE_DATA_DIRECTORY Resources;
  IMAGE_DATA_DIRECTORY StrongNameSignature;
  ULONGLONG CodeManagerTable;
  IMAGE_DATA_DIRECTORY VTableFixups;
  ULONGLONG ExportAddressTableJumps;
  ULONGLONG ManagedNativeHeader;
} CLI_HEADER, *PCLI_HEADER;

#define NET_METADATA_MAGIC 0x424a5342

//
// Runtime flags
// ECMA-335 Section II.25.3.3.1
//
// COMIMAGE_FLAGS_IL_LIBRARY is not part of ECMA-335, but it is in Windows
// header files, to include winnt.h
#define COMIMAGE_FLAGS_ILONLY                 0x00000001
#define COMIMAGE_FLAGS_32BITREQUIRED          0x00000002
#define COMIMAGE_FLAGS_IL_LIBRARY             0x00000004
#define COMIMAGE_FLAGS_STRONGNAMESIGNED       0x00000008
#define COMIMAGE_FLAGS_NATIVE_ENTRYPOINT      0x00000010
#define COMIMAGE_FLAGS_TRACKDEBUGDATA         0x00010000

//
// Flags for methods [MethodAttributes]
// ECMA-335 Section II.23.1.10
//
// These three bits contain one of the following values
#define METHOD_FLAGS_MEMBER_ACCESS_MASK       0x0007
#define METHOD_FLAGS_COMPILER_CONTROLLED      0x0000
#define METHOD_FLAGS_PRIVATE                  0x0001
#define METHOD_FLAGS_FAM_AND_ASSEM            0x0002
#define METHOD_FLAGS_ASSEM                    0x0003
#define METHOD_FLAGS_FAMILY                   0x0004
#define METHOD_FLAGS_FAM_OR_ASSEM             0x0005
#define METHOD_FLAGS_PUBLIC                   0x0006

#define METHOD_FLAGS_STATIC                   0x0010
#define METHOD_FLAGS_FINAL                    0x0020
#define METHOD_FLAGS_VIRTUAL                  0x0040
#define METHOD_FLAGS_HIDE_BY_SIG              0x0080

// Use this mask to retrieve vtable attributes. This bit
// contains one of the following values
#define METHOD_FLAGS_VTABLE_LAYOUT_MASK       0x0100
#define METHOD_FLAGS_REUSE_SLOT               0x0000
#define METHOD_FLAGS_NEW_SLOT                 0x0100

#define METHOD_FLAGS_STRICT                   0x0200
#define METHOD_FLAGS_ABSTRACT                 0x0400
#define METHOD_FLAGS_SPECIAL_NAME             0x0800

// Interop attributes
#define METHOD_FLAGS_PINVOKE_IMPL             0x2000
#define METHOD_FLAGS_UNMANAGED_EXPORT         0x0008

// Additional flags
#define METHOD_FLAGS_RTS_SPECIAL_NAME         0x1000
#define METHOD_FLAGS_HAS_SECURITY             0x4000
#define METHOD_FLAGS_REQUIRE_SEC_OBJECT       0x8000

//
// Flags for methods [MethodImplAttributes]
// ECMA-335 Section II.23.1.11
//

// these two bits contain one of the follwing values
#define METHOD_IMPL_FLAGS_CODE_TYPE_MASK      0x0003
#define METHOD_IMPL_FLAGS_IL                  0x0000
#define METHOD_IMPL_FLAGS_IS_NATIVE           0x0001
#define METHOD_IMPL_FLAGS_OPTIL               0x0002
#define METHOD_IMPL_FLAGS_RUNTIME             0x0003

// Flags specifying whether code is managed or unmanaged.
// This bit contains one of the following values
#define METHOD_IMPL_FLAGS_MANAGED_MASK        0x0004
#define METHOD_IMPL_FLAGS_UNMANAGED           0x0004
#define METHOD_IMPL_FLAGS_MANAGED             0x0000

// Implementation info and interop
#define METHOD_IMPL_FLAGS_FORWARD_REF         0x0010
#define METHOD_IMPL_FLAGS_PRESERVE_SIG        0x0080
#define METHOD_IMPL_FLAGS_INTERNAL_CALL       0x1000
#define METHOD_IMPL_FLAGS_SYNCHRONIZED        0x0020
#define METHOD_IMPL_FLAGS_NO_INLINING         0x0008
#define METHOD_IMPL_FLAGS_NO_OPTIMIZATION     0x0040

//
// Flags for ImplMap [PInvokeAttributes]
// ECMA-335 Section II.23.1.8
//
#define PINVOKE_FLAGS_NO_MANGLE               0x0001
#define PINVOKE_FLAGS_CHAR_SET_MASK           0x0006
#define PINVOKE_FLAGS_CHAR_SET_NOT_SPEC       0x0000
#define PINVOKE_FLAGS_CHAR_SET_ANSI           0x0002
#define PINVOKE_FLAGS_CHAR_SET_UNICODE        0x0004
#define PINVOKE_FLAGS_CHAR_SET_AUTO           0x0006
#define PINVOKE_FLAGS_SUPPORT_GET_LAST_ERROR  0x0040
#define PINVOKE_FLAGS_CALL_CONV_MASK          0x0700
#define PINVOKE_FLAGS_CALL_CONV_PLATFORM_API  0x0100
#define PINVOKE_FLAGS_CALL_CONV_CDECL         0x0200
#define PINVOKE_FLAGS_CALL_CONV_STDCALL       0x0300
#define PINVOKE_FLAGS_CALL_CONV_THISCALL      0x0400
#define PINVOKE_FLAGS_CALL_CONV_FASTCALL      0x0500

//
// CLI MetaData
// ECMA-335 Section II.24.2.1
//
// Note: This is only part of the struct, as the rest of it is variable length.
//
typedef struct _NET_METADATA
{
  DWORD Magic;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Reserved;
  DWORD Length;
  char Version[0];
} NET_METADATA, *PNET_METADATA;

#define DOTNET_STREAM_NAME_SIZE 32

//
// CLI Stream Header
// ECMA-335 Section II.24.2.2
//
typedef struct _STREAM_HEADER
{
  DWORD Offset;
  DWORD Size;
  char Name[0];
} STREAM_HEADER, *PSTREAM_HEADER;

//
// CLI #~ Stream Header
// ECMA-335 Section II.24.2.6
//
typedef struct _TILDE_HEADER
{
  DWORD Reserved1;
  BYTE MajorVersion;
  BYTE MinorVersion;
  BYTE HeapSizes;
  BYTE Reserved2;
  ULONGLONG Valid;
  ULONGLONG Sorted;
} TILDE_HEADER, *PTILDE_HEADER;

// These are the bit positions in Valid which will be set if the table
// exists.
#define BIT_MODULE                 0x00
#define BIT_TYPEREF                0x01
#define BIT_TYPEDEF                0x02
#define BIT_FIELDPTR               0x03  // Not documented in ECMA-335
#define BIT_FIELD                  0x04
#define BIT_METHODDEFPTR           0x05  // Not documented in ECMA-335
#define BIT_METHODDEF              0x06
#define BIT_PARAMPTR               0x07  // Not documented in ECMA-335
#define BIT_PARAM                  0x08
#define BIT_INTERFACEIMPL          0x09
#define BIT_MEMBERREF              0x0A
#define BIT_CONSTANT               0x0B
#define BIT_CUSTOMATTRIBUTE        0x0C
#define BIT_FIELDMARSHAL           0x0D
#define BIT_DECLSECURITY           0x0E
#define BIT_CLASSLAYOUT            0x0F
#define BIT_FIELDLAYOUT            0x10
#define BIT_STANDALONESIG          0x11
#define BIT_EVENTMAP               0x12
#define BIT_EVENTPTR               0x13  // Not documented in ECMA-335
#define BIT_EVENT                  0x14
#define BIT_PROPERTYMAP            0x15
#define BIT_PROPERTYPTR            0x16  // Not documented in ECMA-335
#define BIT_PROPERTY               0x17
#define BIT_METHODSEMANTICS        0x18
#define BIT_METHODIMPL             0x19
#define BIT_MODULEREF              0x1A
#define BIT_TYPESPEC               0x1B
#define BIT_IMPLMAP                0x1C
#define BIT_FIELDRVA               0x1D
#define BIT_ENCLOG                 0x1E  // Not documented in ECMA-335
#define BIT_ENCMAP                 0x1F  // Not documented in ECMA-335
#define BIT_ASSEMBLY               0x20
#define BIT_ASSEMBLYPROCESSOR      0x21
#define BIT_ASSEMBLYOS             0x22
#define BIT_ASSEMBLYREF            0x23
#define BIT_ASSEMBLYREFPROCESSOR   0x24
#define BIT_ASSEMBLYREFOS          0x25
#define BIT_FILE                   0x26
#define BIT_EXPORTEDTYPE           0x27
#define BIT_MANIFESTRESOURCE       0x28
#define BIT_NESTEDCLASS            0x29
#define BIT_GENERICPARAM           0x2A
#define BIT_METHODSPEC             0x2B
#define BIT_GENERICPARAMCONSTRAINT 0x2C
// These are not documented in ECMA-335 nor is it clear what the format is.
// They are for debugging information as far as I can tell.
//#define BIT_DOCUMENT               0x30
//#define BIT_METHODDEBUGINFORMATION 0x31
//#define BIT_LOCALSCOPE             0x32
//#define BIT_LOCALVARIABLE          0x33
//#define BIT_LOCALCONSTANT          0x34
//#define BIT_IMPORTSCOPE            0x35
//#define BIT_STATEMACHINEMETHOD     0x36

//
// Element types. Note this is not a complete list as we aren't parsing all of
// them. This only includes the ones we care about.
// ECMA-335 Section II.23.1.16
//
#define ELEMENT_TYPE_STRING 0x0E

// The string length of a typelib attribute is at most 0xFF.
#define MAX_TYPELIB_SIZE 0xFF

//
// Module table
// ECMA-335 Section II.22.25
//
typedef struct _MEMBERREF_TABLE
{
  union
  {
    WORD Class_Short;
    DWORD Class_Long;
  } Class;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
  union
  {
    WORD Signature_Short;
    DWORD Signature_Long;
  } Signature;
}MEMBERREF_TABLE, *PMEMBERREF_TABLE;

//
// Module table
// ECMA-335 Section II.22.30
//
typedef struct _MODULE_TABLE
{
  WORD Generation;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
  union
  {
    WORD Mvid_Short;
    DWORD Mvid_Long;
  } Mvid;
  union
  {
    WORD EncId_Short;
    DWORD EncId_Long;
  } EncId;
  union
  {
    WORD EncBaseId_Short;
    DWORD EncBaseId_Long;
  } EncBaseId;
} MODULE_TABLE, *PMODULE_TABLE;

//
// Assembly Table
// ECMA-335 Section II.22.2
//
typedef struct _ASSEMBLY_TABLE
{
  DWORD HashAlgId;
  WORD MajorVersion;
  WORD MinorVersion;
  WORD BuildNumber;
  WORD RevisionNumber;
  DWORD Flags;
  union
  {
    WORD PublicKey_Short;
    DWORD PublicKey_Long;
  } PublicKey;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
} ASSEMBLY_TABLE, *PASSEMBLY_TABLE;

//
// Assembly Reference Table
// ECMA-335 Section II.22.5
//
typedef struct _ASSEMBLYREF_TABLE
{
  WORD MajorVersion;
  WORD MinorVersion;
  WORD BuildNumber;
  WORD RevisionNumber;
  DWORD Flags;
  union
  {
    WORD PublicKeyOrToken_Short;
    DWORD PublicKeyOrToken_Long;
  } PublicKeyOrToken;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
} ASSEMBLYREF_TABLE, *PASSEMBLYREF_TABLE;

//
// Manifest Resource Table
// ECMA-335 Section II.22.22
//
typedef struct _IMPLMAP_TABLE
{
  WORD MappingFlags;
  union
  {
    WORD MemberForwarded_Short;
    DWORD MemberForwarded_Long;
  } MemberForwarded;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } ImportName;
  union
  {
    WORD ImportScope_Short;
    DWORD ImportScope_Long;
  } ImportScope;
} IMPLMAP_TABLE, *PIMPLMAP_TABLE;

//
// Manifest Resource Table
// ECMA-335 Section II.22.24
//
typedef struct _MANIFESTRESOURCE_TABLE
{
  DWORD Offset;
  DWORD Flags;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
  union
  {
    WORD Implementation_Short;
    DWORD Implementation_Long;
  } Implementation;
} MANIFESTRESOURCE_TABLE, *PMANIFESTRESOURCE_TABLE;

//
// TypeRef Table
// ECMA-335 Section II.22.38
//
typedef struct _TYPEREF_TABLE
{
  union
  {
    WORD ResolutionScope_Short;
    DWORD ResolutionScope_Long;
  } ResolutionScope;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Namespace;
} TYPEREF_TABLE, *PTYPEREF_TABLE;

//
// MethodDef Table
// ECMA-335 Section II.22.26
//
typedef struct _METHODDEF_TABLE
{
  DWORD RVA;
  WORD ImplFlags;
  WORD Flags;
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
  union
  {
    WORD Signature_Short;
    DWORD Signature_Long;
  } Signature;
  union
  {
    WORD ParamList_Short;
    DWORD ParamList_Long;
  } ParamList;
} METHODDEF_TABLE, *PMETHODDEF_TABLE;

//
// ModuleRef Table
// ECMA-335 Section II.22.31
//
// This is a short table, but necessary because the field size can change.
//
typedef struct _MODULEREF_TABLE
{
  union
  {
    WORD Name_Short;
    DWORD Name_Long;
  } Name;
} MODULEREF_TABLE, *PMODULEREF_TABLE;

//
// FieldRVA Table
// ECMA-335 Section II.22.18
//
typedef struct _FIELDRVA_TABLE
{
  DWORD RVA;
  union
  {
    WORD Field_Short;
    DWORD Field_LONG;
  } Field;
} FIELDRVA_TABLE, *PFIELDRVA_TABLE;

//
// CustomAttribute Table
// ECMA-335 Section II.22.10
//
typedef struct _CUSTOMATTRIBUTE_TABLE
{
  union
  {
    WORD Parent_Short;
    DWORD Parent_Long;
  } Parent;
  union
  {
    WORD Type_Short;
    DWORD Type_Long;
  } Type;
  union
  {
    WORD Value_Short;
    DWORD Value_Long;
  } Value;
} CUSTOMATTRIBUTE_TABLE, *PCUSTOMATTRIBUTE_TABLE;

//
// Constant TAble
// ECMA-335 Section II.22.9
//
typedef struct _CONSTANT_TABLE
{
  WORD Type;
  union
  {
    WORD Parent_Short;
    DWORD Parent_Long;
  } Parent;
  union
  {
    WORD Value_Short;
    DWORD Value_Long;
  } Value;
} CONSTANT_TABLE, *PCONSTANT_TABLE;

// Used to return offsets to the various headers.
typedef struct _STREAMS
{
  PSTREAM_HEADER guid;
  PSTREAM_HEADER tilde;
  PSTREAM_HEADER string;
  PSTREAM_HEADER blob;
  PSTREAM_HEADER us;
} STREAMS, *PSTREAMS;

// Used to return the value of parsing a #US or #Blob entry.
// ECMA-335 Section II.24.2.4
typedef struct _BLOB_PARSE_RESULT
{
  uint8_t size;  // Number of bytes parsed. This is the new offset.
  DWORD length;  // Value of the bytes parsed. This is the blob length.
} BLOB_PARSE_RESULT, *PBLOB_PARSE_RESULT;

// Used to store the number of rows of each table.
typedef struct _ROWS
{
  uint32_t module;
  uint32_t moduleref;
  uint32_t assemblyref;
  uint32_t typeref;
  uint32_t methoddef;
  uint32_t memberref;
  uint32_t typedef_;
  uint32_t typespec;
  uint32_t field;
  uint32_t param;
  uint32_t property;
  uint32_t interfaceimpl;
  uint32_t event;
  uint32_t standalonesig;
  uint32_t assembly;
  uint32_t file;
  uint32_t exportedtype;
  uint32_t manifestresource;
  uint32_t genericparam;
  uint32_t genericparamconstraint;
  uint32_t methodspec;
  uint32_t assemblyrefprocessor;
} ROWS, *PROWS;

// Used to store the index sizes for the various tables.
typedef struct _INDEX_SIZES
{
  uint8_t string;
  uint8_t guid;
  uint8_t blob;
  uint8_t field;
  uint8_t methoddef;
  uint8_t memberref;
  uint8_t param;
  uint8_t event;
  uint8_t typedef_;
  uint8_t property;
  uint8_t moduleref;
  uint8_t assemblyrefprocessor;
  uint8_t assemblyref;
  uint8_t genericparam;
} INDEX_SIZES, *PINDEX_SIZES;

#pragma pack(pop)
#endif
