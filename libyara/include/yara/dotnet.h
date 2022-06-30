#ifndef YR_DOTNET_H
#define YR_DOTNET_H

#include <yara/pe.h>
#include <yara/pe_utils.h>
#include <yara/types.h>

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

// flag in HeapSizes that denotes extra 4 bytes after Rows
#define HEAP_EXTRA_DATA 0x40
#define SIG_FLAG_GENERIC 0x10

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

// The string length of a typelib attribute is at most 0xFF.
#define MAX_TYPELIB_SIZE 0xFF

// Flags and Masks for .NET tables
#define TYPE_ATTR_CLASS_SEMANTIC_MASK 0x20
#define TYPE_ATTR_CLASS               0x0
#define TYPE_ATTR_INTERFACE           0x20

#define TYPE_ATTR_VISIBILITY_MASK      0x7
#define TYPE_ATTR_NOT_PUBLIC           0x0
#define TYPE_ATTR_PUBLIC               0x1
#define TYPE_ATTR_NESTED_PUBLIC        0x2
#define TYPE_ATTR_NESTED_PRIVATE       0x3
#define TYPE_ATTR_NESTED_FAMILY        0x4
#define TYPE_ATTR_NESTED_ASSEMBLY      0x5
#define TYPE_ATTR_NESTED_FAM_AND_ASSEM 0x6
#define TYPE_ATTR_NESTED_FAM_OR_ASSEM  0x7

#define TYPE_ATTR_ABSTRACT 0x80
#define TYPE_ATTR_SEALED   0x100

#define METHOD_ATTR_ACCESS_MASK   0x7
#define METHOD_ATTR_PRIVATE       0x1
#define METHOD_ATTR_FAM_AND_ASSEM 0x2
#define METHOD_ATTR_ASSEM         0x3
#define METHOD_ATTR_FAMILY        0x4
#define METHOD_ATTR_FAM_OR_ASSEM  0x5
#define METHOD_ATTR_PUBLIC        0x6

#define METHOD_ATTR_STATIC   0x10
#define METHOD_ATTR_FINAL    0x20
#define METHOD_ATTR_VIRTUAL  0x40
#define METHOD_ATTR_ABSTRACT 0x400

// Element types ECMA-335 Section II.23.1.16
#define TYPE_END         0x0
#define TYPE_VOID        0x1
#define TYPE_BOOL        0x2
#define TYPE_CHAR        0x3
#define TYPE_I1          0x4
#define TYPE_U1          0x5
#define TYPE_I2          0x6
#define TYPE_U2          0x7
#define TYPE_I4          0x8
#define TYPE_U4          0x9
#define TYPE_I8          0xa
#define TYPE_U8          0xb
#define TYPE_R4          0xc
#define TYPE_R8          0xd
#define TYPE_STRING      0xe
#define TYPE_PTR         0xf
#define TYPE_BYREF       0x10
#define TYPE_VALUETYPE   0x11
#define TYPE_CLASS       0x12
#define TYPE_VAR         0x13
#define TYPE_ARRAY       0x14
#define TYPE_GENERICINST 0x15
#define TYPE_TYPEDREF    0x16
#define TYPE_I           0x18
#define TYPE_U           0x19
#define TYPE_FNPTR       0x1b
#define TYPE_OBJECT      0x1c
#define TYPE_SZARRAY     0x1d
#define TYPE_MVAR        0x1e
#define TYPE_CMOD_REQD   0x1f
#define TYPE_CMOD_OPT    0x20
#define TYPE_INTERNAL    0x21
#define TYPE_MODIFIER    0x40
#define TYPE_SENTINEL    0x41
#define TYPE_PINNED      0x45

// Sane boundaries for invalid files
#define MAX_ARRAY_RANK      50
#define MAX_PARAM_COUNT     2000
#define MAX_GEN_PARAM_COUNT 1000
#define MAX_METHOD_COUNT    20000
#define MAX_STRING_LENGTH   10000
// Sanity check for loops in type parser
#define MAX_TYPE_DEPTH      0x10
#define MAX_NAMESPACE_DEPTH 0x0a

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

// ECMA 335 - II.22.37
typedef struct _TYPEDEF_ROW
{
  uint32_t Flags;
  uint32_t Name;
  uint32_t Namespace;
  uint32_t Extends;
  uint32_t Field;
  uint32_t Method;
} TYPEDEF_ROW, *PTYPEDEF_ROW;

// ECMA 335 - II.22.38
typedef struct _TYPEREF_ROW
{
  uint32_t ResolutionScope;
  uint32_t Name;
  uint32_t Namespace;
} TYPEREF_ROW, *PTYPEREF_ROW;

// ECMA 335 - II.22.39
typedef struct _TYPESPEC_ROW
{
  uint32_t Signature;
} TYPESPEC_ROW, *PTYPESPEC_ROW;

// ECMA 335 - II.22.23
typedef struct _INTERFACEIMPL_ROW
{
  uint32_t Class;
  uint32_t Interface;
} INTERFACEIMPL_ROW, *PINTERFACEIMPL_ROW;

// ECMA 335 II.22.26
typedef struct _METHODDEF_ROW
{
  uint32_t Rva;
  uint16_t ImplFlags;
  uint16_t Flags;
  uint32_t Name;
  uint32_t Signature;
  uint32_t ParamList;
} METHODDEF_ROW, *PMETHODDEF_ROW;

// ECMA 335 II.22.33
typedef struct _PARAM_ROW
{
  uint16_t Flags;
  uint16_t Sequence;
  uint32_t Name;
} PARAM_ROW, *PPARAM_ROW;

// ECMA 335 II.22.20
typedef struct _GENERICPARAM_ROW
{
  uint16_t Number;
  uint16_t Flags;
  uint32_t Owner;
  uint32_t Name;
} GENERICPARAM_ROW, *PGENERICPARAM_ROW;

// ECMA 335 II.22.32
typedef struct _NESTEDCLASS_ROW
{
  uint32_t NestedClass;
  uint32_t EnclosingClass;
} NESTEDCLASS_ROW, *PNESTEDCLASS_ROW;

// For easy passing of gen param collection
typedef struct _GENERIC_PARAMETERS
{
  char **names;
  uint32_t len;
} GENERIC_PARAMETERS, *PGENERIC_PARAMETERS;

// Used to return offsets to the various headers.
typedef struct _STREAMS
{
  int64_t metadata_root;  // base from which are stream offsets relative
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
  uint32_t length;  // Value of the bytes parsed. This is the blob length.
} BLOB_PARSE_RESULT, *PBLOB_PARSE_RESULT;

typedef struct _TABLE_INFO
{
  uint8_t *Offset;
  uint32_t RowCount;
  uint32_t RowSize;
} TABLE_INFO, *PTABLE_INFO;

// Structure that stores table information for parsing
typedef struct _TABLES
{
  TABLE_INFO typedef_;
  TABLE_INFO typespec;
  TABLE_INFO typeref;
  TABLE_INFO methoddef;
  TABLE_INFO param;
  TABLE_INFO module;
  TABLE_INFO moduleref;
  TABLE_INFO assembly;
  TABLE_INFO assemblyref;
  TABLE_INFO intefaceimpl;
  TABLE_INFO genericparam;
  TABLE_INFO nestedclass;
} TABLES, *PTABLES;

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
  uint8_t methodspec;
  uint8_t memberref;
  uint8_t param;
  uint8_t event;
  uint8_t typedef_;
  uint8_t typeref;
  uint8_t typespec;
  uint8_t interfaceimpl;
  uint8_t property;
  uint8_t moduleref;
  uint8_t module;
  uint8_t assemblyrefprocessor;
  uint8_t assemblyref;
  uint8_t assembly;
  uint8_t genericparam;
} INDEX_SIZES, *PINDEX_SIZES;

typedef struct _CLASS_CONTEXT
{
  PE* pe;
  TABLES* tables;
  INDEX_SIZES* index_sizes;
  const uint8_t* str_heap;
  uint32_t str_size;
  const uint8_t* blob_heap;
  uint32_t blob_size;
} CLASS_CONTEXT, *PCLASS_CONTEXT;

typedef struct _PARAMETERS
{
  char* name;
  char* type;
  bool alloc;  // if name is allocated and needs to be free
} PARAMETERS, *PPARAMETERS;

#pragma pack(pop)
#endif
