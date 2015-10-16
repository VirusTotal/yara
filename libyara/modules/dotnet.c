/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

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
#include <time.h>
#include <config.h>

#include <yara/pe.h>
#include <yara/dotnet.h>
#include <yara/modules.h>
#include <yara/mem.h>

#include <yara/pe_utils.h>

#define MODULE_NAME dotnet

/*
typedef struct _PE
{
  uint8_t* data;
  size_t data_size;

  union {
    PIMAGE_NT_HEADERS32 header;
    PIMAGE_NT_HEADERS64 header64;
  };

  YR_OBJECT* object;

} PE;
*/


char* pe_get_dotnet_string(
    PE* pe,
    uint8_t* string_offset,
    DWORD string_index)
{
  size_t remaining;

  // Start of string must be within boundary
  if (!(string_offset + string_index >= pe->data &&
        string_offset + string_index < pe->data + pe->data_size))
    return NULL;

  // Calculate how much until end of boundary, don't scan past that.
  remaining = (pe->data + pe->data_size) - (string_offset + string_index);

  // Search for a NULL terminator from string_offset, up to remaining.
  return strnstr((char *) (string_offset + string_index), "\0", remaining);
}


uint32_t max_rows(int count, ...)
{
  va_list ap;
  int i;
  uint32_t biggest;
  uint32_t x;

  if (count == 0)
    return 0;

  va_start(ap, count);
  biggest = va_arg(ap, uint32_t);
  for (i = 1; i < count; i++)
  {
    x = va_arg(ap, uint32_t);
    biggest = (x > biggest) ? x : biggest;
  }

  va_end(ap);
  return biggest;
}

void pe_parse_com(
    PE* pe,
    size_t base_address)
{
  PIMAGE_DATA_DIRECTORY directory;
  PCLI_HEADER cli_header;
  PNET_METADATA metadata;
  PSTREAM_HEADER stream_header;
  PTILDE_HEADER tilde_header = NULL;
  PMODULE_TABLE module_table;
  PASSEMBLY_TABLE assembly_table;
  PMANIFESTRESOURCE_TABLE manifestresource_table;
  PMODULEREF_TABLE moduleref_table;
  WORD streams;
  DWORD guid_size;
  DWORD resource_size;
  DWORD implementation;
  int64_t metadata_root, offset, resource_base, resource_offset;
  uint32_t row_size, counter;
  uint8_t* guid_offset = NULL;
  uint32_t* row_offset = NULL;
  uint8_t* table_offset = NULL;
  uint8_t* row_ptr = NULL;
  uint8_t* string_offset = NULL;
  char *version;
  int i, g, bit_check;
  // This is used as an offset into the rows and tables. For every bit set in
  // Valid this will be incremented. This is because the bit position doesn't
  // matter, just the number of bits that are set, when determining how many
  // rows and what the table structure is.
  int matched_bits = 0;
  // GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
  char guid[37];
  char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
  char *name;
  // We need to know the number of rows for some tables, because they are
  // indexed into. The index will be either 2 or 4 bytes, depending upon the
  // number of rows being indexed into. Default them all to 0 rows and they
  // will be set to actual values later on, if they exist in the file.
  uint32_t module_rows = 0;
  uint32_t moduleref_rows = 0;
  uint32_t assemblyref_rows = 0;
  uint32_t typeref_rows = 0;
  uint32_t methoddef_rows = 0;
  uint32_t memberref_rows = 0;
  uint32_t typedef_rows = 0;
  uint32_t typespec_rows = 0;
  uint32_t field_rows = 0;
  uint32_t param_rows = 0;
  uint32_t property_rows = 0;
  uint32_t interfaceimpl_rows = 0;
  uint32_t event_rows = 0;
  uint32_t standalonesig_rows = 0;
  uint32_t assembly_rows = 0;
  uint32_t file_rows = 0;
  uint32_t exportedtype_rows = 0;
  uint32_t manifestresource_rows = 0;
  uint32_t genericparam_rows = 0;
  uint32_t genericparamconstraint_rows = 0;
  uint32_t methodspec_rows = 0;
  uint32_t assemblyrefprocessor_rows = 0;
  uint32_t rows;
  uint32_t valid_rows = 0;
  uint32_t num_rows = 0;
  // Default index sizes are 2. Will be bumped to 4 if necessary.
  uint8_t string_index_size = 2;
  uint8_t guid_index_size = 2;
  uint8_t blob_index_size = 2;
  uint8_t field_index_size = 2;
  uint8_t methoddef_index_size = 2;
  uint8_t param_index_size = 2;
  uint8_t event_index_size = 2;
  uint8_t typedef_index_size = 2;
  uint8_t property_index_size = 2;
  uint8_t moduleref_index_size = 2;
  uint8_t assemblyrefprocessor_index_size = 2;
  uint8_t assemblyref_index_size = 2;
  uint8_t genericparam_index_size = 2;
  // These are used to determine the size of coded indexes, which are the
  // dynamically sized columns for some tables. The coded indexes are
  // documented in ECMA-335 Section II.24.2.6.
  uint8_t index_size, index_size2;

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

  offset = pe_rva_to_offset(pe, directory->VirtualAddress);

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return;

  cli_header = (PCLI_HEADER) (pe->data + offset);

  offset = metadata_root = pe_rva_to_offset(pe, cli_header->MetaData.VirtualAddress);
  if (!struct_fits_in_pe(pe, pe->data + offset, NET_METADATA))
    return;

  metadata = (PNET_METADATA) (pe->data + offset);

  if (metadata->Magic != NET_METADATA_MAGIC)
    return;

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  if (metadata->Length == 0 ||
      metadata->Length > 255 ||
      metadata->Length % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset, metadata->Length))
    return;

  version = (char*) yr_malloc(metadata->Length + 1);

  if (!version)
    return;

  strncpy(version, metadata->Version, metadata->Length);
  set_string(version, pe->object, "dotnet_version");
  yr_free(version);

  // The metadata structure has some variable length records after the version.
  // We must manually parse things from here on out.
  //
  // Flags are 2 bytes (always 0).
  offset += sizeof(NET_METADATA) + metadata->Length + 2;

  // 2 bytes for Streams.
  if (!fits_in_pe(pe, pe->data + offset, 2))
    return;

  streams = (WORD) *(pe->data + offset);
  offset += 2;

  stream_header = (PSTREAM_HEADER) (pe->data + offset);

  for (i = 0; i < streams; i++)
  {
    if (!struct_fits_in_pe(pe, stream_header, STREAM_HEADER))
      break;

    strncpy(stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
    stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

    set_string(stream_name,
        pe->object, "dotnet_streams[%i].name", i);
    // Offset is relative to metadata_root.
    set_integer(metadata_root + stream_header->Offset,
        pe->object, "dotnet_streams[%i].offset", i);
    set_integer(stream_header->Size,
        pe->object, "dotnet_streams[%i].size", i);

    // Store necessary bits to parse these later. Not all tables will be
    // parsed, but are referenced from others. For example, the #Strings
    // stream is referenced from various tables in the #~ heap.
    if (strncmp(stream_name, "#GUID", 5) == 0)
    {
      guid_offset = pe->data + metadata_root + stream_header->Offset;
      guid_size = stream_header->Size;
    }
    // Believe it or not, I have seen at least one binary which has a #- stream
    // instead of a #~ (215e1b54ae1aac153e55596e6f1a4350). This isn't in the
    // documentation anywhere but the structure is the same. I'm chosing not
    // to parse it for now.
    else if (strncmp(stream_name, "#~", 2) == 0 && tilde_header == NULL)
      tilde_header = (PTILDE_HEADER) ((uint8_t*) pe->data + metadata_root + stream_header->Offset);
    else if (strncmp(stream_name, "#Strings", 8) == 0 && string_offset == NULL)
    {
      string_offset = pe->data + metadata_root + stream_header->Offset;
    }

    // Stream name is padded to a multiple of 4.
    stream_header = (PSTREAM_HEADER) ((uint8_t*) stream_header +
        sizeof(STREAM_HEADER) +
        strlen(stream_name) +
        4 - (strlen(stream_name) % 4));
  }

  set_integer(i, pe->object, "number_of_dotnet_streams");

  // Parse GUIDs if we have them.
  if (guid_offset != NULL)
  {
    g = 0;

    // GUIDs are 16 bytes each.
    while (guid_size >= 16 && fits_in_pe(pe, guid_offset, 16))
    {
      sprintf(guid, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
          *(uint32_t*) guid_offset,
          *(uint16_t*) (guid_offset + 4),
          *(uint16_t*) (guid_offset + 6),
          *(guid_offset + 8),
          *(guid_offset + 9),
          *(guid_offset + 10),
          *(guid_offset + 11),
          *(guid_offset + 12),
          *(guid_offset + 13),
          *(guid_offset + 14),
          *(guid_offset + 15));
      guid[(16 * 2) + 4] = '\0';

      set_string(guid, pe->object, "dotnet_guids[%i]", g);

      g++;
      guid_size -= 16;
    }

    set_integer(g, pe->object, "number_of_dotnet_guids");
  }

  // Parse the #~ stream, which includes various tables of interest.
  if (tilde_header != NULL)
  {
    if (!struct_fits_in_pe(pe,
          pe->data + metadata_root + stream_header->Offset, TILDE_HEADER))
        return;

    // Set index sizes for various heaps.
    if (tilde_header->HeapSizes & 0x01)
      string_index_size = 4;
    if (tilde_header->HeapSizes & 0x02)
      guid_index_size = 4;
    if (tilde_header->HeapSizes & 0x04)
      blob_index_size = 4;

    // Number of rows is the number of bits set to 1 in Valid.
    // Should use this technique:
    // http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
    for (g = 0; g < 64; g++)
      valid_rows += ((tilde_header->Valid >> g) & 0x01);

    // Immediately after the tilde header is an array of 32bit values which
    // indicate how many rows are in each table. The tables are immediately
    // after the rows array.
    //
    // Save the row offset and calculate the table offset.
    row_offset = (uint32_t*) (tilde_header + 1);
    table_offset = (uint8_t*) row_offset;
    table_offset += sizeof(uint32_t) * valid_rows;

    // Walk all the bits first because we need to know the number of rows for
    // some tables in order to parse others. In particular this applies to
    // coded indexes, which are documented in ECMA-335 II.24.2.6.
    for (bit_check = 0; bit_check < 64; bit_check++)
    {
      if (!((tilde_header->Valid >> bit_check) & 0x01))
        continue;

      switch (bit_check)
      {
        case BIT_MODULE:
          module_rows = *(row_offset + matched_bits);
          break;
        case BIT_MODULEREF:
          moduleref_rows = *(row_offset + matched_bits);
          if (moduleref_rows > 0xFFFF)
            moduleref_index_size = 4;
          break;
        case BIT_ASSEMBLYREF:
          assemblyref_rows = *(row_offset + matched_bits);
          if (assemblyref_rows > 0xFFFF)
            assemblyref_index_size = 4;
          break;
        case BIT_ASSEMBLYREFPROCESSOR:
          assemblyrefprocessor_rows = *(row_offset + matched_bits);
          if (assemblyrefprocessor_rows > 0xFFFF)
            assemblyrefprocessor_index_size = 4;
          break;
        case BIT_TYPEREF:
          typeref_rows = *(row_offset + matched_bits);
        case BIT_METHODDEF:
          methoddef_rows = *(row_offset + matched_bits);
          if (methoddef_rows > 0xFFFF)
            methoddef_index_size = 4;
          break;
        case BIT_MEMBERREF:
          memberref_rows = *(row_offset + matched_bits);
          break;
        case BIT_TYPEDEF:
          typedef_rows = *(row_offset + matched_bits);
          if (typedef_rows > 0xFFFF)
            typedef_index_size = 4;
          break;
        case BIT_TYPESPEC:
          typespec_rows = *(row_offset + matched_bits);
          break;
        case BIT_FIELD:
          field_rows = *(row_offset + matched_bits);
          if (field_rows > 0xFFFF)
            field_index_size = 4;
          break;
        case BIT_PARAM:
          param_rows = *(row_offset + matched_bits);
          if (param_rows > 0xFFFF)
            param_index_size = 4;
          break;
        case BIT_PROPERTY:
          property_rows = *(row_offset + matched_bits);
          if (property_rows > 0xFFFF)
            property_index_size = 4;
          break;
        case BIT_INTERFACEIMPL:
          interfaceimpl_rows = *(row_offset + matched_bits);
          break;
        case BIT_EVENT:
          event_rows = *(row_offset + matched_bits);
          if (event_rows > 0xFFFF)
            event_index_size = 4;
          break;
        case BIT_STANDALONESIG:
          standalonesig_rows = *(row_offset + matched_bits);
          break;
        case BIT_ASSEMBLY:
          assembly_rows = *(row_offset + matched_bits);
          break;
        case BIT_FILE:
          file_rows = *(row_offset + matched_bits);
          break;
        case BIT_EXPORTEDTYPE:
          exportedtype_rows = *(row_offset + matched_bits);
          break;
        case BIT_MANIFESTRESOURCE:
          manifestresource_rows = *(row_offset + matched_bits);
          break;
        case BIT_GENERICPARAM:
          genericparam_rows = *(row_offset + matched_bits);
          if (genericparam_rows > 0xFFFF)
            genericparam_index_size = 4;
          break;
        case BIT_GENERICPARAMCONSTRAINT:
          genericparamconstraint_rows = *(row_offset + matched_bits);
          break;
        case BIT_METHODSPEC:
          methodspec_rows = *(row_offset + matched_bits);
          break;
        default:
          break;
      }

      matched_bits++;
    }

    matched_bits = 0;

#define DOTNET_STRING_INDEX(string_index_size, Name) \
    string_index_size == 2 ? Name.Name_Short : Name.Name_Long

    // Now walk again this time parsing out what we care about.
    for (bit_check = 0; bit_check < 64; bit_check++)
    {
      // If the Valid bit is not set for this table, skip it...
      if (!((tilde_header->Valid >> bit_check) & 0x01))
        continue;

      // Make sure table_offset doesn't go crazy by inserting a large value
      // for num_rows. For example edc05e49dd3810be67942b983455fd43 sets a
      // large value for number of rows for the BIT_MODULE section.
      if (!fits_in_pe(pe, table_offset, 1))
        return;

      num_rows = *(row_offset + matched_bits);

      // Those tables which exist, but that we don't care about must be
      // skipped.
      //
      // Sadly, given the dynamic sizes of some columns we can not have well
      // defined structures for all tables and use them accordingly. To deal
      // with this manually move the table_offset pointer by the appropriate
      // number of bytes as described in the documentation for each table.
      //
      // The table structures are documented in ECMA-335 Section II.22.
      switch (bit_check)
      {
        case BIT_MODULE:
          module_table = (PMODULE_TABLE) table_offset;
          name = pe_get_dotnet_string(pe,
              string_offset,
              DOTNET_STRING_INDEX(string_index_size, module_table->Name));
          if (name != NULL)
            set_string(name, pe->object, "dotnet_module_name");

          table_offset += (2 + string_index_size + (guid_index_size * 3)) * num_rows;
          break;
        case BIT_TYPEREF:
          rows = max_rows(4,
              module_rows, moduleref_rows, assemblyref_rows, typeref_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (index_size + (string_index_size * 2)) * num_rows;
          break;
        case BIT_TYPEDEF:
          rows = max_rows(3, typedef_rows, typeref_rows, typespec_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (4 + (string_index_size * 2) + index_size + field_index_size + methoddef_index_size) * num_rows;
          break;
        case BIT_FIELDPTR:
          // This one is not documented in ECMA-335.
          table_offset += (field_index_size) * num_rows;
          break;
        case BIT_FIELD:
          table_offset += (2 + (string_index_size) + blob_index_size) * num_rows;
          break;
        case BIT_METHODDEFPTR:
          // This one is not documented in ECMA-335.
          table_offset += (methoddef_index_size) * num_rows;
          break;
        case BIT_METHODDEF:
          table_offset += (4 + 2 + 2 + string_index_size + blob_index_size + param_index_size) * num_rows;
          break;
        case BIT_PARAM:
          table_offset += (2 + 2 + string_index_size) * num_rows;
          break;
        case BIT_INTERFACEIMPL:
          rows = max_rows(3, typedef_rows, typeref_rows, typespec_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (typedef_index_size + index_size) * num_rows;
          break;
        case BIT_MEMBERREF:
          rows = max_rows(4, methoddef_rows, moduleref_rows, typeref_rows, typespec_rows);

          if (rows > (0xFFFF >> 0x03))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (index_size + string_index_size + blob_index_size) * num_rows;
          break;
        case BIT_CONSTANT:
          rows = max_rows(3, param_rows, field_rows, property_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (1 + 1 + index_size + blob_index_size) * num_rows;
          break;
        case BIT_CUSTOMATTRIBUTE:
          rows = max_rows(21, methoddef_rows, field_rows, typeref_rows,
              typedef_rows, param_rows, interfaceimpl_rows, memberref_rows,
              module_rows, property_rows, event_rows,
              standalonesig_rows, moduleref_rows, typespec_rows, assembly_rows,
              assemblyref_rows, file_rows, exportedtype_rows,
              manifestresource_rows, genericparam_rows,
              genericparamconstraint_rows, methodspec_rows);

          if (rows > (0xFFFF >> 0x05))
            index_size = 4;
          else
            index_size = 2;

          rows = max_rows(2, methoddef_rows, memberref_rows);

          if (rows > (0xFFFF >> 0x03))
            index_size2 = 4;
          else
            index_size2 = 2;

          table_offset += (index_size + index_size2 + blob_index_size) * num_rows;
          break;
        case BIT_FIELDMARSHAL:
          rows = max_rows(2, field_rows, param_rows);

          if (rows > (0xFFFF >> 0x01))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (index_size + blob_index_size) * num_rows;
          break;
        case BIT_DECLSECURITY:
          rows = max_rows(3, typedef_rows, methoddef_rows, assembly_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (2 + index_size + blob_index_size) * num_rows;
          break;
        case BIT_CLASSLAYOUT:
          table_offset += (2 + 4 + typedef_index_size) * num_rows;
          break;
        case BIT_FIELDLAYOUT:
          table_offset += (4 + field_index_size) * num_rows;
          break;
        case BIT_STANDALONESIG:
          table_offset += (blob_index_size) * num_rows;
          break;
        case BIT_EVENTMAP:
          table_offset += (typedef_index_size + event_index_size) * num_rows;
          break;
        case BIT_EVENTPTR:
          // This one is not documented in ECMA-335.
          table_offset += (event_index_size) * num_rows;
          break;
        case BIT_EVENT:
          rows = max_rows(3, typedef_rows, typeref_rows, typespec_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (2 + string_index_size + index_size) * num_rows;
          break;
        case BIT_PROPERTYMAP:
          table_offset += (typedef_index_size + property_index_size) * num_rows;
          break;
        case BIT_PROPERTYPTR:
          // This one is not documented in ECMA-335.
          table_offset += (property_index_size) * num_rows;
          break;
        case BIT_PROPERTY:
          table_offset += (2 + string_index_size + blob_index_size) * num_rows;
          break;
        case BIT_METHODSEMANTICS:
          rows = max_rows(2, event_rows, property_rows);

          if (rows > (0xFFFF >> 0x01))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (2 + methoddef_index_size + index_size) * num_rows;
          break;
        case BIT_METHODIMPL:
          rows = max_rows(2, methoddef_rows, memberref_rows);

          if (rows > (0xFFFF >> 0x01))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (typedef_index_size + (index_size * 2)) * num_rows;
          break;
        case BIT_MODULEREF:
          row_ptr = table_offset;

          // Can't use 'g' here because we only set the string if it is not
          // NULL. Instead use 'counter'.
          counter = 0;
          for (g = 0; g < num_rows; g++)
          {
            moduleref_table = (PMODULEREF_TABLE) row_ptr;
            name = pe_get_dotnet_string(pe,
                string_offset,
                DOTNET_STRING_INDEX(string_index_size,
                moduleref_table->Name));
            if (name != NULL)
            {
              set_string(name, pe->object, "dotnet_modulerefs[%i]", g);
              counter++;
            }

            row_ptr += string_index_size;
          }

          set_integer(counter, pe->object, "number_of_dotnet_modulerefs");

          table_offset += (string_index_size) * num_rows;
          break;
        case BIT_TYPESPEC:
          table_offset += (blob_index_size) * num_rows;
          break;
        case BIT_IMPLMAP:
          rows = max_rows(2, field_rows, methoddef_rows);

          if (rows > (0xFFFF >> 0x01))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (2 + index_size + string_index_size + moduleref_index_size) * num_rows;
          break;
        case BIT_FIELDRVA:
          table_offset += (4 + field_index_size) * num_rows;
          break;
        case BIT_ENCLOG:
          table_offset += (4 + 4) * num_rows;
          break;
        case BIT_ENCMAP:
          table_offset += (4) * num_rows;
          break;
        case BIT_ASSEMBLY:
          row_size = (4 + 2 + 2 + 2 + 2 + 4 + blob_index_size + (string_index_size * 2));
          if (!fits_in_pe(pe, table_offset, row_size))
            break;

          row_ptr = table_offset;
          assembly_table = (PASSEMBLY_TABLE) table_offset;

          set_integer(assembly_table->MajorVersion,
              pe->object, "dotnet_assembly.version.major");
          set_integer(assembly_table->MinorVersion,
              pe->object, "dotnet_assembly.version.minor");
          set_integer(assembly_table->BuildNumber,
              pe->object, "dotnet_assembly.version.build_number");
          set_integer(assembly_table->RevisionNumber,
              pe->object, "dotnet_assembly.version.revision_number");

          // Can't use assembly_table here because the PublicKey comes before
          // Name and is a variable length field.
          if (string_index_size == 4)
            name = pe_get_dotnet_string(pe,
                string_offset,
                *(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size));
          else
            name = pe_get_dotnet_string(pe,
                string_offset,
                *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size));

          if (name != NULL)
            set_string(name, pe->object, "dotnet_assembly.name");

          // Culture comes after Name.
          if (string_index_size == 4)
            name = pe_get_dotnet_string(pe,
                string_offset,
                *(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size + string_index_size));
          else
            name = pe_get_dotnet_string(pe,
                string_offset,
                *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size + string_index_size));

          // Sometimes it will be a zero length string. This is technically
          // against the specification but happens from time to time.
          if (name != NULL && strlen(name) > 0)
            set_string(name, pe->object, "dotnet_assembly.culture");

          table_offset += row_size * num_rows;
          break;
        case BIT_ASSEMBLYPROCESSOR:
          table_offset += (4) * num_rows;
          break;
        case BIT_ASSEMBLYOS:
          table_offset += (4 + 4 + 4) * num_rows;
          break;
        case BIT_ASSEMBLYREF:
          table_offset += (2 + 2 + 2 + 2 + 4 + (blob_index_size * 2) + (string_index_size * 2)) * num_rows;
          break;
        case BIT_ASSEMBLYREFPROCESSOR:
          table_offset += (4 + assemblyrefprocessor_index_size) * num_rows;
          break;
        case BIT_ASSEMBLYREFOS:
          table_offset += (4 + 4 + 4 + assemblyref_index_size) * num_rows;
          break;
        case BIT_FILE:
          table_offset += (4 + string_index_size + blob_index_size) * num_rows;
          break;
        case BIT_EXPORTEDTYPE:
          rows = max_rows(3, file_rows, assemblyref_rows, exportedtype_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (4 + 4 + (string_index_size * 2) + index_size) * num_rows;
          break;
        case BIT_MANIFESTRESOURCE:
          // This is an Implementation coded index with no 3rd bit specified.
          rows = max_rows(2, file_rows, assemblyref_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          row_size = (4 + 4 + string_index_size + index_size);

          resource_base = pe_rva_to_offset(pe, cli_header->Resources.VirtualAddress);

          // Using 'g' is insufficent since we may skip certain resources and
          // it would give an inaccurate count in that case.
          counter = 0;
          row_ptr = table_offset;
          // First DWORD is the offset.
          for (g = 0; g < num_rows; g++)
          {
            if (!fits_in_pe(pe, row_ptr, row_size))
              break;

            manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;
            resource_offset = manifestresource_table->Offset;

            // Only set offset if it is in this file (implementation != 0).
            // Can't use manifestresource_table here because the Name and
            // Implementation fields are variable size.
            if (index_size == 4)
              implementation = *(DWORD*) (row_ptr + 4 + 4 + string_index_size);
            else
              implementation = *(WORD*) (row_ptr + 4 + 4 + string_index_size);

            if (implementation != 0)
            {
              row_ptr += row_size;
              continue;
            }

            if (!fits_in_pe(pe, pe->data + resource_base + resource_offset, sizeof(DWORD)))
            {
              row_ptr += row_size;
              continue;
            }

            resource_size = *(DWORD*) (pe->data + resource_base + resource_offset);

            if (!fits_in_pe(pe, pe->data + resource_base + resource_offset, resource_size))
            {
              row_ptr += row_size;
              continue;
            }

            // Add 4 to skip the size.
            set_integer(resource_base + resource_offset + 4,
                pe->object, "dotnet_resources[%i].offset", g);

            set_integer(resource_size,
                pe->object, "dotnet_resources[%i].length", g);

            name = pe_get_dotnet_string(pe,
                string_offset,
                DOTNET_STRING_INDEX(string_index_size,
                manifestresource_table->Name));
            if (name != NULL)
              set_string(name, pe->object, "dotnet_resources[%i].name", g);

            row_ptr += row_size;
            counter++;
          }

          set_integer(counter, pe->object, "number_of_dotnet_resources");

          table_offset += row_size * num_rows;
          break;
        case BIT_NESTEDCLASS:
          table_offset += (typedef_index_size * 2) * num_rows;
          break;
        case BIT_GENERICPARAM:
          rows = max_rows(2, typedef_rows, methoddef_rows);

          if (rows > (0xFFFF >> 0x01))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (2 + 2 + index_size + string_index_size) * num_rows;
          break;
        case BIT_METHODSPEC:
          rows = max_rows(2, methoddef_rows, memberref_rows);

          if (rows > (0xFFFF >> 0x1))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (index_size + blob_index_size) * num_rows;
          break;
        case BIT_GENERICPARAMCONSTRAINT:
          rows = max_rows(3, typedef_rows, typeref_rows, typespec_rows);

          if (rows > (0xFFFF >> 0x02))
            index_size = 4;
          else
            index_size = 2;

          table_offset += (genericparam_index_size + index_size) * num_rows;
          break;
        default:
          //printf("Unknown bit: %i\n", bit_check);
          return;
      }

      matched_bits++;
    }
  }
}


begin_declarations;

  declare_string("dotnet_version");
  declare_string("dotnet_module_name");
  begin_struct_array("dotnet_streams");
    declare_string("name");
    declare_integer("offset");
    declare_integer("size");
  end_struct_array("dotnet_streams");
  declare_integer("number_of_dotnet_streams");
  declare_string_array("dotnet_guids");
  declare_integer("number_of_dotnet_guids");
  begin_struct_array("dotnet_resources");
    declare_integer("offset");
    declare_integer("length");
    declare_string("name");
  end_struct_array("dotnet_resources");
  declare_integer("number_of_dotnet_resources");
  begin_struct("dotnet_assembly");
    begin_struct("version");
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version");
    declare_string("name");
    declare_string("culture");
  end_struct("dotnet_assembly");
  declare_string_array("dotnet_modulerefs");
  declare_integer("number_of_dotnet_modulerefs");

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
        pe->object = module_object;
        pe->header = pe_header;

        module_object->data = pe;

        pe_parse_com(pe, block->base);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  PE* pe = (PE *) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  yr_free(pe);

  return ERROR_SUCCESS;
}
