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


void dotnet_parse_guid(
    PE* pe,
    int64_t metadata_root,
    PSTREAM_HEADER guid_header)
{
  // GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
  char guid[37];
  int i = 0;

  uint8_t* guid_offset = pe->data + metadata_root + guid_header->Offset;
  DWORD guid_size = guid_header->Size;

  // Parse GUIDs if we have them.
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

    set_string(guid, pe->object, "guids[%i]", i);

    i++;
    guid_size -= 16;
  }

  set_integer(i, pe->object, "number_of_guids");
}


STREAMS dotnet_parse_stream_headers(
    PE* pe,
    int64_t offset,
    int64_t metadata_root,
    DWORD num_streams)
{
  int i;
  STREAMS headers;
  char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
  PSTREAM_HEADER stream_header;

  memset(&headers, '\0', sizeof(STREAMS));

  stream_header = (PSTREAM_HEADER) (pe->data + offset);

  for (i = 0; i < num_streams; i++)
  {
    if (!struct_fits_in_pe(pe, stream_header, STREAM_HEADER))
      break;

    strncpy(stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
    stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

    set_string(stream_name,
        pe->object, "streams[%i].name", i);
    // Offset is relative to metadata_root.
    set_integer(metadata_root + stream_header->Offset,
        pe->object, "streams[%i].offset", i);
    set_integer(stream_header->Size,
        pe->object, "streams[%i].size", i);

    // Store necessary bits to parse these later. Not all tables will be
    // parsed, but are referenced from others. For example, the #Strings
    // stream is referenced from various tables in the #~ heap.
    if (strncmp(stream_name, "#GUID", 5) == 0)
      headers.guid = stream_header;
    // Believe it or not, I have seen at least one binary which has a #- stream
    // instead of a #~ (215e1b54ae1aac153e55596e6f1a4350). This isn't in the
    // documentation anywhere but the structure is the same. I'm chosing not
    // to parse it for now.
    else if (strncmp(stream_name, "#~", 2) == 0 && headers.tilde == NULL)
      headers.tilde = stream_header;
    else if (strncmp(stream_name, "#Strings", 8) == 0 && headers.string == NULL)
      headers.string = stream_header;

    // Stream name is padded to a multiple of 4.
    stream_header = (PSTREAM_HEADER) ((uint8_t*) stream_header +
        sizeof(STREAM_HEADER) +
        strlen(stream_name) +
        4 - (strlen(stream_name) % 4));
  }

  set_integer(i, pe->object, "number_of_streams");

  return headers;
}


// This is the second pass through the data for #~. The first pass collects
// information on the number of rows for tables which have coded indexes.
// This pass uses that information and the index_sizes to parse the tables
// of interest.
//
// Because the indexes can vary in size depending upon the number of rows in
// other tables it is impossible to use static sized structures. To deal with
// this hardcode the sizes of each table based upon the documentation (for the
// static sized portions) and use the variable sizes accordingly.
void dotnet_parse_tilde_2(
    PE* pe,
    PTILDE_HEADER tilde_header,
    uint8_t* string_offset,
    int64_t resource_base,
    ROWS rows,
    INDEX_SIZES index_sizes)
{
  PMODULE_TABLE module_table;
  PASSEMBLY_TABLE assembly_table;
  PMANIFESTRESOURCE_TABLE manifestresource_table;
  PMODULEREF_TABLE moduleref_table;
  DWORD resource_size, implementation;
  char *name;
  int i, bit_check;
  int64_t resource_offset;
  uint32_t row_size, row_count, counter;
  int matched_bits = 0;
  uint32_t num_rows = 0;
  uint32_t valid_rows = 0;
  uint32_t* row_offset = NULL;
  uint8_t* table_offset = NULL;
  uint8_t* row_ptr = NULL;
  // These are used to determine the size of coded indexes, which are the
  // dynamically sized columns for some tables. The coded indexes are
  // documented in ECMA-335 Section II.24.2.6.
  uint8_t index_size, index_size2;

  // Number of rows is the number of bits set to 1 in Valid.
  // Should use this technique:
  // http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
  for (i = 0; i < 64; i++)
    valid_rows += ((tilde_header->Valid >> i) & 0x01);

  row_offset = (uint32_t*) (tilde_header + 1);
  table_offset = (uint8_t*) row_offset;
  table_offset += sizeof(uint32_t) * valid_rows;

#define DOTNET_STRING_INDEX(Name) \
  index_sizes.string == 2 ? Name.Name_Short : Name.Name_Long

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
            DOTNET_STRING_INDEX(module_table->Name));
        if (name != NULL)
          set_string(name, pe->object, "module_name");

        table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
        break;
      case BIT_TYPEREF:
        row_count = max_rows(4, rows.module, rows.moduleref, rows.assemblyref,
            rows.typeref);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_size + (index_sizes.string * 2)) * num_rows;
        break;
      case BIT_TYPEDEF:
        row_count = max_rows(3, rows.typedef_, rows.typeref, rows.typespec);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (4 + (index_sizes.string * 2) + index_size + index_sizes.field + index_sizes.methoddef) * num_rows;
        break;
      case BIT_FIELDPTR:
        // This one is not documented in ECMA-335.
        table_offset += (index_sizes.field) * num_rows;
        break;
      case BIT_FIELD:
        table_offset += (2 + (index_sizes.string) + index_sizes.blob) * num_rows;
        break;
      case BIT_METHODDEFPTR:
        // This one is not documented in ECMA-335.
        table_offset += (index_sizes.methoddef) * num_rows;
        break;
      case BIT_METHODDEF:
        table_offset += (4 + 2 + 2 + index_sizes.string + index_sizes.blob + index_sizes.param) * num_rows;
        break;
      case BIT_PARAM:
        table_offset += (2 + 2 + index_sizes.string) * num_rows;
        break;
      case BIT_INTERFACEIMPL:
        row_count = max_rows(3, rows.typedef_, rows.typeref, rows.typespec);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_sizes.typedef_ + index_size) * num_rows;
        break;
      case BIT_MEMBERREF:
        row_count = max_rows(4, rows.methoddef, rows.moduleref, rows.typeref,
            rows.typespec);

        if (row_count > (0xFFFF >> 0x03))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_size + index_sizes.string + index_sizes.blob) * num_rows;
        break;
      case BIT_CONSTANT:
        row_count = max_rows(3, rows.param, rows.field, rows.property);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (1 + 1 + index_size + index_sizes.blob) * num_rows;
        break;
      case BIT_CUSTOMATTRIBUTE:
        row_count = max_rows(21, rows.methoddef, rows.field, rows.typeref,
            rows.typedef_, rows.param, rows.interfaceimpl, rows.memberref,
            rows.module, rows.property, rows.event, rows.standalonesig,
            rows.moduleref, rows.typespec, rows.assembly, rows.assemblyref,
            rows.file, rows.exportedtype, rows.manifestresource,
            rows.genericparam, rows.genericparamconstraint, rows.methodspec);

        if (row_count > (0xFFFF >> 0x05))
          index_size = 4;
        else
          index_size = 2;

        row_count = max_rows(2, rows.methoddef, rows.memberref);

        if (row_count > (0xFFFF >> 0x03))
          index_size2 = 4;
        else
          index_size2 = 2;

        table_offset += (index_size + index_size2 + index_sizes.blob) * num_rows;
        break;
      case BIT_FIELDMARSHAL:
        row_count = max_rows(2, rows.field, rows.param);

        if (row_count > (0xFFFF >> 0x01))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_size + index_sizes.blob) * num_rows;
        break;
      case BIT_DECLSECURITY:
        row_count = max_rows(3, rows.typedef_, rows.methoddef, rows.assembly);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (2 + index_size + index_sizes.blob) * num_rows;
        break;
      case BIT_CLASSLAYOUT:
        table_offset += (2 + 4 + index_sizes.typedef_) * num_rows;
        break;
      case BIT_FIELDLAYOUT:
        table_offset += (4 + index_sizes.field) * num_rows;
        break;
      case BIT_STANDALONESIG:
        table_offset += (index_sizes.blob) * num_rows;
        break;
      case BIT_EVENTMAP:
        table_offset += (index_sizes.typedef_ + index_sizes.event) * num_rows;
        break;
      case BIT_EVENTPTR:
        // This one is not documented in ECMA-335.
        table_offset += (index_sizes.event) * num_rows;
        break;
      case BIT_EVENT:
        row_count = max_rows(3, rows.typedef_, rows.typeref, rows.typespec);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (2 + index_sizes.string + index_size) * num_rows;
        break;
      case BIT_PROPERTYMAP:
        table_offset += (index_sizes.typedef_ + index_sizes.property) * num_rows;
        break;
      case BIT_PROPERTYPTR:
        // This one is not documented in ECMA-335.
        table_offset += (index_sizes.property) * num_rows;
        break;
      case BIT_PROPERTY:
        table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
        break;
      case BIT_METHODSEMANTICS:
        row_count = max_rows(2, rows.event, rows.property);

        if (row_count > (0xFFFF >> 0x01))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (2 + index_sizes.methoddef + index_size) * num_rows;
        break;
      case BIT_METHODIMPL:
        row_count = max_rows(2, rows.methoddef, rows.memberref);

        if (row_count > (0xFFFF >> 0x01))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_sizes.typedef_ + (index_size * 2)) * num_rows;
        break;
      case BIT_MODULEREF:
        row_ptr = table_offset;

        // Can't use 'i' here because we only set the string if it is not
        // NULL. Instead use 'counter'.
        counter = 0;
        for (i = 0; i < num_rows; i++)
        {
          moduleref_table = (PMODULEREF_TABLE) row_ptr;
          name = pe_get_dotnet_string(pe,
              string_offset,
              DOTNET_STRING_INDEX(moduleref_table->Name));
          if (name != NULL)
          {
            set_string(name, pe->object, "modulerefs[%i]", i);
            counter++;
          }

          row_ptr += index_sizes.string;
        }

        set_integer(counter, pe->object, "number_of_modulerefs");

        table_offset += (index_sizes.string) * num_rows;
        break;
      case BIT_TYPESPEC:
        table_offset += (index_sizes.blob) * num_rows;
        break;
      case BIT_IMPLMAP:
        row_count = max_rows(2, rows.field, rows.methoddef);

        if (row_count > (0xFFFF >> 0x01))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (2 + index_size + index_sizes.string + index_sizes.moduleref) * num_rows;
        break;
      case BIT_FIELDRVA:
        table_offset += (4 + index_sizes.field) * num_rows;
        break;
      case BIT_ENCLOG:
        table_offset += (4 + 4) * num_rows;
        break;
      case BIT_ENCMAP:
        table_offset += (4) * num_rows;
        break;
      case BIT_ASSEMBLY:
        row_size = (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2));
        if (!fits_in_pe(pe, table_offset, row_size))
          break;

        row_ptr = table_offset;
        assembly_table = (PASSEMBLY_TABLE) table_offset;

        set_integer(assembly_table->MajorVersion,
            pe->object, "assembly.version.major");
        set_integer(assembly_table->MinorVersion,
            pe->object, "assembly.version.minor");
        set_integer(assembly_table->BuildNumber,
            pe->object, "assembly.version.build_number");
        set_integer(assembly_table->RevisionNumber,
            pe->object, "assembly.version.revision_number");

        // Can't use assembly_table here because the PublicKey comes before
        // Name and is a variable length field.
        if (index_sizes.string == 4)
          name = pe_get_dotnet_string(pe,
              string_offset,
              *(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob));
        else
          name = pe_get_dotnet_string(pe,
              string_offset,
              *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob));

        if (name != NULL)
          set_string(name, pe->object, "assembly.name");

        // Culture comes after Name.
        if (index_sizes.string == 4)
          name = pe_get_dotnet_string(pe,
              string_offset,
              *(DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + index_sizes.string));
        else
          name = pe_get_dotnet_string(pe,
              string_offset,
              *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + index_sizes.string));

        // Sometimes it will be a zero length string. This is technically
        // against the specification but happens from time to time.
        if (name != NULL && strlen(name) > 0)
          set_string(name, pe->object, "assembly.culture");

        table_offset += row_size * num_rows;
        break;
      case BIT_ASSEMBLYPROCESSOR:
        table_offset += (4) * num_rows;
        break;
      case BIT_ASSEMBLYOS:
        table_offset += (4 + 4 + 4) * num_rows;
        break;
      case BIT_ASSEMBLYREF:
        table_offset += (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) + (index_sizes.string * 2)) * num_rows;
        break;
      case BIT_ASSEMBLYREFPROCESSOR:
        table_offset += (4 + index_sizes.assemblyrefprocessor) * num_rows;
        break;
      case BIT_ASSEMBLYREFOS:
        table_offset += (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
        break;
      case BIT_FILE:
        table_offset += (4 + index_sizes.string + index_sizes.blob) * num_rows;
        break;
      case BIT_EXPORTEDTYPE:
        row_count = max_rows(3, rows.file, rows.assemblyref, rows.exportedtype);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (4 + 4 + (index_sizes.string * 2) + index_size) * num_rows;
        break;
      case BIT_MANIFESTRESOURCE:
        // This is an Implementation coded index with no 3rd bit specified.
        row_count = max_rows(2, rows.file, rows.assemblyref);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        row_size = (4 + 4 + index_sizes.string + index_size);

        // Using 'i' is insufficent since we may skip certain resources and
        // it would give an inaccurate count in that case.
        counter = 0;
        row_ptr = table_offset;
        // First DWORD is the offset.
        for (i = 0; i < num_rows; i++)
        {
          if (!fits_in_pe(pe, row_ptr, row_size))
            break;

          manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;
          resource_offset = manifestresource_table->Offset;

          // Only set offset if it is in this file (implementation != 0).
          // Can't use manifestresource_table here because the Name and
          // Implementation fields are variable size.
          if (index_size == 4)
            implementation = *(DWORD*) (row_ptr + 4 + 4 + index_sizes.string);
          else
            implementation = *(WORD*) (row_ptr + 4 + 4 + index_sizes.string);

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
              pe->object, "resources[%i].offset", i);

          set_integer(resource_size,
              pe->object, "resources[%i].length", i);

          name = pe_get_dotnet_string(pe,
              string_offset,
              DOTNET_STRING_INDEX(manifestresource_table->Name));
          if (name != NULL)
            set_string(name, pe->object, "resources[%i].name", i);

          row_ptr += row_size;
          counter++;
        }

        set_integer(counter, pe->object, "number_of_resources");

        table_offset += row_size * num_rows;
        break;
      case BIT_NESTEDCLASS:
        table_offset += (index_sizes.typedef_ * 2) * num_rows;
        break;
      case BIT_GENERICPARAM:
        row_count = max_rows(2, rows.typedef_, rows.methoddef);

        if (row_count > (0xFFFF >> 0x01))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (2 + 2 + index_size + index_sizes.string) * num_rows;
        break;
      case BIT_METHODSPEC:
        row_count = max_rows(2, rows.methoddef, rows.memberref);

        if (row_count > (0xFFFF >> 0x1))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_size + index_sizes.blob) * num_rows;
        break;
      case BIT_GENERICPARAMCONSTRAINT:
        row_count = max_rows(3, rows.typedef_, rows.typeref, rows.typespec);

        if (row_count > (0xFFFF >> 0x02))
          index_size = 4;
        else
          index_size = 2;

        table_offset += (index_sizes.genericparam + index_size) * num_rows;
        break;
      default:
        //printf("Unknown bit: %i\n", bit_check);
        return;
    }

    matched_bits++;
  }
}


// Parsing the #~ stream is done in two parts. The first part (this function)
// parses enough of the Stream to provide context for the second pass. In
// particular it is collecting the number of rows for each of the tables. The
// second part parses the actual tables of interest.
void dotnet_parse_tilde(
    PE* pe,
    int64_t metadata_root,
    PCLI_HEADER cli_header,
    PSTREAM_HEADER string_header,
    PSTREAM_HEADER stream_header)
{
  PTILDE_HEADER tilde_header;
  int64_t resource_base;
  uint32_t* row_offset = NULL;
  uint8_t* string_offset;
  int bit_check;
  // This is used as an offset into the rows and tables. For every bit set in
  // Valid this will be incremented. This is because the bit position doesn't
  // matter, just the number of bits that are set, when determining how many
  // rows and what the table structure is.
  int matched_bits = 0;
  // We need to know the number of rows for some tables, because they are
  // indexed into. The index will be either 2 or 4 bytes, depending upon the
  // number of rows being indexed into.
  ROWS rows;
  INDEX_SIZES index_sizes;

  // Default all rows to 0. They will be set to actual values later on, if
  // they exist in the file.
  memset(&rows, '\0', sizeof(ROWS));

  // Default index sizes are 2. Will be bumped to 4 if necessary.
  memset(&index_sizes, 2, sizeof(index_sizes));

  string_offset = pe->data + metadata_root + string_header->Offset;
  tilde_header = (PTILDE_HEADER) (pe->data + metadata_root + stream_header->Offset);

  if (!struct_fits_in_pe(pe, tilde_header, TILDE_HEADER))
      return;

  // Set index sizes for various heaps.
  if (tilde_header->HeapSizes & 0x01)
    index_sizes.string = 4;
  if (tilde_header->HeapSizes & 0x02)
    index_sizes.guid = 4;
  if (tilde_header->HeapSizes & 0x04)
    index_sizes.blob = 4;

  // Immediately after the tilde header is an array of 32bit values which
  // indicate how many rows are in each table. The tables are immediately
  // after the rows array.
  //
  // Save the row offset.
  row_offset = (uint32_t*) (tilde_header + 1);

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
        rows.module = *(row_offset + matched_bits);
        break;
      case BIT_MODULEREF:
        rows.moduleref = *(row_offset + matched_bits);
        if (rows.moduleref > 0xFFFF)
          index_sizes.moduleref = 4;
        break;
      case BIT_ASSEMBLYREF:
        rows.assemblyref = *(row_offset + matched_bits);
        if (rows.assemblyref > 0xFFFF)
          index_sizes.assemblyref = 4;
        break;
      case BIT_ASSEMBLYREFPROCESSOR:
        rows.assemblyrefprocessor = *(row_offset + matched_bits);
        if (rows.assemblyrefprocessor > 0xFFFF)
          index_sizes.assemblyrefprocessor = 4;
        break;
      case BIT_TYPEREF:
        rows.typeref = *(row_offset + matched_bits);
      case BIT_METHODDEF:
        rows.methoddef = *(row_offset + matched_bits);
        if (rows.methoddef > 0xFFFF)
          index_sizes.methoddef = 4;
        break;
      case BIT_MEMBERREF:
        rows.memberref = *(row_offset + matched_bits);
        break;
      case BIT_TYPEDEF:
        rows.typedef_ = *(row_offset + matched_bits);
        if (rows.typedef_ > 0xFFFF)
          index_sizes.typedef_ = 4;
        break;
      case BIT_TYPESPEC:
        rows.typespec = *(row_offset + matched_bits);
        break;
      case BIT_FIELD:
        rows.field = *(row_offset + matched_bits);
        if (rows.field > 0xFFFF)
          index_sizes.field = 4;
        break;
      case BIT_PARAM:
        rows.param = *(row_offset + matched_bits);
        if (rows.param > 0xFFFF)
          index_sizes.param = 4;
        break;
      case BIT_PROPERTY:
        rows.property = *(row_offset + matched_bits);
        if (rows.property > 0xFFFF)
          index_sizes.property = 4;
        break;
      case BIT_INTERFACEIMPL:
        rows.interfaceimpl = *(row_offset + matched_bits);
        break;
      case BIT_EVENT:
        rows.event = *(row_offset + matched_bits);
        if (rows.event > 0xFFFF)
          index_sizes.event = 4;
        break;
      case BIT_STANDALONESIG:
        rows.standalonesig = *(row_offset + matched_bits);
        break;
      case BIT_ASSEMBLY:
        rows.assembly = *(row_offset + matched_bits);
        break;
      case BIT_FILE:
        rows.file = *(row_offset + matched_bits);
        break;
      case BIT_EXPORTEDTYPE:
        rows.exportedtype = *(row_offset + matched_bits);
        break;
      case BIT_MANIFESTRESOURCE:
        rows.manifestresource = *(row_offset + matched_bits);
        break;
      case BIT_GENERICPARAM:
        rows.genericparam = *(row_offset + matched_bits);
        if (rows.genericparam > 0xFFFF)
          index_sizes.genericparam = 4;
        break;
      case BIT_GENERICPARAMCONSTRAINT:
        rows.genericparamconstraint = *(row_offset + matched_bits);
        break;
      case BIT_METHODSPEC:
        rows.methodspec = *(row_offset + matched_bits);
        break;
      default:
        break;
    }

    matched_bits++;
  }

  // This is used when parsing the MANIFEST RESOURCE table.
  resource_base = pe_rva_to_offset(pe, cli_header->Resources.VirtualAddress);

  dotnet_parse_tilde_2(pe, tilde_header, string_offset, resource_base, rows,
          index_sizes);
}

void dotnet_parse_com(
    PE* pe,
    size_t base_address)
{
  PIMAGE_DATA_DIRECTORY directory;
  PCLI_HEADER cli_header;
  PNET_METADATA metadata;
  int64_t metadata_root, offset;
  char *version;
  STREAMS headers;
  WORD num_streams;

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
  set_string(version, pe->object, "version");
  yr_free(version);

  // The metadata structure has some variable length records after the version.
  // We must manually parse things from here on out.
  //
  // Flags are 2 bytes (always 0).
  offset += sizeof(NET_METADATA) + metadata->Length + 2;

  // 2 bytes for Streams.
  if (!fits_in_pe(pe, pe->data + offset, 2))
    return;

  num_streams = (WORD) *(pe->data + offset);
  offset += 2;

  headers = dotnet_parse_stream_headers(pe, offset, metadata_root, num_streams);

  if (headers.guid != NULL)
    dotnet_parse_guid(pe, metadata_root, headers.guid);

  // Parse the #~ stream, which includes various tables of interest.
  if (headers.tilde != NULL)
    dotnet_parse_tilde(pe, metadata_root, cli_header, headers.string,
        headers.tilde);
}


begin_declarations;

  declare_string("version");
  declare_string("module_name");
  begin_struct_array("streams");
    declare_string("name");
    declare_integer("offset");
    declare_integer("size");
  end_struct_array("streams");
  declare_integer("number_of_streams");
  declare_string_array("guids");
  declare_integer("number_of_guids");
  begin_struct_array("resources");
    declare_integer("offset");
    declare_integer("length");
    declare_string("name");
  end_struct_array("resources");
  declare_integer("number_of_resources");
  begin_struct("assembly");
    begin_struct("version");
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version");
    declare_string("name");
    declare_string("culture");
  end_struct("assembly");
  declare_string_array("modulerefs");
  declare_integer("number_of_modulerefs");

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

        dotnet_parse_com(pe, block->base);

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
