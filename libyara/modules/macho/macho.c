/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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
#include <yara/macho.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME macho

// Check for Mach-O binary magic constant.
int is_macho_file_block(const uint32_t* magic)
{
  return *magic == MH_MAGIC || *magic == MH_CIGAM || *magic == MH_MAGIC_64 ||
         *magic == MH_CIGAM_64;
}

// Check if file is for 32-bit architecture.
int macho_is_32(uint32_t magic)
{
  return magic == MH_MAGIC || magic == MH_CIGAM;
}

// Check for Mach-O fat binary magic constant.
int is_fat_macho_file_block(const uint32_t* magic)
{
  return *magic == FAT_MAGIC || *magic == FAT_CIGAM || *magic == FAT_MAGIC_64 ||
         *magic == FAT_CIGAM_64;
}

// Check if file is 32-bit fat file.
int macho_fat_is_32(const uint32_t* magic)
{
  return yr_be32toh(*magic) == FAT_MAGIC;
}

static int should_swap_bytes(const uint32_t magic)
{
// In big-endian platforms byte swapping is needed for little-endian files
// but in little-endian platforms the files that need swapping are the
// the big-endian ones.
#if defined(WORDS_BIGENDIAN)
  return magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM ||
         magic == FAT_CIGAM_64;
#else
  return magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == FAT_MAGIC ||
         magic == FAT_MAGIC_64;
#endif
}

static void swap_mach_header(yr_mach_header_64_t* mh)
{
  // Don't swap the magic number so we can tell if swapping is needed
  mh->cputype = yr_bswap32(mh->cputype);
  mh->cpusubtype = yr_bswap32(mh->cpusubtype);
  mh->filetype = yr_bswap32(mh->filetype);
  mh->ncmds = yr_bswap32(mh->ncmds);
  mh->sizeofcmds = yr_bswap32(mh->sizeofcmds);
  mh->flags = yr_bswap32(mh->flags);

  if (!macho_is_32(mh->magic))
    mh->reserved = yr_bswap32(mh->reserved);
}

static void swap_load_command(yr_load_command_t* lc)
{
  lc->cmd = yr_bswap32(lc->cmd);
  lc->cmdsize = yr_bswap32(lc->cmdsize);
}

static void swap_segment_command(yr_segment_command_32_t* sg)
{
  sg->cmd = yr_bswap32(sg->cmd);
  sg->cmdsize = yr_bswap32(sg->cmdsize);
  sg->vmaddr = yr_bswap32(sg->vmaddr);
  sg->vmsize = yr_bswap32(sg->vmsize);
  sg->fileoff = yr_bswap32(sg->fileoff);
  sg->filesize = yr_bswap32(sg->filesize);
  sg->maxprot = yr_bswap32(sg->maxprot);
  sg->initprot = yr_bswap32(sg->initprot);
  sg->nsects = yr_bswap32(sg->nsects);
  sg->flags = yr_bswap32(sg->flags);
}

static void swap_segment_command_64(yr_segment_command_64_t* sg)
{
  sg->cmd = yr_bswap32(sg->cmd);
  sg->cmdsize = yr_bswap32(sg->cmdsize);
  sg->vmaddr = yr_bswap64(sg->vmaddr);
  sg->vmsize = yr_bswap64(sg->vmsize);
  sg->fileoff = yr_bswap64(sg->fileoff);
  sg->filesize = yr_bswap64(sg->filesize);
  sg->maxprot = yr_bswap32(sg->maxprot);
  sg->initprot = yr_bswap32(sg->initprot);
  sg->nsects = yr_bswap32(sg->nsects);
  sg->flags = yr_bswap32(sg->flags);
}

static void swap_section(yr_section_32_t* sec)
{
  sec->addr = yr_bswap32(sec->addr);
  sec->size = yr_bswap32(sec->size);
  sec->offset = yr_bswap32(sec->offset);
  sec->align = yr_bswap32(sec->align);
  sec->reloff = yr_bswap32(sec->reloff);
  sec->nreloc = yr_bswap32(sec->nreloc);
  sec->flags = yr_bswap32(sec->flags);
  sec->reserved1 = yr_bswap32(sec->reserved1);
  sec->reserved2 = yr_bswap32(sec->reserved2);
}

static void swap_section_64(yr_section_64_t* sec)
{
  sec->addr = yr_bswap64(sec->addr);
  sec->size = yr_bswap64(sec->size);
  sec->offset = yr_bswap32(sec->offset);
  sec->align = yr_bswap32(sec->align);
  sec->reloff = yr_bswap32(sec->reloff);
  sec->nreloc = yr_bswap32(sec->nreloc);
  sec->flags = yr_bswap32(sec->flags);
  sec->reserved1 = yr_bswap32(sec->reserved1);
  sec->reserved2 = yr_bswap32(sec->reserved2);
  sec->reserved3 = yr_bswap32(sec->reserved3);
}

static void swap_entry_point_command(yr_entry_point_command_t* ep_command)
{
  ep_command->cmd = yr_bswap32(ep_command->cmd);
  ep_command->cmdsize = yr_bswap32(ep_command->cmdsize);
  ep_command->entryoff = yr_bswap64(ep_command->entryoff);
  ep_command->stacksize = yr_bswap64(ep_command->stacksize);
}

// Convert virtual address to file offset. Segments have to be already loaded.

bool macho_rva_to_offset(uint64_t address, uint64_t* result, YR_OBJECT* object)
{
  uint64_t segment_count = yr_get_integer(object, "number_of_segments");

  for (int i = 0; i < segment_count; i++)
  {
    uint64_t start = yr_get_integer(object, "segments[%i].vmaddr", i);
    uint64_t end = start + yr_get_integer(object, "segments[%i].vmsize", i);

    if (address >= start && address < end)
    {
      uint64_t fileoff = yr_get_integer(object, "segments[%i].fileoff", i);
      *result = fileoff + (address - start);
      return true;
    }
  }

  return false;
}

// Convert file offset to virtual address. Segments have to be already loaded.

int macho_offset_to_rva(uint64_t offset, uint64_t* result, YR_OBJECT* object)
{
  uint64_t segment_count = yr_get_integer(object, "number_of_segments");

  for (int i = 0; i < segment_count; i++)
  {
    uint64_t start = yr_get_integer(object, "segments[%i].fileoff", i);
    uint64_t end = start + yr_get_integer(object, "segments[%i].fsize", i);

    if (offset >= start && offset < end)
    {
      uint64_t vmaddr = yr_get_integer(object, "segments[%i].vmaddr", i);
      *result = vmaddr + (offset - start);
      return true;
    }
  }

  return false;
}

// Get entry point address from LC_UNIXTHREAD load command.
void macho_handle_unixthread(
    const uint8_t* data,
    size_t size,
    uint64_t base_address,
    YR_OBJECT* object,
    YR_SCAN_CONTEXT* context)
{
  int should_swap = should_swap_bytes(yr_get_integer(object, "magic"));
  bool is64 = false;

  if (size < sizeof(yr_thread_command_t))
    return;

  // command_size is the size indicated in yr_thread_command_t structure, but
  // limited to the data's size because we can't rely on the structure having
  // a valid size.
  uint32_t command_size = yr_min(size, ((yr_thread_command_t*) data)->cmdsize);

  // command_size should be at least the size of yr_thread_command_t.
  if (command_size < sizeof(yr_thread_command_t))
    return;

  // command_size includes the size of yr_thread_command_t and the thread
  // state structure that follows, let's compute the size of the thread state
  // structure.
  size_t thread_state_size = command_size - sizeof(yr_thread_command_t);

  // The structure that contains the thread state starts where
  // yr_thread_command_t ends.
  const void* thread_state = data + sizeof(yr_thread_command_t);

  uint64_t address = 0;

  switch (yr_get_integer(object, "cputype"))
  {
  case CPU_TYPE_MC680X0:
  {
    if (thread_state_size < sizeof(yr_m68k_thread_state_t))
      return;
    address = ((yr_m68k_thread_state_t*) thread_state)->pc;
    break;
  }
  case CPU_TYPE_MC88000:
  {
    if (thread_state_size < sizeof(yr_m88k_thread_state_t))
      return;
    address = ((yr_m88k_thread_state_t*) thread_state)->xip;
    break;
  }
  case CPU_TYPE_SPARC:
  {
    if (thread_state_size < sizeof(yr_sparc_thread_state_t))
      return;
    address = ((yr_sparc_thread_state_t*) thread_state)->pc;
    break;
  }
  case CPU_TYPE_POWERPC:
  {
    if (thread_state_size < sizeof(yr_ppc_thread_state_t))
      return;
    address = ((yr_ppc_thread_state_t*) thread_state)->srr0;
    break;
  }
  case CPU_TYPE_X86:
  {
    if (thread_state_size < sizeof(yr_x86_thread_state_t))
      return;
    address = ((yr_x86_thread_state_t*) thread_state)->eip;
    break;
  }
  case CPU_TYPE_ARM:
  {
    if (thread_state_size < sizeof(yr_arm_thread_state_t))
      return;
    address = ((yr_arm_thread_state_t*) thread_state)->pc;
    break;
  }
  case CPU_TYPE_X86_64:
  {
    if (thread_state_size < sizeof(yr_x86_thread_state64_t))
      return;
    address = ((yr_x86_thread_state64_t*) thread_state)->rip;
    is64 = true;
    break;
  }
  case CPU_TYPE_ARM64:
  {
    if (thread_state_size < sizeof(yr_arm_thread_state64_t))
      return;
    address = ((yr_arm_thread_state64_t*) thread_state)->pc;
    is64 = true;
    break;
  }
  case CPU_TYPE_POWERPC64:
  {
    if (thread_state_size < sizeof(yr_ppc_thread_state64_t))
      return;
    address = ((yr_ppc_thread_state64_t*) thread_state)->srr0;
    is64 = true;
    break;
  }

  default:
    return;
  }

  if (should_swap)
  {
    if (is64)
      address = yr_bswap64(address);
    else
      address = yr_bswap32(address);
  }

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
  {
    yr_set_integer(base_address + address, object, "entry_point");
  }
  else
  {
    uint64_t offset = 0;
    if (macho_rva_to_offset(address, &offset, object))
    {
      yr_set_integer(offset, object, "entry_point");
    }
  }
}

// Get entry point offset and stack-size from LC_MAIN load command.

void macho_handle_main(
    void* data,
    size_t size,
    YR_OBJECT* object,
    YR_SCAN_CONTEXT* context)
{
  yr_entry_point_command_t ep_command;

  if (size < sizeof(yr_entry_point_command_t))
    return;

  memcpy(&ep_command, data, sizeof(yr_entry_point_command_t));

  if (should_swap_bytes(yr_get_integer(object, "magic")))
    swap_entry_point_command(&ep_command);

  if (context->flags & SCAN_FLAGS_PROCESS_MEMORY)
  {
    uint64_t address = 0;
    if (macho_offset_to_rva(ep_command.entryoff, &address, object))
    {
      yr_set_integer(address, object, "entry_point");
    }
  }
  else
  {
    yr_set_integer(ep_command.entryoff, object, "entry_point");
  }
  yr_set_integer(ep_command.stacksize, object, "stack_size");
}

// Load segment and its sections.

void macho_handle_segment(
    const uint8_t* data,
    size_t size,
    const unsigned i,
    YR_OBJECT* object)
{
  if (size < sizeof(yr_segment_command_32_t))
    return;

  yr_segment_command_32_t sg;

  memcpy(&sg, data, sizeof(yr_segment_command_32_t));

  int should_swap = should_swap_bytes(yr_get_integer(object, "magic"));

  if (should_swap)
    swap_segment_command(&sg);

  yr_set_sized_string(
      sg.segname, strnlen(sg.segname, 16), object, "segments[%i].segname", i);

  yr_set_integer(sg.vmaddr, object, "segments[%i].vmaddr", i);
  yr_set_integer(sg.vmsize, object, "segments[%i].vmsize", i);
  yr_set_integer(sg.fileoff, object, "segments[%i].fileoff", i);
  yr_set_integer(sg.filesize, object, "segments[%i].fsize", i);
  yr_set_integer(sg.maxprot, object, "segments[%i].maxprot", i);
  yr_set_integer(sg.initprot, object, "segments[%i].initprot", i);
  yr_set_integer(sg.nsects, object, "segments[%i].nsects", i);
  yr_set_integer(sg.flags, object, "segments[%i].flags", i);

  uint64_t parsed_size = sizeof(yr_segment_command_32_t);

  // The array of yr_section_32_t starts where yr_segment_command_32_t ends.
  yr_section_32_t* sections =
      (yr_section_32_t*) (data + sizeof(yr_segment_command_32_t));

  for (unsigned j = 0; j < sg.nsects; ++j)
  {
    yr_section_32_t sec;

    parsed_size += sizeof(yr_section_32_t);

    if (sg.cmdsize < parsed_size)
      break;

    memcpy(&sec, &sections[j], sizeof(yr_section_32_t));

    if (should_swap)
      swap_section(&sec);

    yr_set_sized_string(
        sec.segname,
        strnlen(sec.segname, 16),
        object,
        "segments[%i].sections[%i].segname",
        i,
        j);

    yr_set_sized_string(
        sec.sectname,
        strnlen(sec.sectname, 16),
        object,
        "segments[%i].sections[%i].sectname",
        i,
        j);

    yr_set_integer(sec.addr, object, "segments[%i].sections[%i].addr", i, j);

    yr_set_integer(sec.size, object, "segments[%i].sections[%i].size", i, j);

    yr_set_integer(
        sec.offset, object, "segments[%i].sections[%i].offset", i, j);

    yr_set_integer(sec.align, object, "segments[%i].sections[%i].align", i, j);

    yr_set_integer(
        sec.reloff, object, "segments[%i].sections[%i].reloff", i, j);

    yr_set_integer(
        sec.nreloc, object, "segments[%i].sections[%i].nreloc", i, j);

    yr_set_integer(sec.flags, object, "segments[%i].sections[%i].flags", i, j);

    yr_set_integer(
        sec.reserved1, object, "segments[%i].sections[%i].reserved1", i, j);

    yr_set_integer(
        sec.reserved2, object, "segments[%i].sections[%i].reserved2", i, j);
  }
}

void macho_handle_segment_64(
    const uint8_t* data,
    size_t size,
    const unsigned i,
    YR_OBJECT* object)
{
  if (size < sizeof(yr_segment_command_64_t))
    return;

  yr_segment_command_64_t sg;

  memcpy(&sg, data, sizeof(yr_segment_command_64_t));

  int should_swap = should_swap_bytes(yr_get_integer(object, "magic"));

  if (should_swap)
    swap_segment_command_64(&sg);

  yr_set_sized_string(
      sg.segname, strnlen(sg.segname, 16), object, "segments[%i].segname", i);

  yr_set_integer(sg.vmaddr, object, "segments[%i].vmaddr", i);
  yr_set_integer(sg.vmsize, object, "segments[%i].vmsize", i);
  yr_set_integer(sg.fileoff, object, "segments[%i].fileoff", i);
  yr_set_integer(sg.filesize, object, "segments[%i].fsize", i);
  yr_set_integer(sg.maxprot, object, "segments[%i].maxprot", i);
  yr_set_integer(sg.initprot, object, "segments[%i].initprot", i);
  yr_set_integer(sg.nsects, object, "segments[%i].nsects", i);
  yr_set_integer(sg.flags, object, "segments[%i].flags", i);

  uint64_t parsed_size = sizeof(yr_segment_command_64_t);

  yr_section_64_t sec;

  for (unsigned j = 0; j < sg.nsects; ++j)
  {
    parsed_size += sizeof(yr_section_64_t);

    if (sg.cmdsize < parsed_size)
      break;

    memcpy(
        &sec,
        data + sizeof(yr_segment_command_64_t) + (j * sizeof(yr_section_64_t)),
        sizeof(yr_section_64_t));

    if (should_swap)
      swap_section_64(&sec);

    yr_set_sized_string(
        sec.segname,
        strnlen(sec.segname, 16),
        object,
        "segments[%i].sections[%i].segname",
        i,
        j);

    yr_set_sized_string(
        sec.sectname,
        strnlen(sec.sectname, 16),
        object,
        "segments[%i].sections[%i].sectname",
        i,
        j);

    yr_set_integer(sec.addr, object, "segments[%i].sections[%i].addr", i, j);

    yr_set_integer(sec.size, object, "segments[%i].sections[%i].size", i, j);

    yr_set_integer(
        sec.offset, object, "segments[%i].sections[%i].offset", i, j);

    yr_set_integer(sec.align, object, "segments[%i].sections[%i].align", i, j);

    yr_set_integer(
        sec.reloff, object, "segments[%i].sections[%i].reloff", i, j);

    yr_set_integer(
        sec.nreloc, object, "segments[%i].sections[%i].nreloc", i, j);

    yr_set_integer(sec.flags, object, "segments[%i].sections[%i].flags", i, j);

    yr_set_integer(
        sec.reserved1, object, "segments[%i].sections[%i].reserved1", i, j);

    yr_set_integer(
        sec.reserved2, object, "segments[%i].sections[%i].reserved2", i, j);

    yr_set_integer(
        sec.reserved3, object, "segments[%i].sections[%i].reserved3", i, j);
  }
}

// Parse Mach-O file.

void macho_parse_file(
    const uint8_t* data,
    const uint64_t size,
    const uint64_t base_address,
    YR_OBJECT* object,
    YR_SCAN_CONTEXT* context)
{
  // Size must be large enough the hold yr_mach_header_64_t, which is larger
  // than yr_mach_header_32_t.
  if (size < sizeof(yr_mach_header_64_t))
    return;

  // yr_mach_header_64_t is used for storing the header for both for 32-bits
  // and 64-bits files. yr_mach_header_64_t is exactly like
  // yr_mach_header_32_t but with an extra "reserved" field at the end.
  yr_mach_header_64_t header;

  memcpy(&header, data, sizeof(yr_mach_header_64_t));

  // The magic number is always handled as big-endian. If the magic bytes are
  // CA FE BA BE, then header.magic is 0xCAFEBABE.
  header.magic = yr_be32toh(header.magic);

  size_t header_size = (header.magic == MH_MAGIC || header.magic == MH_CIGAM)
                           ? sizeof(yr_mach_header_32_t)
                           : sizeof(yr_mach_header_64_t);

  int should_swap = should_swap_bytes(header.magic);

  if (should_swap)
    swap_mach_header(&header);

  yr_set_integer(header.magic, object, "magic");
  yr_set_integer(header.cputype, object, "cputype");
  yr_set_integer(header.cpusubtype, object, "cpusubtype");
  yr_set_integer(header.filetype, object, "filetype");
  yr_set_integer(header.ncmds, object, "ncmds");
  yr_set_integer(header.sizeofcmds, object, "sizeofcmds");
  yr_set_integer(header.flags, object, "flags");

  // The "reserved" field exists only in 64 bits files.
  if (!macho_is_32(header.magic))
    yr_set_integer(header.reserved, object, "reserved");

  // The first command parsing pass handles only segments.
  uint64_t seg_count = 0;
  uint64_t parsed_size = header_size;
  uint8_t* command = (uint8_t*) (data + header_size);

  yr_load_command_t command_struct;

  for (unsigned i = 0; i < header.ncmds; i++)
  {
    if (data + size < command + sizeof(yr_load_command_t))
      break;

    memcpy(&command_struct, command, sizeof(yr_load_command_t));

    if (should_swap)
      swap_load_command(&command_struct);

    if (size - parsed_size < command_struct.cmdsize)
      break;

    if (command_struct.cmdsize < sizeof(yr_load_command_t))
      break;

    switch (command_struct.cmd)
    {
    case LC_SEGMENT:
      macho_handle_segment(command, size - parsed_size, seg_count++, object);
      break;
    case LC_SEGMENT_64:
      macho_handle_segment_64(command, size - parsed_size, seg_count++, object);
      break;
    }

    command += command_struct.cmdsize;
    parsed_size += command_struct.cmdsize;
  }

  yr_set_integer(seg_count, object, "number_of_segments");

  // The second command parsing pass handles others, who use segment count.
  parsed_size = header_size;
  command = (uint8_t*) (data + header_size);

  for (unsigned i = 0; i < header.ncmds; i++)
  {
    if (data + size < command + sizeof(yr_load_command_t))
      break;

    memcpy(&command_struct, command, sizeof(yr_load_command_t));

    if (should_swap)
      swap_load_command(&command_struct);

    if (size - parsed_size < command_struct.cmdsize)
      break;

    if (command_struct.cmdsize < sizeof(yr_load_command_t))
      break;

    switch (command_struct.cmd)
    {
    case LC_UNIXTHREAD:
      macho_handle_unixthread(
          command, size - parsed_size, base_address, object, context);
      break;
    case LC_MAIN:
      macho_handle_main(command, size - parsed_size, object, context);
      break;
    }

    command += command_struct.cmdsize;
    parsed_size += command_struct.cmdsize;
  }
}

// Parse Mach-O fat file.

void macho_load_fat_arch_header(
    const uint8_t* data,
    const uint64_t size,
    uint32_t num,
    yr_fat_arch_64_t* arch)
{
  if (macho_fat_is_32((uint32_t*) data))
  {
    yr_fat_arch_32_t* arch32 =
        (yr_fat_arch_32_t*) (data + sizeof(yr_fat_header_t) +
                             (num * sizeof(yr_fat_arch_32_t)));

    arch->cputype = yr_be32toh(arch32->cputype);
    arch->cpusubtype = yr_be32toh(arch32->cpusubtype);
    arch->offset = yr_be32toh(arch32->offset);
    arch->size = yr_be32toh(arch32->size);
    arch->align = yr_be32toh(arch32->align);
    arch->reserved = 0;
  }
  else
  {
    yr_fat_arch_64_t* arch64 =
        (yr_fat_arch_64_t*) (data + sizeof(yr_fat_header_t) +
                             (num * sizeof(yr_fat_arch_64_t)));

    arch->cputype = yr_be32toh(arch64->cputype);
    arch->cpusubtype = yr_be32toh(arch64->cpusubtype);
    arch->offset = yr_be64toh(arch64->offset);
    arch->size = yr_be64toh(arch64->size);
    arch->align = yr_be32toh(arch64->align);
    arch->reserved = yr_be32toh(arch64->reserved);
  }
}

void macho_parse_fat_file(
    const uint8_t* data,
    const uint64_t size,
    const uint64_t base_address,
    YR_OBJECT* object,
    YR_SCAN_CONTEXT* context)
{
  size_t fat_arch_sz = sizeof(yr_fat_arch_64_t);

  if (macho_fat_is_32((uint32_t*) data))
    fat_arch_sz = sizeof(yr_fat_arch_32_t);

  if (size < sizeof(yr_fat_header_t))
    return;

  /* All data in Mach-O fat binary headers are in big-endian byte order. */

  const yr_fat_header_t* header = (yr_fat_header_t*) data;
  yr_set_integer(yr_be32toh(header->magic), object, "fat_magic");

  uint32_t count = yr_be32toh(header->nfat_arch);
  yr_set_integer(count, object, "nfat_arch");

  if (size < sizeof(yr_fat_header_t) + count * fat_arch_sz)
    return;

  yr_fat_arch_64_t arch;

  for (uint32_t i = 0; i < count; i++)
  {
    macho_load_fat_arch_header(data, size, i, &arch);

    yr_set_integer(arch.cputype, object, "fat_arch[%i].cputype", i);
    yr_set_integer(arch.cpusubtype, object, "fat_arch[%i].cpusubtype", i);
    yr_set_integer(arch.offset, object, "fat_arch[%i].offset", i);
    yr_set_integer(arch.size, object, "fat_arch[%i].size", i);
    yr_set_integer(arch.align, object, "fat_arch[%i].align", i);
    yr_set_integer(arch.reserved, object, "fat_arch[%i].reserved", i);

    // Check for integer overflow.
    if (arch.offset + arch.size < arch.offset)
      continue;

    if (size < arch.offset + arch.size)
      continue;

    // Force 'file' array entry creation.
    yr_set_integer(YR_UNDEFINED, object, "file[%i].magic", i);

    // Get specific Mach-O file data.
    macho_parse_file(
        data + arch.offset,
        arch.size,
        base_address,
        yr_get_object(object, "file[%i]", i),
        context);
  }
}

// Sets all necessary Mach-O constants and definitions.

void macho_set_definitions(YR_OBJECT* object)
{
  // Magic constants

  yr_set_integer(MH_MAGIC, object, "MH_MAGIC");
  yr_set_integer(MH_CIGAM, object, "MH_CIGAM");
  yr_set_integer(MH_MAGIC_64, object, "MH_MAGIC_64");
  yr_set_integer(MH_CIGAM_64, object, "MH_CIGAM_64");

  // Fat magic constants

  yr_set_integer(FAT_MAGIC, object, "FAT_MAGIC");
  yr_set_integer(FAT_CIGAM, object, "FAT_CIGAM");
  yr_set_integer(FAT_MAGIC_64, object, "FAT_MAGIC_64");
  yr_set_integer(FAT_CIGAM_64, object, "FAT_CIGAM_64");

  // 64-bit masks

  yr_set_integer(CPU_ARCH_ABI64, object, "CPU_ARCH_ABI64");
  yr_set_integer(CPU_SUBTYPE_LIB64, object, "CPU_SUBTYPE_LIB64");

  // CPU types

  yr_set_integer(CPU_TYPE_MC680X0, object, "CPU_TYPE_MC680X0");
  yr_set_integer(CPU_TYPE_X86, object, "CPU_TYPE_X86");
  yr_set_integer(CPU_TYPE_X86, object, "CPU_TYPE_I386");
  yr_set_integer(CPU_TYPE_X86_64, object, "CPU_TYPE_X86_64");
  yr_set_integer(CPU_TYPE_MIPS, object, "CPU_TYPE_MIPS");
  yr_set_integer(CPU_TYPE_MC98000, object, "CPU_TYPE_MC98000");
  yr_set_integer(CPU_TYPE_ARM, object, "CPU_TYPE_ARM");
  yr_set_integer(CPU_TYPE_ARM64, object, "CPU_TYPE_ARM64");
  yr_set_integer(CPU_TYPE_MC88000, object, "CPU_TYPE_MC88000");
  yr_set_integer(CPU_TYPE_SPARC, object, "CPU_TYPE_SPARC");
  yr_set_integer(CPU_TYPE_POWERPC, object, "CPU_TYPE_POWERPC");
  yr_set_integer(CPU_TYPE_POWERPC64, object, "CPU_TYPE_POWERPC64");

  // CPU sub-types

  yr_set_integer(
      CPU_SUBTYPE_INTEL_MODEL_ALL, object, "CPU_SUBTYPE_INTEL_MODEL_ALL");
  yr_set_integer(CPU_SUBTYPE_386, object, "CPU_SUBTYPE_386");
  yr_set_integer(CPU_SUBTYPE_386, object, "CPU_SUBTYPE_I386_ALL");
  yr_set_integer(CPU_SUBTYPE_386, object, "CPU_SUBTYPE_X86_64_ALL");
  yr_set_integer(CPU_SUBTYPE_486, object, "CPU_SUBTYPE_486");
  yr_set_integer(CPU_SUBTYPE_486SX, object, "CPU_SUBTYPE_486SX");
  yr_set_integer(CPU_SUBTYPE_586, object, "CPU_SUBTYPE_586");
  yr_set_integer(CPU_SUBTYPE_PENT, object, "CPU_SUBTYPE_PENT");
  yr_set_integer(CPU_SUBTYPE_PENTPRO, object, "CPU_SUBTYPE_PENTPRO");
  yr_set_integer(CPU_SUBTYPE_PENTII_M3, object, "CPU_SUBTYPE_PENTII_M3");
  yr_set_integer(CPU_SUBTYPE_PENTII_M5, object, "CPU_SUBTYPE_PENTII_M5");
  yr_set_integer(CPU_SUBTYPE_CELERON, object, "CPU_SUBTYPE_CELERON");
  yr_set_integer(
      CPU_SUBTYPE_CELERON_MOBILE, object, "CPU_SUBTYPE_CELERON_MOBILE");
  yr_set_integer(CPU_SUBTYPE_PENTIUM_3, object, "CPU_SUBTYPE_PENTIUM_3");
  yr_set_integer(CPU_SUBTYPE_PENTIUM_3_M, object, "CPU_SUBTYPE_PENTIUM_3_M");
  yr_set_integer(
      CPU_SUBTYPE_PENTIUM_3_XEON, object, "CPU_SUBTYPE_PENTIUM_3_XEON");
  yr_set_integer(CPU_SUBTYPE_PENTIUM_M, object, "CPU_SUBTYPE_PENTIUM_M");
  yr_set_integer(CPU_SUBTYPE_PENTIUM_4, object, "CPU_SUBTYPE_PENTIUM_4");
  yr_set_integer(CPU_SUBTYPE_PENTIUM_4_M, object, "CPU_SUBTYPE_PENTIUM_4_M");
  yr_set_integer(CPU_SUBTYPE_ITANIUM, object, "CPU_SUBTYPE_ITANIUM");
  yr_set_integer(CPU_SUBTYPE_ITANIUM_2, object, "CPU_SUBTYPE_ITANIUM_2");
  yr_set_integer(CPU_SUBTYPE_XEON, object, "CPU_SUBTYPE_XEON");
  yr_set_integer(CPU_SUBTYPE_XEON_MP, object, "CPU_SUBTYPE_XEON_MP");
  yr_set_integer(CPU_SUBTYPE_ARM_ALL, object, "CPU_SUBTYPE_ARM_ALL");
  yr_set_integer(CPU_SUBTYPE_ARM_V4T, object, "CPU_SUBTYPE_ARM_V4T");
  yr_set_integer(CPU_SUBTYPE_ARM_V6, object, "CPU_SUBTYPE_ARM_V6");
  yr_set_integer(CPU_SUBTYPE_ARM_V5, object, "CPU_SUBTYPE_ARM_V5");
  yr_set_integer(CPU_SUBTYPE_ARM_V5TEJ, object, "CPU_SUBTYPE_ARM_V5TEJ");
  yr_set_integer(CPU_SUBTYPE_ARM_XSCALE, object, "CPU_SUBTYPE_ARM_XSCALE");
  yr_set_integer(CPU_SUBTYPE_ARM_V7, object, "CPU_SUBTYPE_ARM_V7");
  yr_set_integer(CPU_SUBTYPE_ARM_V7F, object, "CPU_SUBTYPE_ARM_V7F");
  yr_set_integer(CPU_SUBTYPE_ARM_V7S, object, "CPU_SUBTYPE_ARM_V7S");
  yr_set_integer(CPU_SUBTYPE_ARM_V7K, object, "CPU_SUBTYPE_ARM_V7K");
  yr_set_integer(CPU_SUBTYPE_ARM_V6M, object, "CPU_SUBTYPE_ARM_V6M");
  yr_set_integer(CPU_SUBTYPE_ARM_V7M, object, "CPU_SUBTYPE_ARM_V7M");
  yr_set_integer(CPU_SUBTYPE_ARM_V7EM, object, "CPU_SUBTYPE_ARM_V7EM");
  yr_set_integer(CPU_SUBTYPE_ARM64_ALL, object, "CPU_SUBTYPE_ARM64_ALL");
  yr_set_integer(CPU_SUBTYPE_SPARC_ALL, object, "CPU_SUBTYPE_SPARC_ALL");
  yr_set_integer(CPU_SUBTYPE_POWERPC_ALL, object, "CPU_SUBTYPE_POWERPC_ALL");
  yr_set_integer(CPU_SUBTYPE_MC980000_ALL, object, "CPU_SUBTYPE_MC980000_ALL");
  yr_set_integer(CPU_SUBTYPE_POWERPC_601, object, "CPU_SUBTYPE_POWERPC_601");
  yr_set_integer(CPU_SUBTYPE_MC98601, object, "CPU_SUBTYPE_MC98601");
  yr_set_integer(CPU_SUBTYPE_POWERPC_602, object, "CPU_SUBTYPE_POWERPC_602");
  yr_set_integer(CPU_SUBTYPE_POWERPC_603, object, "CPU_SUBTYPE_POWERPC_603");
  yr_set_integer(CPU_SUBTYPE_POWERPC_603e, object, "CPU_SUBTYPE_POWERPC_603e");
  yr_set_integer(
      CPU_SUBTYPE_POWERPC_603ev, object, "CPU_SUBTYPE_POWERPC_603ev");
  yr_set_integer(CPU_SUBTYPE_POWERPC_604, object, "CPU_SUBTYPE_POWERPC_604");
  yr_set_integer(CPU_SUBTYPE_POWERPC_604e, object, "CPU_SUBTYPE_POWERPC_604e");
  yr_set_integer(CPU_SUBTYPE_POWERPC_620, object, "CPU_SUBTYPE_POWERPC_620");
  yr_set_integer(CPU_SUBTYPE_POWERPC_750, object, "CPU_SUBTYPE_POWERPC_750");
  yr_set_integer(CPU_SUBTYPE_POWERPC_7400, object, "CPU_SUBTYPE_POWERPC_7400");
  yr_set_integer(CPU_SUBTYPE_POWERPC_7450, object, "CPU_SUBTYPE_POWERPC_7450");
  yr_set_integer(CPU_SUBTYPE_POWERPC_970, object, "CPU_SUBTYPE_POWERPC_970");

  // File types

  yr_set_integer(MH_OBJECT, object, "MH_OBJECT");
  yr_set_integer(MH_EXECUTE, object, "MH_EXECUTE");
  yr_set_integer(MH_FVMLIB, object, "MH_FVMLIB");
  yr_set_integer(MH_CORE, object, "MH_CORE");
  yr_set_integer(MH_PRELOAD, object, "MH_PRELOAD");
  yr_set_integer(MH_DYLIB, object, "MH_DYLIB");
  yr_set_integer(MH_DYLINKER, object, "MH_DYLINKER");
  yr_set_integer(MH_BUNDLE, object, "MH_BUNDLE");
  yr_set_integer(MH_DYLIB_STUB, object, "MH_DYLIB_STUB");
  yr_set_integer(MH_DSYM, object, "MH_DSYM");
  yr_set_integer(MH_KEXT_BUNDLE, object, "MH_KEXT_BUNDLE");

  // Header flags

  yr_set_integer(MH_NOUNDEFS, object, "MH_NOUNDEFS");
  yr_set_integer(MH_INCRLINK, object, "MH_INCRLINK");
  yr_set_integer(MH_DYLDLINK, object, "MH_DYLDLINK");
  yr_set_integer(MH_BINDATLOAD, object, "MH_BINDATLOAD");
  yr_set_integer(MH_PREBOUND, object, "MH_PREBOUND");
  yr_set_integer(MH_SPLIT_SEGS, object, "MH_SPLIT_SEGS");
  yr_set_integer(MH_LAZY_INIT, object, "MH_LAZY_INIT");
  yr_set_integer(MH_TWOLEVEL, object, "MH_TWOLEVEL");
  yr_set_integer(MH_FORCE_FLAT, object, "MH_FORCE_FLAT");
  yr_set_integer(MH_NOMULTIDEFS, object, "MH_NOMULTIDEFS");
  yr_set_integer(MH_NOFIXPREBINDING, object, "MH_NOFIXPREBINDING");
  yr_set_integer(MH_PREBINDABLE, object, "MH_PREBINDABLE");
  yr_set_integer(MH_ALLMODSBOUND, object, "MH_ALLMODSBOUND");
  yr_set_integer(
      MH_SUBSECTIONS_VIA_SYMBOLS, object, "MH_SUBSECTIONS_VIA_SYMBOLS");
  yr_set_integer(MH_CANONICAL, object, "MH_CANONICAL");
  yr_set_integer(MH_WEAK_DEFINES, object, "MH_WEAK_DEFINES");
  yr_set_integer(MH_BINDS_TO_WEAK, object, "MH_BINDS_TO_WEAK");
  yr_set_integer(MH_ALLOW_STACK_EXECUTION, object, "MH_ALLOW_STACK_EXECUTION");
  yr_set_integer(MH_ROOT_SAFE, object, "MH_ROOT_SAFE");
  yr_set_integer(MH_SETUID_SAFE, object, "MH_SETUID_SAFE");
  yr_set_integer(MH_NO_REEXPORTED_DYLIBS, object, "MH_NO_REEXPORTED_DYLIBS");
  yr_set_integer(MH_PIE, object, "MH_PIE");
  yr_set_integer(MH_DEAD_STRIPPABLE_DYLIB, object, "MH_DEAD_STRIPPABLE_DYLIB");
  yr_set_integer(MH_HAS_TLV_DESCRIPTORS, object, "MH_HAS_TLV_DESCRIPTORS");
  yr_set_integer(MH_NO_HEAP_EXECUTION, object, "MH_NO_HEAP_EXECUTION");
  yr_set_integer(MH_APP_EXTENSION_SAFE, object, "MH_APP_EXTENSION_SAFE");

  // Segment flags masks

  yr_set_integer(SG_HIGHVM, object, "SG_HIGHVM");
  yr_set_integer(SG_FVMLIB, object, "SG_FVMLIB");
  yr_set_integer(SG_NORELOC, object, "SG_NORELOC");
  yr_set_integer(SG_PROTECTED_VERSION_1, object, "SG_PROTECTED_VERSION_1");

  // Section flags masks

  yr_set_integer(SECTION_TYPE, object, "SECTION_TYPE");
  yr_set_integer(SECTION_ATTRIBUTES, object, "SECTION_ATTRIBUTES");

  // Section types

  yr_set_integer(S_REGULAR, object, "S_REGULAR");
  yr_set_integer(S_ZEROFILL, object, "S_ZEROFILL");
  yr_set_integer(S_CSTRING_LITERALS, object, "S_CSTRING_LITERALS");
  yr_set_integer(S_4BYTE_LITERALS, object, "S_4BYTE_LITERALS");
  yr_set_integer(S_8BYTE_LITERALS, object, "S_8BYTE_LITERALS");
  yr_set_integer(
      S_NON_LAZY_SYMBOL_POINTERS, object, "S_NON_LAZY_SYMBOL_POINTERS");
  yr_set_integer(S_LAZY_SYMBOL_POINTERS, object, "S_LAZY_SYMBOL_POINTERS");
  yr_set_integer(S_LITERAL_POINTERS, object, "S_LITERAL_POINTERS");
  yr_set_integer(S_SYMBOL_STUBS, object, "S_SYMBOL_STUBS");
  yr_set_integer(S_MOD_INIT_FUNC_POINTERS, object, "S_MOD_INIT_FUNC_POINTERS");
  yr_set_integer(S_MOD_TERM_FUNC_POINTERS, object, "S_MOD_TERM_FUNC_POINTERS");
  yr_set_integer(S_COALESCED, object, "S_COALESCED");
  yr_set_integer(S_GB_ZEROFILL, object, "S_GB_ZEROFILL");
  yr_set_integer(S_INTERPOSING, object, "S_INTERPOSING");
  yr_set_integer(S_16BYTE_LITERALS, object, "S_16BYTE_LITERALS");
  yr_set_integer(S_DTRACE_DOF, object, "S_DTRACE_DOF");
  yr_set_integer(
      S_LAZY_DYLIB_SYMBOL_POINTERS, object, "S_LAZY_DYLIB_SYMBOL_POINTERS");
  yr_set_integer(S_THREAD_LOCAL_REGULAR, object, "S_THREAD_LOCAL_REGULAR");
  yr_set_integer(S_THREAD_LOCAL_ZEROFILL, object, "S_THREAD_LOCAL_ZEROFILL");
  yr_set_integer(S_THREAD_LOCAL_VARIABLES, object, "S_THREAD_LOCAL_VARIABLES");
  yr_set_integer(
      S_THREAD_LOCAL_VARIABLE_POINTERS,
      object,
      "S_THREAD_LOCAL_VARIABLE_POINTERS");
  yr_set_integer(
      S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
      object,
      "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS");

  // Section attributes

  yr_set_integer(S_ATTR_PURE_INSTRUCTIONS, object, "S_ATTR_PURE_INSTRUCTIONS");
  yr_set_integer(S_ATTR_NO_TOC, object, "S_ATTR_NO_TOC");
  yr_set_integer(S_ATTR_STRIP_STATIC_SYMS, object, "S_ATTR_STRIP_STATIC_SYMS");
  yr_set_integer(S_ATTR_NO_DEAD_STRIP, object, "S_ATTR_NO_DEAD_STRIP");
  yr_set_integer(S_ATTR_LIVE_SUPPORT, object, "S_ATTR_LIVE_SUPPORT");
  yr_set_integer(
      S_ATTR_SELF_MODIFYING_CODE, object, "S_ATTR_SELF_MODIFYING_CODE");
  yr_set_integer(S_ATTR_DEBUG, object, "S_ATTR_DEBUG");
  yr_set_integer(S_ATTR_SOME_INSTRUCTIONS, object, "S_ATTR_SOME_INSTRUCTIONS");
  yr_set_integer(S_ATTR_EXT_RELOC, object, "S_ATTR_EXT_RELOC");
  yr_set_integer(S_ATTR_LOC_RELOC, object, "S_ATTR_LOC_RELOC");
}

// Get Mach-O file index in fat file by cputype field.

define_function(file_index_type)
{
  YR_OBJECT* module = yr_module();
  int64_t type_arg = integer_argument(1);

  uint64_t nfat = yr_get_integer(module, "nfat_arch");
  if (yr_is_undefined(module, "nfat_arch"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < nfat; i++)
  {
    int64_t type = yr_get_integer(module, "file[%i].cputype", i);
    if (type == type_arg)
    {
      return_integer(i);
    }
  }
  return_integer(YR_UNDEFINED);
}

// Get Mach-O file index in fat file by cputype and cpusubtype fields.

define_function(file_index_subtype)
{
  YR_OBJECT* module = yr_module();
  int64_t type_arg = integer_argument(1);
  int64_t subtype_arg = integer_argument(2);
  uint64_t nfat = yr_get_integer(module, "nfat_arch");

  if (yr_is_undefined(module, "nfat_arch"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < nfat; i++)
  {
    int64_t type = yr_get_integer(module, "file[%i].cputype", i);
    int64_t subtype = yr_get_integer(module, "file[%i].cpusubtype", i);

    if (type == type_arg && subtype == subtype_arg)
    {
      return_integer(i);
    }
  }

  return_integer(YR_UNDEFINED);
}

// Get real entry point offset for specific architecture in fat Mach-O.

define_function(ep_for_arch_type)
{
  YR_OBJECT* module = yr_module();
  int64_t type_arg = integer_argument(1);
  uint64_t nfat = yr_get_integer(module, "nfat_arch");

  if (yr_is_undefined(module, "nfat_arch"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < nfat; i++)
  {
    int64_t type = yr_get_integer(module, "fat_arch[%i].cputype", i);
    if (type == type_arg)
    {
      uint64_t file_offset = yr_get_integer(module, "fat_arch[%i].offset", i);
      uint64_t entry_point = yr_get_integer(module, "file[%i].entry_point", i);
      return_integer(file_offset + entry_point);
    }
  }

  return_integer(YR_UNDEFINED);
}

// Get real entry point offset for specific architecture in fat Mach-O.

define_function(ep_for_arch_subtype)
{
  YR_OBJECT* module = yr_module();
  int64_t type_arg = integer_argument(1);
  int64_t subtype_arg = integer_argument(2);
  uint64_t nfat = yr_get_integer(module, "nfat_arch");

  if (yr_is_undefined(module, "nfat_arch"))
    return_integer(YR_UNDEFINED);

  for (int i = 0; i < nfat; i++)
  {
    int64_t type = yr_get_integer(module, "fat_arch[%i].cputype", i);
    int64_t subtype = yr_get_integer(module, "fat_arch[%i].cpusubtype", i);

    if (type == type_arg && subtype == subtype_arg)
    {
      uint64_t entry_point = yr_get_integer(module, "file[%i].entry_point", i);
      uint64_t file_offset = yr_get_integer(module, "fat_arch[%i].offset", i);

      if (entry_point == YR_UNDEFINED)
      {
        return_integer(YR_UNDEFINED);
      }
      else
      {
        return_integer(file_offset + entry_point);
      }
    }
  }

  return_integer(YR_UNDEFINED);
}

begin_declarations
  // Magic constants
  declare_integer("MH_MAGIC");
  declare_integer("MH_CIGAM");
  declare_integer("MH_MAGIC_64");
  declare_integer("MH_CIGAM_64");

  // Fat magic constants
  declare_integer("FAT_MAGIC");
  declare_integer("FAT_CIGAM");
  declare_integer("FAT_MAGIC_64");
  declare_integer("FAT_CIGAM_64");

  // 64-bit masks
  declare_integer("CPU_ARCH_ABI64");
  declare_integer("CPU_SUBTYPE_LIB64");

  // CPU types
  declare_integer("CPU_TYPE_MC680X0");
  declare_integer("CPU_TYPE_X86");
  declare_integer("CPU_TYPE_I386");
  declare_integer("CPU_TYPE_X86_64");
  declare_integer("CPU_TYPE_MIPS");
  declare_integer("CPU_TYPE_MC98000");
  declare_integer("CPU_TYPE_ARM");
  declare_integer("CPU_TYPE_ARM64");
  declare_integer("CPU_TYPE_MC88000");
  declare_integer("CPU_TYPE_SPARC");
  declare_integer("CPU_TYPE_POWERPC");
  declare_integer("CPU_TYPE_POWERPC64");

  // CPU sub-types
  declare_integer("CPU_SUBTYPE_INTEL_MODEL_ALL");
  declare_integer("CPU_SUBTYPE_386");
  declare_integer("CPU_SUBTYPE_I386_ALL");
  declare_integer("CPU_SUBTYPE_X86_64_ALL");
  declare_integer("CPU_SUBTYPE_486");
  declare_integer("CPU_SUBTYPE_486SX");
  declare_integer("CPU_SUBTYPE_586");
  declare_integer("CPU_SUBTYPE_PENT");
  declare_integer("CPU_SUBTYPE_PENTPRO");
  declare_integer("CPU_SUBTYPE_PENTII_M3");
  declare_integer("CPU_SUBTYPE_PENTII_M5");
  declare_integer("CPU_SUBTYPE_CELERON");
  declare_integer("CPU_SUBTYPE_CELERON_MOBILE");
  declare_integer("CPU_SUBTYPE_PENTIUM_3");
  declare_integer("CPU_SUBTYPE_PENTIUM_3_M");
  declare_integer("CPU_SUBTYPE_PENTIUM_3_XEON");
  declare_integer("CPU_SUBTYPE_PENTIUM_M");
  declare_integer("CPU_SUBTYPE_PENTIUM_4");
  declare_integer("CPU_SUBTYPE_PENTIUM_4_M");
  declare_integer("CPU_SUBTYPE_ITANIUM");
  declare_integer("CPU_SUBTYPE_ITANIUM_2");
  declare_integer("CPU_SUBTYPE_XEON");
  declare_integer("CPU_SUBTYPE_XEON_MP");
  declare_integer("CPU_SUBTYPE_ARM_ALL");
  declare_integer("CPU_SUBTYPE_ARM_V4T");
  declare_integer("CPU_SUBTYPE_ARM_V6");
  declare_integer("CPU_SUBTYPE_ARM_V5");
  declare_integer("CPU_SUBTYPE_ARM_V5TEJ");
  declare_integer("CPU_SUBTYPE_ARM_XSCALE");
  declare_integer("CPU_SUBTYPE_ARM_V7");
  declare_integer("CPU_SUBTYPE_ARM_V7F");
  declare_integer("CPU_SUBTYPE_ARM_V7S");
  declare_integer("CPU_SUBTYPE_ARM_V7K");
  declare_integer("CPU_SUBTYPE_ARM_V6M");
  declare_integer("CPU_SUBTYPE_ARM_V7M");
  declare_integer("CPU_SUBTYPE_ARM_V7EM");
  declare_integer("CPU_SUBTYPE_ARM64_ALL");
  declare_integer("CPU_SUBTYPE_SPARC_ALL");
  declare_integer("CPU_SUBTYPE_POWERPC_ALL");
  declare_integer("CPU_SUBTYPE_MC980000_ALL");
  declare_integer("CPU_SUBTYPE_POWERPC_601");
  declare_integer("CPU_SUBTYPE_MC98601");
  declare_integer("CPU_SUBTYPE_POWERPC_602");
  declare_integer("CPU_SUBTYPE_POWERPC_603");
  declare_integer("CPU_SUBTYPE_POWERPC_603e");
  declare_integer("CPU_SUBTYPE_POWERPC_603ev");
  declare_integer("CPU_SUBTYPE_POWERPC_604");
  declare_integer("CPU_SUBTYPE_POWERPC_604e");
  declare_integer("CPU_SUBTYPE_POWERPC_620");
  declare_integer("CPU_SUBTYPE_POWERPC_750");
  declare_integer("CPU_SUBTYPE_POWERPC_7400");
  declare_integer("CPU_SUBTYPE_POWERPC_7450");
  declare_integer("CPU_SUBTYPE_POWERPC_970");

  // File types
  declare_integer("MH_OBJECT");
  declare_integer("MH_EXECUTE");
  declare_integer("MH_FVMLIB");
  declare_integer("MH_CORE");
  declare_integer("MH_PRELOAD");
  declare_integer("MH_DYLIB");
  declare_integer("MH_DYLINKER");
  declare_integer("MH_BUNDLE");
  declare_integer("MH_DYLIB_STUB");
  declare_integer("MH_DSYM");
  declare_integer("MH_KEXT_BUNDLE");

  // Header flags
  declare_integer("MH_NOUNDEFS");
  declare_integer("MH_INCRLINK");
  declare_integer("MH_DYLDLINK");
  declare_integer("MH_BINDATLOAD");
  declare_integer("MH_PREBOUND");
  declare_integer("MH_SPLIT_SEGS");
  declare_integer("MH_LAZY_INIT");
  declare_integer("MH_TWOLEVEL");
  declare_integer("MH_FORCE_FLAT");
  declare_integer("MH_NOMULTIDEFS");
  declare_integer("MH_NOFIXPREBINDING");
  declare_integer("MH_PREBINDABLE");
  declare_integer("MH_ALLMODSBOUND");
  declare_integer("MH_SUBSECTIONS_VIA_SYMBOLS");
  declare_integer("MH_CANONICAL");
  declare_integer("MH_WEAK_DEFINES");
  declare_integer("MH_BINDS_TO_WEAK");
  declare_integer("MH_ALLOW_STACK_EXECUTION");
  declare_integer("MH_ROOT_SAFE");
  declare_integer("MH_SETUID_SAFE");
  declare_integer("MH_NO_REEXPORTED_DYLIBS");
  declare_integer("MH_PIE");
  declare_integer("MH_DEAD_STRIPPABLE_DYLIB");
  declare_integer("MH_HAS_TLV_DESCRIPTORS");
  declare_integer("MH_NO_HEAP_EXECUTION");
  declare_integer("MH_APP_EXTENSION_SAFE");

  // Segment flags
  declare_integer("SG_HIGHVM");
  declare_integer("SG_FVMLIB");
  declare_integer("SG_NORELOC");
  declare_integer("SG_PROTECTED_VERSION_1");

  // Section masks
  declare_integer("SECTION_TYPE");
  declare_integer("SECTION_ATTRIBUTES");

  // Section types
  declare_integer("S_REGULAR");
  declare_integer("S_ZEROFILL");
  declare_integer("S_CSTRING_LITERALS");
  declare_integer("S_4BYTE_LITERALS");
  declare_integer("S_8BYTE_LITERALS");
  declare_integer("S_LITERAL_POINTERS");
  declare_integer("S_NON_LAZY_SYMBOL_POINTERS");
  declare_integer("S_LAZY_SYMBOL_POINTERS");
  declare_integer("S_SYMBOL_STUBS");
  declare_integer("S_MOD_INIT_FUNC_POINTERS");
  declare_integer("S_MOD_TERM_FUNC_POINTERS");
  declare_integer("S_COALESCED");
  declare_integer("S_GB_ZEROFILL");
  declare_integer("S_INTERPOSING");
  declare_integer("S_16BYTE_LITERALS");
  declare_integer("S_DTRACE_DOF");
  declare_integer("S_LAZY_DYLIB_SYMBOL_POINTERS");
  declare_integer("S_THREAD_LOCAL_REGULAR");
  declare_integer("S_THREAD_LOCAL_ZEROFILL");
  declare_integer("S_THREAD_LOCAL_VARIABLES");
  declare_integer("S_THREAD_LOCAL_VARIABLE_POINTERS");
  declare_integer("S_THREAD_LOCAL_INIT_FUNCTION_POINTERS");

  // Section attributes
  declare_integer("S_ATTR_PURE_INSTRUCTIONS");
  declare_integer("S_ATTR_NO_TOC");
  declare_integer("S_ATTR_STRIP_STATIC_SYMS");
  declare_integer("S_ATTR_NO_DEAD_STRIP");
  declare_integer("S_ATTR_LIVE_SUPPORT");
  declare_integer("S_ATTR_SELF_MODIFYING_CODE");
  declare_integer("S_ATTR_DEBUG");
  declare_integer("S_ATTR_SOME_INSTRUCTIONS");
  declare_integer("S_ATTR_EXT_RELOC");
  declare_integer("S_ATTR_LOC_RELOC");

  // Header
  declare_integer("magic");
  declare_integer("cputype");
  declare_integer("cpusubtype");
  declare_integer("filetype");
  declare_integer("ncmds");
  declare_integer("sizeofcmds");
  declare_integer("flags");
  declare_integer("reserved");

  // Segments and nested sections
  declare_integer("number_of_segments");

  begin_struct_array("segments")
    declare_string("segname");
    declare_integer("vmaddr");
    declare_integer("vmsize");
    declare_integer("fileoff");
    declare_integer("fsize");
    declare_integer("maxprot");
    declare_integer("initprot");
    declare_integer("nsects");
    declare_integer("flags");
    begin_struct_array("sections")
      declare_string("sectname");
      declare_string("segname");
      declare_integer("addr");
      declare_integer("size");
      declare_integer("offset");
      declare_integer("align");
      declare_integer("reloff");
      declare_integer("nreloc");
      declare_integer("flags");
      declare_integer("reserved1");
      declare_integer("reserved2");
      declare_integer("reserved3");
    end_struct_array("sections");
  end_struct_array("segments")

  // Entry point and stack size
  declare_integer("entry_point");
  declare_integer("stack_size");

  // Mach-O fat binary header
  declare_integer("fat_magic");
  declare_integer("nfat_arch");

  begin_struct_array("fat_arch")
    declare_integer("cputype");
    declare_integer("cpusubtype");
    declare_integer("offset");
    declare_integer("size");
    declare_integer("align");
  end_struct_array("fat_arch")

  // Included Mach-O files (must be same as single file structure above)
  begin_struct_array("file")

    // Single file header
    declare_integer("magic");
    declare_integer("cputype");
    declare_integer("cpusubtype");
    declare_integer("filetype");
    declare_integer("ncmds");
    declare_integer("sizeofcmds");
    declare_integer("flags");
    declare_integer("reserved");

    // Segments and nested sections
    declare_integer("number_of_segments");

    begin_struct_array("segments")
      declare_string("segname");
      declare_integer("vmaddr");
      declare_integer("vmsize");
      declare_integer("fileoff");
      declare_integer("fsize");
      declare_integer("maxprot");
      declare_integer("initprot");
      declare_integer("nsects");
      declare_integer("flags");
      begin_struct_array("sections")
        declare_string("sectname");
        declare_string("segname");
        declare_integer("addr");
        declare_integer("size");
        declare_integer("offset");
        declare_integer("align");
        declare_integer("reloff");
        declare_integer("nreloc");
        declare_integer("flags");
        declare_integer("reserved1");
        declare_integer("reserved2");
        declare_integer("reserved3");
      end_struct_array("sections");
    end_struct_array("segments")

    // Entry point and stack size
    declare_integer("entry_point");
    declare_integer("stack_size");

  end_struct_array("file");

  // Mach-O fat binary helper functions
  declare_function("file_index_for_arch", "i", "i", file_index_type);
  declare_function("file_index_for_arch", "ii", "i", file_index_subtype);
  declare_function("entry_point_for_arch", "i", "i", ep_for_arch_type);
  declare_function("entry_point_for_arch", "ii", "i", ep_for_arch_subtype);
end_declarations

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
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = yr_fetch_block_data(block);

    if (block_data == NULL || block->size < 4)
      continue;

    // Parse Mach-O binary.
    if (is_macho_file_block((uint32_t*) block_data))
    {
      macho_parse_file(
          block_data, block->size, block->base, module_object, context);
      break;
    }

    // Parse fat Mach-O binary.
    if (is_fat_macho_file_block((uint32_t*) block_data))
    {
      macho_parse_fat_file(
          block_data, block->size, block->base, module_object, context);
      break;
    }
  }

  macho_set_definitions(module_object);
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
