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

#ifndef _MACHO_H
#define _MACHO_H

#include <yara/integers.h>

// Mach-O file format magic constants

#define MH_MAGIC     0xfeedface
#define MH_CIGAM     0xcefaedfe
#define MH_MAGIC_64  0xfeedfacf
#define MH_CIGAM_64  0xcffaedfe

// Mach-O universal binary magic constants

#define FAT_MAGIC     0xcafebabe
#define FAT_CIGAM     0xbebafeca
#define FAT_MAGIC_64  0xcafebabf
#define FAT_CIGAM_64  0xbfbafeca

// Mach-O 64-bit masks

#define CPU_ARCH_ABI64     0x01000000  // 64-bit ABI mask (for cputype)
#define CPU_SUBTYPE_LIB64  0x80000000  // 64-bit library mask (for cpusubtype)

// Mach-O CPU types

#define CPU_TYPE_MC680X0    0x00000006  // Motorola 68000
#define CPU_TYPE_I386       0x00000007  // AMD/Intel x86
#define CPU_TYPE_X86        0x00000007  // AMD/Intel x86
#define CPU_TYPE_X86_64     0x01000007  // AMD/Intel x86-64
#define CPU_TYPE_MIPS       0x00000008  // MIPS
#define CPU_TYPE_MC98000    0x0000000a  // Motorola PowerPC
#define CPU_TYPE_HPPA       0x0000000b  // HP PA-RISC
#define CPU_TYPE_ARM        0x0000000c  // ARM
#define CPU_TYPE_ARM64      0x0100000c  // ARM 64-bit
#define CPU_TYPE_MC88000    0x0000000d  // Motorola 88000
#define CPU_TYPE_SPARC      0x0000000e  // SPARC
#define CPU_TYPE_I860       0x0000000f  // Intel i860
#define CPU_TYPE_ALPHA      0x00000010  // DEC Alpha
#define CPU_TYPE_POWERPC    0x00000012  // PowerPC
#define CPU_TYPE_POWERPC64  0x01000012  // PowerPC 64-bit

// Mach-O Intel CPU sub-types

#define CPU_SUBTYPE_INTEL_MODEL_ALL  0x00
#define CPU_SUBTYPE_386              0x03
#define CPU_SUBTYPE_486              0x04
#define CPU_SUBTYPE_486SX            0x84
#define CPU_SUBTYPE_586              0x05
#define CPU_SUBTYPE_PENT             0x05
#define CPU_SUBTYPE_PENTPRO          0x16
#define CPU_SUBTYPE_PENTII_M3        0x36
#define CPU_SUBTYPE_PENTII_M5        0x56
#define CPU_SUBTYPE_CELERON          0x67
#define CPU_SUBTYPE_CELERON_MOBILE   0x77
#define CPU_SUBTYPE_PENTIUM_3        0x08
#define CPU_SUBTYPE_PENTIUM_3_M      0x18
#define CPU_SUBTYPE_PENTIUM_3_XEON   0x28
#define CPU_SUBTYPE_PENTIUM_M        0x09
#define CPU_SUBTYPE_PENTIUM_4        0x0a
#define CPU_SUBTYPE_PENTIUM_4_M      0x1a
#define CPU_SUBTYPE_ITANIUM          0x0b
#define CPU_SUBTYPE_ITANIUM_2        0x1b
#define CPU_SUBTYPE_XEON             0x0c
#define CPU_SUBTYPE_XEON_MP          0x1c

// Mach-O ARM CPU sub-types

#define CPU_SUBTYPE_ARM_ALL          0x00
#define CPU_SUBTYPE_ARM_V4T          0x05
#define CPU_SUBTYPE_ARM_V6           0x06
#define CPU_SUBTYPE_ARM_V5           0x07
#define CPU_SUBTYPE_ARM_V5TEJ        0x07
#define CPU_SUBTYPE_ARM_XSCALE       0x08
#define CPU_SUBTYPE_ARM_V7           0x09
#define CPU_SUBTYPE_ARM_V7F          0x0a
#define CPU_SUBTYPE_ARM_V7S          0x0b
#define CPU_SUBTYPE_ARM_V7K          0x0c
#define CPU_SUBTYPE_ARM_V6M          0x0e
#define CPU_SUBTYPE_ARM_V7M          0x0f
#define CPU_SUBTYPE_ARM_V7EM         0x10

// Mach-O ARM 64-bit CPU sub-types

#define CPU_SUBTYPE_ARM64_ALL        0x00

// Mach-O SPARC CPU sub-types

#define CPU_SUBTYPE_SPARC_ALL        0x00

// Mach-O PowerPC CPU sub-types

#define CPU_SUBTYPE_POWERPC_ALL      0x00
#define CPU_SUBTYPE_MC980000_ALL     0x00
#define CPU_SUBTYPE_POWERPC_601      0x01
#define CPU_SUBTYPE_MC98601          0x01
#define CPU_SUBTYPE_POWERPC_602      0x02
#define CPU_SUBTYPE_POWERPC_603      0x03
#define CPU_SUBTYPE_POWERPC_603e     0x04
#define CPU_SUBTYPE_POWERPC_603ev    0x05
#define CPU_SUBTYPE_POWERPC_604      0x06
#define CPU_SUBTYPE_POWERPC_604e     0x07
#define CPU_SUBTYPE_POWERPC_620      0x08
#define CPU_SUBTYPE_POWERPC_750      0x09
#define CPU_SUBTYPE_POWERPC_7400     0x0a
#define CPU_SUBTYPE_POWERPC_7450     0x0b
#define CPU_SUBTYPE_POWERPC_970      0x64

// Mach-O file types

#define MH_OBJECT       0x01  // Object file
#define MH_EXECUTE      0x02  // Executable file
#define MH_FVMLIB       0x03  // Fixed VM shared library
#define MH_CORE         0x04  // Core dump file
#define MH_PRELOAD      0x05  // Preloaded executable file
#define MH_DYLIB        0x06  // Dynamic shared library
#define MH_DYLINKER     0x07  // Dynamic linker shared library
#define MH_BUNDLE       0x08  // Bundle file
#define MH_DYLIB_STUB   0x09  // Dynamic shared library stub
#define MH_DSYM         0x0a  // Companion debug sections file
#define MH_KEXT_BUNDLE  0x0b  // Kernel extension

// Mach-O file flags

#define MH_NOUNDEFS                 0x00000001
#define MH_INCRLINK                 0x00000002
#define MH_DYLDLINK                 0x00000004
#define MH_BINDATLOAD               0x00000008
#define MH_PREBOUND                 0x00000010
#define MH_SPLIT_SEGS               0x00000020
#define MH_LAZY_INIT                0x00000040
#define MH_TWOLEVEL                 0x00000080
#define MH_FORCE_FLAT               0x00000100
#define MH_NOMULTIDEFS              0x00000200
#define MH_NOFIXPREBINDING          0x00000400
#define MH_PREBINDABLE              0x00000800
#define MH_ALLMODSBOUND             0x00001000
#define MH_SUBSECTIONS_VIA_SYMBOLS  0x00002000
#define MH_CANONICAL                0x00004000
#define MH_WEAK_DEFINES             0x00008000
#define MH_BINDS_TO_WEAK            0x00010000
#define MH_ALLOW_STACK_EXECUTION    0x00020000
#define MH_ROOT_SAFE                0x00040000
#define MH_SETUID_SAFE              0x00080000
#define MH_NO_REEXPORTED_DYLIBS     0x00100000
#define MH_PIE                      0x00200000
#define MH_DEAD_STRIPPABLE_DYLIB    0x00400000
#define MH_HAS_TLV_DESCRIPTORS      0x00800000
#define MH_NO_HEAP_EXECUTION        0x01000000
#define MH_APP_EXTENSION_SAFE       0x02000000

// Mach-O load commands

#define LC_SEGMENT                   0x00000001
#define LC_SYMTAB                    0x00000002
#define LC_SYMSEG                    0x00000003
#define LC_THREAD                    0x00000004
#define LC_UNIXTHREAD                0x00000005
#define LC_LOADFVMLIB                0x00000006
#define LC_IDFVMLIB                  0x00000007
#define LC_IDENT                     0x00000008
#define LC_FVMFILE                   0x00000009
#define LC_PREPAGE                   0x0000000a
#define LC_DYSYMTAB                  0x0000000b
#define LC_LOAD_DYLIB                0x0000000c
#define LC_ID_DYLIB                  0x0000000d
#define LC_LOAD_DYLINKER             0x0000000e
#define LC_ID_DYLINKER               0x0000000f
#define LC_PREBOUND_DYLIB            0x00000010
#define LC_ROUTINES                  0x00000011
#define LC_SUB_FRAMEWORK             0x00000012
#define LC_SUB_UMBRELLA              0x00000013
#define LC_SUB_CLIENT                0x00000014
#define LC_SUB_LIBRARY               0x00000015
#define LC_TWOLEVEL_HINTS            0x00000016
#define LC_PREBIND_CKSUM             0x00000017
#define LC_LOAD_WEAK_DYLIB           0x80000018
#define LC_SEGMENT_64                0x00000019
#define LC_ROUTINES_64               0x0000001A
#define LC_UUID                      0x0000001B
#define LC_RPATH                     0x8000001C
#define LC_CODE_SIGNATURE            0x0000001D
#define LC_SEGMENT_SPLIT_INFO        0x0000001E
#define LC_REEXPORT_DYLIB            0x8000001F
#define LC_LAZY_LOAD_DYLIB           0x00000020
#define LC_ENCRYPTION_INFO           0x00000021
#define LC_DYLD_INFO                 0x00000022
#define LC_DYLD_INFO_ONLY            0x80000022
#define LC_LOAD_UPWARD_DYLIB         0x80000023
#define LC_VERSION_MIN_MACOSX        0x00000024
#define LC_VERSION_MIN_IPHONEOS      0x00000025
#define LC_FUNCTION_STARTS           0x00000026
#define LC_DYLD_ENVIRONMENT          0x00000027
#define LC_MAIN                      0x80000028
#define LC_DATA_IN_CODE              0x00000029
#define LC_SOURCE_VERSION            0x0000002A
#define LC_DYLIB_CODE_SIGN_DRS       0x0000002B
#define LC_ENCRYPTION_INFO_64        0x0000002C
#define LC_LINKER_OPTION             0x0000002D
#define LC_LINKER_OPTIMIZATION_HINT  0x0000002E
#define LC_VERSION_MIN_TVOS          0x0000002F
#define LC_VERSION_MIN_WATCHOS       0x00000030

// Segment flags

#define SG_HIGHVM               0x00000001  // Use high part of VM (stack)
#define SG_FVMLIB               0x00000002  // Allocated by a fixed VM library
#define SG_NORELOC              0x00000004  // No associated relocations
#define SG_PROTECTED_VERSION_1  0x00000008  // Segment is encryption protected

// Section flag masks

#define SECTION_TYPE            0x000000ff  // Section type mask
#define SECTION_ATTRIBUTES      0xffffff00  // Section attributes mask

// Section type (use SECTION_TYPE mask)

#define S_REGULAR                              0x00
#define S_ZEROFILL                             0x01
#define S_CSTRING_LITERALS                     0x02
#define S_4BYTE_LITERALS                       0x03
#define S_8BYTE_LITERALS                       0x04
#define S_LITERAL_POINTERS                     0x05
#define S_NON_LAZY_SYMBOL_POINTERS             0x06
#define S_LAZY_SYMBOL_POINTERS                 0x07
#define S_SYMBOL_STUBS                         0x08
#define S_MOD_INIT_FUNC_POINTERS               0x09
#define S_MOD_TERM_FUNC_POINTERS               0x0a
#define S_COALESCED                            0x0b
#define S_GB_ZEROFILL                          0x0c
#define S_INTERPOSING                          0x0d
#define S_16BYTE_LITERALS                      0x0e
#define S_DTRACE_DOF                           0x0f
#define S_LAZY_DYLIB_SYMBOL_POINTERS           0x10
#define S_THREAD_LOCAL_REGULAR                 0x11
#define S_THREAD_LOCAL_ZEROFILL                0x12
#define S_THREAD_LOCAL_VARIABLES               0x13
#define S_THREAD_LOCAL_VARIABLE_POINTERS       0x14
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS  0x15

// Section attributes (use SECTION_ATTRIBUTES mask)

#define S_ATTR_PURE_INSTRUCTIONS    0x80000000  // Only pure instructions
#define S_ATTR_NO_TOC               0x40000000  // Contains coalesced symbols
#define S_ATTR_STRIP_STATIC_SYMS    0x20000000  // Can strip static symbols
#define S_ATTR_NO_DEAD_STRIP        0x10000000  // No dead stripping
#define S_ATTR_LIVE_SUPPORT         0x08000000  // Live blocks support
#define S_ATTR_SELF_MODIFYING_CODE  0x04000000  // Self modifying code
#define S_ATTR_DEBUG                0x02000000  // Debug section
#define S_ATTR_SOME_INSTRUCTIONS    0x00000400  // Some machine instructions
#define S_ATTR_EXT_RELOC            0x00000200  // Has external relocations
#define S_ATTR_LOC_RELOC            0x00000100  // Has local relocations

#pragma pack(push,1)

typedef struct {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
} yr_mach_header_32_t;


typedef struct {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
} yr_mach_header_64_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
} yr_load_command_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
} yr_segment_command_32_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
} yr_segment_command_64_t;


typedef struct {
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
} yr_section_32_t;


typedef struct {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} yr_section_64_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
} yr_uuid_command_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t entryoff;
  uint64_t stacksize;
} yr_entry_point_command_t;


typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t flavor;
  uint32_t count;
  // cpu_thread_state
} yr_thread_command_t;


typedef struct {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t edi;
  uint32_t esi;
  uint32_t ebp;
  uint32_t esp;
  uint32_t ss;
  uint32_t eflags;
  uint32_t eip;
  uint32_t cs;
  uint32_t ds;
  uint32_t es;
  uint32_t fs;
  uint32_t gs;
} yr_x86_thread_state_t;


typedef struct {
  uint32_t r[13];
  uint32_t sp;
  uint32_t lr;
  uint32_t pc;
  uint32_t cpsr;
} yr_arm_thread_state_t;


typedef struct {
  uint32_t srr0;
  uint32_t srr1;
  uint32_t r[32];
  uint32_t cr;
  uint32_t xer;
  uint32_t lr;
  uint32_t ctr;
  uint32_t mq;
  uint32_t vrsavead;
} yr_ppc_thread_state_t;


typedef struct {
  uint32_t psr;
  uint32_t pc;
  uint32_t npc;
  uint32_t y;
  uint32_t g1;
  uint32_t g2;
  uint32_t g3;
  uint32_t g4;
  uint32_t g5;
  uint32_t g6;
  uint32_t g7;
  uint32_t o0;
  uint32_t o1;
  uint32_t o2;
  uint32_t o3;
  uint32_t o4;
  uint32_t o5;
  uint32_t o6;
  uint32_t o7;
} yr_sparc_thread_state_t;


typedef struct {
  uint32_t dreg[8];
  uint32_t areg[8];
  uint16_t pad;
  uint16_t sr;
  uint32_t pc;
} yr_m68k_thread_state_t;


typedef struct {
  uint32_t r1;
  uint32_t r2;
  uint32_t r3;
  uint32_t r4;
  uint32_t r5;
  uint32_t r6;
  uint32_t r7;
  uint32_t r8;
  uint32_t r9;
  uint32_t r10;
  uint32_t r11;
  uint32_t r12;
  uint32_t r13;
  uint32_t r14;
  uint32_t r15;
  uint32_t r16;
  uint32_t r17;
  uint32_t r18;
  uint32_t r19;
  uint32_t r20;
  uint32_t r21;
  uint32_t r22;
  uint32_t r23;
  uint32_t r24;
  uint32_t r25;
  uint32_t r26;
  uint32_t r27;
  uint32_t r28;
  uint32_t r29;
  uint32_t r30;
  uint32_t r31;
  uint32_t xip;
  uint32_t xip_in_bd;
  uint32_t nip;
} yr_m88k_thread_state_t;


typedef struct {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
  uint64_t cs;
  uint64_t fs;
  uint64_t gs;
} yr_x86_thread_state64_t;


typedef struct {
  uint64_t r[29];
  uint64_t fp;
  uint64_t lr;
  uint64_t sp;
  uint64_t pc;
  uint64_t cpsr;
} yr_arm_thread_state64_t;


typedef struct {
  uint64_t srr0;
  uint64_t srr1;
  uint64_t r[32];
  uint32_t cr;
  uint64_t xer;
  uint64_t lr;
  uint64_t ctr;
  uint32_t vrsave;
} yr_ppc_thread_state64_t;


typedef struct {
  uint32_t magic;
  uint32_t nfat_arch;
} yr_fat_header_t;


typedef struct {
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
} yr_fat_arch_32_t;


typedef struct {
  uint32_t cputype;
  uint32_t cpusubtype;
  uint64_t offset;
  uint64_t size;
  uint32_t align;
  uint32_t reserved;
} yr_fat_arch_64_t;

#pragma pack(pop)

#endif
