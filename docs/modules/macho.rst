
.. _macho-module:

##########
macho module
##########

The MACHO module is very similar to the :ref:`elf-module`, but for macho files.
This module exposes most of the fields present in an macho header. Let's see
some examples:

.. code-block:: yara

    import "macho"

    rule single_section
    {
        condition:
            macho.number_of_segments == 1
    }

Reference
---------

.. c:type:: magic

    Integer with one of the following values:

    .. c:type:: MH_MAGIC

        0xfeedface - Constant for the magic field of the mach_header (32-bit
        architectures). The machine is the same endianness as the binary.

    .. c:type:: MH_CIGAM

        0xcefaedfe Constant for the magic field of the mach_header (32-bit
        architectures). The machine and the binary don't have the same
        endianness.

    .. c:type:: MH_MAGIC_64

        0xfeedfacf - Constant for the magic field of the mach_header (64-bit
        architectures). The machine is the same endianness as the binary.

    .. c:type:: MH_CIGAM_64

        0xcffaedfe Constant for the magic field of the mach_header (64-bit
        architectures). The machine and the binary don't have the same
        endianness.

    *Example: macho.magic == macho.MH_MAGIC_64*

.. c:type:: fat_magic

    Integer with one of the following values:

    .. c:type:: FAT_MAGIC

        0xcafebabe - Constant for the magic field of the mach_header (32-bit
        architectures). The machine is the same endianness as the binary.

    .. c:type:: FAT_CIGAM

        0xbebafeca Constant for the magic field of the mach_header (32-bit
        architectures). The machine and the binary don't have the same
        endianness.

    .. c:type:: FAT_MAGIC_64

        0xfeedfacf - Constant for the magic field of the mach_header (64-bit
        architectures). The machine is the same endianness as the binary.

    .. c:type:: FAT_CIGAM_64

        0xcffaedfe Constant for the magic field of the mach_header (64-bit
        architectures). The machine and the binary don't have the same
        endianness.

    *Example: macho.magic == macho.FAT_MAGIC_64*

.. c:type:: cputype

    Integer with one of the following values:

    .. c:type:: CPU_ARCH_ABI64
    .. c:type:: CPU_TYPE_MC680X0
    .. c:type:: CPU_TYPE_X86
    .. c:type:: CPU_TYPE_I386
    .. c:type:: CPU_TYPE_X86_64
    .. c:type:: CPU_TYPE_MIPS
    .. c:type:: CPU_TYPE_MC98000
    .. c:type:: CPU_TYPE_ARM
    .. c:type:: CPU_TYPE_ARM64
    .. c:type:: CPU_TYPE_MC88000
    .. c:type:: CPU_TYPE_SPARC
    .. c:type:: CPU_TYPE_POWERPC
    .. c:type:: CPU_TYPE_POWERPC64

    *Example: macho.cputype == macho.CPU_TYPE_X86_64*

.. c:type:: cpusubtype

    Integer with one of the following values:

    .. c:type:: CPU_SUBTYPE_LIB64
    .. c:type:: CPU_SUBTYPE_INTEL_MODEL_ALL
    .. c:type:: CPU_SUBTYPE_386
    .. c:type:: CPU_SUBTYPE_I386_ALL
    .. c:type:: CPU_SUBTYPE_X86_64_ALL
    .. c:type:: CPU_SUBTYPE_486
    .. c:type:: CPU_SUBTYPE_486SX
    .. c:type:: CPU_SUBTYPE_586
    .. c:type:: CPU_SUBTYPE_PENT
    .. c:type:: CPU_SUBTYPE_PENTPRO
    .. c:type:: CPU_SUBTYPE_PENTII_M3
    .. c:type:: CPU_SUBTYPE_PENTII_M5
    .. c:type:: CPU_SUBTYPE_CELERON
    .. c:type:: CPU_SUBTYPE_CELERON_MOBILE
    .. c:type:: CPU_SUBTYPE_PENTIUM_3
    .. c:type:: CPU_SUBTYPE_PENTIUM_3_M
    .. c:type:: CPU_SUBTYPE_PENTIUM_3_XEON
    .. c:type:: CPU_SUBTYPE_PENTIUM_M
    .. c:type:: CPU_SUBTYPE_PENTIUM_4
    .. c:type:: CPU_SUBTYPE_PENTIUM_4_M
    .. c:type:: CPU_SUBTYPE_ITANIUM
    .. c:type:: CPU_SUBTYPE_ITANIUM_2
    .. c:type:: CPU_SUBTYPE_XEON
    .. c:type:: CPU_SUBTYPE_XEON_MP
    .. c:type:: CPU_SUBTYPE_ARM_ALL
    .. c:type:: CPU_SUBTYPE_ARM_V4T
    .. c:type:: CPU_SUBTYPE_ARM_V6
    .. c:type:: CPU_SUBTYPE_ARM_V5
    .. c:type:: CPU_SUBTYPE_ARM_V5TEJ
    .. c:type:: CPU_SUBTYPE_ARM_XSCALE
    .. c:type:: CPU_SUBTYPE_ARM_V7
    .. c:type:: CPU_SUBTYPE_ARM_V7F
    .. c:type:: CPU_SUBTYPE_ARM_V7S
    .. c:type:: CPU_SUBTYPE_ARM_V7K
    .. c:type:: CPU_SUBTYPE_ARM_V6M
    .. c:type:: CPU_SUBTYPE_ARM_V7M
    .. c:type:: CPU_SUBTYPE_ARM_V7EM
    .. c:type:: CPU_SUBTYPE_ARM64_ALL
    .. c:type:: CPU_SUBTYPE_SPARC_ALL
    .. c:type:: CPU_SUBTYPE_POWERPC_ALL
    .. c:type:: CPU_SUBTYPE_MC980000_ALL
    .. c:type:: CPU_SUBTYPE_POWERPC_601
    .. c:type:: CPU_SUBTYPE_MC98601
    .. c:type:: CPU_SUBTYPE_POWERPC_602
    .. c:type:: CPU_SUBTYPE_POWERPC_603
    .. c:type:: CPU_SUBTYPE_POWERPC_603e
    .. c:type:: CPU_SUBTYPE_POWERPC_603ev
    .. c:type:: CPU_SUBTYPE_POWERPC_604
    .. c:type:: CPU_SUBTYPE_POWERPC_604e
    .. c:type:: CPU_SUBTYPE_POWERPC_620
    .. c:type:: CPU_SUBTYPE_POWERPC_750
    .. c:type:: CPU_SUBTYPE_POWERPC_7400
    .. c:type:: CPU_SUBTYPE_POWERPC_7450
    .. c:type:: CPU_SUBTYPE_POWERPC_970

    *Example: macho.cpusubtype == macho.CPU_TYPE_X86_64*

.. c:type:: filetype

    Integer with one of the following values:

    .. c:type:: MH_OBJECT

        Relocatable object file.

    .. c:type:: MH_EXECUTE

        Demand paged executable file.

    .. c:type:: MH_FVMLIB

        Fixed VM shared library file.

    .. c:type:: MH_CORE

        Core file.

    .. c:type:: MH_PRELOAD

        Preloaded executable file.

    .. c:type:: MH_DYLIB

        Dynamically bound shared library.

    .. c:type:: MH_DYLINKER

        Dynamic link editor.

    .. c:type:: MH_BUNDLE

        Dynamically bound bundle file.

    .. c:type:: MH_DYLIB_STUB

        Shared library stub for static linking only, no section contents.

    .. c:type:: MH_DSYM

        Companion file with only debug sections.

    .. c:type:: MH_KEXT_BUNDLE

        x86_64 kexts.

    *Example: macho.filetype == macho.MH_EXECUTE*

.. c:type:: ncmds

    Type of load command. Integer with one of the following values:

    .. c:type:: LC_SEGMENT

        Segment of this file to be mapped.

    .. c:type:: LC_SYMTAB

        Link-edit stab symbol table info.

    .. c:type:: LC_SYMSEG

        Link-edit gdb symbol table info (obsolete).

    .. c:type:: LC_THREAD

        Thread.

    .. c:type:: LC_UNIXTHREAD

        Unix thread (includes a stack).

    .. c:type:: LC_LOADFVMLIB

        Load a specified fixed VM shared library.

    .. c:type:: LC_IDFVMLIB

        Fixed VM shared library identification.

    .. c:type:: LC_IDENT

        Object identification info (obsolete).

    .. c:type:: LC_FVMFILE

        Fixed VM file inclusion (internal use).

    .. c:type:: LC_PREPAGE

        Prepage command (internal use).

    .. c:type:: LC_DYSYMTAB

        Dynamic link-edit symbol table info.

    .. c:type:: LC_LOAD_DYLIB

        Load a dynamically linked shared library.

    .. c:type:: LC_ID_DYLIB

        Dynamically linked shared lib ident.

    .. c:type:: LC_LOAD_DYLINKER

        Load a dynamic linker.

    .. c:type:: LC_ID_DYLINKER

        Dynamic linker identification.

    .. c:type:: LC_PREBOUND_DYLIB

        Modules prebound for a dynamically linked shared library.

    .. c:type:: LC_ROUTINES

        Image routines.

    .. c:type:: LC_SUB_FRAMEWORK

        Sub framework.

    .. c:type:: LC_SUB_UMBRELLA

        Sub umbrella.

    .. c:type:: LC_SUB_CLIENT

        Sub client.

    .. c:type:: LC_SUB_LIBRARY

        Sub library.

    .. c:type:: LC_TWOLEVEL_HINTS

        Two-level namespace lookup hints.

    .. c:type:: LC_PREBIND_CKSUM

        Prebind checksum.

    .. c:type:: LC_LOAD_WEAK_DYLIB

        Load a dynamically linked shared library that is allowed to be missing
        (all symbols are weak imported).

    .. c:type:: LC_SEGMENT_64

        64-bit segment of this file to be mapped.

    .. c:type:: LC_ROUTINES_64

        64-bit image routines.

    .. c:type:: LC_UUID

        The uuid.

    .. c:type:: LC_RPATH

        Runpath additions.

    .. c:type:: LC_CODE_SIGNATURE

        Local of code signature.

    .. c:type:: LC_SEGMENT_SPLIT_INFO

        Local of info to split segments.

    .. c:type:: LC_REEXPORT_DYLIB

        Load and re-export dylib.

    .. c:type:: LC_LAZY_LOAD_DYLIB

        Delay load of dylib until first use.

    .. c:type:: LC_ENCRYPTION_INFO

        Encrypted segment information.

    .. c:type:: LC_DYLD_INFO

        Compressed dyld information.

    .. c:type:: LC_DYLD_INFO_ONLY

        Compressed dyld information only.

    .. c:type:: LC_LOAD_UPWARD_DYLIB

        Load upward dylib.

    .. c:type:: LC_VERSION_MIN_MACOSX

        Build for MacOSX min OS version.

    .. c:type:: LC_VERSION_MIN_IPHONEOS

        Build for iPhoneOS min OS version.

    .. c:type:: LC_FUNCTION_STARTS

        Compressed table of function start addresses.

    .. c:type:: LC_DYLD_ENVIRONMENT

        String for dyld to treat like environment variable.

    .. c:type:: LC_MAIN

        Replacement for LC_UNIXTHREAD.

    .. c:type:: LC_DATA_IN_CODE

        Table of non-instructions in __text.

    .. c:type:: LC_SOURCE_VERSION

        Source version used to build binary.

    .. c:type:: LC_DYLIB_CODE_SIGN_DRS

        Code signing DRs copied from linked dylibs.

.. c:type:: sizeofcmds

    The size of all load commands, in bytes, in the Mach-O

.. c:type:: reserved

    Reserved

.. c:type:: flags

    Integer with one of the following values:

    .. c:type:: MH_NOUNDEFS

        The object file has no undefined references.

    .. c:type:: MH_INCRLINK

        The object file is the output of anincremental link against a base file
        and can't be link edited again.

    .. c:type:: MH_DYLDLINK

        The object file is input for the dynamic linker and can't be staticly
        link edited again.

    .. c:type:: MH_BINDATLOAD

        The object file's undefined references are bound by the dynamic linker
        when loaded.

    .. c:type:: MH_PREBOUND

        The file has its dynamic undefined references prebound.

    .. c:type:: MH_SPLIT_SEGS

        The file has its read-only and read-write segments split.

    .. c:type:: MH_LAZY_INIT

        The shared library init routine is to be run lazily via catching memory
        faults to its writeable segments (obsolete).

    .. c:type:: MH_TWOLEVEL

        The image is using two-level name space bindings.

    .. c:type:: MH_FORCE_FLAT

        The executable is forcing all images to use flat name space bindings.

    .. c:type:: MH_NOMULTIDEFS

        This umbrella guarantees no multiple defintions of symbols in its
        sub-images so the two-level namespace hints can always be used.

    .. c:type:: MH_NOFIXPREBINDING

        Do not have dyld notify the prebinding agent about this executable.

    .. c:type:: MH_PREBINDABLE

        The binary is not prebound but can have its prebinding redone. only used
        when MH_PREBOUND is not set.

    .. c:type:: MH_ALLMODSBOUND

        Indicates that this binary binds to all two-level namespace modules of
        its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL
        are both set. 

    .. c:type:: MH_SUBSECTIONS_VIA_SYMBOLS

        Safe to divide up the sections into sub-sections via symbols for dead
        code stripping.

    .. c:type:: MH_CANONICAL

        The binary has been canonicalized via the unprebind operation.

    .. c:type:: MH_WEAK_DEFINES

        The final linked image contains external weak symbols.

    .. c:type:: MH_BINDS_TO_WEAK

        The final linked image uses weak symbols.

    .. c:type:: MH_ALLOW_STACK_EXECUTION

        When this bit is set, all stacks in the task will be given stack
        execution privilege.  Only used in MH_EXECUTE filetypes.

    .. c:type:: MH_ROOT_SAFE

        When this bit is set, the binary declares it is safe for use in
        processes with uid zero.

    .. c:type:: MH_SETUID_SAFE

        When this bit is set, the binary declares it is safe for use in
        processes when issetugid() is true.

    .. c:type:: MH_NO_REEXPORTED_DYLIBS

        When this bit is set on a dylib, the static linker does not need to
        examine dependent dylibs to see if any are re-exported.

    .. c:type:: MH_PIE

        When this bit is set, the OS will load the main executable at a random
        address.  Only used in MH_EXECUTE filetypes.

    .. c:type:: MH_DEAD_STRIPPABLE_DYLIB

        Only for use on dylibs. When linking against a dylib that has this bit
        set, the static linker will automatically not create a LC_LOAD_DYLIB
        load command to the dylib if no symbols are being referenced from the
        dylib.

    .. c:type:: MH_HAS_TLV_DESCRIPTORS

        Contains a section of type S_THREAD_LOCAL_VARIABLES.

    .. c:type:: MH_NO_HEAP_EXECUTION

        When this bit is set, the OS will run the main executable with a
        non-executable heap even on platforms (e.g. i386) that don't require it.
        Only used in MH_EXECUTE filetypes.

    .. c:type:: MH_APP_EXTENSION_SAFE

        The code was linked for use in an application extension.

.. c:type:: entry_point

    Entry point raw offset or virtual address depending on whether YARA is
    scanning a file or process memory respectively. This is equivalent to the
    deprecated ``entrypoint`` keyword.

.. c:type:: stack_size

    If stack_size was used at link time, the stacksize field will contain the
    stack size need for the main thread.

.. c:type:: number_of_segments

    Number of segments in the MACHO file.

.. c:type:: segments

    A zero-based array of segment objects, one for each segment the MACHO has.
    Individual segments can be accessed by using the [] operator. Each segment
    object has the following attributes:

    .. c:member:: segname

        Segment name.

            *Example: macho.segments[1].segname == "__TEXT"*

    .. c:member:: vmaddr

        Memory address of this segment.

    .. c:member:: vmsize

        Memory size of this segment.

    .. c:member:: fileoff

        File offset of this segment.

    .. c:member:: fsize

        Amount to map from the file.

    .. c:member:: maxprot

        Maximum VM protection.

    .. c:member:: initprot

        Initial VM protection.

    .. c:member:: nsects

        Number of sections in segment.

    .. c:member:: flags

        Integer with one of the following values:

        .. c:type:: SG_HIGHVM
        .. c:type:: SG_FVMLIB
        .. c:type:: SG_NORELOC
        .. c:type:: SG_PROTECTED_VERSION_1

    .. c:member:: sections

        A segment is made up of zero or more sections.

        .. c:type:: sectname

            Name of this section

        .. c:type:: segname

            Segment this section goes in.
                *Example: macho.segments[1].sections[0].segname == "__TEXT"*

        .. c:type:: addr

            Memory address of this section.

        .. c:type:: size

            Size in bytes of this section.

        .. c:type:: offset

            File offset of this section.

        .. c:type:: align

            Section alignment (power of 2).

        .. c:type:: reloff

            File offset of relocation entries.

        .. c:type:: nreloc

            Number of relocation entries.

        .. c:type:: flags

            Flags (section type and attributes). The flags field of a section
            structure is separated into two parts a section type and section
            attributes.  The section types are mutually exclusive (it can only
            have one type) but the section attributes are not (it may have more
            than one attribute).

                Section types

                .. c:type:: S_REGULAR
                .. c:type:: S_ZEROFILL
                .. c:type:: S_CSTRING_LITERALS
                .. c:type:: S_4BYTE_LITERALS
                .. c:type:: S_8BYTE_LITERALS
                .. c:type:: S_LITERAL_POINTERS
                .. c:type:: S_NON_LAZY_SYMBOL_POINTERS
                .. c:type:: S_LAZY_SYMBOL_POINTERS
                .. c:type:: S_SYMBOL_STUBS
                .. c:type:: S_MOD_INIT_FUNC_POINTERS
                .. c:type:: S_MOD_TERM_FUNC_POINTERS
                .. c:type:: S_COALESCED
                .. c:type:: S_GB_ZEROFILL
                .. c:type:: S_INTERPOSING
                .. c:type:: S_16BYTE_LITERALS
                .. c:type:: S_DTRACE_DOF
                .. c:type:: S_LAZY_DYLIB_SYMBOL_POINTERS
                .. c:type:: S_THREAD_LOCAL_REGULAR
                .. c:type:: S_THREAD_LOCAL_ZEROFILL
                .. c:type:: S_THREAD_LOCAL_VARIABLES
                .. c:type:: S_THREAD_LOCAL_VARIABLE_POINTERS
                .. c:type:: S_THREAD_LOCAL_INIT_FUNCTION_POINTERS

                Section attributes

                .. c:type:: S_ATTR_PURE_INSTRUCTIONS
                .. c:type:: S_ATTR_NO_TOC
                .. c:type:: S_ATTR_STRIP_STATIC_SYMS
                .. c:type:: S_ATTR_NO_DEAD_STRIP
                .. c:type:: S_ATTR_LIVE_SUPPORT
                .. c:type:: S_ATTR_SELF_MODIFYING_CODE
                .. c:type:: S_ATTR_DEBUG
                .. c:type:: S_ATTR_SOME_INSTRUCTIONS
                .. c:type:: S_ATTR_EXT_RELOC
                .. c:type:: S_ATTR_LOC_RELOC

        .. c:type:: reserved1

            Reserved.

        .. c:type:: reserved2

            Reserved.

        .. c:type:: reserved3

            Reserved. (Mach-O fat binary only)
