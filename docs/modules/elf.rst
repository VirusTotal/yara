
.. _elf-module:

##########
ELF module
##########

.. versionadded:: 3.2.0

The ELF module is very similar to the :ref:`pe-module`, but for ELF files. This
module exposes most of the fields present in an ELF header. Let's see some
examples:

.. code-block:: yara

    import "elf"

    rule single_section
    {
        condition:
            elf.number_of_sections == 1
    }

    rule elf_64
    {
        condition:
            elf.machine == elf.EM_X86_64
    }

Reference
---------

.. c:type:: type

    Integer with one of the following values:

    .. c:type:: ET_NONE

        No file type.

    .. c:type:: ET_REL

        Relocatable file.

    .. c:type:: ET_EXEC

        Executable file.

    .. c:type:: ET_DYN

        Shared object file.

    .. c:type:: ET_CORE

        Core file.

    *Example: elf.type == elf.ET_EXEC*

.. c:type:: machine

    Integer with one of the following values:

    .. c:type:: EM_M32
    .. c:type:: EM_SPARC
    .. c:type:: EM_386
    .. c:type:: EM_68K
    .. c:type:: EM_88K
    .. c:type:: EM_860
    .. c:type:: EM_MIPS
    .. c:type:: EM_MIPS_RS3_LE
    .. c:type:: EM_PPC
    .. c:type:: EM_PPC64
    .. c:type:: EM_ARM
    .. c:type:: EM_X86_64
    .. c:type:: EM_AARCH64

    *Example: elf.machine == elf.EM_X86_64*

.. c:type:: entry_point

    Entry point raw offset or virtual address depending on whether YARA is
    scanning a file or process memory respectively. This is equivalent to the
    deprecated ``entrypoint`` keyword.

.. c:type:: number_of_sections

    Number of sections in the ELF file.

.. c:type:: sections

    A zero-based array of section objects, one for each section the ELF has.
    Individual sections can be accessed by using the [] operator. Each section
    object has the following attributes:

    .. c:member:: name

        Section's name.

        *Example: elf.sections[3].name == ".bss"*

    .. c:member:: size

        Section's size in bytes. Unless the section type is SHT_NOBITS, the
        section occupies sh_size bytes in the file. A section of
        :c:type:`SHT_NOBITS` may have a non-zero size, but it occupies no space
        in the file.

    .. c:member:: offset

        Offset from the beginning of the file to the first byte in the section.
        One section type, :c:type:`SHT_NOBITS` described below, occupies no
        space in the file, and its :c:member:`offset` member locates the
        conceptual placement in the file.

    .. c:member:: type

        Integer with one of the following values:

        .. c:type:: SHT_NULL

            This value marks the section as inactive; it does not have
            an associated section. Other members of the section header have
            undefined values.

        .. c:type:: SHT_PROGBITS

            The section holds information defined by the program, whose format
            and meaning are determined solely by the program.

        .. c:type:: SHT_SYMTAB

            The section holds a symbol table.

        .. c:type:: SHT_STRTAB

            The section holds a string table. An object file may have multiple
            string table sections.

        .. c:type:: SHT_RELA

            The section holds relocation entries.

        .. c:type:: SHT_HASH

            The section holds a symbol hash table.

        .. c:type:: SHT_DYNAMIC

            The section holds information for dynamic linking.

        .. c:type:: SHT_NOTE

            The section holds information that marks the file in some way.

        .. c:type:: SHT_NOBITS

            A section of this type occupies no space in the file but otherwise resembles :c:type:`SHT_PROGBITS`.

        .. c:type:: SHT_REL

            The section holds relocation entries.

        .. c:type:: SHT_SHLIB

            This section type is reserved but has unspecified semantics.

        .. c:type:: SHT_DYNSYM

            This section holds dynamic linking symbols.

    .. c:member:: flags

        Integer with section's flags as defined below:

        .. c:type:: SHF_WRITE

            The section contains data that should be writable during process
            execution.

        .. c:type:: SHF_ALLOC

            The section occupies memory during process execution. Some control sections do not reside in the memory image of an object file; this attribute is off for those sections.

        .. c:type:: SHF_EXECINSTR

            The section contains executable machine instructions.

        *Example: elf.sections[2].flags & elf.SHF_WRITE*

    .. c:member:: address

        .. versionadded:: 3.6.0

        The virtual address the section starts at.


.. c:type:: number_of_segments

    .. versionadded:: 3.4.0

    Number of segments in the ELF file.

.. c:type:: segments

    .. versionadded:: 3.4.0

    A zero-based array of segment objects, one for each segment the ELF has.
    Individual segments can be accessed by using the [] operator. Each segment
    object has the following attributes:

    .. c:member:: alignment

        Value to which the segments are aligned in memory and in the file.

    .. c:member:: file_size

        Number of bytes in the file image of the segment.  It may be zero.

    .. c:member:: flags

        A combination of the following segment flags:

        .. c:type:: PF_R

            The segment is readable.

        .. c:type:: PF_W

            The segment is writable.

        .. c:type:: PF_X

            The segment is executable.

    .. c:member:: memory_size

        In-memory segment size.

    .. c:member:: offset

        Offset from the beginning of the file where the segment resides.

    .. c:member:: physical_address

        On systems for which physical addressing is relevant, contains the
        segment's physical address.

    .. c:member:: type

        Type of segment indicated by one of the following values:

        .. c:type:: PT_NULL
        .. c:type:: PT_LOAD
        .. c:type:: PT_DYNAMIC
        .. c:type:: PT_INTERP
        .. c:type:: PT_NOTE
        .. c:type:: PT_SHLIB
        .. c:type:: PT_PHDR
        .. c:type:: PT_LOPROC
        .. c:type:: PT_HIPROC
        .. c:type:: PT_GNU_STACK

    .. c:member:: virtual_address

        Virtual address at which the segment resides in memory.

.. c:type:: dynamic_section_entries

    .. versionadded:: 3.6.0

    Number of entries in the dynamic section in the ELF file.

.. c:type:: dynamic

    .. versionadded:: 3.6.0

    A zero-based array of dynamic objects, one for each entry in found in the
    ELF's dynamic section. Individual dynamic objects can be accessed by using
    the [] operator. Each dynamic object has the following attributes:

    .. c:member:: type

        Value that describes the type of dynamic section. Builtin values are:

        .. c:type:: DT_NULL
        .. c:type:: DT_NEEDED
        .. c:type:: DT_PLTRELSZ
        .. c:type:: DT_PLTGOT
        .. c:type:: DT_HASH
        .. c:type:: DT_STRTAB
        .. c:type:: DT_SYMTAB
        .. c:type:: DT_RELA
        .. c:type:: DT_RELASZ
        .. c:type:: DT_RELAENT
        .. c:type:: DT_STRSZ
        .. c:type:: DT_SYMENT
        .. c:type:: DT_INIT
        .. c:type:: DT_FINI
        .. c:type:: DT_SONAME
        .. c:type:: DT_RPATH
        .. c:type:: DT_SYMBOLIC
        .. c:type:: DT_REL
        .. c:type:: DT_RELSZ
        .. c:type:: DT_RELENT
        .. c:type:: DT_PLTREL
        .. c:type:: DT_DEBUG
        .. c:type:: DT_TEXTREL
        .. c:type:: DT_JMPREL
        .. c:type:: DT_BIND_NOW
        .. c:type:: DT_INIT_ARRAY
        .. c:type:: DT_FINI_ARRAY
        .. c:type:: DT_INIT_ARRAYSZ
        .. c:type:: DT_FINI_ARRAYSZ
        .. c:type:: DT_RUNPATH
        .. c:type:: DT_FLAGS
        .. c:type:: DT_ENCODING

    .. c:member:: value

        A value associated with the given type. The type of value (address,
        size, etc.) is dependant on the type of dynamic entry.

.. c:type:: symtab_entries

    .. versionadded:: 3.6.0

    Number of entries in the symbol table found in the ELF file.

.. c:type:: symtab

    .. versionadded:: 3.6.0

    A zero-based array of symbol objects, one for each entry in found in the
    ELF's SYMBTAB. Individual symbol objects can be accessed by using the []
    operator. Each symbol object has the following attributes:

    .. c:member:: name

        The symbol's name.

    .. c:member:: value

        A value associated with the symbol. Generally a virtual address.

    .. c:member:: size

        The symbol's size.

    .. c:member:: type

        The type of symbol. Built values are:

        .. c:type:: STT_NOTYPE
        .. c:type:: STT_OBJECT
        .. c:type:: STT_FUNC
        .. c:type:: STT_SECTION
        .. c:type:: STT_FILE
        .. c:type:: STT_COMMON
        .. c:type:: STT_TLS

    .. c:member:: bind

        The binding of the symbol. Builtin values are:

        .. c:type:: STB_LOCAL
        .. c:type:: STB_GLOBAL
        .. c:type:: STB_WEAK

    .. c:member:: shndx

        The section index which the symbol is associated with.








