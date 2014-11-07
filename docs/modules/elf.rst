
.. _elf-module:

##########
ELF module
##########

.. versionadded:: 3.2.0

The ELF module is very similar to the :ref:`pe-module`, but for ELF files. This
module exposes most of the fields present in a ELF header. Let's see some
examples::

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
    .. c:type:: EM_ARM"
    .. c:type:: EM_MIPS
    .. c:type:: EM_X86_64

    *Example: elf.machine == elf.EM_X86_64*

.. c:type:: entry_point

    Entry point raw offset or virtual address depending if YARA is scanning a
    file or process memory respectively. This is equivalent to the deprecated
    ``entrypoint`` keyword.

.. c:type:: number_of_sections

    Number of sections in the ELF file.

.. c:type:: sections

    An zero-based array of section objects, one for each section the ELF has.
    Individual sections can be accessed by using the [] operator. Each section
    object has the following attributes:

    .. c:member:: name

        Section's name.

        *Example: elf.section[3].name == ".bss"*

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

        Integer with one of the following value:

        .. c:type:: SHT_NULL

            This value marks the section as inactive; it does not have
            an associated section. Other members of the section header have
            undefined values.

        .. c:type:: SHT_PROGBITS

            The section holds information defined by the program, whose format
            and meaning are determined solely by the program.

        .. c:type:: SHT_SYMTAB

            The section hold a symbol table.

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

        Integer with sections's flags as defined below:

        .. c:type:: SHF_WRITE

            The section contains data that should be writable during process
            execution.

        .. c:type:: SHF_ALLOC

            The section occupies memory during process execution. Some control sections do not reside in the memory image of an object file; this attribute is off for those sections.

        .. c:type:: SHF_EXECINSTR

            The section contains executable machine instructions.

        *Example: elf.section[2].flags & elf.SHF_WRITE*












