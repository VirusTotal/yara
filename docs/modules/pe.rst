
.. _pe-module:

#########
PE module
#########

The PE module allows you to create more fine-grained rules for PE files by
using attributes and features of the PE file format. This module exposes most of
the fields present in a PE header and provides functions which can be used to
write more expressive and targeted rules. Let's see some examples:

.. code-block:: yara

    import "pe"

    rule single_section
    {
        condition:
            pe.number_of_sections == 1
    }

    rule control_panel_applet
    {
        condition:
            pe.exports("CPlApplet")
    }

    rule is_dll
    {
        condition:
            pe.characteristics & pe.DLL
    }

Reference
---------

.. c:type:: machine

    .. versionchanged:: 3.3.0

    Integer with one of the following values:

    .. c:type:: MACHINE_UNKNOWN
    .. c:type:: MACHINE_AM33
    .. c:type:: MACHINE_AMD64
    .. c:type:: MACHINE_ARM
    .. c:type:: MACHINE_ARMNT
    .. c:type:: MACHINE_ARM64
    .. c:type:: MACHINE_EBC
    .. c:type:: MACHINE_I386
    .. c:type:: MACHINE_IA64
    .. c:type:: MACHINE_M32R
    .. c:type:: MACHINE_MIPS16
    .. c:type:: MACHINE_MIPSFPU
    .. c:type:: MACHINE_MIPSFPU16
    .. c:type:: MACHINE_POWERPC
    .. c:type:: MACHINE_POWERPCFP
    .. c:type:: MACHINE_R4000
    .. c:type:: MACHINE_SH3
    .. c:type:: MACHINE_SH3DSP
    .. c:type:: MACHINE_SH4
    .. c:type:: MACHINE_SH5
    .. c:type:: MACHINE_THUMB
    .. c:type:: MACHINE_WCEMIPSV2

    *Example: pe.machine == pe.MACHINE_AMD64*

.. c:type:: checksum

    .. versionadded:: 3.6.0

    Integer with the "PE checksum" as stored in the OptionalHeader

.. c:type:: calculate_checksum

    .. versionadded:: 3.6.0

    Function that calculates the "PE checksum"

    *Example: pe.checksum == pe.calculate_checksum()*

.. c:type:: subsystem

    Integer with one of the following values:

    .. c:type:: SUBSYSTEM_UNKNOWN
    .. c:type:: SUBSYSTEM_NATIVE
    .. c:type:: SUBSYSTEM_WINDOWS_GUI
    .. c:type:: SUBSYSTEM_WINDOWS_CUI
    .. c:type:: SUBSYSTEM_OS2_CUI
    .. c:type:: SUBSYSTEM_POSIX_CUI
    .. c:type:: SUBSYSTEM_NATIVE_WINDOWS
    .. c:type:: SUBSYSTEM_WINDOWS_CE_GUI
    .. c:type:: SUBSYSTEM_EFI_APPLICATION
    .. c:type:: SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
    .. c:type:: SUBSYSTEM_EFI_RUNTIME_DRIVER
    .. c:type:: SUBSYSTEM_XBOX
    .. c:type:: SUBSYSTEM_WINDOWS_BOOT_APPLICATION

    *Example: pe.subsystem == pe.SUBSYSTEM_NATIVE*

.. c:type:: timestamp

    PE timestamp.

.. c:type:: pointer_to_symbol_table

    .. versionadded:: 3.8.0

    Value of IMAGE_FILE_HEADER::PointerToSymbolTable. Used when the PE image has
    COFF debug info.

.. c:type:: pointer_to_symbol_table

    .. versionadded:: 3.8.0

    Value of IMAGE_FILE_HEADER::PointerToSymbolTable. Used when the PE image has
    COFF debug info.

.. c:type:: number_of_symbols

    .. versionadded:: 3.8.0

    Value of IMAGE_FILE_HEADER::NumberOfSymbols. Used when the PE image has COFF
    debug info.

.. c:type:: size_of_optional_header

    .. versionadded:: 3.8.0

    Value of IMAGE_FILE_HEADER::SizeOfOptionalHeader. This is real size of the
    optional header and reflects differences between 32-bit and 64-bit optional
    header and number of data directories.

.. c:type:: opthdr_magic

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::Magic.

.. c:type:: size_of_code

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfCode. This is the sum of raw data
    sizes in code sections.

.. c:type:: size_of_initialized_data

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfInitializedData.

.. c:type:: size_of_uninitialized_data

    Value of IMAGE_OPTIONAL_HEADER::SizeOfUninitializedData.

.. c:type:: entry_point

    Entry point raw offset or virtual address depending on whether YARA is
    scanning a file or process memory respectively. This is equivalent to the
    deprecated ``entrypoint`` keyword.

.. c:type:: base_of_code

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::BaseOfCode.

.. c:type:: base_of_data

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::BaseOfData. This field only exists in 32-bit
    PE files.

.. c:type:: image_base

    Image base relative virtual address.

.. c:type:: section_alignment

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SectionAlignment. When Windows maps a PE
    image to memory, all raw sizes (including size of header) are aligned up to
    this value.

.. c:type:: file_alignment

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::FileAlignment. All raw data sizes of sections
    in the PE image are aligned to this value.

.. c:type:: win32_version_value

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::Win32VersionValue.

.. c:type:: size_of_image

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfImage. This is the total virtual size
    of header and all sections.

.. c:type:: size_of_headers

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfHeaders. This is the raw data size of
    the PE headers including DOS header, file header, optional header and all
    section headers. When PE is mapped to memory, this value is subject to
    aligning up to SectionAlignment.

.. c:type:: characteristics

    Bitmap with PE FileHeader characteristics. Individual characteristics
    can be inspected by performing a bitwise AND operation with the
    following constants:

    .. c:type:: RELOCS_STRIPPED
    
        Relocation info stripped from file.
    
    .. c:type:: EXECUTABLE_IMAGE
    
        File is executable  (i.e. no unresolved external references).
    
    .. c:type:: LINE_NUMS_STRIPPED
    
        Line numbers stripped from file.
    
    .. c:type:: LOCAL_SYMS_STRIPPED
    
        Local symbols stripped from file.
    
    .. c:type:: AGGRESIVE_WS_TRIM
    
        Aggressively trim working set
    
    .. c:type:: LARGE_ADDRESS_AWARE
    
        App can handle >2gb addresses
    
    .. c:type:: BYTES_REVERSED_LO
    
        Bytes of machine word are reversed.
    
    .. c:type:: MACHINE_32BIT
    
        32 bit word machine.
    
    .. c:type:: DEBUG_STRIPPED
    
        Debugging info stripped from file in .DBG file
    
    .. c:type:: REMOVABLE_RUN_FROM_SWAP
    
        If Image is on removable media, copy and run from the swap file.
    
    .. c:type:: NET_RUN_FROM_SWAP
    
        If Image is on Net, copy and run from the swap file.
    
    .. c:type:: SYSTEM
    
        System File.
    
    .. c:type:: DLL
    
        File is a DLL.
    
    .. c:type:: UP_SYSTEM_ONLY
    
        File should only be run on a UP machine
    
    .. c:type:: BYTES_REVERSED_HI
    
        Bytes of machine word are reversed.

    *Example:  pe.characteristics & pe.DLL*

.. c:type:: linker_version

    An object with two integer attributes, one for each major and minor linker
    version.

    .. c:member:: major

        Major linker version.

    .. c:member:: minor

        Minor linker version.

.. c:type:: os_version

    An object with two integer attributes, one for each major and minor OS
    version.

    .. c:member:: major

        Major OS version.

    .. c:member:: minor

        Minor OS version.

.. c:type:: image_version

    An object with two integer attributes, one for each major and minor image
    version.

    .. c:member:: major

        Major image version.

    .. c:member:: minor

        Minor image version.

.. c:type:: subsystem_version

    An object with two integer attributes, one for each major and minor subsystem
    version.

    .. c:member:: major

        Major subsystem version.

    .. c:member:: minor

        Minor subsystem version.

.. c:type:: dll_characteristics

    Bitmap with PE OptionalHeader DllCharacteristics.  Do not confuse these
    flags with the PE FileHeader Characteristics. Individual
    characteristics can be inspected by performing a bitwise AND
    operation with the following constants:

    .. c:type:: DYNAMIC_BASE

        File can be relocated - also marks the file as ASLR compatible

    .. c:type:: FORCE_INTEGRITY
    .. c:type:: NX_COMPAT

        Marks the file as DEP compatible

    .. c:type:: NO_ISOLATION
    .. c:type:: NO_SEH

        The file does not contain structured exception handlers, this must be
        set to use SafeSEH

    .. c:type:: NO_BIND
    .. c:type:: WDM_DRIVER

        Marks the file as a Windows Driver Model (WDM) device driver.

    .. c:type:: TERMINAL_SERVER_AWARE

        Marks the file as terminal server compatible

.. c:type:: size_of_stack_reserve

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfStackReserve. This is the default
    amount of virtual memory that will be reserved for stack.

.. c:type:: size_of_stack_commit

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfStackCommit. This is the default
    amount of virtual memory that will be allocated for stack.

.. c:type:: size_of_heap_reserve

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfHeapReserve. This is the default
    amount of virtual memory that will be reserved for main process heap.

.. c:type:: size_of_heap_commit

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::SizeOfHeapCommit. This is the default
    amount of virtual memory that will be allocated for main process heap.

.. c:type:: loader_flags

    .. versionadded:: 3.8.0

    Value of IMAGE_OPTIONAL_HEADER::LoaderFlags.

.. c:type:: number_of_rva_and_sizes

    Value of IMAGE_OPTIONAL_HEADER::NumberOfRvaAndSizes. This is the number of
    items in the IMAGE_OPTIONAL_HEADER::DataDirectory array.

.. c:type:: data_directories

    .. versionadded:: 3.8.0

    A zero-based array of data directories. Each data directory contains virtual
    address and length of the appropriate data directory. Each data directory
    has the following entries:

    .. c:member:: virtual_address

        Relative virtual address (RVA) of the PE data directory. If this is zero,
        then the data directory is missing.
        Note that for digital signature, this is the file offset, not RVA.

    .. c:member:: size

        Size of the PE data directory, in bytes.

        The index for the data directory entry can be one of the following values:

    .. c:type:: IMAGE_DIRECTORY_ENTRY_EXPORT

        Data directory for exported functions.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_IMPORT

        Data directory for import directory.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_RESOURCE

        Data directory for resource section.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_EXCEPTION

        Data directory for exception information.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_SECURITY

        This is the raw file offset and length of the image digital signature.
        If the image has no embedded digital signature, this directory will contain zeros.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_BASERELOC

        Data directory for image relocation table.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_DEBUG

        Data directory for debug information.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_TLS

        Data directory for image thread local storage.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG

        Data directory for image load configuration.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT

        Data directory for image bound import table.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_IAT

        Data directory for image Import Address Table.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT

        Data directory for Delayed Import Table. Structure of the delayed import table
        is linker-dependent. Microsoft version of delayed imports is described
        in the souces "delayimp.h" and "delayimp.cpp", which can be found
        in MS Visual Studio 2008 CRT sources.

    .. c:type:: IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

        Data directory for .NET headers.

    *Example:  pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address != 0*

.. c:type:: number_of_sections

    Number of sections in the PE.

.. c:type:: sections

    .. versionadded:: 3.3.0

    A zero-based array of section objects, one for each section the PE has.
    Individual sections can be accessed by using the [] operator. Each section
    object has the following attributes:

    .. c:member:: name

        Section name.

    .. c:member:: characteristics

        Section characteristics.

    .. c:member:: virtual_address

        Section virtual address.

    .. c:member:: virtual_size

        Section virtual size.

    .. c:member:: raw_data_offset

        Section raw offset.

    .. c:member:: raw_data_size

        Section raw size.

    .. c:member:: pointer_to_relocations

        .. versionadded:: 3.8.0

        Value of IMAGE_SECTION_HEADER::PointerToRelocations.

    .. c:member:: pointer_to_line_numbers

        .. versionadded:: 3.8.0

        Value of IMAGE_SECTION_HEADER::PointerToLinenumbers.

    .. c:member:: number_of_relocations

        .. versionadded:: 3.8.0

        Value of IMAGE_SECTION_HEADER::NumberOfRelocations.

    .. c:member:: number_of_line_numbers

        .. versionadded:: 3.8.0

        Value of IMAGE_SECTION_HEADER::NumberOfLineNumbers.

    *Example:  pe.sections[0].name == ".text"*

    Individual section characteristics can be inspected using a bitwise AND
    operation with the following constants:

    .. c:type:: SECTION_CNT_CODE
    .. c:type:: SECTION_CNT_INITIALIZED_DATA
    .. c:type:: SECTION_CNT_UNINITIALIZED_DATA
    .. c:type:: SECTION_GPREL
    .. c:type:: SECTION_MEM_16BIT
    .. c:type:: SECTION_LNK_NRELOC_OVFL
    .. c:type:: SECTION_MEM_DISCARDABLE
    .. c:type:: SECTION_MEM_NOT_CACHED
    .. c:type:: SECTION_MEM_NOT_PAGED
    .. c:type:: SECTION_MEM_SHARED
    .. c:type:: SECTION_MEM_EXECUTE
    .. c:type:: SECTION_MEM_READ
    .. c:type:: SECTION_MEM_WRITE

    *Example: pe.sections[1].characteristics & SECTION_CNT_CODE*

.. c:type:: overlay

    .. versionadded:: 3.6.0

    A structure containing the following integer members:

    .. c:member:: offset

        Overlay section offset.

    .. c:member:: size

        Overlay section size.

    *Example: uint8(0x0d) at pe.overlay.offset and pe.overlay.size > 1024*

.. c:type:: number_of_resources

    Number of resources in the PE.

.. c:type:: resource_timestamp

    Resource timestamp. This is stored as an integer.

.. c:type:: resource_version

    An object with two integer attributes, major and minor versions.

    .. c:member:: major

        Major resource version.

    .. c:member:: minor

        Minor resource version.

.. c:type:: resources

    .. versionchanged:: 3.3.0

    A zero-based array of resource objects, one for each resource the PE has.
    Individual resources can be accessed by using the [] operator. Each
    resource object has the following attributes:

    .. c:member:: offset

        Offset for the resource data.

    .. c:member:: length

        Length of the resource data.

    .. c:member:: type

        Type of the resource (integer).

    .. c:member:: id

        ID of the resource (integer).

    .. c:member:: language

        Language of the resource (integer).

    .. c:member:: type_string

        Type of the resource as a string, if specified.

    .. c:member:: name_string

        Name of the resource as a string, if specified.

    .. c:member:: language_string

        Language of the resource as a string, if specified.

    All resources must have a type, id (name), and language specified. They can
    be either an integer or string, but never both, for any given level.

    *Example: pe.resources[0].type == pe.RESOURCE_TYPE_RCDATA*

    *Example: pe.resources[0].name_string == "F\\x00I\\x00L\\x00E\\x00"*

    Resource types can be inspected using the following constants:

    .. c:type:: RESOURCE_TYPE_CURSOR
    .. c:type:: RESOURCE_TYPE_BITMAP
    .. c:type:: RESOURCE_TYPE_ICON
    .. c:type:: RESOURCE_TYPE_MENU
    .. c:type:: RESOURCE_TYPE_DIALOG
    .. c:type:: RESOURCE_TYPE_STRING
    .. c:type:: RESOURCE_TYPE_FONTDIR
    .. c:type:: RESOURCE_TYPE_FONT
    .. c:type:: RESOURCE_TYPE_ACCELERATOR
    .. c:type:: RESOURCE_TYPE_RCDATA
    .. c:type:: RESOURCE_TYPE_MESSAGETABLE
    .. c:type:: RESOURCE_TYPE_GROUP_CURSOR
    .. c:type:: RESOURCE_TYPE_GROUP_ICON
    .. c:type:: RESOURCE_TYPE_VERSION
    .. c:type:: RESOURCE_TYPE_DLGINCLUDE
    .. c:type:: RESOURCE_TYPE_PLUGPLAY
    .. c:type:: RESOURCE_TYPE_VXD
    .. c:type:: RESOURCE_TYPE_ANICURSOR
    .. c:type:: RESOURCE_TYPE_ANIICON
    .. c:type:: RESOURCE_TYPE_HTML
    .. c:type:: RESOURCE_TYPE_MANIFEST

    For more information refer to:

    http://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx

.. c:type:: version_info

    .. versionadded:: 3.2.0

    Dictionary containing the PE's version information. Typical keys are:

        ``Comments``
        ``CompanyName``
        ``FileDescription``
        ``FileVersion``
        ``InternalName``
        ``LegalCopyright``
        ``LegalTrademarks``
        ``OriginalFilename``
        ``ProductName``
        ``ProductVersion``

    For more information refer to:

    http://msdn.microsoft.com/en-us/library/windows/desktop/ms646987(v=vs.85).aspx

    *Example:  pe.version_info["CompanyName"] contains "Microsoft"*

.. c:type:: number_of_signatures

    Number of authenticode signatures in the PE.

.. c:type:: signatures

    A zero-based array of signature objects, one for each authenticode
    signature in the PE file. Usually PE files have a single signature.

    .. c:member:: thumbprint

        .. versionadded:: 3.8.0

        A string containing the thumbprint of the signature.

    .. c:member:: issuer

        A string containing information about the issuer. These are some
        examples::

            "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Code Signing PCA"

            "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA"

            "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO Code Signing CA 2"

    .. c:member:: subject

        A string containing information about the subject.

    .. c:member:: version

        Version number.

    .. c:member:: algorithm

        Algorithm used for this signature. Usually "sha1WithRSAEncryption".

    .. c:member:: serial

        A string containing the serial number. This is an example::

        "52:00:e5:aa:25:56:fc:1a:86:ed:96:c9:d4:4b:33:c7"

    .. c:member:: not_before

        Unix timestamp on which the validity period for this signature begins.

    .. c:member:: not_after

        Unix timestamp on which the validity period for this signature ends.

    .. c:member:: valid_on(timestamp)

        Function returning true if the signature was valid on the date
        indicated by *timestamp*. The following sentence::

            pe.signatures[n].valid_on(timestamp)

        Is equivalent to::

            timestamp >= pe.signatures[n].not_before and timestamp <= pe.signatures[n].not_after

.. c:type:: rich_signature

    Structure containing information about the PE's rich signature as
    documented `here <http://www.ntcore.com/files/richsign.htm>`_.

    .. c:member:: offset

        Offset where the rich signature starts. It will be undefined if the
        file doesn't have a rich signature.

    .. c:member:: length

        Length of the rich signature, not including the final "Rich" marker.

    .. c:member:: key

        Key used to encrypt the data with XOR.

    .. c:member:: raw_data

        Raw data as it appears in the file.

    .. c:member:: clear_data

        Data after being decrypted by XORing it with the key.

    .. c:function:: version(version, [toolid])

        .. versionadded:: 3.5.0

        Function returning true if the PE has the specified *version* in the PE's rich
        signature. Provide the optional *toolid* argument to only match when both match
        for one entry. More information can be found here:

        http://www.ntcore.com/files/richsign.htm

        *Example: pe.rich_signature.version(21005)*

    .. c:function:: toolid(toolid, [version])

        .. versionadded:: 3.5.0

        Function returning true if the PE has the specified *id* in the PE's rich
        signature. Provide the optional *version* argument to only match when both
        match for one entry. More information can be found here:

        http://www.ntcore.com/files/richsign.htm

        *Example: pe.rich_signature.toolid(222)*

.. c:function:: exports(function_name)

    Function returning true if the PE exports *function_name* or
    false otherwise.

    *Example:  pe.exports("CPlApplet")*

.. c:function:: exports(ordinal)

    .. versionadded:: 3.6.0

    Function returning true if the PE exports *ordinal* or
    false otherwise.

    *Example:  pe.exports(72)*

.. c:function:: exports(/regular_expression/)

    .. versionadded:: 3.7.1

    Function returning true if the PE exports *regular_expression* or
    false otherwise.

    *Example:  pe.exports(/^AXS@@/)*

.. c:type:: number_of_exports

    .. versionadded:: 3.6.0

    Number of exports in the PE.

.. c:type:: number_of_imports

    .. versionadded:: 3.6.0

    Number of imports in the PE.

.. c:function:: imports(dll_name, function_name)

    Function returning true if the PE imports *function_name* from *dll_name*,
    or false otherwise. *dll_name* is case insensitive.

    *Example:  pe.imports("kernel32.dll", "WriteProcessMemory")*

.. c:function:: imports(dll_name)

    .. versionadded:: 3.5.0

    Function returning true if the PE imports anything from *dll_name*,
    or false otherwise. *dll_name* is case insensitive.

    *Example:  pe.imports("kernel32.dll")*

.. c:function:: imports(dll_name, ordinal)

    .. versionadded:: 3.5.0

    Function returning true if the PE imports *ordinal* from *dll_name*,
    or false otherwise. *dll_name* is case insensitive.

    *Example:  pe.imports("WS2_32.DLL", 3)*

.. c:function:: imports(dll_regexp, function_regexp)

    .. versionadded:: 3.8.0

    Function returning true if the PE imports a function name matching
    *function_regexp* from a DLL matching *dll_regexp*. *dll_regexp* is case
    sensitive unless you use the "/i" modifier in the regexp, as shown in the
    example below.

    *Example:  pe.imports(/kernel32\.dll/i, /(Read|Write)ProcessMemory/)*

.. c:function:: locale(locale_identifier)

    .. versionadded:: 3.2.0

    Function returning true if the PE has a resource with the specified locale
    identifier. Locale identifiers are 16-bit integers and can be found here:

    http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

    *Example: pe.locale(0x0419) // Russian (RU)*

.. c:function:: language(language_identifier)

    .. versionadded:: 3.2.0

    Function returning true if the PE has a resource with the specified language
    identifier. Language identifiers are 8-bit integers and can be found here:

    http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

    *Example: pe.language(0x0A) // Spanish*

.. c:function:: imphash()

    .. versionadded:: 3.2.0

    Function returning the import hash or imphash for the PE. The imphash is
    a MD5 hash of the PE's import table after some normalization. The imphash
    for a PE can be also computed with `pefile <http://code.google.com/p/pefile/>`_
    and you can find more information in `Mandiant's blog <https://www.mandiant.com/blog/tracking-malware-import-hashing/>`_.

    *Example: pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e"*

.. c:function:: section_index(name)

    Function returning the index into the sections array for the section that has
    *name*. *name* is case sensitive.

    *Example: pe.section_index(".TEXT")*

.. c:function:: section_index(addr)

    .. versionadded:: 3.3.0

    Function returning the index into the sections array for the section that has
    *addr*. *addr* can be an offset into the file or a memory address.

    *Example: pe.section_index(pe.entry_point)*

.. c:function:: is_dll()

    .. versionadded:: 3.5.0

    Function returning true if the PE is a DLL.

    *Example: pe.is_dll()*

.. c:function:: is_32bit()

    .. versionadded:: 3.5.0

    Function returning true if the PE is 32bits.

    *Example: pe.is_32bit()*

.. c:function:: is_64bit()

    .. versionadded:: 3.5.0

    Function returning true if the PE is 64bits.

    *Example: pe.is_64bit()*

.. c:function:: rva_to_offset(addr)

    .. versionadded:: 3.6.0

    Function returning the file offset for RVA *addr*.

    *Example: pe.rva_to_offset(pe.entry_point)*
