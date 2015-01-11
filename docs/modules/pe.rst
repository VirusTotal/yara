
.. _pe-module:

#########
PE module
#########

The PE module allows you to create more fine-grained rules for PE files by
using attributes and features of the PE file format. This module exposes most of
the fields present in a PE header and provides functions which can be used to
write more expressive and targeted rules. Let's see some examples::

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

    .. versionadded:: Expanded in 3.3.0

.. c:type:: subsystem

    Integer with one of the following values:

    .. c:type:: SUBSYSTEM_UNKNOWN
    .. c:type:: SUBSYSTEM_NATIVE
    .. c:type:: SUBSYSTEM_WINDOWS_GUI
    .. c:type:: SUBSYSTEM_WINDOWS_CUI
    .. c:type:: SUBSYSTEM_OS2_CUI
    .. c:type:: SUBSYSTEM_POSIX_CUI
    .. c:type:: SUBSYSTEM_NATIVE_WINDOWS

    *Example: pe.subsystem == pe.SUBSYSTEM_NATIVE*

.. c:type:: timestamp

    PE timestamp.

.. c:type:: entry_point

    Entry point raw offset or virtual address depending if YARA is scanning a
    file or process memory respectively. This is equivalent to the deprecated
    ``entrypoint`` keyword.

.. c:type:: image_base

    Image base relative virtual address.

.. c:type:: characteristics

    Bitmap with PE characteristics. Individual characteristics can be inspected
    by performing a bitwise AND operation with the following constants:

    .. c:type:: RELOCS_STRIPPED
    .. c:type:: EXECUTABLE_IMAGE
    .. c:type:: LINE_NUMS_STRIPPED
    .. c:type:: LOCAL_SYMS_STRIPPED
    .. c:type:: AGGRESIVE_WS_TRIM
    .. c:type:: LARGE_ADDRESS_AWARE
    .. c:type:: BYTES_REVERSED_LO
    .. c:type:: 32BIT_MACHINE
    .. c:type:: DEBUG_STRIPPED
    .. c:type:: REMOVABLE_RUN_FROM_SWAP
    .. c:type:: NET_RUN_FROM_SWAP
    .. c:type:: SYSTEM
    .. c:type:: DLL
    .. c:type:: UP_SYSTEM_ONLY
    .. c:type:: BYTES_REVERSED_HI

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

.. c:type:: number_of_sections

    Number of sections in the PE.

.. c:type:: sections

    An zero-based array of section objects, one for each section the PE has.
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

    .. versionadded:: Constants added in 3.3.0

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

    An zero-based array of resource objects, one for each resource the PE has.
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

    All resources must have an type, id (name), and language specified. They
    can be either an integer or string, but never both, for any given level.

    *Example:  pe.sections[0].type == pe.RESOURCE_TYPE_RCDATA and pe.sections[0].name == "F\x00I\x00L\x00E\x00"*

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

    .. versionadded:: Expanded in 3.3.0

.. c:type:: version_info

    Dictionary containing PE's version information. Typical keys are:

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

    .. versionadded:: 3.2.0

.. c:type:: number_of_signatures

    Number of authenticode signatures in the PE.

.. c:type:: signatures

    An zero-based array of signature objects, one for each authenticode
    signature in the PE file. Usually PE files have a single signature.

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

        Unix timestamp on which validity period for this signature begins.

    .. c:member:: not_after

        Unix timestamp on which validity period for this signature ends.

    .. c:member:: valid_on(timestamp)

        Function returning true if the signature was valid the on date
        indicated by *timestamp*. The following sentence::

            pe.signature[n].valid_on(timestamp)

        Is equivalent to::

            timestamp >= pe.signature[n].not_before and timestamp <= pe.signature[n].not_after

.. c:type:: rich_signature

    Structure containing information about PE's rich signature as documented
    `here <http://www.ntcore.com/files/richsign.htm>`_.

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

.. c:function:: exports(function_name)

    Function returning true if the PE exports *function_name* or
    false otherwise.

    *Example:  pe.exports("CPlApplet")*

.. c:function:: imports(dll_name, function_name)

    Function returning true if the PE imports *function_name* from *dll_name*,
    or false otherwise. *dll_name* is case insensitive.

    *Example:  pe.imports("kernel32.dll", "WriteProcessMemory")*

.. c:function:: locale(locale_identifier)

    Function returning true if the PE has a resource with the specified locale
    identifier. Locale identifiers are 16-bit integers and can be found here:

    http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

    *Example: pe.locale(0x0419) // Russian (RU)*

    .. versionadded:: 3.2.0

.. c:function:: language(language_identifier)

    Function returning true if the PE has a resource with the specified language
    identifier. Language identifiers are 8-bit integers and can be found here:

    http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

    *Example: pe.language(0x0A) // Spanish*

    .. versionadded:: 3.2.0

.. c:function:: imphash()

    Function returning the import hash or imphash for the PE. The imphash is
    a MD5 hash of the PE's import table after some normalization. The imphash
    for a PE can be also computed with `pefile <http://code.google.com/p/pefile/>`_ and you can find more information in
    `Mandiant's blog <https://www.mandiant.com/blog/tracking-malware-import-hashing/>`_.

    *Example: pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e"*

    .. versionadded:: 3.2.0

.. c:function:: section_index(name)

  Function returning the index into the sections array for the section that has
  *name*. *name* is case sensitive.

  *Example: pe.section_index(".TEXT")*

.. c:function:: section_index(addr)

  Function returning the index into the sections array for the section that has
  *addr*. *addr* can be an offset into the file or a memory address.

  *Example: pe.section_index(pe.entry_point)*

  .. versionadded:: 3.3.0
