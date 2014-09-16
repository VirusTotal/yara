
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

    .. c:type:: MACHINE_I386
    .. c:type:: MACHINE_AMD64

    *Example: pe.machine == pe.MACHINE_AMD64*

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

    .. c:type:: characteristics

        Section characteristics.

    .. c:type:: virtual_address

        Section virtual address.

    .. c:type:: virtual_size

        Section virtual size.

    .. c:type:: raw_data_offset

        Section raw offset.

    .. c:type:: raw_data_size

        Section raw size.

    *Example:  pe.sections[0].name == ".text"*

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

.. c:function:: language(language_identifier)

    Function returning true if the PE has a resource with the specified language
    identifier. Language identifiers are 8-bit integers and can be found here:

    http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

    *Example: pe.language(0x0A) // Spanish*

