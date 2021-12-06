
.. _dotnet-module:

#############
dotnet module
#############

.. versionadded:: 3.6.0

The dotnet module allows you to create more fine-grained rules for .NET files by
using attributes and features of the .NET file format. Let's see some examples:

.. code-block:: yara

    import "dotnet"

    rule not_exactly_five_streams
    {
        condition:
            dotnet.number_of_streams != 5
    }

    rule blop_stream
    {
        condition:
            for any i in (0..dotnet.number_of_streams - 1):
                (dotnet.streams[i].name == "#Blop")
    }

Reference
---------

.. c:type:: version

    The version string contained in the metadata root.

    *Example: dotnet.version == "v2.0.50727"*

.. c:type:: module_name

    The name of the module.

    *Example: dotnet.module_name == "axs"*

.. c:type:: number_of_streams

    The number of streams in the file.

.. c:type:: streams

    A zero-based array of stream objects, one for each stream contained in the
    file. Individual streams can be accessed by using the [] operator. Each
    stream object has the following attributes:

    .. c:member:: name

        Stream name.

    .. c:member:: offset

        Stream offset.

    .. c:member:: size

        Stream size.

    *Example: dotnet.streams[0].name == "#~"*

.. c:type:: number_of_guids

    The number of GUIDs in the guids array.

.. c:type:: guids

    A zero-based array of strings, one for each GUID. Individual guids can be
    accessed by using the [] operator.

    *Example: dotnet.guids[0] == "99c08ffd-f378-a891-10ab-c02fe11be6ef"*

.. c:type:: number_of_classes
    The number of classes in the file.

.. c:type:: classes
    An array of .NET classes stored in the metadata. Individual classes can be accessed
    using the [] operator. Each class object contains the following attributes:

    .. c:member:: fullname
        Class full name.

    .. c:member:: name
        Class name.

    .. c:member:: namespace
        Class namespace.

    .. c:member:: visibility
        Class visibility specifier, options are:

        ``private``
        ``public``
        ``protected``
        ``internal``
        ``private protected``
        ``protected internal``

    .. c:member:: type
        Type of the object, options are:

        ``class``
        ``interface``

    .. c:member:: abstract
        Boolean representing if class is abstract.

    .. c:member:: sealed
        Boolean representing if class is sealed.

    .. c:member:: number_of_generic_parameters
        Number of generic parameters.

    .. c:member:: generic_parameters
        A zero-based array of generic parameters name. Individual parameters can be accessed using the [] operator.

    .. c:member:: number_of_base_types
        Number of the base types.

    .. c:member:: base_types
        A zero-based array of base types name. Individual base types can be accessed using the [] operator.

    .. c:member:: number_of_methods
        Number of the methods.

    .. c:member:: methods
        A zero-based array of method objects. Individual methods can be accessed by
        using the [] operator. Each object contains following attributes:

        .. c:member:: name
            Method name.

        .. c:member:: visibility
            Method visibility specifier, options are:

            ``private``
            ``public``
            ``protected``
            ``internal``
            ``private protected``
            ``protected internal``

        .. c:member:: static
            Boolean representing if method is static.

        .. c:member:: virtual
            Boolean representing if method is virtual. 

        .. c:member:: final
            Boolean representing if method is final. 

        .. c:member:: abstract
            Boolean representing if method is abstract. 

        .. c:member:: return_type
            Method return type name.

        .. c:member:: number_of_parameters
            Number of the method parameters.

        .. c:member:: parameters
            A zero-based array of method parameters. Individual parameters can be accessed by using the [] operator.

            .. c:member:: name
                Parameter name.

            .. c:member:: type
                Parameter type.

        .. c:member:: number_of_generic_parameters
            Number of the method generic parameters.

        .. c:member:: generic_parameters
            A zero-based array of method generic parameters. Individual parameters can be accessed by using the [] operator.

    *Example: dotnet.classes[0].fullname == "Launcher.Program"*

.. c:type:: number_of_resources

    The number of resources in the .NET file. These are different from normal PE
    resources.

.. c:type:: resources

    A zero-based array of resource objects, one for each resource the .NET file
    has.  Individual resources can be accessed by using the [] operator. Each
    resource object has the following attributes:

    .. c:member:: offset

        Offset for the resource data.

    .. c:member:: length

        Length of the resource data.

    .. c:member:: name

        Name of the resource (string).

    *Example: uint16be(dotnet.resources[0].offset) == 0x4d5a*

.. c:type:: assembly

    Object for .NET assembly information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: culture

        String containing the culture (language/country/region) for this
        assembly.

    *Example: dotnet.assembly.name == "Keylogger"*

    *Example: dotnet.assembly.version.major == 7 and dotnet.assembly.version.minor == 0*

.. c:type:: number_of_modulerefs

    The number of module references in the .NET file.

.. c:type:: modulerefs

    A zero-based array of strings, one for each module reference the .NET file
    has.  Individual module references can be accessed by using the []
    operator.

    *Example: dotnet.modulerefs[0] == "kernel32"*

.. c:type:: typelib

    The typelib of the file.

.. c:type:: assembly_refs

    Object for .NET assembly reference information.

    .. c:member:: version

        An object with integer values representing version information for this
        assembly. Attributes are:

        ``major``
        ``minor``
        ``build_number``
        ``revision_number``

    .. c:member:: name

        String containing the assembly name.

    .. c:member:: public_key_or_token

        String containing the public key or token which identifies the author of
        this assembly.

.. c:type:: number_of_user_strings

    The number of user strings in the file.

.. c:type:: user_strings

    An zero-based array of user strings, one for each stream contained in the
    file. Individual strings can be accessed by using the [] operator.

.. c:type:: number_of_field_offsets

    The number of fields in the field_offsets array.

.. c:type:: field_offsets

    A zero-based array of integers, one for each field. Individual field offsets
    can be accessed by using the [] operator.

    *Example: dotnet.field_offsets[0] == 8675309*
