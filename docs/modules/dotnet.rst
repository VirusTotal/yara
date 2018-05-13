
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
