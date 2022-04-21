
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

.. c:type:: major_runtime_version

    The major version contained in the CLI header

.. c:type:: minor_runtime_version

    The minor version contained in the CLI header

.. c:type:: flags

    CLI header runtime flags contains the following values
    
    .. c:type:: COMIMAGE_FLAGS_ILONLY 
    .. c:type:: COMIMAGE_FLAGS_32BITREQUIRED    
    .. c:type:: COMIMAGE_FLAGS_IL_LIBRARY       
    .. c:type:: COMIMAGE_FLAGS_STRONGNAMESIGNED 
    .. c:type:: COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
    .. c:type:: COMIMAGE_FLAGS_TRACKDEBUGDATA

.. c:type:: entry_point

    If CORHEADER_NATIVE_ENTRYPOINT is set, entry_point represents an RVA 
    to a native entrypoint. If CORHEADER_NATIVE_ENTRYPOINT is not set, 
    entry_point represents a metadata token for entrypoint.

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
    
        Stream name

    .. c:member:: offset

        Stream offset

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

.. c:type:: number_of_memberrefs

    the number of memberrefs in the file

.. c:type:: memberrefs

    a zero-based array of memberrefs associating Methods to fields of a class.
    Individual memberrefs can be access by using the [] operator. Each
    memberref has the following attributes:

    .. c:member:: name

        memberref name

        *Example: dotnet.memberrefs[18].name == "CompareTo"*

    

.. c:type:: number_of_methods

    the number of methods in the file

.. c:type:: methods

    A zero-based array of methods associating operations with a type. Individual
    methods can be accessed by using the [] operator. Each method has the
    following attributes:

    .. c:member:: rva

        A relative virtual address of the method

    .. c:member:: impl_flags

        Integer representing method implementation attributes with one of the 
        following values:

        .. c:type:: METHOD_IMPL_FLAGS_CODE_TYPE_MASK      
        .. c:type:: METHOD_IMPL_FLAGS_IL            
        .. c:type:: METHOD_IMPL_FLAGS_IS_NATIVE     
        .. c:type:: METHOD_IMPL_FLAGS_OPTIL                
        .. c:type:: METHOD_IMPL_FLAGS_RUNTIME              
        .. c:type:: METHOD_IMPL_FLAGS_MANAGED_MASK         
        .. c:type:: METHOD_IMPL_FLAGS_UNMANAGED            
        .. c:type:: METHOD_IMPL_FLAGS_MANAGED               
        .. c:type:: METHOD_IMPL_FLAGS_FORWARD_REF          
        .. c:type:: METHOD_IMPL_FLAGS_PRESERVE_SIG         
        .. c:type:: METHOD_IMPL_FLAGS_INTERNAL_CALL        
        .. c:type:: METHOD_IMPL_FLAGS_SYNCHRONIZED         
        .. c:type:: METHOD_IMPL_FLAGS_NO_INLINING          
        .. c:type:: METHOD_IMPL_FLAGS_NO_OPTIMIZATION

        *Example: dotnet.methods[0].impl_flags & dotnet.METHOD_IMPL_FLAGS_IS_NATIVE*

    .. c:member:: flags

        .. c:type:: METHOD_FLAGS_MEMBER_ACCESS_MASK
        .. c:type:: METHOD_FLAGS_COMPILER_CONTROLLED
        .. c:type:: METHOD_FLAGS_PRIVATE           
        .. c:type:: METHOD_FLAGS_FAM_AND_ASSEM     
        .. c:type:: METHOD_FLAGS_ASSEM             
        .. c:type:: METHOD_FLAGS_FAMILY            
        .. c:type:: METHOD_FLAGS_FAM_OR_ASSEM      
        .. c:type:: METHOD_FLAGS_PUBLIC            
        .. c:type:: METHOD_FLAGS_STATIC            
        .. c:type:: METHOD_FLAGS_FINAL             
        .. c:type:: METHOD_FLAGS_VIRTUAL           
        .. c:type:: METHOD_FLAGS_HIDE_BY_SIG       
        .. c:type:: METHOD_FLAGS_VTABLE_LAYOUT_MASK
        .. c:type:: METHOD_FLAGS_REUSE_SLOT        
        .. c:type:: METHOD_FLAGS_NEW_SLOT          
        .. c:type:: METHOD_FLAGS_STRICT            
        .. c:type:: METHOD_FLAGS_ABSTRACT          
        .. c:type:: METHOD_FLAGS_SPECIAL_NAME      
        .. c:type:: METHOD_FLAGS_PINVOKE_IMPL      
        .. c:type:: METHOD_FLAGS_UNMANAGED_EXPORT  
        .. c:type:: METHOD_FLAGS_RTS_SPECIAL_NAME  
        .. c:type:: METHOD_FLAGS_HAS_SECURITY      
        .. c:type:: METHOD_FLAGS_REQUIRE_SEC_OBJECT

        *Example: dotnet.methods[0].Flags & dotnet.METHOD_FLAGS_STATIC*

    .. c:member:: name

        method name

        *Example: dotnet.methods[0].name == "Foo"*

.. c:type:: number_of_typerefs

    the number of type references in the file

.. c:type:: typerefs

    A zero based array of type references, logical descriptions of user-defined 
    types that are referenced in the current module. Individual typerefs can
    be access by using the [] operator. Each typeref has the following
    attributes:

    .. c:member:: name
        
        typeref name

        *Example: dotnet.typerefs[0].name == "Decoder"*

    .. c:member:: nameSpace

        typeref namespace

        *Example: dotnet.typerefs[0].namespace == "System.Text"*

.. c:type:: number_of_impl_maps

    The number of PInvoke implmaps in the file

.. c:type:: impl_maps

    A zero based array of impl_map table row. Each entry holds information 
    about unmanaged methods that can be reached from managed code, using PInvoke 
    dispatch. A row is entered in the impl_map table for each parent method that
    is defined with a .pinvokeimpl interoperation attribute. Individual 
    impl_maps can be accessed by using the [] operator.Each impl_map has the 
    following attributes.

    .. c:member:: import_name

        impl_map import name
    
    .. c:member:: mapping_flags

        Integer representing flags for the impl_map entry with one of the
        following values:

        .. c:type:: PINVOKE_FLAGS_NO_MANGLE
        .. c:type:: PINVOKE_FLAGS_CHAR_SET_MASK
        .. c:type:: PINVOKE_FLAGS_CHAR_SET_NOT_SPEC
        .. c:type:: PINVOKE_FLAGS_CHAR_SET_ANSI       
        .. c:type:: PINVOKE_FLAGS_CHAR_SET_UNICODE      
        .. c:type:: PINVOKE_FLAGS_CHAR_SET_AUTO      
        .. c:type:: PINVOKE_FLAGS_SUPPORT_GET_LAST_ERROR      
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_MASK      
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_PLATFORM_API      
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_CDECL       
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_STDCALL        
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_THISCALL        
        .. c:type:: PINVOKE_FLAGS_CALL_CONV_FASTCALL

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

.. c:type:: is_dotnet

    .. versionadded:: 4.2.0

    Function returning true if the PE is indeed .NET.

    *Example: dotnet.is_dotnet*
