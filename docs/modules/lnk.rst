
.. _lnk-module:

#########
LNK module
#########

The PE module allows you to create more fine-grained rules for LNK files by
using attributes and features of the LNK file format. This module exposes most of
the fields present in an LNK file. Let's see some examples:

.. code-block:: yara

    import "lnk"

    rule is_lnk
    {
        condition:
            lnk.is_lnk
    }

    rule machine_id_tracking
    {
        condition:
            lnk.tracker_data.machine_id == "chris-xps"
    }

    rule local_base_path
    {
        condition:
            lnk.link_info.local_base_path == "C:\\test\\a.txt"
    }
    
The LNK documentation can be found on Microsoft's website:
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943

Reference
---------

.. c:type:: is_lnk

    Return true if the file is an LNK.

    *Example: lnk.is_lnk*
    
.. c:type:: creation_time

    An epoch integer that specifies the creation time (UTC) of the link target

    *Example: lnk.creation_time == 1221247637*
    
.. c:type:: access_time

    An epoch integer that specifies the access time (UTC) of the link target

    *Example: lnk.access_time == 1221247637*
    
.. c:type:: write_time

    An epoch integer that specifies the write time (UTC) of the link target

    *Example: lnk.write_time == 1221247637*
    
.. c:type:: file_size

    An unsigned integer that specifies the size, in bytes, of the link target

    *Example: lnk.file_size > 100KB*
    
.. c:type:: link_flags

    The LinkFlags value specifies information about the shell link and the presence of optional portions of the LNK file. Values can be checked by performing a bitwise AND operation with the following constants:
    
    .. c:member:: HasLinkTargetIDList
    .. c:member:: HasLinkInfo
    .. c:member:: HasName
    .. c:member:: HasRelativePath
    .. c:member:: HasWorkingDir
    .. c:member:: HasArguments
    .. c:member:: HasIconLocation
    .. c:member:: IsUnicode
    .. c:member:: ForceNoLinkInfo
    .. c:member:: HasExpString
    .. c:member:: RunInSeparateProcess
    .. c:member:: Unused1
    .. c:member:: HasDarwinID
    .. c:member:: RunAsUser
    .. c:member:: HasExpIcon
    .. c:member:: NoPidlAlias
    .. c:member:: Unused2
    .. c:member:: RunWithShimLayer
    .. c:member:: ForceNoLinkTrack
    .. c:member:: EnableTargetMetadata
    .. c:member:: DisableLinkPathTracking
    .. c:member:: DisableKnownFolderTracking
    .. c:member:: DisableKnownFolderAlias
    .. c:member:: AllowLinkToLink
    .. c:member:: UnaliasOnSave
    .. c:member:: PreferEnvironmentPath
    .. c:member:: KeepLocalIDListForUNCTarget
    
    *Example: lnk.link_flags & lnk.HasLinkInfo*
    
.. c:type:: file_attributes_flags
    A file attributes flag that specifies information about the link target. Values can be checked by performing a bitwise AND operation with the following constants:
    
    .. c:member:: FILE_ATTRIBUTE_READONLY
    .. c:member:: FILE_ATTRIBUTE_HIDDEN
    .. c:member:: FILE_ATTRIBUTE_SYSTEM
    .. c:member:: Reserved1
    .. c:member:: FILE_ATTRIBUTE_DIRECTORY
    .. c:member:: FILE_ATTRIBUTE_ARCHIVE
    .. c:member:: Reserved2
    .. c:member:: FILE_ATTRIBUTE_NORMAL
    .. c:member:: FILE_ATTRIBUTE_TEMPORARY
    .. c:member:: FILE_ATTRIBUTE_SPARSE_FILE
    .. c:member:: FILE_ATTRIBUTE_REPARSE_POINT
    .. c:member:: FILE_ATTRIBUTE_COMPRESSED
    .. c:member:: FILE_ATTRIBUTE_OFFLINE
    .. c:member:: FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    .. c:member:: FILE_ATTRIBUTE_ENCRYPTED
    
    *Example: lnk.file_attributes_flags & lnk.FILE_ATTRIBUTE_READONLY*
    
.. c:type:: icon_index
    An integer that specifies the index of an icon within a given icon location.

.. c:type:: show_command
    An unsigned integer that specifies the expected window state of an application launched by the link. This value should be equal to one of the following:
    
    .. c:member:: FILE_ATTRIBUTE_READONLY
    .. c:member:: FILE_ATTRIBUTE_HIDDEN
    .. c:member:: FILE_ATTRIBUTE_SYSTEM
    
    *Example: lnk.show_command == lnk.SW_SHOWNORMAL*

.. c:type:: has_hotkey
    Boolean value to indicate whether a hotkey is present for the LNK file.
    
    *Example: lnk.has_hotkey*
    
.. c:type:: hotkey_flags
    Flags that detail the hotkey that's present (if applicable), and modifiers for how it should operate.

.. c:type:: hotkey
    A string representing the hotkey that is assigned to launch the LNK.
    
    *Example: lnk.hotkey == "F5"*

.. c:type:: hotkey_modifier_flags
    An unsigned integer that specifies bits that correspond to modifier keys on the keyboard. This value must be one or a combination of the following:
    
    .. c:member:: HOTKEYF_SHIFT
    .. c:member:: HOTKEYF_CONTROL
    .. c:member:: HOTKEYF_ALT
    
    *Example: lnk.hotkey_modifier_flags & lnk.HOTKEYF_SHIFT*
    
.. c:type:: link_target_id_list
    An optional structure that specifies the target of the link.
    
    .. c:member:: number_of_item_ids
    The number of ItemIDs within the list.
    
    *Example: lnk.link_target_id_list.number_of_item_ids == 4*
    
    .. c:member:: item_id_list_size
    The size of the ItemID list.
    
    *Example: lnk.link_target_id_list.item_id_list_size == 0xBD*
    
    .. c:type:: item_id_list
    A zero-based array of ItemIDs structures. The data stored in a given ItemID is defined by the source that corresponds to the location in the target namespace of the preceding ItemIDs. This data uniquely identifies the items in that part of the namespace. Each ItemID has the following members:
    
        .. c:member:: data
        The shell data source-defined data that specifies an item.
        
        *Example: lnk.link_target_id_list.item_id_list[0].data == "\x1fP\xe0O\xd0 \xea:i\x10\xa2\xd8\x08\x00+00\x9d"*
        
        .. c:member:: size
        The size of the ItemID.
        
        *Example: lnk.link_target_id_list.item_id_list[0].size == 0x12*

.. c:type:: link_info
    The LinkInfo structure provides information necessary to resolve a link target if it is not found in its original location.
    
    .. c:member:: size
    An unsigned integer that specifies the size, in bytes, of the LinkInfo structure. All offsets specified in this structure MUST be less than this value, and all strings contained in this structure MUST fit within the extent defined by this size.
    
    *Example: lnk.link_info.size == 0x3C*
    
    .. c:member:: header_size
    An unsigned integer that specifies the size, in bytes, of the LinkInfo header section. Note that if the value is 0x1C, then offsets to some optional fields (local_base_path_offset_unicode and common_path_suffix_offset_unicode) will not be set.
    
    *Example: lnk.link_info.header_size == 0x1C*
    
    .. c:member:: flags
    Flags that specify whether the VolumeID, LocalBasePath, LocalBasePathUnicode, and CommonNetworkRelativeLink fields are present in this structure. Values can be checked by performing a bitwise AND operation with the following constants:
    
        .. c:member:: VolumeIDAndLocalBasePath
        .. c:member:: CommonNetworkRelativeLinkAndPathSuffix
    
    *Example: lnk.link_info.flags & lnk.VolumeIDAndLocalBasePath*
    
    .. c:member:: volume_id_offset
    An unsigned integer that specifies the location of the VolumeID field.
    
    *Example: lnk.link_info.volume_id_offset == 0x1C*
    
    .. c:member:: local_base_path_offset
    An unsigned integer that specifies the location of the LocalBasePath field.
    
    *Example: lnk.link_info.local_base_path_offset == 0x2D*
    
    .. c:member:: common_network_relative_link_offset
    An unsigned integer that specifies the location of the CommonNetworkRelativeLink field.
    
    .. c:member:: common_path_suffix_offset
    An unsigned integer that specifies the location of the CommonPathSuffix field.
    
    .. c:member:: local_base_path_offset_unicode
    An optional unsigned integer that specifies the location of the LocalBasePathUnicode field.
    
    .. c:member:: common_path_suffix_offset_unicode
    An optional unsigned integer that specifies the location of the CommonPathSuffixUnicode field.
    
    .. c:type:: volume_id
    An optional VolumeID structure (section 2.3.1) that specifies information about the volume that the link target was on when the link was created.

        .. c:member:: size
        The size of the structure.

        .. c:member:: drive_type
        An unsigned integer that specifies the type of drive the link target is stored on. It must be equal to one of the following:
        
            .. c:member:: DRIVE_UNKNOWN
            .. c:member:: DRIVE_NO_ROOT_DIR
            .. c:member:: DRIVE_REMOVABLE
            .. c:member:: DRIVE_FIXED
            .. c:member:: DRIVE_REMOTE
            .. c:member:: DRIVE_CDROM
            .. c:member:: DRIVE_RAMDISK
            
        *Example: lnk.link_info.volume_id.drive_type & lnk.DRIVE_FIXED*
        
        .. c:member:: drive_serial_number
        An unsigned integer that specifies the drive serial number of the volume the link target is stored on.
        
        *Example: lnk.link_info.volume_id.drive_serial_number == 0x307A8A81*
        
        .. c:member:: volume_label_offset
        An unsigned integer that specifies the location of a string that contains the volume label of the drive that the link target is stored on.

        .. c:member:: volume_label_offset_unicode
        An optional unsigned integer that specifies the location of a string that contains the volume label of the drive that the link target is stored on.

        .. c:member:: data
        A buffer of data that contains the volume label of the drive as a string defined by the system default code page or Unicode characters, as specified by preceding fields.
        
        *Example: lnk.link_info.volume_id.data == "\x00"*

    .. c:member:: local_base_path
    An optional, NULL–terminated string, defined by the system default code page, which is used to construct the full path to the link item or link target by appending the string in the CommonPathSuffix field.
    
    *Example: lnk.link_info.local_base_path == "C:\\test\\a.txt"*

    .. c:type:: common_network_relative_link
    The CommonNetworkRelativeLink structure specifies information about the network location where a link target is stored, including the mapped drive letter and the UNC path prefix. 
    
        .. c:member:: size
        The size of the structure.
        
        .. c:member:: flags
        Flags that specify the contents of the DeviceNameOffset and NetProviderType fields. Values can be checked by performing a bitwise AND operation with the following constants:
        
            .. c:member:: ValidDevice
            .. c:member:: ValidNetType
            
        *Example: lnk.common_network_relative_link.flags & lnk.ValidDevice*
        
        .. c:member:: net_name_offset
        An unsigned integer that specifies the location of the NetName field.
        
        .. c:member:: device_name_offset
        An unsigned integer that specifies the location of the DeviceName field.
        
        .. c:member:: network_provider_type
        An unsigned integer that specifies the type of network provider. If present, it must be one of the following:
        
            .. c:member:: WNNC_NET_AVID
            .. c:member:: WNNC_NET_DOCUSPACE
            .. c:member:: WNNC_NET_MANGOSOFT
            .. c:member:: WNNC_NET_SERNET
            .. c:member:: WNNC_NET_RIVERFRONT1
            .. c:member:: WNNC_NET_RIVERFRONT2
            .. c:member:: WNNC_NET_DECORB
            .. c:member:: WNNC_NET_PROTSTOR
            .. c:member:: WNNC_NET_FJ_REDIR
            .. c:member:: WNNC_NET_DISTINCT
            .. c:member:: WNNC_NET_TWINS
            .. c:member:: WNNC_NET_RDR2SAMPLE
            .. c:member:: WNNC_NET_CSC
            .. c:member:: WNNC_NET_3IN1
            .. c:member:: WNNC_NET_EXTENDNET
            .. c:member:: WNNC_NET_STAC
            .. c:member:: WNNC_NET_FOXBAT
            .. c:member:: WNNC_NET_YAHOO
            .. c:member:: WNNC_NET_EXIFS
            .. c:member:: WNNC_NET_DAV
            .. c:member:: WNNC_NET_KNOWARE
            .. c:member:: WNNC_NET_OBJECT_DIRE
            .. c:member:: WNNC_NET_MASFAX
            .. c:member:: WNNC_NET_HOB_NFS
            .. c:member:: WNNC_NET_SHIVA
            .. c:member:: WNNC_NET_IBMAL
            .. c:member:: WNNC_NET_LOCK
            .. c:member:: WNNC_NET_TERMSRV
            .. c:member:: WNNC_NET_SRT
            .. c:member:: WNNC_NET_QUINCY
            .. c:member:: WNNC_NET_OPENAFS
            .. c:member:: WNNC_NET_AVID1
            .. c:member:: WNNC_NET_DFS
            .. c:member:: WNNC_NET_KWNP
            .. c:member:: WNNC_NET_ZENWORKS
            .. c:member:: WNNC_NET_DRIVEONWEB
            .. c:member:: WNNC_NET_VMWARE
            .. c:member:: WNNC_NET_RSFX
            .. c:member:: WNNC_NET_MFILES
            .. c:member:: WNNC_NET_MS_NFS
            .. c:member:: WNNC_NET_GOOGLE
            
        *Example: lnk.common_network_relative_link.network_provider_type == lnk.WNNC_NET_GOOGLE*
        
        .. c:member:: net_name_offset_unicode
        An unsigned integer that specifies the location of the NetNameUnicode field.
        
        .. c:member:: device_name_offset_unicode
        An unsigned integer that specifies the location of the DeviceNameUnicode field. 
        
        .. c:member:: net_name
        A NULL–terminated string, as defined by the system default code page, which specifies a server share path.
        
        *Example: lnk.link_info.common_network_relative_link.net_name == "\\\\server\\share"*
        
        .. c:member:: device_name
        A NULL–terminated string, as defined by the system default code page, which specifies a device.
        
        *Example: lnk.link_info.common_network_relative_link.device_name == "Z:"*
        
        .. c:member:: net_name_unicode
        An optional, NULL–terminated, Unicode string that is the Unicode version of the NetName string.
        
        .. c:member:: device_name_unicode
        An optional, NULL–terminated, Unicode string that is the Unicode version of the DeviceName string. 

    .. c:member:: common_path_suffix
    A NULL–terminated string, defined by the system default code page, which is used to construct the full path to the link item or link target by being appended to the string in the LocalBasePath field.
    
    *Example: lnk.link_info.common_path_suffix == "\x00"*
    
    .. c:member:: local_base_path_unicode
    An optional, NULL–terminated, Unicode string that is used to construct the full path to the link item or link target by appending the string in the CommonPathSuffixUnicode field. 
    
    .. c:member:: common_path_suffix_unicode
    An optional, NULL–terminated, Unicode string that is used to construct the full path to the link item or link target by being appended to the string in the LocalBasePathUnicode field. 