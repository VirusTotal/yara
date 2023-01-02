
.. _lnk-module:

##########
LNK module
##########

The LNK module allows you to create more fine-grained rules for LNK files by
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
    
    .. c:member:: HAS_LINK_TARGET_ID_LIST
    .. c:member:: HAS_LINK_INFO
    .. c:member:: HAS_NAME
    .. c:member:: HAS_RELATIVE_PATH
    .. c:member:: HAS_WORKING_DIR
    .. c:member:: HAS_ARGUMENTS
    .. c:member:: HAS_ICON_LOCATION
    .. c:member:: IS_UNICODE
    .. c:member:: FORCE_NO_LINK_INFO
    .. c:member:: HAS_EXP_STRING
    .. c:member:: RUN_IN_SEPARATE_PROCESS
    .. c:member:: UNUSED_1
    .. c:member:: HAS_DARWIN_ID
    .. c:member:: RUN_AS_USER
    .. c:member:: HAS_EXP_ICON
    .. c:member:: NO_PIDL_ALIAS
    .. c:member:: UNUSED_2
    .. c:member:: RUN_WITH_SHIM_LAYER
    .. c:member:: FORCE_NO_LINK_TRACK
    .. c:member:: ENABLE_TARGET_METADATA
    .. c:member:: DISABLE_LINK_PATH_TRACKING
    .. c:member:: DISABLE_KNOWN_FOLDER_TRACKING
    .. c:member:: DISABLE_KNOWN_FOLDER_ALIAS
    .. c:member:: ALLOW_LINK_TO_LINK
    .. c:member:: UNALIAS_ON_SAVE
    .. c:member:: PREFER_ENVIRONMENT_PATH
    .. c:member:: KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET
    
    *Example: lnk.link_flags & lnk.HAS_LINK_INFO*
    
.. c:type:: file_attributes_flags
    A file attributes flag that specifies information about the link target. Values can be checked by performing a bitwise AND operation with the following constants:
    
    .. c:member:: FILE_ATTRIBUTE_READONLY
    .. c:member:: FILE_ATTRIBUTE_HIDDEN
    .. c:member:: FILE_ATTRIBUTE_SYSTEM
    .. c:member:: RESERVED_1
    .. c:member:: FILE_ATTRIBUTE_DIRECTORY
    .. c:member:: FILE_ATTRIBUTE_ARCHIVE
    .. c:member:: RESERVED_2
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
        
        *Example: lnk.link_target_id_list.item_id_list[0].data == "\\x1fP\\xe0O\\xd0 \\xea:i\\x10\\xa2\\xd8\\x08\\x00+00\\x9d"*
        
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
    
        .. c:member:: VOLUME_ID_AND_LOCAL_BASE_PATH
        .. c:member:: COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX
    
    *Example: lnk.link_info.flags & lnk.VOLUME_ID_AND_LOCAL_BASE_PATH*
    
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
    
    .. c:type:: has_volume_id
    Boolean flag which is set if a VolumeID structure is present.

    *Example: lnk.link_info.has_volume_id*
    
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
        
        *Example: lnk.link_info.volume_id.data == "\\x00"*

    .. c:member:: local_base_path
    An optional, NULL–terminated string, defined by the system default code page, which is used to construct the full path to the link item or link target by appending the string in the CommonPathSuffix field.
    
    *Example: lnk.link_info.local_base_path == "C:\\test\\a.txt"*

    .. c:type:: common_network_relative_link
    The CommonNetworkRelativeLink structure specifies information about the network location where a link target is stored, including the mapped drive letter and the UNC path prefix. 
    
        .. c:member:: size
        The size of the structure.
        
        .. c:member:: flags
        Flags that specify the contents of the DeviceNameOffset and NetProviderType fields. Values can be checked by performing a bitwise AND operation with the following constants:
        
            .. c:member:: VALID_DEVICE
            .. c:member:: VALID_NET_TYPE
            
        *Example: lnk.common_network_relative_link.flags & lnk.VALID_DEVICE*
        
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
    
    *Example: lnk.link_info.common_path_suffix == "\\x00"*
    
    .. c:member:: local_base_path_unicode
    An optional, NULL–terminated, Unicode string that is used to construct the full path to the link item or link target by appending the string in the CommonPathSuffixUnicode field. 
    
    .. c:member:: common_path_suffix_unicode
    An optional, NULL–terminated, Unicode string that is used to construct the full path to the link item or link target by being appended to the string in the LocalBasePathUnicode field.

.. c:type:: name_string
An optional string that specifies a description of the shortcut that is displayed to end users to identify the purpose of the shell link. 

*Example: lnk.name_string == "P\\x00e\\x00a\\x00Z\\x00i\\x00p\\x00 \\x00a\\x00r\\x00c\\x00h\\x00i\\x00v\\x00e\\x00r\\x00,\\x00 \\x00a\\x00d\\x00d\\x00 \\x00t\\x00o\\x00 \\x00e\\x00n\\x00c\\x00r\\x00y\\x00p\\x00t\\x00e\\x00d\\x00 \\x00.\\x00p\\x00e\\x00a\\x00 \\x00a\\x00r\\x00c\\x00h\\x00i\\x00v\\x00e\\x00"*

.. c:type:: relative_path
An optional string that specifies the location of the link target relative to the file that contains the shell link.

*Example: lnk.relative_path == ".\\x00\\\\\\x00a\\x00.\\x00t\\x00x\\x00t\\x00"*

.. c:type:: working_dir
An optional string that specifies the file system path of the working directory to be used when activating the link target.

*Example: lnk.working_dir == "C\\x00:\\x00\\\\\\x00t\\x00e\\x00s\\x00t\\x00"*

.. c:type:: command_line_arguments
An optional string that stores the command-line arguments that are specified when activating the link target

*Example: lnk.command_line_arguments == "-\\x00a\\x00d\\x00d\\x002\\x00c\\x00r\\x00y\\x00p\\x00t\\x00"*

.. c:type:: icon_location
An optional string that specifies the location of the icon to be used when displaying a shell link item in an icon view.

*Example: lnk.icon_location == "C\\x00:\\x00\\\\x00P\\x00r\\x00o\\x00g\\x00r\\x00a\\x00m\\x00 \\x00F\\x00i\\x00l\\x00e\\x00s\\x00\\\\x00P\\x00e\\x00a\\x00Z\\x00i\\x00p\\x00\\\\x00r\\x00e\\x00s\\x00\\\\x00i\\x00c\\x00o\\x00n\\x00s\\x00\\\\x00p\\x00e\\x00a\\x00z\\x00i\\x00p\\x00_\\x00n\\x00e\\x00w\\x00.\\x00i\\x00c\\x00l\\x00"*

.. c:type:: has_console_data
Boolean flag which is set if a ConsoleDataBlock structure is present.

*Example: lnk.has_console_data*

.. c:type:: console_data
The ConsoleDataBlock structure specifies the display settings to use when a link target specifies an application that is run in a console window.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.CONSOLE_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.CONSOLE_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: fill_attributes
    An unsigned integer that specifies the fill attributes that control the foreground and background text colors in the console window. The following bit definitions can be combined to specify 16 different values each for the foreground and background color:
    
        .. c:member:: FOREGROUND_BLUE
        .. c:member:: FOREGROUND_GREEN
        .. c:member:: FOREGROUND_RED
        .. c:member:: FOREGROUND_INTENSITY
        .. c:member:: BACKGROUND_BLUE
        .. c:member:: BACKGROUND_GREEN
        .. c:member:: BACKGROUND_RED
        .. c:member:: BACKGROUND_INTENSITY
        
    *Example: lnk.console_data.fill_attributes & lnk.FOREGROUND_BLUE*
    
    .. c:member:: popup_fill_attributes
    An unsigned integer that specifies the fill attributes that control the foreground and background text color in the console window popup. The values are the same as for the FillAttributes field.
    
    .. c:member:: screen_buffer_size_x
    A signed integer that specifies the horizontal size (X axis), in characters, of the console window buffer.
    
    *Example: lnk.console_data.screen_buffer_size_x == 120*
    
    .. c:member:: screen_buffer_size_y
    A signed integer that specifies the vertical size (Y axis), in characters, of the console window buffer.
    
    *Example: lnk.console_data.screen_buffer_size_y == 3000*
    
    .. c:member:: window_size_x
    A signed integer that specifies the horizontal size (X axis), in characters, of the console window.
    
    *Example: lnk.console_data.window_size_x == 120*
    
    .. c:member:: window_size_y
    A signed integer that specifies the vertical size (Y axis), in characters, of the console window.
    
    *Example: lnk.console_data.window_size_x == 50*
    
    .. c:member:: window_origin_x
    A signed integer that specifies the horizontal coordinate (X axis), in pixels, of the console window origin.
    
    *Example: lnk.console_data.window_origin_x == 0*
    
    .. c:member:: window_origin_y
    A signed integer that specifies the vertical coordinate (Y axis), in pixels, of the console window origin.
    
    *Example: lnk.console_data.window_origin_y == 0*
    
    .. c:member:: font_size
    An unsigned integer that specifies the size, in pixels, of the font used in the console window. The two most significant bytes contain the font height and the two least significant bytes contain the font width. For vector fonts, the width is set to zero.
    
    .. c:member:: font_family
    An unsigned integer that specifies the family of the font used in the console window. This value must be comprised of a font family and a font pitch. The values for the font family are as follows:
    
        .. c:member:: FF_DONTCARE
        .. c:member:: FF_ROMAN
        .. c:member:: FF_SWISS
        .. c:member:: FF_MODERN
        .. c:member:: FF_SCRIPT
        .. c:member:: FF_DECORATIVE
        
    A bitwise OR of one or more of the following font-pitch bits is added to the font family from the previous values:
    
        .. c:member:: TMPF_NONE
        .. c:member:: TMPF_FIXED_PITCH
        .. c:member:: TMPF_VECTOR
        .. c:member:: TMPF_TRUETYPE
        .. c:member:: TMPF_DEVICE
    
    .. c:member:: font_weight
    An unsigned integer that specifies the stroke weight of the font used in the console window.
    
    .. c:member:: face_name
    A 32-character Unicode string that specifies the face name of the font used in the console window.
    
    .. c:member:: cursor_size
    An unsigned integer that specifies the size of the cursor, in pixels, used in the console window.
    
    .. c:member:: full_screen
    An unsigned integer that specifies whether to open the console window in full-screen mode.
    
    .. c:member:: quick_edit
    An unsigned integer that specifies whether to open the console window in QuickEdit mode.
    
    .. c:member:: insert_mode
    An unsigned integer that specifies insert mode in the console window.
    
    .. c:member:: auto_position
    An unsigned integer that specifies auto-position mode of the console window.
    
    .. c:member:: history_buffer_size
    An unsigned integer that specifies the size, in characters, of the buffer that is used to store a history of user input into the console window
    
    .. c:member:: number_of_history_buffers
    An unsigned integer that specifies the number of history buffers to use.
    
    .. c:member:: history_no_dup
    An unsigned integer that specifies whether to remove duplicates in the history buffer.
    
    .. c:member:: color_table
    A table of 16 32-bit, unsigned integers specifying the RGB colors that are used for text in the console window. The values of the fill attribute fields FillAttributes and PopupFillAttributes are used as indexes into this table to specify the final foreground and background color for a character.
    
.. c:type:: has_console_fe_data
Boolean flag which is set if a ConsoleFEDataBlock structure is present.

*Example: lnk.has_console_fe_data*
    
.. c:type:: console_fe_data
The ConsoleFEDataBlock structure specifies the code page to use for displaying text when a link target specifies an application that is run in a console window.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.CONSOLE_FE_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.CONSOLE_FE_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: code_page
    An unsigned integer that specifies a code page language code identifier.

.. c:type:: has_darwin_data
Boolean flag which is set if a DarwinDataBlock structure is present.

*Example: lnk.has_darwin_data*
    
.. c:type:: darwin_data
The DarwinDataBlock structure specifies an application identifier that can be used instead of a link target IDList to install an application when a shell link is activated.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.DARWIN_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.DARWIN_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: darwin_data_ansi
    A NULL–terminated string, defined by the system default code page, which specifies an application identifier. 
    
    .. c:member:: darwin_data_unicode
    An optional, NULL–terminated, Unicode string that specifies an application identifier.

.. c:type:: has_environment_variable_data
Boolean flag which is set if a EnvironmentVariableDataBlock structure is present.

*Example: lnk.has_environment_variable_data*
    
.. c:type:: environment_variable_data
The EnvironmentVariableDataBlock structure specifies a path to environment variable information when the link target refers to a location that has a corresponding environment variable.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.ENVIRONMENT_VARIABLE_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.ENVIRONMENT_VARIABLE_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: target_ansi
    A NULL-terminated string, defined by the system default code page, which specifies a path to environment variable information
    
    *Example: lnk.environment_variable_data.target_ansi == "%SystemRoot%\\sysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"*
    
    .. c:member:: target_unicode
    An optional, NULL-terminated, Unicode string that specifies a path to environment variable information.

.. c:type:: has_icon_environment_data
Boolean flag which is set if a IconEnvironmentDataBlock structure is present.

*Example: lnk.has_icon_environment_data*
    
.. c:type:: icon_environment_data
The IconEnvironmentDataBlock structure specifies the path to an icon. The path is encoded using environment variables, which makes it possible to find the icon across machines where the locations vary but are expressed using environment variables.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.ICON_ENVIRONMENT_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.ICON_ENVIRONMENT_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: target_ansi
    A NULL-terminated string, defined by the system default code page, which specifies a path that is constructed with environment variables
    
    *Example: lnk.icon_environment_data.target_ansi == "%ProgramFiles%\\PeaZip\\res\\icons\\peazip_new.icl"*
    
    .. c:member:: target_unicode
    An optional, NULL-terminated, Unicode string that specifies a path that is constructed with environment variables.

.. c:type:: has_known_folder_data
Boolean flag which is set if a KnownFolderDataBlock structure is present.

*Example: lnk.has_known_folder_data*
    
.. c:type:: known_folder_data
The KnownFolderDataBlock structure specifies the location of a known folder. This data can be used when a link target is a known folder to keep track of the folder so that the link target IDList can be translated when the link is loaded.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.KNOWN_FOLDER_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.KNOWN_FOLDER_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: offset
    An unsigned integer that specifies the location of the ItemID of the first child segment of the IDList specified by KnownFolderID. This value is the offset, in bytes, into the link target IDList.
    
    *Example: lnk.known_folder_data.offset == 177*
    
    .. c:member:: known_folder_id
    A value in GUID packet representation that specifies the folder GUID ID.
    
    *Example: lnk.known_folder_data.known_folder_id[15] == 142*

.. c:type:: has_property_store_data
Boolean flag which is set if a PropertyStoreDataBlock structure is present.

*Example: lnk.has_property_store_data*
    
.. c:type:: property_store_data
A PropertyStoreDataBlock structure specifies a set of properties that can be used by applications to store extra data in the shell link. (TODO: implement the rest of this structure)

    .. c:member:: block_size
    The block size of this structure, which will be greater than or equal to lnk.PROPERTY_STORE_DATA_BLOCK_MIN_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.PROPERTY_STORE_DATA_BLOCK_SIGNATURE.

.. c:type:: has_shim_data
Boolean flag which is set if a ShimDataBlock structure is present.

*Example: lnk.has_shim_data*
    
.. c:type:: shim_data
The ShimDataBlock structure specifies the name of a shim that can be applied when activating a link target.

    .. c:member:: block_size
    The block size of this structure, which will be greater than or equal to lnk.SHIM_DATA_BLOCK_MIN_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.SHIM_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: layer_name
     A Unicode string that specifies the name of a shim layer to apply to a link target when it is being activated.

.. c:type:: has_special_folder_data
Boolean flag which is set if a SpecialFolderDataBlock structure is present.

*Example: lnk.has_special_folder_data*
    
.. c:type:: special_folder_data
The SpecialFolderDataBlock structure specifies the location of a special folder. This data can be used when a link target is a special folder to keep track of the folder, so that the link target IDList can be translated when the link is loaded.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.SPECIAL_FOLDER_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.SPECIAL_FOLDER_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: offset
    An unsigned integer that specifies the location of the ItemID of the first child segment of the IDList specified by SpecialFolderID. This value is the offset, in bytes, into the link target IDList.
    
    .. c:member:: special_folder_id
    An unsigned integer that specifies the folder integer ID.

.. c:type:: has_tracker_data
Boolean flag which is set if a TrackerDataBlock structure is present.

*Example: lnk.has_tracker_data*
    
.. c:type:: tracker_data
The TrackerDataBlock structure specifies data that can be used to resolve a link target if it is not found in its original location when the link is resolved. This data is passed to the Link Tracking service to find the link target.

    .. c:member:: block_size
    The block size of this structure, which will be equal to lnk.TRACKER_DATA_BLOCK_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.TRACKER_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: machine_id
    A NULL–terminated character string, as defined by the system default code page, which specifies the NetBIOS name of the machine where the link target was last known to reside.
    
    *Example: lnk.tracker_data.machine_id == "chris-xps"*
    
    .. c:member:: droid_volume_identifier
    A parsed Droid volume identifier GUID.
    
    *Example: lnk.tracker_data.droid_volume_identifier == "\\x40\\x78\\xC7\\x94\\x47\\xFA\\xC7\\x46\\xB3\\x56\\x5C\\x2D\\xC6\\xB6\\xD1\\x15"*
    
    .. c:member:: droid_file_identifier
    A parsed Droid file identifier GUID.
    
    .. c:member:: droid_birth_volume_identifier
    A parsed DroidBirth volume identifier GUID.
    
    .. c:member:: droid_birth_file_identifier
    A parsed DroidBirth file identifier GUID.

.. c:type:: has_vista_and_above_id_list_data
Boolean flag which is set if a VistaAndAboveIDListDataBlock structure is present.

*Example: lnk.has_vista_and_above_id_list_data*
    
.. c:type:: vista_and_above_id_list_data
The VistaAndAboveIDListDataBlock structure specifies an alternate IDList that can be used instead of the LinkTargetIDList structure on platforms that support it.

    .. c:member:: block_size
    The block size of this structure, which will be greater than or equal to lnk.VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK_MIN_SIZE.
    
    .. c:member:: block_signature
    The signature of the block, which will be equal to lnk.VISTA_AND_ABOVE_ID_LIST_DATA_BLOCK_SIGNATURE.
    
    .. c:member:: number_of_item_ids
    The number of ItemID entries in the list.
    
    .. c:type:: item_id_list
    A zero-based array of ItemIDs structures. The data stored in a given ItemID is defined by the source that corresponds to the location in the target namespace of the preceding ItemIDs. This data uniquely identifies the items in that part of the namespace. Each ItemID has the following members:
    
        .. c:member:: data
        The shell data source-defined data that specifies an item.
        
        .. c:member:: size
        The size of the ItemID.
        
.. c:type:: has_overlay
A boolean value that is true if the LNK has extra data appended to it.

*Example: lnk.has_overlay*

.. c:type:: overlay_offset
An unsigned integer representing the offset into the LNK file of where the overlay starts (only set if the has_overlay flag is true).

*Example: lnk.overlay_offset == 0x1CB*

.. c:type:: is_malformed
A boolean value that is true if the LNK failed to be parsed due to it having malformed data.

*Example: lnk.is_malformed*