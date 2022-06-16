
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
