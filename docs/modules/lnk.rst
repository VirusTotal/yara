
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

    An unsigned integer that specifies the size, in bytes, of the link tar

    *Example: lnk.file_size > 100KB*