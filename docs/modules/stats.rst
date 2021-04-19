
.. _stats-module:

###########
Stats module
###########

.. versionadded:: 4.2.0

The Stats module allows you to calculate certain statistical information from
portions of your file and create signatures based on those results.

.. c:function:: count(byte/string, offset, size)

    Returns how often a specific byte or substring occurs, starting at *offset*
    and looking at the next *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space.
    *offset* and *size* are optional; if left empty, the complete file is searched.

    *Example: stats.count("$[]", 0, 100) >= 5*

    *Example: stats.count(0x4A) >= 10*

.. c:function:: percentage(byte, offset, size)

    Returns the occurrence rate of a specific byte, starting at *offset*
    and looking at the next *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float between 0 and 1.
    *offset* and *size* are optional; if left empty, the complete file is searched.

    *Example: stats.percentage("[", 0, filesize) >= 0.4*

.. c:function:: mode(offset, size)

    Returns the most common byte, starting at *offset* and looking at the next
    *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float.
    *offset* and *size* are optional; if left empty, the complete file is searched.

    *Example: stats.mode(0, filesize) == 0xFF*
