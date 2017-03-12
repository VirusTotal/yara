
.. _hash-module:

###########
Hash module
###########

.. versionadded:: 3.2.0

The Hash module allows you to calculate hashes (MD5, SHA1, SHA256) from portions
of your file and create signatures based on those hashes.

.. important::
    This module depends on the OpenSSL library. Please refer to
    :ref:`compiling-yara` for information about how to build OpenSSL-dependant
    features into YARA.

    Good news for Windows users: this module is already included in the official
    Windows binaries.

.. c:function:: md5(offset, size)

    Returns the MD5 hash for *size* bytes starting at *offset*. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned string is always in lowercase.

    *Example: hash.md5(0, filesize) == "feba6c919e3797e7778e8f2e85fa033d"*

.. c:function:: md5(string)

    Returns the MD5 hash for the given string.

    *Example: hash.md5("dummy") == "275876e34cf609db118f3d84b799a790"*

.. c:function:: sha1(offset, size)

    Returns the SHA1 hash for the *size* bytes starting at *offset*. When
    scanning a running process the *offset* argument should be a virtual address
    within the process address space. The returned string is always in
    lowercase.

.. c:function:: sha1(string)

    Returns the SHA1 hash for the given string.

.. c:function:: sha256(offset, size)

    Returns the SHA256 hash for the *size* bytes starting at *offset*. When
    scanning a running process the *offset* argument should be a virtual address
    within the process address space. The returned string is always in
    lowercase.

.. c:function:: sha256(string)

    Returns the SHA256 hash for the given string.

.. c:function:: checksum32(offset, size)

    Returns a 32-bit checksum for the *size* bytes starting at *offset*. The
    checksum is just the sum of all the bytes (unsigned).

.. c:function:: checksum32(string)

    Returns a 32-bit checksum for the given string. The checksum is just the
    sum of all the bytes in the string (unsigned).

