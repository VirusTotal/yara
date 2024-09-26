
.. _hash-module:

###########
Hash module
###########

.. versionadded:: 3.2.0

The Hash module allows you to calculate hashes (MD5, SHA1, SHA256) from portions
of your file and create signatures based on those hashes.

It also allows you to work with Locality Sensitive Hashes from Trend Micro (TLSH).
Specifically, you are able to compute the distance between TLSH of the portions of
your file (min. 50 bytes) and input TLSH string. The distance scores can go up to
1000 and even above. A low score (of 50 or less) means that files are quite similar,
while the distance of zero means (very likely) the exact match. Just like MD5 and
SHA1 schemes, collisions can occur and very different files will have the same hash
value.

.. important::
    This module depends on the OpenSSL library. Please refer to
    :ref:`compiling-yara` for information about how to build OpenSSL-dependant
    features into YARA.

    Good news for Windows users: this module is already included in the official
    Windows binaries.

.. warning::
    The returned hash string is always in lowercase. This means that rule condition matching on hashes 
    ``hash.md5(0, filesize) == "feba6c919e3797e7778e8f2e85fa033d"`` 
    requires the hash string to be given in lowercase, otherwise the match condition 
    will not work. (see https://github.com/VirusTotal/yara/issues/1004)

    The TLSH is not valid in lowercase. Therefore, the input hash must be in uppercase which differ
    against traditional hash functions. The module accepts TLSH either with or without the first
    byte "T1" specifying the version of TLSH.

    DISCLAIMER: Computing TLSH is very slow, comparable with SSDEEP hashing which means approx.
    5.4 times slower than SHA1 function. Adding `tlsh_diff` function into YARA rule can extend
    its evaluation up to 15%. Be especially careful while scanning files bigger than 5 MB.

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

.. c:function:: crc32(offset, size)

    Returns a crc32 checksum for the *size* bytes starting at *offset*.

.. c:function:: crc32(string)

    Returns a crc32 checksum for the given string.

.. c:function:: tlsh_diff(tlsh)
    Computes the TLSH hash for the whole file (the offset is set to zero and
    size is set to size of the file). The returned integer is the difference
    between computed TLSH hash and *tlsh* hash string.

    *Example: hash.tlsh_diff("T1A4315014DC89DDDDFB6246C177B3B52BA818B01142CCF89682EACC07D800F79C64BB52") < 50*

.. c:function:: tlsh_diff(tlsh, offset, size)
    Computes the TLSH hash for the *size* bytes starting at *offset*. When
    scanning a running process the *offset* argument should be a virtual address
    within the process address space. The returned integer is the difference
    between computed TLSH hash and *tlsh* hash string.

    *Example: hash.tlsh_diff("A4315014DC89DDDDFB6246C177B3B52BA818B01142CCF89682EACC07D800F79C64BB52", 0, filesize) == 0*

.. c:function:: tlsh_diff(tlsh, string)
    Computes the TLSH hash for the *string* of content. The returned integer
    is the difference between computed TLSH hash and *tlsh* hash string.

