
.. _string-module:

###########
String module
###########

.. versionadded:: 4.3.0

The String module provides functions for manipulating strings as returned by
modules. The strings referenced here are not YARA strings as defined in the
strings section of your rule.

.. c:function:: to_int(string)

    .. versionadded:: 4.3.0

    Convert the given string to a signed integer. If the string starts with "0x"
    it is treated as base 16. If the string starts with "0" it is treated base
    8. Leading '+' or '-' is also supported.

    *Example: string.to_int("1234") == 1234*
    *Example: string.to_int("-10") == -10*
    *Example: string.to_int("-010" == -8*

.. c:function:: to_int(string, base)

    .. versionadded:: 4.3.0

    Convert the given string, interpreted with the given base, to a signed
    integer. Base must be 0 or between 2 and 32 inclusive. If it is zero then
    the string will be intrepreted as base 16 if it starts with "0x" or as base
    8 if it starts with "0". Leading '+' or '-' is also supported.

    *Example: string.to_int("011", 8) == "9"*
    *Example: string.to_int("-011", 0) == "-9"*

.. c:function:: length(string)

    .. versionadded:: 4.3.0

    Return the length of the string, which can be any sequence of bytes. NULL
    bytes included.

    *Example: string.length("AXS\x00ERS") == 7*

