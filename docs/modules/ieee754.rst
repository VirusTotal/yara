
.. _ieee754-module:

###############
IEEE 754 module
###############

.. versionadded:: 4.5.0

The IEEE 754 module allows you to parse float32 and double64 formats from any
offset and to create signatures based on the interpreted floating point value.

.. important::
    All the functions return floating point numbers. YARA is able to convert
    integers to floating point numbers during most operations. For example, if
    we have the number 3.5 stored at offset zero, this condition is true:

    *ieee754.float32be(0) >= 3*

    In most situations you should avoid equality between floating point
    numbers. It is best to check for ranges using less than, greater than, or
    *math.in_range()*. For example, if you have the number 2.000001 at offset
    zero then this condition is true:

    *math.in_range(ieee754.float32be(0), 2, 2.01)*

.. c:function:: float32le(offset)

    Returns the single precision (32 bits) little endian floating point number
    at offset *offset*. This function is an alias for *binary32le*.

.. c:function:: float32be(offset)

    Returns the single precision (32 bits) big endian floating point number at
    offset *offset*. This function is an alias for *binary32be*.

.. c:function:: double64le(offset)

    Returns the double precision (64 bits) little endian floating point number
    at offset *offset*. This function is an alias for *binary64le*.

.. c:function:: double64be(offset)

    Returns the double precision (64 bits) big endian floating point number at
    offset *offset*. This function is an alias for *binary64be*.

