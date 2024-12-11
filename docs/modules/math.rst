
.. _math-module:

###########
Math module
###########

.. versionadded:: 3.3.0

The Math module allows you to calculate certain values from portions of your
file and create signatures based on those results.

.. important::
    Where noted these functions return floating point numbers. YARA is able to
    convert integers to floating point numbers during most operations. For
    example this will convert 7 to 7.0 automatically, because the return type
    of the entropy function is a floating point value:

    *math.entropy(0, filesize) >= 7*

    The one exception to this is when a function requires a floating point
    number as an argument. For example, this will cause a syntax error because
    the arguments must be floating point numbers:

    *math.in_range(2, 1, 3)*

.. c:function:: entropy(offset, size)

    Returns the entropy for *size* bytes starting at *offset*. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float.

    *Example: math.entropy(0, filesize) >= 7*

.. c:function:: entropy(string)

    Returns the entropy for the given string.

    *Example: math.entropy("dummy") > 7*

.. c:function:: monte_carlo_pi(offset, size)

    Returns the percentage away from Pi for the *size* bytes starting at
    *offset* when run through the Monte Carlo from Pi test. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float.

    *Example: math.monte_carlo_pi(0, filesize) < 0.07*

.. c:function:: monte_carlo_pi(string)

    Return the percentage away from Pi for the given string.

.. c:function:: serial_correlation(offset, size)

    Returns the serial correlation for the *size* bytes starting at *offset*.
    When scanning a running process the *offset* argument should be a virtual
    address within the process address space. The returned value is a float
    between 0.0 and 1.0.

    *Example: math.serial_correlation(0, filesize) < 0.2*

.. c:function:: serial_correlation(string)

    Return the serial correlation for the given string.

.. c:function:: mean(offset, size)

    Returns the mean for the *size* bytes starting at *offset*. When scanning
    a running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float.

    *Example: math.mean(0, filesize) < 72.0*

.. c:function:: mean(string)

    Return the mean for the given string.

.. c:function:: deviation(offset, size, mean)

    Returns the deviation from the mean for the *size* bytes starting at
    *offset*. When scanning a running process the *offset* argument should be
    a virtual address within the process address space. The returned value is
    a float.

    The mean of an equally distributed random sample of bytes is 127.5, which
    is available as the constant math.MEAN_BYTES.

    *Example: math.deviation(0, filesize, math.MEAN_BYTES) == 64.0*

.. c:function:: deviation(string, mean)

    Return the deviation from the mean for the given string.

.. c:function:: in_range(test, lower, upper)

    Returns true if the *test* value is between *lower* and *upper* values. The
    comparisons are inclusive.

    *Example: math.in_range(math.deviation(0, filesize, math.MEAN_BYTES), 63.9, 64.1)*

.. c:function:: max(int, int)

    .. versionadded:: 3.8.0

    Returns the maximum of two unsigned integer values.

.. c:function:: min(int, int)

    .. versionadded:: 3.8.0

    Returns the minimum of two unsigned integer values.

.. c:function:: to_number(bool)

    .. versionadded:: 4.1.0

    Returns 0 or 1, it's useful when writing a score based rule.

    *Example: math.to_number(SubRule1) \* 60 + math.to_number(SubRule2) \* 20 + math.to_number(SubRule3) \* 70 > 80*

.. c:function:: abs(int)

    .. versionadded:: 4.2.0

    Returns the absolute value of the signed integer.

    *Example: math.abs(@a - @b) == 1*

.. c:function:: count(byte, offset, size)

    .. versionadded:: 4.2.0

    Returns how often a specific byte occurs, starting at *offset*
    and looking at the next *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space.
    *offset* and *size* are optional; if left empty, the complete file is searched.

    *Example: math.count(0x4A) >= 10*

    *Example: math.count(0x00, 0, 4) < 2*

.. c:function:: percentage(byte, offset, size)

    .. versionadded:: 4.2.0

    Returns the occurrence rate of a specific byte, starting at *offset*
    and looking at the next *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float between 0 and 1.
    *offset* and *size* are optional; if left empty, the complete file is searched.


    *Example: math.percentage(0xFF, filesize-1024, filesize) >= 0.9*

    *Example: math.percentage(0x4A) >= 0.4*

.. c:function:: mode(offset, size)

    .. versionadded:: 4.2.0

    Returns the most common byte, starting at *offset* and looking at the next
    *size* bytes. When scanning a
    running process the *offset* argument should be a virtual address within
    the process address space. The returned value is a float.
    *offset* and *size* are optional; if left empty, the complete file is searched.

    *Example: math.mode(0, filesize) == 0xFF*

    *Example: math.mode() == 0x00*

.. c:function:: to_string(int)

    .. versionadded:: 4.3.0

    Convert the given integer to a string. Note: integers in YARA are signed.

    *Example: math.to_string(10) == "10"*
    *Example: math.to_string(-1) == "-1"*

.. c:function:: to_string(int, base)

    .. versionadded:: 4.3.0

    Convert the given integer to a string in the given base. Supported bases are
    10, 8 and 16. Note: integers in YARA are signed.

    *Example: math.to_string(32, 16) == "20"*
    *Example: math.to_string(-1, 16) == "ffffffffffffffff"*
