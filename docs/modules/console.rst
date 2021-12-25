
.. _console-module:

##############
Console module
##############

.. versionadded:: 4.2.0

The Console module allows you to log information during condition execution. By
default, the log messages are sent to stdout but can be handled differently by
using the C api (:ref:`scanning-data`).

Every function in the console module returns true for the purposes of condition
evaluation. This means you must logically and your statements together to get
the proper output. For example:

.. code-block:: yara

    import "console"

    rule example
    {
        condition:
            console.log("Hello") and console.log("World!")
    }

.. c:function:: log(string)

    Function which sends the string to the main callback.

    *Example: console.log(pe.imphash())*

.. c:function:: log(message, string)

    Function which sends the message and string to the main callback.

    *Example: console.log("The imphash is: ", pe.imphash())*

.. c:function:: log(integer)

    Function which sends the integer to the main callback.

    *Example: console.log(uint32(0))*

.. c:function:: log(message, integer)

    Function which sends the message and integer to the main callback.

    *Example: console.log("32bits at 0: ", uint32(0))*

.. c:function:: log(float)

    Function which sends the floating point value to the main callback.

    *Example: console.log(math.entropy(0, filesize))*

.. c:function:: log(message, float)

    Function which sends the message and the floating point value to the main
    callback.

    *Example: console.log("Entropy: ", math.entropy(0, filesize))*

.. c:function:: hex(integer)

    Function which sends the integer to the main callback, formatted as a hex
    string.

    *Example: console.hex(uint32(0))*

.. c:function:: log(message, float)

    Function which sends the integer to the main callback, formatted as a hex
    string.

    *Example: console.hex("Hex at 0: ", uint32(0))*
