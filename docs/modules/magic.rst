
.. _magic-module:

############
Magic module
############

The Magic module allows you to identify the type of the file based on the
output of `file <http://en.wikipedia.org/wiki/File_(command)>`_, the standard
Unix command.

.. important::
    This module is not built into YARA by default, to learn how to include it
    refer to :ref:`compiling-yara`. Bad news for Windows users: **this module is
    not supported on Windows**.

There are two functions in this module: :c:func:`type` and :c:func:`mime_type`.
The first one returns the descriptive string returned by *file*, for example,
if you run *file* against some PDF document you'll get something like this::

    $file some.pdf
    some.pdf: PDF document, version 1.5

The :c:func:`type` function would return *"PDF document, version 1.5"* in this
case. Using the :c:func:`mime_type` function is similar to passing the
``--mime`` argument to *file*.::

    $file --mime some.pdf
    some.pdf: application/pdf; charset=binary


:c:func:`mime_type` would return *"application/pdf"*, without the charset part.

By experimenting a little with the *file* command you can learn which output to
expect for different file types. These are a few examples:

    * JPEG image data, JFIF standard 1.01
    * PE32 executable for MS Windows (GUI) Intel 80386 32-bit
    * PNG image data, 1240 x 1753, 8-bit/color RGBA, non-interlaced
    * ASCII text, with no line terminators
    * Zip archive data, at least v2.0 to extract



.. c:function:: type()

    Function returning a string with the type of the file.

    *Example: magic.type() contains "PDF"*


.. c:function:: mime_type()

    Function returning a string with the MIME type of the file.

    *Example: magic.mime_type() == "application/pdf"*
