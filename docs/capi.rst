*********
The C API
*********

You can integrate YARA into your C/C++ project by using the API privided by the
*libyara* library. This API gives you access to every YARA feature and it's the
same API used by the command-line tools ``yara`` and ``yarac``.

Initalizing and finalizing *libyara*
====================================

The first thing your program must do when using *libyara* is initializing the
library. This is done by calling the :c:func:`yr_initialize()` function. This
function allocates any resources needed by the library and initalizes internal
data structures. Its counterpart is :c:func:`yr_finalize`, which must be called
when you are finished using the library.

In a multi-threaded program only the main thread must call
:c:func:`yr_initialize` and :c:func:`yr_finalize`, but any additional thread
using the library must call :c:func:`yr_finalize_thread` before exiting.


Compiling rules
===============

Before using your rules to scan any data you need to compile them into binary
form. For that purpose you'll need a YARA compiler, which can be created with
:c:func:`yr_compiler_create`. After being used, the compiler must be destroyed
with :c:func:`yr_compiler_destroy`.

You can use either :c:func:`yr_compiler_add_file` or
:c:func:`yr_compiler_add_string` to add one or more input sources to be
compiled. Both of these functions receive an optional namespace. Rules added
under the same namespace behaves as if they were contained within the same
source file or string, so, rule identifiers must be unique among all the sources
sharing a namespace. If the namespace argument is ``NULL`` the rules are put
in the *default* namespace.

Both :c:func:`yr_compiler_add_file` and :c:func:`yr_compiler_add_string` return
the number of errors found in the source code. If the rules are correct they
will return 0. For more detailed error information you must set a callback
function by using :c:func:`yr_compiler_set_callback` before calling
:c:func:`yr_compiler_add_file` or :c:func:`yr_compiler_add_string`. The
callback function has the following prototype:

.. code-block:: c

  void callback_function(
      int error_level,
      const char* file_name,
      int line_number,
      const char* message,
      void* user_data)

.. versionchanged:: 3.3.0

Possible values for ``error_level`` are ``YARA_ERROR_LEVEL_ERROR`` and
``YARA_ERROR_LEVEL_WARNING``. The arguments ``file_name`` and ``line_number``
contains the file name and line number where the error or warning occurs.
``file_name`` is the one passed to :c:func:`yr_compiler_add_file`. It can
be ``NULL`` if you passed ``NULL`` or if you're using
:c:func:`yr_compiler_add_string`. The ``user_data`` pointer is the same you
passed to :c:func:`yr_compiler_set_callback`.

After you successfully added some sources you can get the compiled rules
using the :c:func:`yr_compiler_get_rules()` function. You'll get a pointer to
a :c:type:`YR_RULES` structure which can be used to scan your data as
described in :ref:`scanning-data`. Once :c:func:`yr_compiler_get_rules()` is
invoked you can not add more sources to the compiler, but you can get multiple
instances of the compiled rules by calling :c:func:`yr_compiler_get_rules()`
multiple times.

Each instance of :c:type:`YR_RULES` must be destroyed with
:c:func:`yr_rules_destroy`.


Saving and retrieving compiled rules
====================================

Compiled rules can be saved to a file and retrieved later by using
:c:func:`yr_rules_save` and :c:func:`yr_rules_load`. Rules compiled and saved
in one machine can be loaded in another machine as long as they have the same
endianness, no matter the operating system or if they are 32-bits or 64-bits
systems. However files saved with older versions of YARA may not work with
newer version due to changes in the file layout.

.. _scanning-data:

Scanning data
=============

Once you have an instance of :c:type:`YR_RULES` you can use it to scan data
either from a file or a memory buffer with :c:func:`yr_rules_scan_file` and
:c:func:`yr_rules_scan_mem` respectively. The results from the scan are
notified to your program via a callback function. The callback has the following
prototype:

.. code-block:: c

  int callback_function(
      int message,
      void* message_data,
      void* user_data);

Possible values for ``message`` are::

  CALLBACK_MSG_RULE_MATCHING
  CALLBACK_MSG_RULE_NOT_MATCHING
  CALLBACK_MSG_SCAN_FINISHED
  CALLBACK_MSG_IMPORT_MODULE

Your callback function will be called once for each existing rule with either
a ``CALLBACK_MSG_RULE_MATCHING`` or ``CALLBACK_MSG_RULE_NOT_MATCHING`` message,
depending if the rule is matching or not. In both cases a pointer to the
:c:type:`YR_RULE` structure associated to the rule is passed in the
``message_data`` argument. You just need to perform a typecast from
``void*`` to ``YR_RULE*`` to access the structure.

The callback is also called once for each imported module, with the
``CALLBACK_MSG_IMPORT_MODULE`` message. In this case ``message_data`` points
to a :c:type:`YR_MODULE_IMPORT` structure. This structure contains a
``module_name`` field pointing to a null terminated string with the name of the
module being imported and two other fields ``module_data`` and
``module_data_size``. These fields are initially set to ``NULL`` and ``0`` ,
but your program can assign a pointer to some arbitrary data to ``module_data``
while setting ``module_data_size`` to the size of the data. This way you can
pass additional data to those modules requiring it, like the
:ref:`Cuckoo-module` for example.

Lastly, the callback function is also called with the
``CALLBACK_MSG_SCAN_FINISHED`` message when the scan is finished. In this case
``message_data`` is ``NULL``.

In all cases the ``user_data`` argument is the same passed to
:c:func:`yr_rules_scan_file` or :c:func:`yr_rules_scan_mem`. This pointer is
not touched by YARA, it's just a way for your program to pass arbitrary data
to the callback function.

Both :c:func:`yr_rules_scan_file` and :c:func:`yr_rules_scan_mem` receive a
``flags`` argument and a ``timeout`` argument. The only flag defined at this
time is ``SCAN_FLAGS_FAST_MODE``, so you must pass either this flag or a zero
value. The ``timeout`` argument forces the function to return after
the specified number of seconds aproximately, with a zero meaning no
timeout at all.

The ``SCAN_FLAGS_FAST_MODE`` flag makes the scanning a little faster by avoiding
multiple matches of the same string when not necessary. Once the string was
found in the file it's subsequently ignored, implying that you'll have a
single match for the string, even if it appears multiple times in the scanned
data. This flag has the same effect of the ``-f`` command-line option described
in :ref:`command-line`.


API reference
=============

Data structures
---------------

.. c:type:: YR_COMPILER

  Data structure representing a YARA compiler.

.. c:type:: YR_RULES

  Data structure representing a set of compiled rules.

.. c:type:: YR_RULE

  Data structure representing a single rule.

  .. c:member:: const char* identifier

    Rule identifier.

  .. c:member:: const char* tags

    Pointer to a sequence of null terminated strings with tag names. An
    additional null character marks the end of the sequence. Example:
    ``tag1\0tag2\0tag3\0\0``. To iterate over the tags you can use
    :c:func:`yr_rule_tags_foreach`.

  .. c:member:: YR_META* metas

    Pointer to a sequence of :c:type:`YR_META` structures. To iterate over the
    structures use :c:func:`yr_rule_metas_foreach`.

  .. c:member:: YR_STRING* strings

    Pointer to a sequence of :c:type:`YR_STRING` structures. To iterate over the
    structures use :c:func:`yr_rule_strings_foreach`.

.. c:type:: YR_META

  Data structure representing a metadata value.

  .. c:member:: const char* identifier

    Meta identifier.

  .. c:member:: int32_t type

    One of the following metadata types:

      ``META_TYPE_NULL``
      ``META_TYPE_INTEGER``
      ``META_TYPE_STRING``
      ``META_TYPE_BOOLEAN``

.. c:type:: YR_STRING

  Data structure representing a string declared in a rule.

  .. c:member:: const char* identifier

      String identifier.


.. c:type:: YR_MATCH

  Data structure representing a string match.

  .. c:member:: int64_t base

    Base offset/address for the match. While scanning a file this field is
    usually zero, while scanning a process memory space this field is the
    virtual address of the memory block where the match was found.

  .. c:member:: int64_t offset

    Offset of the match relative to *base*.

  .. c:member:: int32_t length

    Length of the matching string

  .. c:member:: uint8_t* data

    Pointer to the matching string.


.. c:type:: YR_MODULE_IMPORT

  .. c:member:: const char* module_name

    Name of the module being imported.

  .. c:member:: void* module_data

    Pointer to additional data passed to the module. Initially set to
    ``NULL``, your program is responsible of setting this pointer while
    handling the CALLBACK_MSG_IMPORT_MODULE message.

  .. c:member:: size_t module_data_size

    Size of additional data passed to module. Your program must set the
    appropriate value if ``module_data`` is modified.


Functions
---------

.. c:function:: int yr_initialize(void)

  Initalize the library. Must be called by the main thread before using any
  other function. Return :c:macro:`ERROR_SUCCESS` on success another error
  code in case of error. The list of possible return codes vary according
  to the modules compiled into YARA.

.. c:function:: int yr_finalize(void)

  Finalize the library. Must be called by the main free to release any
  resource allocated by the library. Return :c:macro:`ERROR_SUCCESS` on
  success another error code in case of error. The list of possible return
  codes vary according to the modules compiled into YARA.

.. c:function:: void yr_finalize_thread(void)

  Any thread using the library, except the main thread, must call this
  function when it finishes using the library.

.. c:function:: int yr_compiler_create(YR_COMPILER** compiler)

  Create a YARA compiler. You must pass the address of a pointer to a
  :c:type:`YR_COMPILER`, the function will set the pointer to the newly
  allocated compiler. Returns one of the following error codes:

    :c:macro:`ERROR_SUCCESS`

    :c:macro:`ERROR_INSUFICENT_MEMORY`

.. c:function:: void yr_compiler_destroy(YR_COMPILER* compiler)

  Destroy a YARA compiler.

.. c:function:: void yr_compiler_set_callback(YR_COMPILER* compiler, YR_COMPILER_CALLBACK_FUNC callback, void* user_data)

  Set a callback for receiving error and warning information. The *user_data*
  pointer is passed to the callback function.

.. versionchanged:: 3.3.0

.. c:function:: int yr_compiler_add_file(YR_COMPILER* compiler, FILE* file, const char* namespace, const char* file_name)

  Compile rules from a *file*. Rules are put into the specified *namespace*,
  if *namespace* is ``NULL`` they will be put into the default namespace.
  *file_name* is the name of the file for error reporting purposes and can be
  set to ``NULL``. Returns the number of errors found during compilation.


.. c:function:: int yr_compiler_add_string(YR_COMPILER* compiler, const char* string, const char* namespace_)

  Compile rules from a *string*. Rules are put into the specified *namespace*,
  if *namespace* is ``NULL`` they will be put into the default namespace.
  Returns the number of errors found during compilation.

.. c:function:: int yr_compiler_get_rules(YR_COMPILER* compiler, YR_RULES** rules)

  Get the compiled rules from the compiler. Returns one of the following error
  codes:

    :c:macro:`ERROR_SUCCESS`

    :c:macro:`ERROR_INSUFICENT_MEMORY`

.. c:function:: int yr_compiler_define_integer_variable(YR_COMPILER* compiler, const char* identifier, int64_t value)

  Defines an integer external variable.

.. c:function:: int yr_compiler_define_boolean_variable(YR_COMPILER* compiler, const char* identifier, int value)

  Defines a boolean external variable.

.. c:function:: int yr_compiler_define_string_variable(YR_COMPILER* compiler, const char* identifier, const char* value)

  Defines a string external variable.

.. c:function:: void yr_rules_destroy(YR_RULES* rules)

  Destroy compiled rules.

.. c:function:: int yr_rules_save(YR_RULES* rules, const char* filename)

  Save *rules* into the file specified by *filename*. Returns one of the
  following error codes:

    :c:macro:`ERROR_SUCCESS`

    :c:macro:`ERROR_COULD_NOT_OPEN_FILE`

.. c:function:: int yr_rules_load(const char* filename, YR_RULES** rules)

  Load rules from the file specified by *filename*. Returns one of the
  following error codes:

    :c:macro:`ERROR_SUCCESS`

    :c:macro:`ERROR_INSUFICENT_MEMORY`

    :c:macro:`ERROR_COULD_NOT_OPEN_FILE`

    :c:macro:`ERROR_INVALID_FILE`

    :c:macro:`ERROR_CORRUPT_FILE`

    :c:macro:`ERROR_UNSUPPORTED_FILE_VERSION`

    :c:macro:`ERROR_INSUFICENT_MEMORY`

.. c:function:: int yr_rules_scan_mem(YR_RULES* rules, uint8_t* buffer, size_t buffer_size, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout)

    Scan a memory buffer. Returns one of the following error codes:

      :c:macro:`ERROR_SUCCESS`

      :c:macro:`ERROR_INSUFICENT_MEMORY`

      :c:macro:`ERROR_TOO_MANY_SCAN_THREADS`

      :c:macro:`ERROR_SCAN_TIMEOUT`

      :c:macro:`ERROR_CALLBACK_ERROR`

      :c:macro:`ERROR_TOO_MANY_MATCHES`


.. c:function:: int yr_rules_scan_file(YR_RULES* rules, const char* filename, int flags, YR_CALLBACK_FUNC callback, void* user_data, int timeout)

  Scan a file. Returns one of the following error codes:

    :c:macro:`ERROR_SUCCESS`

    :c:macro:`ERROR_INSUFICENT_MEMORY`

    :c:macro:`ERROR_COULD_NOT_MAP_FILE`

    :c:macro:`ERROR_ZERO_LENGTH_FILE`

    :c:macro:`ERROR_TOO_MANY_SCAN_THREADS`

    :c:macro:`ERROR_SCAN_TIMEOUT`

    :c:macro:`ERROR_CALLBACK_ERROR`

    :c:macro:`ERROR_TOO_MANY_MATCHES`

.. c:function:: yr_rule_tags_foreach(rule, tag)

  Iterate over the tags of a given rule running the block of code that follows
  each time with a different value for *tag* of type ``const char*``. Example:

  .. code-block:: c

    const char* tag;

    /* rule is a YR_RULE object */

    yr_rule_tags_foreach(rule, tag)
    {
      ..do something with tag
    }

.. c:function:: yr_rule_metas_foreach(rule, meta)

  Iterate over the :c:type:`YR_META` structures associated to a given rule
  running the block of code that follows each time with a different value for
  *meta*. Example:

  .. code-block:: c

    YR_META* meta;

    /* rule is a YR_RULE object */

    yr_rule_metas_foreach(rule, meta)
    {
      ..do something with meta
    }

.. c:function:: yr_rule_strings_foreach(rule, string)

  Iterate over the :c:type:`YR_STRING` structures associated to a given rule
  running the block of code that follows each time with a different value for
  *string*. Example:

  .. code-block:: c

    YR_STRING* string;

    /* rule is a YR_RULE object */

    yr_rule_strings_foreach(rule, string)
    {
      ..do something with string
    }

.. c:function:: yr_string_matches_foreach(string, match)

  Iterate over the :c:type:`YR_MATCH` structures associated to a given string
  running the block of code that follows each time with a different value for
  *match*. Example:

  .. code-block:: c

    YR_MATCH* match;

    /* string is a YR_STRING object */

    yr_string_matches_foreach(string, match)
    {
      ..do something with match
    }

.. c:function:: yr_rules_foreach(rules, rule)

  Iterate over each :c:type:`YR_RULE` in a :c:type:`YR_RULES` object running
  the block of code that follows each time with a different value for
  *rule*. Example:

  .. code-block:: c

    YR_RULE* rule;

    /* rules is a YR_RULES object */

    yr_rules_foreach(rules, rule)
    {
      ..do something with rule
    }

Error codes
-----------

.. c:macro:: ERROR_SUCCESS

  Everything went fine.

.. c:macro:: ERROR_INSUFICENT_MEMORY

  Insuficient memory to complete the operation.

.. c:macro:: ERROR_COULD_NOT_OPEN_FILE

  File could not be opened.

.. c:macro:: ERROR_COULD_NOT_MAP_FILE

  File could not be mapped into memory.

.. c:macro:: ERROR_ZERO_LENGTH_FILE

  File length is zero.

.. c:macro:: ERROR_INVALID_FILE

  File is not a valid rules file.

.. c:macro:: ERROR_CORRUPT_FILE

  Rules file is corrupt.

.. c:macro:: ERROR_UNSUPPORTED_FILE_VERSION

  File was generated by a different YARA and can't be loaded by this version.

.. c:macro:: ERROR_TOO_MANY_SCAN_THREADS

  Too many threads trying to use the same :c:type:`YR_RULES` object
  simultaneosly. The limit is defined by ``MAX_THREADS`` in
  *./include/yara/limits.h*

.. c:macro:: ERROR_SCAN_TIMEOUT

  Scan timed out.

.. c:macro:: ERROR_CALLBACK_ERROR

  Callback returned an error.

.. c:macro:: ERROR_TOO_MANY_MATCHES

  Too many matches for some string in your rules. This usually happens when
  your rules contains very short or very common strings like ``01 02`` or
  ``FF FF FF FF``. The limit is defined by ``MAX_STRING_MATCHES`` in
  *./include/yara/limits.h*
