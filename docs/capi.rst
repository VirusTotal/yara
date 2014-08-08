*********
The C API
*********

.. highlight: c

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
      const char* message)

Possible values for ``error_level`` are ``YARA_ERROR_LEVEL_ERROR`` and
``YARA_ERROR_LEVEL_WARNING``. The arguments ``file_name`` and ``line_number``
contains the file name and line number where the error or warning occurs.
``file_name`` is the one passed to :c:func:`yr_compiler_add_file`. It can
be ``NULL`` if you passed ``NULL`` or if you're using
:c:func:`yr_compiler_add_string`.

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
``CALLBACK_MSG_IMPORT_MODULE`` message.


Lastly, the callback function is also called with the
``CALLBACK_MSG_SCAN_FINISHED`` message when the scan is finished. In this case
``message_data`` is ``NULL``.

In all cases the ``user_data`` argument is the same passed to
:c:func:`yr_rules_scan_file` or :c:func:`yr_rules_scan_mem`. This pointer is
not touched by YARA, it's just a way for your program to pass arbitrary data
to the callback function.

Example
=======

Here you have a code snippet showing the most important features

.. code-block:: c


    YR_COMPILER* compiler;
    YR_RULES* rules;
    FILE* file;

    int result;


    result = yr_create_compiler(&compiler);

    if (result == ERROR_SUCCESS)
    {
        file = fopen(file_path, "r");

        yr_compiler_add_file(compiler, file, NULL, file_path);

        result = yr_compiler_get_rules(compiler, &rules);

        if (result == ERROR_SUCCESS)
        {
           ... use rules to scan some data.
        }

        yr_compiler_destroy(compiler);
    }
    else
    {
        ... handle error.
    }







API reference
=============

.. c:type:: YR_COMPILER

    Data structure representing a YARA compiler.

.. c:type:: YR_RULES

    Data structure representing a set of compiled rules.

.. c:type:: YR_RULE

    Data structure representing a single rule.

.. c:function:: void yr_initialize(void)

    Initalize the library. Must be called by the main thread before using any
    other function.

.. c:function:: void yr_finalize(void)

    Finalize the library. Must be called by the main free to release any
    resource allocated by the library.

.. c:function:: void yr_finalize_thread(void)

    Any thread using the library, except the main thread, must call this
    function when it finishes using the library.

.. c:function:: int yr_compiler_create(YR_COMPILER** compiler)

    Create a YARA compiler.

.. c:function:: void yr_compiler_destroy(YR_COMPILER* compiler)

    Destroy a YARA compiler.

.. c:function:: void yr_compiler_set_callback(YR_COMPILER* compiler, YR_COMPILER_CALLBACK_FUNC callback)

    Set a callback for receiving error and warning information.

.. c:function:: int yr_compiler_add_file(YR_COMPILER* compiler, FILE* file, const char* namespace, const char* file_name)

    Compile rules from a *file*. Rules are put into the specified *namespace*,
    if *namespace* is ``NULL`` they will be put into the default namespace.
    *file_name* is the name of the file for error reporting purposes and can be
    set to ``NULL``.


.. c:function:: int yr_compiler_add_string(YR_COMPILER* compiler, const char* string, const char* namespace_)

    Compile rules from a *string*. Rules are put into the specified *namespace*,
    if *namespace* is ``NULL`` they will be put into the default namespace.

.. c:function:: int yr_compiler_get_rules(YR_COMPILER* compiler, YR_RULES** rules)

    Get the compiled rules from the compiler.

.. c:function:: void yr_rules_destroy(YR_RULES* rules)

    Destroy compiled rules.


.. c:function:: int yr_rules_save(YR_RULES* rules, const char* filename)

    Save *rules* into the file specified by *filename*.

.. c:function:: void yr_rules_load(const char* filename, YR_RULES** rules)

    Load rules from the file specified by *filename*.

.. c:function:: int yr_rules_scan_mem(YR_RULES* rules, uint8_t* buffer, size_t buffer_size, YR_CALLBACK_FUNC callback, void* user_data, int fast_scan_mode, int timeout)

    Scan a memory buffer.

.. c:function:: int yr_rules_scan_file(YR_RULES* rules, const char* filename, YR_CALLBACK_FUNC callback, void* user_data, int fast_scan_mode, int timeout)
