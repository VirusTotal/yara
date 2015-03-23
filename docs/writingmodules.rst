.. _writing-modules:

************************
Writing your own modules
************************

For the first time ever, in YARA 3.0 you can extend its features to express
more complex and refined conditions.  YARA 3.0 does this by employing
modules, which you can use to define data structures and functions, which
can be later used from within your rules. You can see some examples of
what a module can do in the :ref:`using-modules` section.

The purpose of the following sections is to teach you how to create your
own modules for giving YARA that cool feature you always dreamed of.


The "Hello World!" module
=========================

Modules are written in C and built into YARA as part of the compiling process.
In order to create your own modules you must be familiar with the C
programming language and how to configure and build YARA from source code. You
don't need to understand how YARA does its magic; YARA exposes a simple API for
modules, which is all you need to know.

The source code for your module must reside in the *libyara/modules* directory
of the source tree. It's recommended to use the module name as the file name for
the source file, if your module's name is *foo* its source file should be
*foo.c*.

In the *libyara/modules* directory you'll find a *demo.c* file we'll use
as our starting point. The file looks like this:

.. code-block:: c

    #include <yara/modules.h>

    #define MODULE_NAME demo

    begin_declarations;

      declare_string("greeting");

    end_declarations;

    int module_initialize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

    int module_finalize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
    {
      set_string("Hello World!", module_object, "greeting");
      return ERROR_SUCCESS;
    }

    int module_unload(
        YR_OBJECT* module_object)
    {
      return ERROR_SUCCESS;
    }

    #undef MODULE_NAME

Let's start dissecting the source code so you can understand every detail. The
first line in the code is:

.. code-block:: c

    #include <yara/modules.h>

The *modules.h* header file is where the definitions for YARA's module API
reside, therefore this include directive is required in all your modules. The
second line is:

.. code-block:: c

    #define MODULE_NAME demo

This is how you define the name of your module and is also required. Every
module must define its name at the start of the source code. Module names must
be unique among the modules built into YARA.

Then follows the declaration section:

.. code-block:: c

    begin_declarations;

      declare_string("greeting");

    end_declarations;

Here is where the module declares the functions and data structures that will
be available for your YARA rules. In this case we are declaring just a
string variable named *greeting*. We are going to discuss these concepts more
in greater detail in the :ref:`declaration-section`.

After the declaration section you'll find a pair of functions:

.. code-block:: c

    int module_initialize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

    int module_finalize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

The ``module_initialize`` function is called during YARA's initializtion while
its counterpart ``module_finalize`` is called while finalizing YARA. These
functions allows you initialize and finalize any global data structure you may
need to use in your module.

Then comes the ``module_load`` function:

.. code-block:: c

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
    {
      set_string("Hello World!", module_object, "greeting");
      return ERROR_SUCCESS;
    }


This function is invoked once for each scanned file, but only if the module is
imported by some rule with the ``import`` directive. The ``module_load``
function is where your module has the opportunity to inspect the file being
scanned, parse or analyze it in the way prefered, and then populate the
data structures defined in the declarations section.

In this example the ``module_load`` function doesn't inspect the file content
at all, it just assigns the string, "Hello World!" to the variable *greeting*
declared before.

And finally, we have the ``module_unload`` function:

.. code-block:: c

    int module_unload(
        YR_OBJECT* module_object)
    {
      return ERROR_SUCCESS;
    }

For each call to ``module_load`` there is a corresponding call to
``module_unload``. This function allows your module to free any resource
allocated during ``module_load``. There's nothing to free in this case, so
the function just returns ``ERROR_SUCCESS``. Both ``module_load`` and
``module_unload`` should return ``ERROR_SUCCESS`` to indicate that everything
went fine. If a different value is returned the scanning will be aborted and an
error reported to the user.

Building our "Hello World!"
---------------------------

Modules are not magically built into YARA just by dropping their source code
into the *libyara/modules* directory, you must follow two further steps in order
to get them to work. The first step is adding your module to the *module_list*
file also found in the *libyara/modules* directory.

The *module_list* file looks like this::

    MODULE(tests)
    MODULE(pe)

    #ifdef CUCKOO
    MODULE(cuckoo)
    #endif

You must add a line *MODULE(<name>)* with the name of your module to this file.
In our case the resulting *module_list* is::

    MODULE(tests)
    MODULE(pe)

    #ifdef CUCKOO
    MODULE(cuckoo)
    #endif

    MODULE(demo)

The second step is modifying the *Makefile.am* to tell the *make* program that
the source code for your module most be compiled and linked into YARA. At the
very beginning of *libyara/Makefile.am* you'll find this::

    MODULES =  modules/tests.c
    MODULES += modules/pe.c

    if CUCKOO
    MODULES += modules/cuckoo.c
    endif


Just add a new line for your module::

    MODULES =  modules/tests.c
    MODULES += modules/pe.c

    if CUCKOO
    MODULES += modules/cuckoo.c
    endif

    MODULES += modules/demo.c

And that's all! Now you're ready to build YARA with your brand-new module
included. Just go to the source tree root directory and type as always::

    make
    sudo make install


Now you should be able to create a rule like this::

    import "demo"

    rule HelloWorld
    {
        condition:
            demo.greeting == "Hello World!"
    }

Any file scanned with this rule will match the ``HelloWord`` because
``demo.greeting == "Hello World!"`` is always true.

.. _declaration-section:

The declaration section
=======================

The declaration section is where you declare the variables, structures and
functions that will be available for your YARA rules. Every module must contain
a declaration section like this::

    begin_declarations;

        <your declarations here>

    end_declarations;

Basic types
-----------

Within the declaration section you can use ``declare_string(<variable name>)``,
``declare_integer(<variable name>)`` and ``declare_float(<variable name>)`` to
declare string, integer, or float variables respectively. For example::

    begin_declarations;

        declare_integer("foo");
        declare_string("bar");
        declare_float("baz");

    end_declarations;

.. note::
    Floating-point variables requiere YARA version 3.3.0 or later.


Variable names can't contain characters other than letters, numbers and
underscores. These variables can be used later in your rules at any place where
an integer or string is expected. Supposing your module name is "mymodule", they
can be used like this::

    mymodule.foo > 5

    mymodule.bar matches /someregexp/


Structures
----------

Your declarations can be organized in a more structured way::

    begin_declarations;

        declare_integer("foo");
        declare_string("bar");
        declare_float("baz");

        begin_struct("some_structure");

            declare_integer("foo");

            begin_struct("nested_structure");

                declare_integer("bar");

            end_struct("nested_structure");

        end_struct("some_structure");

        begin_struct("another_structure");

            declare_integer("foo");
            declare_string("bar");
            declare_string("baz");
            declare_float("tux");

        end_struct("another_structure");

    end_declarations;

In this example we're using ``begin_struct(<structure name>)`` and
``end_struct(<structure name>)`` to delimite two structures named
*some_structure* and *another_structure*. Within the structure delimiters you
can put any other declarations you want, including another structure
declaration. Also notice that members of different structures can have the same
name, but members within the same structure must have unique names.

When refering to these variables from your rules it would be like this::

    mymodule.foo
    mymodule.some_structure.foo
    mymodule.some_structure.nested_structure.bar
    mymodule.another_structure.baz


Arrays
------

In the same way you declare individual strings, integers, floats or structures,
you can declare arrays of them::

    begin_declarations;

        declare_integer_array("foo");
        declare_string_array("bar");
        declare_float_array("baz");

        begin_struct_array("struct_array");

            declare_integer("foo");
            declare_string("bar");

        end_struct_array("struct_array");

    end_declarations;


Individual values in the array are referenced like in most programming
languages::

    foo[0]
    bar[1]
    baz[3]
    struct_array[4].foo
    struct_array[1].bar

Arrays are zero-based and don't have a fixed size, they will grow as needed
when you start initializing its values.


Dictionaries
------------

.. versionadded:: 3.2.0

You can also declare dictionaries of integers, floats, strings, or structures::

    begin_declarations;

        declare_integer_dictionary("foo");
        declare_string_dictionary("bar");
        declare_float_dictionary("baz")

        begin_struct_dictionary("struct_dict");

            declare_integer("foo");
            declare_string("bar");

        end_struct_dictionary("struct_dict");

    end_declarations;

Individual values in the dictionary are accessed by using a string key::

    foo["somekey"]
    bar["anotherkey"]
    baz["yetanotherkey"]
    struct_dict["k1"].foo
    struct_dict["k1"].bar

.. _declaring-functions:

Functions
---------

One of the more powerful features of YARA modules is the possibility of
declaring functions that can be later invoked from your rules. Functions
must appear in the declaration section in this way::

    declare_function(<function name>, <argument types>, <return tuype>, <C function>);

*<function name>* is the name that will be used in your YARA rules to invoke
the function.

*<argument types>* is a string containing one character per
function argument, where the character indicates the type of the argument.
Functions can receive four different types of arguments: string, integer, float
and regular expression, denoted by characters: **s**, **i**, **r** and **f**
respectively. If your function receives two integers *<argument types>* must be
*"ii"*, if it receives an integer as the first argument and a string as the
second one *<argument types>* must be *"is"*, if it receives three strings and
a float *<argument types>* must be "*sssf*".

*<return type>* is a string with a single character indicating the return type.
Possible return types are string (*"s"*) integer (*"i"*) and float (*"f"*).

*<C function>* is the identifier for the actual implementation of your function.

Here you have a full example:

.. code-block:: c

    define_function(isum)
    {
      int64_t a = integer_argument(1);
      int64_t b = integer_argument(2);

      return_integer(a + b);
    }

    define_function(fsum)
    {
      double a = float_argument(1);
      double b = float_argument(2);

      return_integer(a + b);
    }

    begin_declarations;

        declare_function("sum", "ii", "i", sum);

    end_declarations;

As you can see in the example above, your function code must be defined before
the declaration section, like this::

    define_function(<function identifier>)
    {
      ...your code here
    }

Functions can be overloaded as in C++ and other programming languages. You can
declare two functions with the same name as long as they differ in the type or
number of arguments. One example of overloaded functions can be found in the
:ref:`hash-module`, it has two functions for calculating MD5 hashes, one
receiving an offset and length within the file and another one receiving a
string::

    begin_declarations;

        declare_function("md5", "ii", "s", data_md5);
        declare_function("md5", "s", "s", string_md5);

    end_declarations;

We are going to discuss function implementation more in depth in the
:ref:`implementing-functions` section.

Initialization and finalization
===============================

Every module must implement two functions for initialization and finalization:
``module_initialize`` and ``module_finalize``. The former is called during
YARA's initialization by :c:func:`yr_initialize` while the latter is called
during finalization by :c:func:`yr_finalize`. Both functions are invoked
whether or not the module is being imported by some rule.

These functions give your module an opportunity to initialize any global data
structure it may need, but most of the times they are just empty functions:

.. code-block:: c

    int module_initialize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

    int module_finalize(
        YR_MODULE* module)
    {
      return ERROR_SUCCESS;
    }

Any returned value different from ``ERROR_SUCCESS`` will abort YARA's execution.

Implementing the module's logic
===============================

Besides ``module_initialize`` and ``module_finalize`` Every module must
implement two other functions which are called by YARA during the
scanning of a file or process memory space: ``module_load`` and
``module_unload``. Both functions are called once for each scanned file or
process, but only if the module was imported by means of the ``import``
directive. If the module is not imported by some rule neither ``module_load``
nor ``module_unload`` will be called.

The ``module_load`` function has the following prototype:

.. code-block:: c

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)

The ``context`` argument contains information relative to the current scan,
including the data being scanned. The ``module_object`` argument is a pointer to
a ``YR_OBJECT`` structure associated to the module. Each structure, variable or
function declared in a YARA module is represented by a ``YR_OBJECT`` structure.
These structures conform a tree whose root is the module's ``YR_OBJECT``
structure. If you have the following declarations in a module named *mymodule*::

    begin_declarations;

        declare_integer("foo");

        begin_struct("bar");

            declare_string("baz");

        end_struct("bar");

    end_declarations;

Then the tree will look like this::

     YR_OBJECT(type=OBJECT_TYPE_STRUCT, name="mymodule")
      |
      |_ YR_OBJECT(type=OBJECT_TYPE_INTEGER, name="foo")
      |
      |_ YR_OBJECT(type=OBJECT_TYPE_STRUCT, name="bar")
          |
          |_ YR_OBJECT(type=OBJECT_TYPE_STRING, name="baz")

Notice that both *bar* and *mymodule* are of the same type
``OBJECT_TYPE_STRUCT``, which means that the ``YR_OBJECT`` associated to the
module is just another structure like *bar*. In fact, when you write in your
rules something like ``mymodule.foo`` you're performing a field lookup in a
structure in the same way that ``bar.baz`` does.

In resume, the ``module_object`` argument allows you to access every variable,
structure or function declared by the module by providing a pointer to the
root of the objects tree.

The ``module_data`` argument is a pointer to any additional data passed to the
module, and ``module_data_size`` is the size of that data. Not all modules
require additional data, most of them rely on the data being scanned alone, but
a few of them require more information as input. The :ref:`cuckoo-module` is a
good example of this, it receives a behavior report associated to PE
files being scanned which is passed in the ``module_data`` and
``module_data_size`` arguments.

For more information on how to pass additional data to your module take a look
at the ``-x`` argument in :ref:`command-line`.

.. _accessing-scanned-data:

Accessing the scanned data
--------------------------

Most YARA modules needs to access the file or process memory being scanned to
extract information from it. The data being scanned is sent to the module in the
``YR_SCAN_CONTEXT`` structure passed to the ``module_load`` function. The data
is sometimes sliced in blocks, therefore your module needs to iterate over the
blocks by using the ``foreach_memory_block`` macro:

.. code-block:: c

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
    {
        YR_MEMORY_BLOCK* block;

        foreach_memory_block(context, block)
        {
            ..do something with the current memory block
        }
    }

Each memory block is represented by a ``YR_MEMORY_BLOCK`` structure with the
following attributes:

.. c:type:: uint8_t*   data

    Pointer to the actual data for this memory block.

.. c:type:: size_t   size

    Size of the data block.

.. c:type:: size_t   base

    Base offset/address for this block. If a file is being scanned this field
    contains the offset within the file where the block begins, if a process
    memory space is being scanned this contains the virtual address where
    the block begins.

The blocks are always iterated in the same order as they appear in the file
or process memory. In the case of files the first block will contain the
beginning of the file. Actually, a single block will contain the whole file's
content in most cases, but you can't rely on that while writing your code. For
very big files YARA could eventually split the file into two or more blocks,
and your module should be prepared to handle that.

The story is very different for processes. While scanning a process memory
space your module will definitely receive a large number of blocks, one for each
committed memory region in the proccess address space.

However, there are some cases where you don't actually need to iterate over the
blocks. If your module just parses the header of some file format you can safely
assume that the whole header is contained within the first block (put some
checks in your code nevertheless). In those cases you can use the
``first_memory_block`` macro:

.. code-block:: c

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
    {
        YR_MEMORY_BLOCK* block;

        block = first_memory_block(context);

        ..do something with the memory block
    }

Setting variable's values
-------------------------

The ``module_load`` function is where you assign values to the variables
declared in the declarations section, once you've parsed or analized the scanned
data and/or any additional module's data. This is done by using the
``set_integer`` and ``set_string`` functions:

.. c:function:: void set_integer(int64_t value, YR_OBJECT* object, const char* field, ...)

.. c:function:: void set_string(const char* value, YR_OBJECT* object, const char* field, ...)

Both functions receive a value to be assigned to the variable, a pointer to a
``YR_OBJECT`` representing the variable itself or some ancestor of
that variable, a field descriptor, and additional arguments as defined by the
field descriptor.

If we are assigning the value to the variable represented by ``object`` itself,
then the field descriptor must be ``NULL``. For example, assuming that ``object``
points to a ``YR_OBJECT`` structure corresponding to some integer variable, we
can set the value for that integer variable with:

.. code-block:: c

    set_integer(<value>, object, NULL);

The field descriptor is used when you want to assign the value to some
descendant of ``object``. For example, consider the following declarations::

    begin_declarations;

        begin_struct("foo");

            declare_string("bar");

            begin_struct("baz");

                declare_integer("qux");

            end_struct("baz");

        end_struct("foo");

    end_declarations;

If ``object`` points to the ``YR_OBJECT`` associated to the ``foo`` structure
you can set the value for the ``bar`` string like this:

.. code-block:: c

    set_string(<value>, object, "bar");

And the value for ``qux`` like this:

.. code-block:: c

    set_integer(<value>, object, "baz.qux");


Do you remember that the ``module_object`` argument for ``module_load`` was a
pointer to a ``YR_OBJECT``? Do you remember that this ``YR_OBJECT`` is an
structure just like ``bar`` is? Well, you could also set the values for ``bar``
and ``qux`` like this:

.. code-block:: c

    set_string(<value>, module_object, "foo.bar");
    set_integer(<value>, module_object, "foo.baz.qux");

But what happens with arrays? How can I set the value for array items? If
you have the following declarations::

    begin_declarations;

        declare_integer_array("foo");

        begin_struct_array("bar")

            declare_string("baz");
            declare_integer_array("qux");

        end_struct_array("bar");

    end_declarations;

Then the following statements are all valid:

.. code-block:: c

    set_integer(<value>, module, "foo[0]");
    set_integer(<value>, module, "foo[%i]", 2);
    set_string(<value>, module, "bar[%i].baz", 5);
    set_string(<value>, module, "bar[0].qux[0]");
    set_string(<value>, module, "bar[0].qux[%i]", 0);
    set_string(<value>, module, "bar[%i].qux[%i]", 100, 200);

Those ``%i`` in the field descriptor are replaced by the additional
integer arguments passed to the function. This work in the same way than
``printf`` in C programs, but the only format specifiers accepted are ``%i``
and ``%s``, for integer and string arguments respectively.

The ``%s`` format specifiers is used for assigning values to a certain key
in a dictionary:

.. code-block:: c

    set_integer(<value>, module, "foo[\"key\"]");
    set_integer(<value>, module, "foo[%s]", "key");
    set_string(<value>, module, "bar[%s].baz", "another_key");

If you don't explicitely assign a value to a declared variable, array or
dictionary item it will remain in undefined state. That's not a problem at all,
and is even useful in many cases. For example, if your module parses files from
certain format and it receives one from a different format, you can safely leave
all your variables undefined instead of assigning them bogus values that doesn't
make sense. YARA will handle undefined values in rule conditions as described in
:ref:`using-modules`.

In addition to ``set_integer`` and ``set_string`` functions you have their
``get_integer`` and ``get_string`` counterparts. As the names suggest they
are used for getting the value of a variable, which can be useful in the
implementation of your functions to retrieve values previously stored by
``module_load``.


.. c:function:: int64_t get_integer(YR_OBJECT* object, const char* field, ...)

.. c:function:: char* get_string(YR_OBJECT* object, const char* field, ...)

There's also a function to the get any ``YR_OBJECT`` in the objects tree:

.. c:function:: YR_OBJECT* get_object(YR_OBJECT* object, const char* field, ...)

Here goes a little exam...

Are the following two lines equivalent? Why?

.. code-block:: c

    set_integer(1, get_object(module_object, "foo.bar"), NULL);
    set_integer(1, module_object, "foo.bar");

.. _storing-data-for-later-use:

Storing data for later use
--------------------------

Sometimes the information stored directly in your variables by means of
``set_integer`` and ``set_string`` is not enough. You may need to store more
complex data structures or information that don't need to be exposed to YARA
rules.

Storing information is essential when your module exports functions
to be used in YARA rules. The implementation of these functions usually require
to access information generated by ``module_load`` which must kept somewhere.
You may be tempted to define global variables where to put the required
information, but this would make your code non-thread-safe. The correct
approach is using the ``data`` field of the ``YR_OBJECT`` structures.

Each ``YR_OBJECT`` has a ``void* data`` field which can be safely used
by your code to store a pointer to any data you may need. A typical pattern
is using the ``data`` field of the module's ``YR_OBJECT``, like in the
following example:

.. code-block:: c

    typedef struct _MY_DATA
    {
       int some_integer;

    } MY_DATA;

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
    {
        module->data = yr_malloc(sizeof(MY_DATA));
        ((MY_DATA*) module_object->data)->some_integer = 0;

        return ERROR_SUCCESS;
    }

Don't forget to release the allocated memory in the ``module_unload`` function:

.. code-block:: cpp

    int module_unload(
        YR_OBJECT* module_object)
    {
        yr_free(module_object->data);

        return ERROR_SUCCESS;
    }

.. warning:: Don't use global variables for storing data. Functions in a
    module can be invoked from different threads at the same time and data
    corruption or misbehavior can occur.

.. _implementing-functions:

More about functions
====================

We already showed how to declare a function in
:ref:`The declaration section  <declaring-functions>`. Here we are going to
discuss how to provide an implementation for them.

Function arguments
------------------

Within the function's code you get its arguments by using
``integer_argument(n)``, ``float_argument(n)``, ``regexp_argument(n)``,
``string_argument(n)`` or ``sized_string_argument(n)`` depending on the type of
the argument, where *n* is the 1-based argument's number.

``string_argument(n)`` can be used when your function expects to receive a
NULL-terminated C string, if your function can receive arbitrary binary data
possibly containing NULL characters you must use ``sized_string_argument(n)``.

Here you have some examples:

.. code-block:: c

    int64_t arg_1 = integer_argument(1);
    RE_CODE arg_2 = regexp_argument(2);
    char* arg_3 = string_argument(3);
    SIZED_STRING* arg_4 = sized_string_argument(4);
    double arg_5 = float_argument(1);

The C type for integer arguments is ``int64_t``, for float arguments is
``double``, for regular expressions is ``RE_CODE``, for NULL-terminated strings
is ``char*`` and for string possibly contaning NULL characters is
``SIZED_STRING*``. ``SIZED_STRING`` structures have the
following attributes:

.. c:type:: SIZED_STRING

    .. c:member:: length

        String's length.

    .. c:member:: c_string

       ``char*`` pointing to the string content.

Return values
-------------

Functions can return three types of values: strings, integers and floats.
Instead of using the C *return* statement you must use ``return_string(x)``,
``return_integer(x)`` or ``return_float(x)`` to return from a function,
depending on the function's return type. In all cases *x* is a constant,
variable, or expression evaluating to ``char*``, ``int64_t`` or ``double``
respectively.

You can use ``return_string(UNDEFINED)``, ``return_float(UNDEFINED)`` and
``return_integer(UNDEFINED)`` to return undefined values from the function.
This is useful in many situations, for example if the arguments passed to the
functions don't make sense, or if your module expects a particular file format
and the scanned file is from another format, or in any other case where your
function can't a return a valid value.


.. warning:: Don't use the C *return* statement for returning from a function.
    The returned value will be interpreted as an error code.

Accessing objects
-----------------

While writing a function we sometimes need to access values previously assigned
to module's variables, or additional data stored in the ``data`` field of
``YR_OBJECT`` structures as discussed earlier in
:ref:`storing-data-for-later-use`. But for that we need a way to get access to
the corresponding ``YR_OBJECT`` first. There are two functions to do that:
``module()`` and ``parent()``. The ``module()`` function returns a pointer to
the top-level ``YR_OBJECT`` corresponding to the module, the same one passed
to the ``module_load`` function. The ``parent()`` function returns a pointer to
the ``YR_OBJECT`` corresponding to the structure where the function is
contained. For example, consider the following code snipet:

.. code-block:: c

    define_function(f1)
    {
        YR_OBJECT* module = module();
        YR_OBJECT* parent = parent();

        // parent == module;
    }

    define_function(f2)
    {
        YR_OBJECT* module = module();
        YR_OBJECT* parent = parent();

        // parent != module;
    }

    begin_declarations;

        declare_function("f1", "i", "i", f1);

        begin_struct("foo");

            declare_function("f2", "i", "i", f2);

        end_struct("foo");

    end_declarations;

In ``f1`` the ``module`` variable points to the top-level ``YR_OBJECT`` as well
as the ``parent`` variable, because the parent for ``f1`` is the module itself.
In ``f2`` however the ``parent`` variable points to the ``YR_OBJECT``
corresponding to the ``foo`` structure while ``module`` points to the top-level
``YR_OBJECT`` as before.

Scan context
------------

From within a function you can also access the ``YR_SCAN_CONTEXT`` structure
discussed earlier in :ref:`accessing-scanned-data`. This is useful for functions
which needs to inspect the file or process memory being scanned. This is how
you get a pointer to the ``YR_SCAN_CONTEXT`` structure:

.. code-block:: c

    YR_SCAN_CONTEXT* context = scan_context();







