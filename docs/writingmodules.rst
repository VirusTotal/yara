.. _writing-modules:

************************
Writing your own modules
************************

Starting with YARA 2.2 you can extend its features by using modules. With
modules you can define data structures and functions which can be later used
from your rules to express more complex and refined conditions. You can see
some examples of what a module can do in the :ref:`using-modules` section.

The purpose of this sections is teaching you how to create your own modules to
implement that YARA feature you always dreamed of.


The "Hello World!" module
=========================

Modules are written in C and built into YARA as part of the compiling process.
In order to create your own modules you must be familiarized with the C
programming language and how to configure and build YARA from source code. You don't need to understand how YARA does its magic, YARA exposes a simple modules
API which is all you'll need to know.

The source code for your module must reside in the *libyara/modules* directory
in the source tree, in the form of a *.c* file. Its recommended to use the
module name as the file name for the source file, if your module will be named
*foo* its source file should be *foo.c*.

In the *libyara/modules* directory you'll find a *demo.c* file which we'll use
as our starting point. The file looks like this:

.. code-block:: c

    #include <yara/modules.h>

    #define MODULE_NAME demo

    begin_declarations;

      string("greeting");

    end_declarations;

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module,
        void* module_data,
        size_t module_data_size)
    {
      set_string("Hello World!", module, "greeting");
      return ERROR_SUCCESS;
    }

    int module_unload(
        YR_OBJECT* module)
    {
      return ERROR_SUCCESS;
    }

    #undef MODULE_NAME

Let's start dissecting the source code so you can understand every detail. The
first line in the code is:

.. code-block:: c

    #include <yara/modules.h>

The *modules.h* header file is where the definitions for YARA's module API
reside, therefore this include directive is required in all your modules. The second line is:

.. code-block:: c

    #define MODULE_NAME demo

This is how you define the name of your module and is also required. Every
module must define its name at the start of the source code. Module names must
be unique among the modules built into YARA.

Then follows the declaration section:

.. code-block:: c

    begin_declarations;

      string("greeting");

    end_declarations;

Here is where the module declares the functions and data structures that will
be available later for YARA your rules. In this case we are declaring just a
string variable named *greeting*. We are going to discuss more in depth about
the declaration section

Then comes the ``module_load`` function:

.. code-block:: c

    int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module,
        void* module_data,
        size_t module_data_size)
    {
      set_string("Hello World!", module, "greeting");
      return ERROR_SUCCESS;
    }


This function is invoked once for each scanned file, but only if the module is imported by some of your YARA rules with the ``import`` directive. The
``module_load`` function is where your module has the opportunity to inspect
the file being scanned, parse it or analize it the way it may prefer, and then
populate the data structures defined in the declarations section.

In this example the ``module_load`` function doesn't inspect the file content
at all, it just assign the string "Hello World!" to the variable *greeting*
declared before.

And finally we have the ``module_unload`` function:

.. code-block:: c

    int module_unload(
        YR_OBJECT* module)
    {
      return ERROR_SUCCESS;
    }

For each call to ``module_load`` there is a corresponding call to
``module_unload``. This function allows your module to free any resource
allocated during ``module_load``. There's nothing to free in this case, so
the function just returns ``ERROR_SUCCESS``. Both ``module_load`` and
``module_unload`` should return ``ERROR_SUCCESS`` to indicate that everything
went fine. If a different value is returned the scanning will be aborted and the
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


Just add a line for your module::

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

Within the declaration section you can use ``string(<variable name>)`` and
``integer(<variable name>)`` to declare string or integer variables
respectively. For example::

    begin_declarations;

        integer("foo");
        string("bar");

    end_declarations;

Variable names can't contain characters other than letters, numbers and
underscores. These variables can be used later in your rules at any place where
an integer or string is expected. Supposing your module name is "mymodule", they
can be used like this::

    mymodule.foo > 5

    mymodule.bar matches /someregexp/


Structures
----------

Your declarations can be organized in a more structured way by using ::

    begin_declarations;

        integer("foo");
        string("bar");

        begin_struct("some_structure");

            integer("foo");

            begin_struct("nested_structure");

                integer("bar");

            end_struct("nested_structure");

        end_struct("some_structure");

        begin_struct("another_structure");

            integer("foo");
            string("bar");
            string("baz")

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

In the same way you declare individual strings, integers or structures, you can
declare arrays of them::

    begin_declarations;

        integer_array("foo");
        string_array("bar");

        begin_struct_array("struct_array");

            integer("baz");
            string("qux");

        end_struct_array("struct_array");

    end_declarations;


Functions
=========

One of the more powerful features of YARA modules is the possibility of
declaring functions that can be later invoked from your rules. Functions
must appear in the declaration section in this way::

    function(<function name>, <argument types>, <return tuype>, <C function>);

*<function name>* is the name that will be used in your YARA rules to invoke
the function.

*<argument types>* is a string containing one character per
function argument, where the character indicates the type of the argument.
Functions can receive three different types of arguments: string, integer and
regular expression, denoted by characters: *s*, *i* and *r*
respectively. If your function receives two integers *<argument types>* must be
*"ii"*, if it receives an integer as the first argument and a string as the
second one *<argument types>* must be *"is"*, if it receives three strings
*<argument types>* must be "*sss*".

*<return type>* is a string with a single character indicating the return type.
Possible return types are string (*"s"*) and integer (*"i"*).

*<C function>* is the identifier for the actual implementation of your function.

Here you have a full example:

.. code-block:: c

    define_function(sum)
    {
      int64_t a = integer_argument(1);
      int64_t b = integer_argument(2);

      if (a == UNDEFINED || b == UNDEFINED)
        return_integer(UNDEFINED);

      return_integer(a + b);
    }

    begin_declarations;

        function("sum", "ii", "i", sum);

    end_declarations;

As you can see in the example above, your function code must be defined as::

    define_function(<function identifier>)
    {
      ...your code here
    }

Function arguments
------------------

Within the function's code you get its arguments by using
``integer_argument(n)``, ``string_argument(n)`` or ``regexp_argument(n)``
depending on the type of the argument, and where *n* is the 1-based argument's
number.

If your function receives a string, a regular expression and an integer in that
order, you can get their values with:

.. code-block:: c

    char* arg_1 = string_argument(1);
    re_code_t arg_2 = regexp_argument(2);
    int64_t arg_3 = integer_argument(3);


Notice that the C type for integer arguments is ``int64_t`` and for regular
expressions is ``re_code_t``.

Return values
-------------

Functions can return two types of values: strings and integers. Instead of
using the C *return* statement you must use ``return_string(x)`` or ``return_integer(x)`` to return from a function, depending on the function's
return type. In both cases *x* is a constant, variable, or expression
evaluating to ``char*`` or ``int64_t`` respectively.

You can use ``return_string(UNDEFINED)`` and ``return_integer(UNDEFINED)`` to
return undefined values from the function. This is useful in many situations,
for example if the arguments passed to the functions don't make sense, or if
your module expects a particular file format and the scanned file is from
another format, or in any other case where your function can't a return a valid
value.


.. warning:: Don't use the C *return* statement for returning from a function.
    The returned value will be interpreted as an error code.


