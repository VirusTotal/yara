**********************
Using YARA from Python
**********************

YARA can be also used from Python through the ``yara-python`` library. Once
the library is built and installed as described in :ref:`compiling-yara`
you'll have access to the full potential of YARA from your Python scripts.

The first step is importing the YARA library:

.. code-block:: python

  import yara

Then you will need to compile your YARA rules before applying them to your data,
the rules can be compiled from a file path:

.. code-block:: python

  rules = yara.compile(filepath='/foo/bar/myrules')

The default argument is filepath, so you don't need to explicitly specify its
name:

.. code-block:: python

  rules = yara.compile('/foo/bar/myrules')

You can also compile your rules from a file object:

.. code-block:: python

  fh = open('/foo/bar/myrules')
  rules = yara.compile(file=fh)
  fh.close()

Or you can compile them directly from a Python string:

.. code-block:: python

  rules = yara.compile(source='rule dummy { condition: true }')

If you want to compile a group of files or strings at the same time you can do
it by using the filepaths or sources named arguments:

.. code-block:: python

  rules = yara.compile(filepaths={

    'namespace1':'/my/path/rules1',
    'namespace2':'/my/path/rules2'
  })

  rules = yara.compile(sources={

    'namespace1':'rule dummy { condition: true }',
    'namespace2':'rule dummy { condition: false }'
  })

Notice that both ``filepaths`` and ``sources`` must be dictionaries with keys
of string type. The dictionary keys are used as a namespace identifier, allowing
to differentiate between rules with the same name in different sources, as
occurs in the second example with the *dummy* name.

The ``compile`` method also have an optional boolean parameter named
``includes`` which allows you to control whether or not the include directive
should be accepted in the source files, for example:

.. code-block:: python

  rules = yara.compile('/foo/bar/my_rules', includes=False)


If the source file contains include directives the previous line would raise
an exception.

If you are using external variables in your rules you must define those
externals variables either while compiling the rules, or while applying
the rules to some file. To define your variables at the moment of
compilation you should pass the ``externals`` parameter to the ``compile``
method. For example:

.. code-block:: python

  rules = yara.compile('/foo/bar/my_rules’,
    externals= {'var1': 'some string’, 'var2': 4, 'var3': True})

The ``externals`` parameter must be a dictionary with the names of the variables
as keys and an associated value of either string, integer or boolean type.

The ``compile`` method also accepts the optional boolean argument
``error_on_warning``. This arguments tells YARA to raise an exception when a
warning is issued during compilation. Such warnings are typically issued when
your rules contains some construct that could be slowing down the scanning.
The default value for the ``error_on_warning`` argument is False.


In all cases ``compile`` returns an instance of the class :py:class:`yara.Rules`
Rules. This class have a ``save`` method that can be used to save the compiled
rules to a file:

.. code-block:: python

  rules.save('/foo/bar/my_compiled_rules')

The compiled rules can be loaded later by using the ``load`` method:

.. code-block:: python

  rules = yara.load('/foo/bar/my_compiled_rules')

Starting with YARA 3.4 both ``save`` and ``load`` accept file objects. For
example, you can save your rules to a memory buffer with this code:

.. code-block:: python

  import StringIO

  buff = StringIO.StringIO()
  rules.save(file=buff)

The saved rules can be loaded from the memory buffer:

.. code-block:: python

  buff.seek(0)
  rule = yara.load(file=buff)

The result of ``load`` is also an instance of the class :py:class:`yara.Rules`.

Instances of ``Rules`` also have a ``match`` method, which allows to apply the
rules to a file::

.. code-block:: python

  matches = rules.match('/foo/bar/my_file')

But you can also apply the rules to a Python string:

.. code-block:: python

  with open('/foo/bar/my_file', 'rb') as f:
    matches = rules.match(data=f.read())

Or to a running process:

.. code-block:: python

  matches = rules.match(pid=1234)

As in the case of ``compile``, the ``match`` method can receive definitions for
externals variables in the ``externals`` argument.

.. code-block:: python

  matches = rules.match('/foo/bar/my_file',
    externals= {'var1': 'some other string', 'var2': 100})

Externals variables defined during compile-time don’t need to be defined again
in subsequent calls to the ``match`` method. However you can redefine
any variable as needed, or provide additional definitions that weren’t provided
during compilation.

In some situations involving a very large set of rules or huge files the
``match`` method can take too much time to run. In those situations you may
find useful the ``timeout`` argument:

.. code-block:: python

  matches = rules.match('/foo/bar/my_huge_file', timeout=60)

If the ``match`` function does not finish before the specified number of
seconds elapsed, a ``TimeoutError`` exception is raised.

You can also specify a callback function when invoking ``match`` method. The
provided function will be called for every rule, no matter if matching or not.
Your callback function should expect a single parameter of dictionary type,
and should return ``CALLBACK_CONTINUE`` to proceed to the next rule or
``CALLBACK_ABORT`` to stop applying rules to your data.

Here is an example:

.. code-block:: python

  import yara

  def mycallback(data):
    print data
    yara.CALLBACK_CONTINUE

  matches = rules.match('/foo/bar/my_file', callback=mycallback)

The passed dictionary will be something like this:

.. code-block:: python

  {
    'tags': ['foo', 'bar'],
    'matches': True,
    'namespace': 'default',
    'rule': 'my_rule',
    'meta': {},
    'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
  }

The *matches* field indicates if the rules matches the data or not. The
*strings* fields is a list of matching strings, with vectors of the form::

  (<offset>, <string identifier>, <string data>)

The ``match`` method returns a list of instances of the class ``Match``.
Instances of this class have the same attributes as the dictionary passed to the
callback function.


Reference
---------

.. py:module:: yara

.. py:function:: yara.compile(...)

  Compile YARA sources.

  Either *filepath*, *source*, *file*, *filepaths* or *sources* must be
  provided. The remaining arguments are optional.

  :param str filepath: Path to the source file.
  :param str source: String containing the rules code.
  :param file-object file: Source file as a file object.
  :param dict filepaths: Dictionary where keys are namespaces and values are
    paths to source files.
  :param dict sources: Dictionary where keys are namespaces and values are
    strings containing rules code.
  :param dict externals: Dictionary with external variables. Keys are variable
    names and values are variable values.
  :param boolean includes: True if include directives are allowed or False
    otherwise. Default value: *True*.
  :param boolean error_on_warning: If true warnings are treated as errors,
    raising an exception.
  :return: Compiled rules object.
  :rtype: :py:class:`yara.Rules`
  :raises YaraSyntaxError: If a syntax error was found.
  :raises YaraError: If an error occurred.

.. py:function:: yara.load(...)

  Load compiled rules from a path or file object. Either *filepath* or
  *file* must be provided.

  :param str filepath: Path to a compiled rules file
  :param file-object file: A file object supporting the ``read`` method.
  :return: Compiled rules object.
  :rtype: :py:class:`yara.Rules`
  :raises: **YaraError**: If an error occurred while loading the file.

.. py:class:: Rules

  Instances of this class are returned by :py:func:`yara.compile`  and
  represents a set of compiled rules.

  .. py:method:: match(filepath, pid, data, externals=None, callback=None, fast=False, timeout=None, modules_data=None)

    Scan a file, process memory or data string.

    Either *filepath*, *pid* or *data* must be provided. The remaining
    arguments are optional.

    :param str filepath: Path to the file to be scanned.
    :param int pid: Process id to be scanned.
    :param str data: Data to be scanned.
    :param dict externals: Dictionary with external variables. Keys are variable
      names and values are variable values.
    :param function callback: Callback function invoked for each rule.
    :param bool fast: If true performs a fast mode scan.
    :param int timeout: Aborts the scanning when the number of specified seconds
      have elapsed.
    :param dict modules_data: Dictionary with additional data to modules. Keys
      are module names and values are *bytes* objects containing the additional
      data.
    :raises YaraTimeoutError: If the timeout was reached.
    :raises YaraError: If an error occurred during the scan.

  .. py:method:: save(...)

    Save compiled rules to a file. Either *filepath* or *file* must be provided.

    :param str filepath: Path to the file.
    :param file-object file: A file object supporting the ``write`` method.
    :raises: **YaraError**: If an error occurred while saving the file.








