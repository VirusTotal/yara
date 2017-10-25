.. _command-line:

**********************************
Running YARA from the command-line
**********************************

In order to invoke YARA you’ll need two things: a file with the rules you want
to use (either in source code or compiled form) and the target to be scanned.
The target can be a file, a folder, or a process. ::

  yara [OPTIONS] RULES_FILE TARGET


``RULES_FILE`` can be passed directly in source code form, or can be previously
compiled with the ``yarac`` tool. You may prefer to use your rules in compiled
form if you are going to invoke YARA multiple times with the same rules. This
way you’ll save time, because for YARA it is faster to load compiled rules than
compiling the same rules over and over again.

You can also pass multiple source files to `yara` like in the following example::

  yara [OPTIONS] RULES_FILE_1 RULES_FILE_2 RULES_FILE_3 TARGET

Notice however that this only works for rules in source form. When invoking YARA
with compiled rules a single file is accepted.

In the example above all rules share the same "default" namespace, which means
that rule identifiers must be unique among all files. However you can specify a
namespace for individual files. For example ::

  yara [OPTIONS] namespace1:RULES_FILE_1 RULES_FILE_2 RULES_FILE_3 TARGET

In this case ``RULE_FILE_1`` uses ``namespace1`` while ``RULES_FILE_2`` and
``RULES_FILE_3`` share the default namespace.

In all cases rules will be applied to the target specified as the last argument
to YARA, if it’s a path to a directory all the files contained in it will be
scanned. By default YARA does not attempt to scan directories recursively, but
you can use the ``-r`` option for that.

Available options are:

.. program:: yara

.. option:: -t <tag> --tag=<tag>

  Print rules tagged as <tag> and ignore the rest.

.. option:: -i <identifier> --identifier=<identifier>

  Print rules named <identifier> and ignore the rest.

.. option:: -c --count

  Print only number of matches.

.. option:: -n

  Print not satisfied rules only (negate).

.. option:: -D --print-module-data

  Print module data.

.. option:: -g --print-tags

  Print tags.

.. option:: -m --print-meta

  Print metadata.

.. option:: -s --print-strings

  Print matching strings.

.. option:: -L --print-string-length

  Print length of matching strings.

.. option:: -e --print-namespace

  Print rules' namespace.

.. option:: -p <number> --threads=<number>

  Use the specified <number> of threads to scan a directory.

.. option:: -l <number> --max-rules=<number>

  Abort scanning after matching a number of rules.

.. option:: -a <seconds> --timeout=<seconds>

  Abort scanning after a number of seconds has elapsed.

.. option:: -k <slots> --stack-size=<slots>

  Allocate a stack size of "slots" number of slots. Default: 16384. This
  will allow you to use larger rules, albeit with more memory overhead.

  .. versionadded:: 3.5.0

.. option:: --max-strings-per-rule=<number>

  Set maximum number of strings per rule (default=10000). If a rule has more
  then the specified number of strings an error will occur.

  .. versionadded:: 3.7.0

.. option:: -d <identifier>=<value>

  Define external variable.

.. option:: -x <module>=<file>

  Pass file's content as extra data to module.

.. option:: -r --recursive

  Recursively search for directories.

.. option:: -f --fast-scan

  Fast matching mode.

.. option:: -w --no-warnings

  Disable warnings.

.. option:: --fail-on-warnings

  Treat warnings as errors. Has no effect if used with --no-warnings.

.. option:: -v --version

  Show version information.

.. option:: -h --help

  Show help.

Here you have some examples:

* Apply rule in */foo/bar/rules* to all files in the current directory.
  Subdirectories are not scanned::

    yara /foo/bar/rules  .

* Apply rules in */foo/bar/rules* to *bazfile*. Only reports rules tagged as
  *Packer* or *Compiler*::

    yara -t Packer -t Compiler /foo/bar/rules bazfile

* Scan all files in the */foo* directory and its subdirectories::

    yara -r /foo

* Defines three external variables *mybool*, *myint* and *mystring*::

    yara -d mybool=true -d myint=5 -d mystring="my string" /foo/bar/rules bazfile

* Apply rules in */foo/bar/rules* to *bazfile* while passing the content of
  *cuckoo_json_report* to the cuckoo module::

    yara -x cuckoo=cuckoo_json_report /foo/bar/rules bazfile
