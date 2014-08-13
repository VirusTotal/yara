.. _command-line:

**********************************
Running YARA from the command-line
**********************************

In order to invoke YARA you’ll need two things: a file with the rules you want
to use (either in source code or compiled form) and the target to be scanned.
The target can be a file, a folder, or a process. ::

  yara [OPTIONS] RULES_FILE TARGET


Rule files can be passed directly in source code form, or can be previously
compiled with the ``yarac`` tool. You may prefer to use your rules in compiled
form if you are going to invoke YARA multiple times with the same rules. This
way you’ll save time, because for YARA is faster to load compiled rules than
compiling the same rules over and over again.

The rules will be applied to the target specified as the last argument to YARA,
if it’s a path to a directory all the files contained in it will be scanned.
By default YARA does not attempt to scan directories recursively, but you can
use the ``-r`` option for that.

Available options are:

.. program:: yara

.. option:: -t <tag>

   Print rules tagged as <tag> and ignore the rest.

.. option:: -i <identifier>

   Print rules named <identifier> and ignore the rest.

.. option:: -n

   Print not satisfied rules only (negate).

.. option:: -g

   Print tags.

.. option:: -m

   Print metadata.

.. option:: -s

   Print matching strings.

.. option:: -p <number>

   Use the specified <number> of threads to scan a directory.

.. option:: -l <number>

   Abort scanning after matching a number of rules.

.. option:: -a <seconds>

   Abort scanning after a number of seconds has elapsed.

.. option:: -d <identifier>=<value>

   Define external variable.

.. option:: -x <module>=<file>

   Pass file's content as extra data to module.

.. option:: -r

   Recursively search for directories.

.. option:: -f

   Fast matching mode.

.. option:: -w

   Disable warnings.

.. option:: -v

   Show version information.

Here you have some examples:

* Apply rules on */foo/bar/rules1* and */foo/bar/rules2* to all files on current
  directory. Subdirectories are not scanned::

    yara /foo/bar/rules1 /foo/bar/rules2 .

* Apply rules on */foo/bar/rules* to *bazfile*. Only reports rules tagged as
  *Packer* or *Compiler*::

    yara -t Packer -t Compiler /foo/bar/rules bazfile

* Scan all files in the */foo* directory and its subdirectories::

    yara -r /foo

* Defines three external variables *mybool*, *myint* and *mystring*::

    yara -d mybool=true -d myint=5 -d mystring="my string" /foo/bar/rules bazfile

* Apply rules on */foo/bar/rules* to *bazfile* while passing the content of
  *cuckoo_json_report* to the cuckoo module::

    yara -x cuckoo=cuckoo_json_report /foo/bar/rules bazfile

