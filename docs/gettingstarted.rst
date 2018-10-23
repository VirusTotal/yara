***************
Getting started
***************

YARA is a multi-platform program running on Windows, Linux and Mac OS X. You can
find the latest release at https://github.com/VirusTotal/yara/releases.

.. _compiling-yara:

Compiling and installing YARA
=============================

Download the source tarball and get prepared for compiling it::

    tar -zxf yara-3.8.1.tar.gz
    cd yara-3.8.1
    ./bootstrap.sh

Make sure you have ``automake``, ``libtool``, ``make``  and ``gcc`` installed
in your system. Ubuntu and Debian users can use::

    sudo apt-get install automake libtool make gcc

If you plan to modify YARA's source code you may also need ``flex`` and
``bison`` for generating lexers and parsers::

   sudo apt-get install flex bison

Compile and install YARA in the standard way::

    ./configure
    make
    sudo make install

Run the test cases to make sure that everything is fine::

    make check

Some of YARA's features depend on the OpenSSL library. Those features are
enabled only if you have the OpenSSL library installed in your system. If not,
YARA is going to work fine but you won't be able to use the disabled features.
The ``configure`` script will automatically detect if OpenSSL is installed or
not. If you want to enforce the OpenSSL-dependent features you must pass
``--with-crypto`` to the ``configure`` script. Ubuntu and Debian users can use
``sudo apt-get install libssl-dev`` to install the OpenSSL library.

The following modules are not compiled into YARA by default:

* cuckoo
* magic
* dotnet

If you plan to use them you must pass the corresponding ``--enable-<module
name>`` arguments to the ``configure`` script.

For example::

    ./configure --enable-cuckoo
    ./configure --enable-magic
    ./configure --enable-dotnet
    ./configure --enable-cuckoo --enable-magic --enable-dotnet

Modules usually depend on external libraries, depending on the modules you
choose to install you'll need the following libraries:

* cuckoo:
        Depends on `Jansson <http://www.digip.org/jansson/>`_ for parsing JSON.
        Some Ubuntu and Debian versions already include a package named
        ``libjansson-dev``, if ``sudo apt-get install libjansson-dev`` doesn't
        work for you then get the source code from
        `its repository <https://github.com/akheron/jansson>`_.


* magic:
        Depends on *libmagic*, a library used by the Unix standard program
        `file <http://en.wikipedia.org/wiki/File_(command)>`_.
        Ubuntu, Debian and CentOS include a package
        ``libmagic-dev``. The source code can be found
        `here <ftp://ftp.astron.com/pub/file/>`_.


Installing on Windows
---------------------

Compiled binaries for Windows in both 32 and 64 bit flavors can be found in the
link below. Just download the version you want, unzip the archive, and put the
``yara.exe`` and ``yarac.exe`` binaries anywhere in your disk.

To install the ``yara-python`` extension download and execute the installer
corresponding to the version of Python you're using.

`Download Windows binaries <https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0>`_


Installing on Mac OS X with Homebrew
------------------------------------

To install YARA using `Homebrew <https://brew.sh>`_, simply type
``brew install yara``.


Installing yara-python
----------------------

If you plan to use YARA from your Python scripts you need to install the
``yara-python`` extension. Please refer to https://github.com/VirusTotal/yara-python
for instructions on how to install it.


Running YARA for the first time
===============================

Now that you have installed YARA you can write a very simple rule and use the
command-line tool to scan some file:

.. code-block:: sh

    echo "rule dummy { condition: true }" > my_first_rule
    yara my_first_rule my_first_rule

Don't get confused by the repeated ``my_first_rule`` in the arguments to
``yara``, I'm just passing the same file as both the rules and the file to
be scanned. You can pass any file you want to be scanned (second argument).

If everything goes fine you should get the following output::

    dummy my_first_rule

Which means that the file ``my_first_rule`` is matching the rule named ``dummy``.

If you get an error like this::

    yara: error while loading shared libraries: libyara.so.2: cannot open shared
    object file: No such file or directory

It means that the loader is not finding the ``libyara`` library which is
located in ``/usr/local/lib``. In some Linux flavors the loader doesn't look for
libraries in this path by default, we must instruct it to do so by adding
``/usr/local/lib`` to the loader configuration file ``/etc/ld.so.conf``::

    sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
    sudo ldconfig
