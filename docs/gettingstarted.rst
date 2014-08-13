***************
Getting started
***************

YARA is a multi-platform program running on Windows, Linux and Mac OS X. You can
find the latest release at https://github.com/plusvic/yara/releases.

.. _compiling-yara:

Compiling and installing YARA
=============================

Download the source tarball and get prepared for compiling it::

    tar -zxf yara-3.0.0.tar.gz
    cd yara-3.0.0
    ./bootstrap.sh

YARA uses GNU autotools, so it's compiled and installed in the standard
way::

    ./configure
    make
    sudo make install


The Cuckoo module is not compiled into YARA by default, if you plan to
use the Cuckoo module you must pass the ``--enable-cuckoo`` argument to the
``configure`` script. The Cuckoo module depends on the
`Jansson library <http://www.digip.org/jansson///>`_, you'll need to install it
beforehand. Some Debian and Ubuntu versions already include a package named
``libjansson-dev``, if ``sudo apt-get install libjansson-dev`` doesn't work for
you then get the source code from
`its repository <https://github.com/akheron/jansson>`_.

To build and install the ``yara-python`` extension::

    cd yara-python
    python setup.py build
    sudo setup.py install

.. note:: You may need to install the Python development package (usually
    ``python-dev``) before compiling ``yara-python``. Additionally,
    ``yara-python`` depends on the ``libyara`` library which gets installed
    with YARA, so don't proceed to build ``yara-python`` without previously installing YARA as described above.

Running YARA for the first time
===============================

Now that you have installed YARA you can write a very simple rule and use the
command-line tool to scan some file::

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
libraries in this path by default, we must instruct him to do so by adding
``/usr/local/lib`` to the loader configuration file ``/etc/ld.so.conf``::

    sudo echo "/usr/local/lib" >> /etc/ld.so.conf
    sudo ldconfig




