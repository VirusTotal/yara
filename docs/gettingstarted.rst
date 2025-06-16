***************
Getting started
***************

YARA is a multi-platform program running on Windows, Linux and Mac OS X. You can
find the latest release at https://github.com/VirusTotal/yara/releases.

.. _compiling-yara:

Compiling and installing YARA
=============================

Download the source tarball and get prepared for compiling it::

    tar -zxf yara-4.5.0.tar.gz
    cd yara-4.5.0
    ./bootstrap.sh

Make sure you have ``automake``, ``libtool``, ``make``  and ``gcc`` and ``pkg-config`` installed in your system. Ubuntu and Debian users can use::

    sudo apt-get install automake libtool make gcc pkg-config

If you plan to modify YARA's source code you may also need ``flex`` and
``bison`` for generating lexers and parsers::

   sudo apt-get install flex bison

Compile and install YARA in the standard way::

    ./bootstrap.sh
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

If you plan to use them you must pass the corresponding ``--enable-<module
name>`` arguments to the ``configure`` script.

For example::

    ./configure --enable-cuckoo
    ./configure --enable-magic
    ./configure --enable-cuckoo --enable-magic

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

Installing with vcpkg
---------------------

You can also download and install YARA using the `vcpkg <https://github.com/Microsoft/vcpkg/>`_ dependency manager::

    git clone https://github.com/microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    ./vcpkg integrate install
    vcpkg install yara

The YARA port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out
of date, please `create an issue or pull request <https://github.com/Microsoft/vcpkg/>`_ on the vcpkg repository.


Installing on Windows
---------------------

Compiled binaries for Windows in both 32 and 64 bit flavors can be found in the
link below. Just download the version you want, unzip the archive, and put the
``yara.exe`` and ``yarac.exe`` binaries anywhere in your disk.

`Download Windows binaries <https://github.com/VirusTotal/yara/releases/latest>`_

To install YARA using `Scoop <https://scoop.sh>`_ or `Chocolatey <https://chocolatey.org>`_, simply type
``scoop install yara`` or ``choco install yara``. The integration with both `Scoop` and `Chocolatey` are
not maintained their respective teams, not by the YARA authors.


Installing on Mac OS X with Homebrew
------------------------------------

To install YARA using `Homebrew <https://brew.sh>`_, simply type
``brew install yara``.


Installing ``yara-python``
----------------------

If you plan to use YARA from your Python scripts you need to install the
``yara-python`` extension. Please refer to https://github.com/VirusTotal/yara-python
for instructions on how to install it.

<<<<<<< HEAD
Building on OpenHarmony
-----------------------

Prerequisites : Preparing OpenHarmony SDK
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenHarmony provides SDKs for Linux, Windows, and macOS platforms, enabling cross-compilation across these systems. This guide focuses on Linux-based cross-compilation.

1. Download the SDK for your target platform from the `official release channel <https://gitcode.com/openharmony/docs/blob/master/en/release-notes/OpenHarmony-v5.0.1-release.md#acquiring-source-code-from-mirrors>`_.
2. Extract the SDK package::

   owner@ubuntu:$WORKSPACE_DIR$ tar -zxvf ohos-sdk-windows_linux-public.tar.tar.gz

3. Navigate to the SDK's Linux directory and extract all toolchain packages::

   owner@ubuntu:$WORKSPACE_DIR$ cd ohos_sdk/linux
   owner@ubuntu:$WORKSPACE_DIR/ohos-sdk/linux$ for i in *.zip;do unzip ${i};done
   owner@ubuntu:$WORKSPACE_DIR/ohos-sdk/linux$ ls
   total 1228400
   85988 -rw-r--r-- 1 wshi wshi  88050148 Nov 20  2024 ets-linux-x64-5.0.1.111-Release.zip          # ArkTS compiler tools
   56396 -rw-r--r-- 1 wshi wshi  57747481 Nov 20  2024 js-linux-x64-5.0.1.111-Release.zip           # JS compiler tools
   888916 -rw-r--r-- 1 wshi wshi 910243125 Nov 20  2024 native-linux-x64-5.0.1.111-Release.zip      # C/C++ cross-compilation tools
   175084 -rw-r--r-- 1 wshi wshi 179281763 Nov 20  2024 previewer-linux-x64-5.0.1.111-Release.zip   # App preview tools
   22008 -rw-r--r-- 1 wshi wshi  22533501 Nov 20  2024 toolchains-linux-x64-5.0.1.111-Release.zip   # Utilities (e.g., signing tool, device connector)

Compiling configure-Based Projects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Review configuration options::

   owner@ubuntu:$WORKSPACE_DIR/yara$ ./configure --help       # {yara} is Source code to be compiled

2. Set cross-compilation environment variables (for 64-bit ARM)::

   export OHOS_SDK=${your sdk path}/ohos-sdk/linux/   # Configure the SDK path, which should be set to the directory of your own unzipped SDK here.
   export AS=${OHOS_SDK}/native/llvm/bin/llvm-as
   export CC="${OHOS_SDK}/native/llvm/bin/clang --target=aarch64-linux-ohos"
   export CXX="${OHOS_SDK}/native/llvm/bin/clang++ --target=aarch64-linux-ohos"
   export LD=${OHOS_SDK}/native/llvm/bin/ld.lld
   export STRIP=${OHOS_SDK}/native/llvm/bin/llvm-strip
   export RANLIB=${OHOS_SDK}/native/llvm/bin/llvm-ranlib
   export OBJDUMP=${OHOS_SDK}/native/llvm/bin/llvm-objdump
   export OBJCOPY=${OHOS_SDK}/native/llvm/bin/llvm-objcopy
   export NM=${OHOS_SDK}/native/llvm/bin/llvm-nm
   export AR=${OHOS_SDK}/native/llvm/bin/llvm-ar
   export CFLAGS="-fPIC -D__MUSL__=1"      # For 32-bit: add "-march=armv7a"
   export CXXFLAGS="-fPIC -D__MUSL__=1"    # For 32-bit: add "-march=armv7a"

3. Run configure with cross-compilation parameters::

   owner@ubuntu:~/workspace/{SRC}$ ./configure --prefix=/home/owner/workspace/{SRC} --host=aarch64-linux

4. Compile and install::

   owner@ubuntu:~/workspace/{SRC}$ make
   owner@ubuntu:~/workspace/{SRC}$ make install
=======
>>>>>>> 802aa3c8e49895b7abe27486f3594afaed580dfc

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

On newer Ubuntu releases such as 22.04 LTS, the correct loader configuration is
installed via dependencies to ``/etc/ld.so.conf.d/libc.conf``. In this case, the
following command alone is sufficient to configure the dynamic linker run-time
bindings.

    sudo ldconfig

If you're using Windows PowerShell as your command shell, ``yara my_first_rule my_first_rule`` may return this error::

    my_first_rule(1): error: non-ascii character

You can avoid this by using the ``Set-Content`` cmdlet to specify ascii output when creating your rule file::

    Set-Content -path .\my_first_rule -Value "rule dummy { condition: true }" -Encoding Ascii
    .\yara my_first_rule my_first_rule
