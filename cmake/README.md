# Build Yara with CMake

This directory contains *CMake* files that can be used to build yara with MSVC on Windows, or Makefile on Unix based system.

## Generating

We will use shadow building to separate the temporary files from the yara source code.

### Windows
To create cmake project and build yara on _windows_:

```bash
git clone https://github.com/VirusTotal/yara
mkdir build_yara
cd build_yara
cmake -G "Visual Studio 15 2017 Win64" ..\yara\cmake
cmake --build . --config [release|debug]
```

### Linux
To create cmake project and build yara on _linux_:

```bash
git clone https://github.com/VirusTotal/yara
mkdir build_yara
cd build_yara
cmake -G "Unix Makefiles" ../yara/cmake
cmake --build . --config [release|debug]
```

## Configuring

CMake configuration files can accept some build options.

### Module

Yara could be built with optional external module, like cuckoo support, or .net assembly.
To build yara with cukoo module support, simply activate *yara_CUCKOO_MODULE* during cmake generation:

```bash
cmake -G "Visual Studio 15 2017 Win64" ..\yara\cmake -Dyara_CUCKOO_MODULE=ON
```

These modules are available from cmake generation and *not* included by default:

* yara_CUCKOO_MODULE
* yara_MAGIC_MODULE
* yara_HASH_MODULE
* yara_DOTNET_MODULE
* yara_MACHO_MODULE
* yara_DEX_MODULE

## Testing

You can call all test suite of yara directly from CMake using *ctest*:

```bash
ctest . -c [release|debug]
```

Test suite can be disable setting *yara_BUILD_TESTS* to OFF

## Installing

You can install yara where you want on your local computer, setting CMAKE_INSTALL_PREFIX during *Genearating* step:

```
cmake -G "Unix Makefiles" ../yara/cmake -DCMAKE_INSTALL_PREFIX="myFolder"
``` 

Then you can install release config with:

```
cmake --build . --config release --target install
```
