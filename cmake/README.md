# Build YARA with CMake

This directory contains *CMake* files that can be used to build YARA with MSVC on Windows, or Makefile on Unix-based systems.

## Generating

We will use shadow building to separate the temporary files from the YARA source code.

### Windows
To generate a Visual Studio project and build YARA on _Windows_:

```bash
git clone https://github.com/VirusTotal/yara
mkdir build_yara
cd build_yara
cmake -G "Visual Studio 15 2017 Win64" ..\yara\cmake
cmake --build . --config [release|debug]
```

### Linux
To create a Makefile and build YARA on _Linux_:

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

YARA can be built with optional external module, like cuckoo support, or .NET assembly.
To build YARA with cukoo module support, simply activate `yara_CUCKOO_MODULE` during the CMake generation step:

```bash
cmake -G "Visual Studio 15 2017 Win64" ..\yara\cmake -Dyara_CUCKOO_MODULE=ON
```

These modules are available from CMake generation and are *not* enabled by default:

* `yara_CUCKOO_MODULE`
* `yara_MAGIC_MODULE`
* `yara_HASH_MODULE`
* `yara_DOTNET_MODULE`
* `yara_MACHO_MODULE`
* `yara_DEX_MODULE`

## Testing

You can call the YARA test suite directly from CMake using `ctest`:

```bash
ctest . -c [release|debug]
```

The test suite can be disabled by setting the `yara_BUILD_TESTS` variable to `OFF`

## Installing

You can install YARA where you want on your local computer by setting `CMAKE_INSTALL_PREFIX` during the *generation* step:

```
cmake -G "Unix Makefiles" ../yara/cmake -DCMAKE_INSTALL_PREFIX="myFolder"
``` 

Then you can install the release config with:

```
cmake --build . --config release --target install
```


