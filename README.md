## YARA in a nutshell

YARA is a tool aimed at (but not limited to) helping malware researchers to
identify and classify malware samples. With YARA you can create descriptions of
malware families (or whatever you want to describe) based on textual or binary
patterns. Each description, a.k.a rule, consists of a set of strings and a
boolean expression which determine its logic. Let's see an example:

```
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
```

The above rule is telling YARA that any file containing one of the three strings
must be reported as *silent_banker*. This is just a simple example, more
complex and powerful rules can be created by using wild-cards, case-insensitive
strings, regular expressions, special operators and many other features that
you'll find explained in [YARA's documentation](http://yara.readthedocs.org/).

YARA is multi-platform, running on Windows, Linux and Mac OS X, and can be used
through its command-line interface or from your own Python scripts with the
yara-python extension.

## What's new in YARA 3.0

YARA 3.0 introduces a new concept that will skyrocket its potential: extension
modules. With extension modules you can implement new features for YARA in a
simple and easy way. Modules can be used for dissecting file formats and then
creating YARA rules based on features of the format, for implenting new
functions that you can invoke later from your rules, and for much more!

You can get a grasp of what modules can do by looking at the documentation of
the two modules included in this release, the
[Cuckoo module](http://yara.readthedocs.org/en/latest/modules.html#cuckoo-module)
and the [PE module](http://yara.readthedocs.org/en/latest/modules.html#pe-module).

More details about how to implement your own modules can be found in the
[new documentation](http://yara.readthedocs.org/).

If you want to contribute with ideas or code for new YARA modules, don't
hesitate! Share your thoughts!

## Who's using YARA

* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [jsunpack-n](http://jsunpack.jeek.org/)
* [We Watch Your Website](http://www.wewatchyourwebsite.com/)
* [FireEye, Inc.](http://www.fireeye.com)
* [Fidelis XPS](http://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [RSA ECAT](http://www.emc.com/security/rsa-ecat.htm)
* [CrowdStrike FMS](https://github.com/CrowdStrike/CrowdFMS)
* [ThreatConnect](http://www.threatconnect.com)
* [YALIH](https://github.com/Masood-M/YALIH)
* [Bayshore Networks, Inc.](http://www.bayshorenetworks.com)
* [ThreatStream, Inc.](http://threatstream.com)
* [Fox-IT](https://www.fox-it.com)
* [Lastline, Inc.](http://www.lastline.com)
* [Blue Coat](http://www.bluecoat.com/products/malware-analysis-appliance)
* [Blueliv](http://www.blueliv.com)
* [Adlice](http://www.adlice.com/)

Are you using it? Want to see your site listed here?

## Releases

### 3.0.0 (13/08/2014)

* Support for modules
* PE module
* Cuckoo module
* Some improvements in the C API
* More comprehensive documentation
* BUGFIX: Start anchor (^) not working properly with the "matches" operator
* BUGFIX: False negative with certain regular expressions
* BUGFIX: Improper handling of nested includes with relative pathes
* BUGFIX: \s character class not recognizing \n, \r, \v and \f as spaces
* BUGFIX: YARA for Win64 scanning only the first 4GB of files.
* BUGFIX: Segmentation fault when using nested loops
* BUGFIX: Segmentation fault caused by invalid characters in regular expressions
* BUGFIX: Segmentation fault while scanning some processes in Windows
* BUGFIX: Segmentation fault caused by regexp code spanning over non-contiguous
memory pages


### 2.1.0 (03/03/2014)

* Improve regexp engine
* Improve multithreading support
* Case-insensitive and single-line matching modes for "matches" operator's regexps
* Added "error_on_warning" argument to "match" in yara-python
* Recognize x64 PE files
* BUGFIX: Mutex handle leak
* BUGFIX: NULL pointer dereferences
* BUGFIX: Buffer overflow
* BUGFIX: Crash while using compiled rules with yara64 in Windows
* BUGFIX: Infinite loop while scanning 64bits process in Windows
* BUGFIX: Side-effect on "externals" argument in yara-python's "match" function
* BUGFIX: "x of them" not working with strings containing unbounded jumps

### 2.0.0 (26/12/2013)
* Faster matching algorithm
* Command-line scanner is now multi-threaded
* Compiled rules can be saved to and loaded from a file
* Added support for unbounded jumps
* New libyara API

### 1.7.2 (02/12/2013)
* BUGFIX: Regular expressions marked as both "wide" and "ascii" were treated as
just "wide"
* BUGFIX: Bug in "n of (<string_set>)" operator
* BUGFIX: Bug in get_process_memory could cause infinite loop

### 1.7.1 (25/11/2013)
* BUGFIX: Fix SIGABORT in ARM
* BUGFIX: Failing to detect one-byte strings at the end of a file.
* BUGFIX: Strings being incorrectly printed when marked both as wide and ascii
* BUGFIX: Stack overflow while following circular symlinks
* BUGFIX: Expression "/re/ matches var" always matching if "var" was an empty
string
* BUGFIX: Strings marked as "fullword" were incorrectly matching in some cases.

### 1.7 (29/03/2013)
* Faster compilation
* Added suport for modulus (%) and bitwise xor (|) operators
* Better hashing of regular expressions
* BUGFIX: yara-python segfault when using dir() on Rules and Match classes
* BUGFIX: Integer overflow causing infinite loop
* BUGFIX: Handling strings containing \x00 characters correctly
* BUGFIX: Regular expressions not matching at the end of the file when compiled
with RE2
* BUGFIX: Memory leaks
* BUGFIX: File handle leaks

### 1.6 (04/08/2011)
* Added support for bitwise operators
* Added support for multi-line hex strings
* Scan speed improvement for regular expressions (with PCRE)
* yara-python ported to Python 3.x
* yara-python support for 64-bits Python under Windows
* BUGFIX: Buffer overflow in error printing

### 1.5 (22/03/2011)
* Added -l parameter to abort scanning after a number of matches
* Added support for scanning processes memory
* Entrypoint now works with ELF as well as PE files
* Added support for linking with the faster RE2 library
(http://code.google.com/p/re2/) instead of PCRE
* Implemented index operator to access offsets where string was found
* Implemented new operator
"for < quantifier > < variable > in < set or range > : (< expression >) "
* BUGFIX: Memory leaks in yara-python
* BUGFIX: yara.compile namespaces not working with filesources

### 1.4 (13/05/2010)
* Added external variables
* Scan speed improvements
* Added fast scan mode
* BUGFIX: crash in 64-bits Windows

### 1.3 (26/10/2009)
* Added a C-like "include" directive
* Added support for multi-sources compilation in yara-python
* Added support for metadata declaration in rules
* BUGFIX: Incorrect handling of single-line comments at the end of the file
* BUGFIX: Integer underflow when scanning files of size <= 2 bytes

### 1.2.1 (14/04/2009)
* libyara: added support for compiling rules directly from memory
* libyara: interface refactored
* libyara: is thread-safe now
* BUGFIX: Invoking pcre_compile with non-terminated string
* BUGFIX: Underscore not recognized in string identifiers
* BUGFIX: Memory leak
* BUGFIX: Access violation on xxcompare functions

### 1.2 (13/01/2009)
* Added support for global rules
* Added support for declaring alternative sub-strings in hex strings
* Added support for anonymous strings
* Added support for intXX and uintXX functions
* Operator "of" was enhanced
* Implemented new operator "for..of"
* "widechar" is now "wide" and can be used in conjuntion with "ascii"
* Improved syntax error reporting in yara-python
* "compile" method in yara-python was enhanced
* "matchfile" method in yara-python was substituted by "match"
* Some performance improvements
* BUGFIX: Wrong behavior of escaped characters in regular expressions
* BUGFIX: Fatal error in yara-python when invoking matchfile with invalid path
twice
* BUGFIX: Wrong precedence of OR and AND operators
* BUGFIX: Access violation when scanning MZ files with e_lfanew == -1
* BUGFIX: Incorrect handling of hex strings in lexer

### 1.1 (05/01/2009)
* Added support for strings containing null (\x00) chars
* Added syntactic construct "x of them"
* Regular expressions syntax changed
* Now regular expressions can begin with any character

### 1.0 (24/09/2008)
* First release

