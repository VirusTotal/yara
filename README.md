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
you'll find explained in [YARA's documentation](https://googledrive.com/host/0BznOMqZ9f3VUek8yN3VvSGdhRFU/YARA-Manual.pdf).

YARA is multi-platform, running on Windows, Linux and Mac OS X, and can be used
through its command-line interface or from your own Python scripts with the
yara-python extension.

Python users can also use [yara-ctyles](https://github.com/mjdorma/yara-ctypes)
by Michael Dorman. He has also written a multi-threaded command-line YARA
scanner based on yara-ctypes that can exploit the benefits of current multi-core
CPUs when scanning big file collections.

If you are a Ruby user you can use [yara-ruby](https://github.com/SpiderLabs/yara-ruby),
written by Eric Monti.


## What's new in YARA 2.0

YARA has experiencied an almost complete rewrite for version 2.0, as a result
this new version has the following advantages over previous ones:

* It's faster, [believe me](http://www.youtube.com/watch?v=ApAFU5ROo10), a
LOT faster. With YARA 2.0 scanning speed is from 2X to 100X faster depending
on your rules. The 100X speedup is only experienced with certain corner cases,
but if you have a large and diverse set of rules you'll definitely notice the
improvement.

* Better multi-threading support. Previous versions of YARA were thread-safe up
to a certain level. You could compile rules and scan multiple files
simultaneously, provided that each thread was using its own set of compiled
rules. In YARA 2.0 multiple threads can share the same compiled rules to scan
multiple files at the same time. The new YARA's command-line scanner takes
advance of that and is now multi-threaded, allowing to scan whole directories
blazingly fast.

* Rules can be saved to binary form. In the same way you would compile your
program's source code to create an executable file, with YARA 2.0 you can
compile your rules and save them into a binary file for later use. This way you
can use pre-compiled rules without having to parse them again, or you can share
rules with someone else without revealing the actual source code (but beware
that each time you do that God kills a kitten).

The drawsbacks for this rewrite are:

* You can find some incompatibilities in regular expressions. YARA 2.0 replaced
external libraries like PCRE or RE2 with its own regular expression engine. Most
regular expression features are present in the new implementation, but a few
ones like POSIX character classes and backreferences are missing. If you were
using RE2 instead of PCRE with previous versions of YARA you won't miss
backreferences, because RE2 don't support them neither.

* The C API provided by libyara has changed. If you're a developer using this
API you'll need to make some changes to your application in order to adapt it
to YARA 2.0. But don't worry, it won't be too much work and the benefits worth
the effort. Users of yara-python are not affected, the Python interface remains
the same.


## Who's using YARA


* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [jsunpack-n](http://jsunpack.jeek.org/)
* [We Watch Your Website](http://www.wewatchyourwebsite.com/)
* [FireEye, Inc.](http://www.fireeye.com)
* [Fidelis XPS](http://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [RSA ECAT](http://www.emc.com/security/rsa-ecat.htm)
* [CrowdStrike FMS](https://github.com/CrowdStrike/CrowdFMS)

Are you using it too? Tell me!

## Releases

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

