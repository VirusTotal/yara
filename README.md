## YARA in a nutshell

YARA is a tool aimed at helping malware researchers to identify and classify
malware samples. With YARA you can create descriptions of malware families based
on textual or binary patterns contained on samples of those families. Each
description consists of a set of strings and a boolean expression which
determines its logic. Let's see an example:

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

The rule above is telling YARA that any file containing one of the three strings
must be reported as *silent_banker*. This is just a simple example, more complex
and powerful rules can be created by using wild-cards, case-insensitive strings,
regular expressions, special operators and many other features that you'll find
explained in [YARA's documentation](http://yara-project.googlecode.com/files/YARA%20User%27s%20Manual%201.6.pdf).

YARA is multi-platform, running on Windows, Linux and Mac OS X, and can be used
through its command-line interface or from your own Python scripts with the
yara-python extension.

Python users can also use [yara-ctyles](https://github.com/mjdorma/yara-ctypes)
by Michael Dorman. He has also written a multi-threaded command-line YARA
scanner based on yara-ctypes that can exploit the benefits of current multi-core
CPUs when scanning big file collections.

If you are a Ruby user you can use [yara-ruby](https://github.com/SpiderLabs/yara-ruby),
written by Eric Monti.


## Who's using YARA

* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [jsunpack-n](http://jsunpack.jeek.org/)
* [We Watch Your Website](http://www.wewatchyourwebsite.com/)
* [FireEye, Inc.](http://www.fireeye.com)
* [Fidelis XPS](http://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [RSA ECAT](http://www.emc.com/security/rsa-ecat.htm)

## Releases

### 1.7.2 (02/12/2013)

* BUGFIX: Regular expressions marked as both "wide" and "ascii" were treated as
just "wide"
* BUGFIX: Bug in "n of (<string_set>)" operator
* BUGFIX: Bug in get_process_memory could cause infinite loop

### 1.7.1 (25/11/2013)

* BUGFIX: Fix SIGABORT in ARM
* BUGFIX: Failing to detect one-byte strings at the end of a file.
* BUGFIX: Strings being incorrectly printed when markes both as wide and ascii
* BUGFIX: Stack overflow while following circular symlinks
* BUGFIX: Expression "/re/ matches var" always matching if "var" was an empty
string
* BUGFIX: Strings marked as "fullword" were incorrectly matching in some cases

### 1.7 (29/03/2013)
* faster compilation
* added suport for modulus (%) and bitwise xor (|) operators
* better hashing of regular expressions
* BUGFIX: yara-python segfault when using dir() on Rules and Match classes
* BUGFIX: Integer overflow causing infinite loop
* BUGFIX: Handling strings containing \x00 characters correctly
* BUGFIX: Regular expressions not matching at the end of the file when compiled
with RE2
* BUGFIX: Memory leaks
* BUGFIX: File handle leaks

### 1.6 (04/08/2011)
* added support for bitwise operators
* added support for multi-line hex strings
* scan speed improvement for regular expressions (with PCRE)
* yara-python ported to Python 3.x
* yara-python support for 64-bits Python under Windows
* BUGFIX: Buffer overflow in error printing

### 1.5 (22/03/2011)
* added -l parameter to abort scanning after a number of matches
* added support for scanning processes memory
* entrypoint now works with ELF as well as PE files
* added support for linking with the faster RE2 library
(http://code.google.com/p/re2/) instead of PCRE
* implemented index operator to access offsets where string was found
* implemented new operator
"for < quantifier > < variable > in < set or range > : (< expression >) "
* BUGFIX: Memory leaks in yara-python
* BUGFIX: yara.compile namespaces not working with filesources

### 1.4 (13/05/2010)
* added external variables
* scan speed improvements
* added fast scan mode
* BUGFIX: crash in 64-bits Windows

### 1.3 (26/10/2009)
* added a C-like "include" directive
* added support for multi-sources compilation in yara-python
* added support for metadata declaration in rules
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
* added support for global rules
* added support for declaring alternative sub-strings in hex strings
* added support for anonymous strings
* added support for intXX and uintXX functions
* operator "of" was enhanced
* implemented new operator "for..of"
* "widechar" is now "wide" and can be used in conjuntion with "ascii"
* improved syntax error reporting in yara-python
* "compile" method in yara-python was enhanced
* "matchfile" method in yara-python was substituted by "match"
* some performance improvements
* BUGFIX: Wrong behavior of escaped characters in regular expressions
* BUGFIX: Fatal error in yara-python when invoking matchfile with invalid path
twice
* BUGFIX: Wrong precedence of OR and AND operators
* BUGFIX: Access violation when scanning MZ files with e_lfanew == -1
* BUGFIX: Incorrect handling of hex strings in lexer

### 1.1 (05/01/2009)
* added support for strings containing null (\x00) chars
* added syntactic construct "x of them"
* regular expressions syntax changed
* now regular expressions can begin with any character

### 1.0 (24/09/2008)
* first release




