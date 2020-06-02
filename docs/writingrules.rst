*******************
Writing YARA rules
*******************

YARA rules are easy to write and understand, and they have a syntax that
resembles the C language. Here is the simplest rule that you can write for
YARA, which does absolutely nothing:

.. code-block:: yara

    rule dummy
    {
        condition:
            false
    }

Each rule in YARA starts with the keyword ``rule`` followed by a rule
identifier. Identifiers must follow the same lexical conventions of the C
programming language, they can contain any alphanumeric character and the
underscore character, but the first character cannot be a digit. Rule
identifiers are case sensitive and cannot exceed 128 characters. The following
keywords are reserved and cannot be used as an identifier:


.. list-table:: YARA keywords
   :widths: 10 10 10 10 10 10 10 10

   * - all
     - and
     - any
     - ascii
     - at
     - base64
     - base64wide
     - condition
   * - contains
     - entrypoint
     - false
     - filesize
     - for
     - fullword
     - global
     - import
   * - in
     - include
     - int16
     - int16be
     - int32
     - int32be
     - int8
     - int8be
   * - matches
     - meta
     - nocase
     - not
     - of
     - or
     - private
     - rule
   * - strings
     - them
     - true
     - uint16
     - uint16be
     - uint32
     - uint32be
     - uint8
   * - uint8be
     - wide
     - xor
     -
     -
     -
     -
     -

Rules are generally composed of two sections: strings definition and condition.
The strings definition section can be omitted if the rule doesn't rely on any
string, but the condition section is always required. The strings definition
section is where the strings that will be part of the rule are defined. Each
string has an identifier consisting of a $ character followed by a sequence of
alphanumeric characters and underscores, these identifiers can be used in the
condition section to refer to the corresponding string. Strings can be defined
in text or hexadecimal form, as shown in the following example:

.. code-block:: yara

    rule ExampleRule
    {
        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
    }

Text strings are enclosed in double quotes just like in the C language. Hex
strings are enclosed by curly brackets, and they are composed by a sequence of
hexadecimal numbers that can appear contiguously or separated by spaces. Decimal
numbers are not allowed in hex strings.

The condition section is where the logic of the rule resides. This section must
contain a boolean expression telling under which circumstances a file or process
satisfies the rule or not. Generally, the condition will refer to previously
defined strings by using their identifiers. In this context the string
identifier acts as a boolean variable which evaluate to true if the string was
found in the file or process memory, or false if otherwise.

Comments
========

You can add comments to your YARA rules just as if it was a C source file, both
single-line and multi-line C-style comments are supported.

.. code-block:: yara

    /*
        This is a multi-line comment ...
    */

    rule CommentExample   // ... and this is single-line comment
    {
        condition:
            false  // just a dummy rule, don't do this
    }

Strings
=======

There are three types of strings in YARA: hexadecimal strings, text strings and
regular expressions. Hexadecimal strings are used for defining raw sequences of
bytes, while text strings and regular expressions are useful for defining
portions of legible text. However text strings and regular expressions can be
also used for representing raw bytes by mean of escape sequences as will be
shown below.

Hexadecimal strings
-------------------

Hexadecimal strings allow three special constructions that make them more
flexible: wild-cards, jumps, and alternatives. Wild-cards are just placeholders
that you can put into the string indicating that some bytes are unknown and they
should match anything. The placeholder character is the question mark (?). Here
you have an example of a hexadecimal string with wild-cards:

.. code-block:: yara

    rule WildcardExample
    {
        strings:
            $hex_string = { E2 34 ?? C8 A? FB }

        condition:
            $hex_string
    }

As shown in the example the wild-cards are nibble-wise, which means that you can
define just one nibble of the byte and leave the other unknown.

Wild-cards are useful when defining strings whose content can vary but you know
the length of the variable chunks, however, this is not always the case. In some
circumstances you may need to define strings with chunks of variable content and
length. In those situations you can use jumps instead of wild-cards:

.. code-block:: yara

    rule JumpExample
    {
        strings:
            $hex_string = { F4 23 [4-6] 62 B4 }

        condition:
            $hex_string
    }

In the example above we have a pair of numbers enclosed in square brackets and
separated by a hyphen, that's a jump. This jump is indicating that any arbitrary
sequence from 4 to 6 bytes can occupy the position of the jump. Any of the
following strings will match the pattern::

    F4 23 01 02 03 04 62 B4
    F4 23 00 00 00 00 00 62 B4
    F4 23 15 82 A3 04 45 22 62 B4

Any jump [X-Y] must meet the condition 0 <= X <= Y. In previous versions of
YARA both X and Y must be lower than 256, but starting with YARA 2.0 there is
no limit for X and Y.

These are valid jumps::

    FE 39 45 [0-8] 89 00
    FE 39 45 [23-45] 89 00
    FE 39 45 [1000-2000] 89 00

This is invalid::

    FE 39 45 [10-7] 89 00

If the lower and higher bounds are equal you can write a single number enclosed
in brackets, like this::

    FE 39 45 [6] 89 00

The above string is equivalent to both of these::

    FE 39 45 [6-6] 89 00
    FE 39 45 ?? ?? ?? ?? ?? ?? 89 00

Starting with YARA 2.0 you can also use unbounded jumps::

    FE 39 45 [10-] 89 00
    FE 39 45 [-] 89 00

The first one means ``[10-infinite]``, the second one means ``[0-infinite]``.

There are also situations in which you may want to provide different
alternatives for a given fragment of your hex string. In those situations you
can use a syntax which resembles a regular expression:

.. code-block:: yara

    rule AlternativesExample1
    {
        strings:
            $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

        condition:
            $hex_string
    }

This rule will match any file containing ``F42362B445`` or ``F4235645``.

But more than two alternatives can be also expressed. In fact, there are no
limits to the amount of alternative sequences you can provide, and neither to
their lengths.

.. code-block:: yara

    rule AlternativesExample2
    {
        strings:
            $hex_string = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }

        condition:
            $hex_string
    }

As can be seen also in the above example, strings containing wild-cards are
allowed as part of alternative sequences.

Text strings
------------

As shown in previous sections, text strings are generally defined like this:

.. code-block:: yara

    rule TextExample
    {
        strings:
            $text_string = "foobar"

        condition:
            $text_string
    }

This is the simplest case: an ASCII-encoded, case-sensitive string. However,
text strings can be accompanied by some useful modifiers that alter the way in
which the string will be interpreted. Those modifiers are appended at the end of
the string definition separated by spaces, as will be discussed below.

Text strings can also contain the following subset of the escape sequences
available in the C language:

.. list-table::
   :widths: 3 10

   * - ``\"``
     - Double quote
   * - ``\\``
     - Backslash
   * - ``\t``
     - Horizontal tab
   * - ``\n``
     - New line
   * - ``\xdd``
     - Any byte in hexadecimal notation

Case-insensitive strings
^^^^^^^^^^^^^^^^^^^^^^^^

Text strings in YARA are case-sensitive by default, however you can turn your
string into case-insensitive mode by appending the modifier nocase at the end
of the string definition, in the same line:

.. code-block:: yara

    rule CaseInsensitiveTextExample
    {
        strings:
            $text_string = "foobar" nocase

        condition:
            $text_string
    }

With the ``nocase`` modifier the string *foobar* will match *Foobar*, *FOOBAR*,
and *fOoBaR*. This modifier can be used in conjunction with any modifier,
except ``base64`` and ``base64wide``.

Wide-character strings
^^^^^^^^^^^^^^^^^^^^^^

The ``wide`` modifier can be used to search for strings encoded with two bytes
per character, something typical in many executable binaries.



For example, if the string "Borland" appears encoded as two bytes per
character (i.e. ``B\x00o\x00r\x00l\x00a\x00n\x00d\x00``), then the following rule will match:

.. code-block:: yara

    rule WideCharTextExample1
    {
        strings:
            $wide_string = "Borland" wide

        condition:
            $wide_string
    }

However, keep in mind that this modifier just interleaves the ASCII codes of
the characters in the string with zeroes, it does not support truly UTF-16
strings containing non-English characters. If you want to search for strings
in both ASCII and wide form, you can use the ``ascii`` modifier in conjunction
with ``wide`` , no matter the order in which they appear.

.. code-block:: yara

    rule WideCharTextExample2
    {
        strings:
            $wide_and_ascii_string = "Borland" wide ascii

        condition:
            $wide_and_ascii_string
    }

The ``ascii`` modifier can appear alone, without an accompanying ``wide``
modifier, but it's not necessary to write it because in absence of ``wide`` the
string is assumed to be ASCII by default.

XOR strings
^^^^^^^^^^^

The ``xor`` modifier can be used to search for strings with a single byte XOR
applied to them.

The following rule will search for every single byte XOR applied to the string
"This program cannot" (including the plaintext string):

.. code-block:: yara

    rule XorExample1
    {
        strings:
            $xor_string = "This program cannot" xor

        condition:
            $xor_string
    }

The above rule is logically equivalent to:

.. code-block:: yara

    rule XorExample2
    {
        strings:
            $xor_string_00 = "This program cannot"
            $xor_string_01 = "Uihr!qsnfs`l!b`oonu"
            $xor_string_02 = "Vjkq\"rpmepco\"acllmv"
            // Repeat for every single byte XOR
        condition:
            any of them
    }

You can also combine the ``xor`` modifier with ``wide`` and ``ascii``
modifiers. For example, to search for the ``wide`` and ``ascii`` versions of a
string after every single byte XOR has been applied you would use:

.. code-block:: yara

    rule XorExample3
    {
        strings:
            $xor_string = "This program cannot" xor wide ascii
        condition:
            $xor_string
    }

The ``xor`` modifier is applied after every other modifier. This means that
using the ``xor`` and ``wide`` together results in the XOR applying to the
interleaved zero bytes. For example, the following two rules are logically
equivalent:

.. code-block:: yara

    rule XorExample4
    {
        strings:
            $xor_string = "This program cannot" xor wide
        condition:
            $xor_string
    }

    rule XorExample4
    {
        strings:
            $xor_string_00 = "T\x00h\x00i\x00s\x00 \x00p\x00r\x00o\x00g\x00r\x00a\x00m\x00 \x00c\x00a\x00n\x00n\x00o\x00t\x00"
            $xor_string_01 = "U\x01i\x01h\x01r\x01!\x01q\x01s\x01n\x01f\x01s\x01`\x01l\x01!\x01b\x01`\x01o\x01o\x01n\x01u\x01"
            $xor_string_02 = "V\x02j\x02k\x02q\x02\"\x02r\x02p\x02m\x02e\x02p\x02c\x02o\x02\"\x02a\x02c\x02l\x02l\x02m\x02v\x02"
            // Repeat for every single byte XOR operation.
        condition:
            any of them
    }

Since YARA 3.11, if you want more control over the range of bytes used with the ``xor`` modifier use:

.. code-block:: yara

    rule XorExample5
    {
        strings:
            $xor_string = "This program cannot" xor(0x01-0xff)
        condition:
            $xor_string
    }

The above example will apply the bytes from 0x01 to 0xff, inclusively, to the
string when searching. The general syntax is ``xor(minimum-maximum)``.

Base64 strings
^^^^^^^^^^^^^^

The ``base64`` modifier can be used to search for strings that have been base64
encoded. A good explanation of the technique is at:

https://www.leeholmes.com/blog/2019/12/10/searching-for-content-in-base-64-strings-2/

The following rule will search for the three base64 permutations of the string
"This program cannot":

.. code-block:: yara

    rule Base64Example1
    {
        strings:
            $a = "This program cannot" base64

        condition:
            $a
    }

This will cause YARA to search for these three permutations:

| VGhpcyBwcm9ncmFtIGNhbm5vd
| RoaXMgcHJvZ3JhbSBjYW5ub3
| UaGlzIHByb2dyYW0gY2Fubm90

The ``base64wide`` modifier works just like the ``base64`` modifier but the results
of the ``base64`` modifier are converted to wide.

The interaction between ``base64`` (or ``base64wide``) and ``wide`` and
``ascii`` is as you might expect. ``wide`` and ``ascii`` are applied to the
string first, and then the ``base64`` and ``base64wide`` modifiers are applied.
At no point is the plaintext of the ``ascii`` or ``wide`` versions of the
strings included in the search. If you want to also include those you can put
them in a secondary string.

The ``base64`` and ``base64wide`` modifiers also support a custom alphabet. For
example:

.. code-block:: yara

    rule Base64Example2
    {
        strings:
            $a = "This program cannot" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")

        condition:
            $a
    }

The alphabet must be 64 bytes long.

The ``base64`` and ``base64wide`` modifiers are only supported with text
strings. Using these modifiers with a hexadecimal string or a regular expression
will cause a compiler error. Also, the ``xor``, ``fullword``, and ``nocase``
modifiers used in combination with ``base64`` or ``base64wide`` will cause
a compiler error.

Because of the way that YARA strips the leading and trailing characters after
base64 encoding, one of the base64 encodings of "Dhis program cannow" and
"This program cannot" are identical. Similarly, using the ``base64`` keyword on
single ASCII characters is not recommended. For example, "a" with the
``base64`` keyword matches "\`", "b", "c", "!", "\\xA1", or "\\xE1" after base64
encoding, and will not match where the base64 encoding matches the
``[GWm2][EFGH]`` regular expression.

Searching for full words
^^^^^^^^^^^^^^^^^^^^^^^^

Another modifier that can be applied to text strings is ``fullword``. This
modifier guarantees that the string will match only if it appears in the file
delimited by non-alphanumeric characters. For example the string *domain*, if
defined as ``fullword``, doesn't match *www.mydomain.com* but it matches
*www.my-domain.com* and *www.domain.com*.

Regular expressions
-------------------

Regular expressions are one of the most powerful features of YARA. They are
defined in the same way as text strings, but enclosed in forward slashes instead
of double-quotes, like in the Perl programming language.

.. code-block:: yara

    rule RegExpExample1
    {
        strings:
            $re1 = /md5: [0-9a-fA-F]{32}/
            $re2 = /state: (on|off)/

        condition:
            $re1 and $re2
    }

Regular expressions can be also followed by ``nocase``, ``ascii``, ``wide``,
and ``fullword`` modifiers just like in text strings. The semantics of these
modifiers are the same in both cases.

In previous versions of YARA, external libraries like PCRE and RE2 were used
to perform regular expression matching, but starting with version 2.0 YARA uses
its own regular expression engine. This new engine implements most features
found in PCRE, except a few of them like capture groups, POSIX character
classes and backreferences.

YARA’s regular expressions recognise the following metacharacters:

.. list-table::
   :widths: 3 10

   * - ``\``
     - Quote the next metacharacter
   * - ``^``
     - Match the beginning of the file
   * - ``$``
     - Match the end of the file
   * - ``|``
     - Alternation
   * - ``()``
     - Grouping
   * - ``[]``
     - Bracketed character class

The following quantifiers are recognised as well:

.. list-table::
   :widths: 3 10

   * - ``*``
     - Match 0 or more times
   * - ``+``
     - Match 1 or more times
   * - ``?``
     - Match 0 or 1 times
   * - ``{n}``
     - Match exactly n times
   * - ``{n,}``
     - Match at least n times
   * - ``{,m}``
     - Match at most m times
   * - ``{n,m}``
     - Match n to m times

All these quantifiers have a non-greedy variant, followed by a question
mark (?):

.. list-table::
   :widths: 3 10

   * - ``*?``
     - Match 0 or more times, non-greedy
   * - ``+?``
     - Match 1 or more times, non-greedy
   * - ``??``
     - Match 0 or 1 times, non-greedy
   * - ``{n}?``
     - Match exactly n times, non-greedy
   * - ``{n,}?``
     - Match at least n times, non-greedy
   * - ``{,m}?``
     - Match at most m times, non-greedy
   * - ``{n,m}?``
     - Match n to m times, non-greedy

The following escape sequences are recognised:

.. list-table::
   :widths: 3 10

   * - ``\t``
     - Tab (HT, TAB)
   * - ``\n``
     - New line (LF, NL)
   * - ``\r``
     - Return (CR)
   * - ``\f``
     - Form feed (FF)
   * - ``\a``
     - Alarm bell
   * - ``\xNN``
     - Character whose ordinal number is the given hexadecimal number


These are the recognised character classes:

.. list-table::
   :widths: 3 10

   * - ``\w``
     - Match a *word* character (alphanumeric plus “_”)
   * - ``\W``
     - Match a *non-word* character
   * - ``\s``
     - Match a whitespace character
   * - ``\S``
     - Match a non-whitespace character
   * - ``\d``
     - Match a decimal digit character
   * - ``\D``
     - Match a non-digit character


Starting with version 3.3.0 these zero-width assertions are also recognized:

.. list-table::
   :widths: 3 10

   * - ``\b``
     - Match a word boundary
   * - ``\B``
     - Match except at a word boundary

Private strings
---------------

All strings in YARA can be marked as ``private`` which means they will never be
included in the output of YARA. They are treated as normal strings everywhere
else, so you can still use them as you wish in the condition, but they will
never be shown with the ``-s`` flag or seen in the YARA callback if you're using
the C API.

.. code-block:: yara

    rule PrivateStringExample
    {
        strings:
            $text_string = "foobar" private

        condition:
            $text_string
    }

String Modifier Summary
-----------------------

The following string modifiers are processed in the following order, but are only applicable
to the string types listed.

.. list-table:: Text string modifiers
   :widths: 3 5 10 10
   :header-rows: 1

   * - Keyword
     - String Types
     - Summary
     - Restrictions
   * - ``nocase``
     - Text, Regex
     - Ignore case
     - Cannot use with ``xor``, ``base64``, or ``base64wide``
   * - ``wide``
     - Text, Regex
     - Emulate UTF16 by interleaving null (0x00) characters
     - None
   * - ``ascii``
     - Text, Regex
     - Also match ASCII characters, only required if ``wide`` is used
     - None
   * - ``xor``
     - Text
     - XOR text string with single byte keys
     - Cannot use with ``nocase``, ``base64``, or ``base64wide``
   * - ``base64``
     - Text
     - Convert to 3 base64 encoded strings
     - Cannot use with ``nocase``, ``xor``, or ``fullword``
   * - ``base64wide``
     - Text
     - Convert to 3 base64 encoded strings, then interleaving null characters like ``wide``
     - Cannot use with ``nocase``, ``xor``, or ``fullword``
   * - ``fullword``
     - Text, Regex
     - Match is not preceded or followed by an alphanumeric character
     - Cannot use with ``base64`` or ``base64wide``
   * - ``private``
     - Hex, Text, Regex
     - Match never included in output
     - None


Conditions
==========

Conditions are nothing more than Boolean expressions as those that can be found
in all programming languages, for example in an *if* statement. They can contain
the typical Boolean operators ``and``, ``or``, and ``not``, and relational operators
``>=``, ``<=``, ``<``, ``>``, ``==`` and ``!=``. Also, the arithmetic operators (``+``, ``-``, ``*``, ``\``, ``%``)
and bitwise operators (``&``, ``|``, ``<<``, ``>>``, ``~``, ``^``) can be used on numerical
expressions.

Integers are always 64-bits long, even the results of functions like `uint8`,
`uint16` and `uint32` are promoted to 64-bits. This is something you must take
into account, specially while using bitwise operators (for example, ~0x01 is not
0xFE but 0xFFFFFFFFFFFFFFFE).

The following table lists the precedence and associativity of all operators. The
table is sorted in descending precedence order, which means that operators listed
on a higher row in the list are grouped prior operators listed in rows further
below it. Operators within the same row have the same precedence, if they appear
together in a expression the associativity determines how they are grouped.

==========  ========  =========================================  =============
Precedence  Operator  Description                                Associativity
==========  ========  =========================================  =============
1           []        Array subscripting                         Left-to-right

            .         Structure member access
----------  --------  -----------------------------------------  -------------
2           `-`       Unary minus                                Right-to-left

            `~`       Bitwise not
----------  --------  -----------------------------------------  -------------
3           `*`       Multiplication                             Left-to-right

            \\        Division

            %         Remainder
----------  --------  -----------------------------------------  -------------
4           `+`       Addition                                   Left-to-right

            `-`       Subtraction
----------  --------  -----------------------------------------  -------------
5           `<<`      Bitwise left shift                         Left-to-right

            `>>`      Bitwise right shift
----------  --------  -----------------------------------------  -------------
6           &         Bitwise AND                                Left-to-right
----------  --------  -----------------------------------------  -------------
7           ^         Bitwise XOR                                Left-to-right
----------  --------  -----------------------------------------  -------------
8           `|`       Bitwise OR                                 Left-to-right
----------  --------  -----------------------------------------  -------------
9           <         Less than                                  Left-to-right

            <=        Less than or equal to

            >         Greater than

            >=        Greater than or equal to
----------  --------  -----------------------------------------  -------------
10          ==        Equal to                                   Left-to-right

            !=        Not equal to

            contains  String contains substring

            matches   String matches regular expression
----------  --------  -----------------------------------------  -------------
11          not       Logical NOT                                Right-to-left
----------  --------  -----------------------------------------  -------------
12          and       Logical AND                                Left-to-right
----------  --------  -----------------------------------------  -------------
13          or        Logical OR                                 Left-to-right
==========  ========  =========================================  =============


String identifiers can be also used within a condition, acting as Boolean
variables whose value depends on the presence or not of the associated string
in the file.

.. code-block:: yara

    rule Example
    {
        strings:
            $a = "text1"
            $b = "text2"
            $c = "text3"
            $d = "text4"

        condition:
            ($a or $b) and ($c or $d)
    }



Counting strings
----------------

Sometimes we need to know not only if a certain string is present or not,
but how many times the string appears in the file or process memory. The number
of occurrences of each string is represented by a variable whose name is the
string identifier but with a # character in place of the $ character.
For example:

.. code-block:: yara

    rule CountExample
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"

        condition:
            #a == 6 and #b > 10
    }


This rule matches any file or process containing the string $a exactly six times,
and more than ten occurrences of string $b.

.. _string-offsets:

String offsets or virtual addresses
-----------------------------------

In the majority of cases, when a string identifier is used in a condition, we
are willing to know if the associated string is anywhere within the file or
process memory, but sometimes we need to know if the string is at some specific
offset on the file or at some virtual address within the process address space.
In such situations the operator ``at`` is what we need. This operator is used as
shown in the following example:

.. code-block:: yara

    rule AtExample
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"

        condition:
            $a at 100 and $b at 200
    }

The expression ``$a at 100`` in the above example is true only if string $a is
found at offset 100 within the file (or at virtual address 100 if applied to
a running process). The string $b should appear at offset 200. Please note
that both offsets are decimal, however hexadecimal numbers can be written by
adding the prefix 0x before the number as in the C language, which comes very
handy when writing virtual addresses. Also note the higher precedence of the
operator ``at`` over the ``and``.

While the ``at`` operator allows to search for a string at some fixed offset in
the file or virtual address in a process memory space, the ``in`` operator
allows to search for the string within a range of offsets or addresses.

.. code-block:: yara

    rule InExample
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"

        condition:
            $a in (0..100) and $b in (100..filesize)
    }

In the example above the string $a must be found at an offset between 0 and
100, while string $b must be at an offset between 100 and the end of the file.
Again, numbers are decimal by default.

You can also get the offset or virtual address of the i-th occurrence of string
$a by using @a[i]. The indexes are one-based, so the first occurrence would be
@a[1] the second one @a[2] and so on. If you provide an index greater then the
number of occurrences of the string, the result will be a NaN (Not A Number)
value.


Match length
------------

For many regular expressions and hex strings containing jumps, the length of
the match is variable. If you have the regular expression /fo*/ the strings
"fo", "foo" and "fooo" can be matches, all of them with a different length.

You can use the length of the matches as part of your condition by using the
character ! in front of the string identifier, in a similar way you use the @
character for the offset. !a[1] is the length for the first match of $a, !a[2]
is the length for the second match, and so on. !a is a abbreviated form of
!a[1].


File size
---------

String identifiers are not the only variables that can appear in a condition
(in fact, rules can be defined without any string definition as will be shown
below), there are other special variables that can be used as well. One of
these special variables is ``filesize``, which holds, as its name indicates,
the size of the file being scanned. The size is expressed in bytes.

.. code-block:: yara

    rule FileSizeExample
    {
        condition:
            filesize > 200KB
    }

The previous example also demonstrates the use of the ``KB`` postfix. This
postfix, when attached to a numerical constant, automatically multiplies the
value of the constant by 1024. The ``MB`` postfix can be used to multiply the
value by 2^20. Both postfixes can be used only with decimal constants.

The use of ``filesize`` only makes sense when the rule is applied to a file. If
the rule is applied to a running process it won’t ever match because
``filesize`` doesn’t make sense in this context.

Executable entry point
----------------------

Another special variable than can be used in a rule is ``entrypoint``. If the
file is a Portable Executable (PE) or Executable and Linkable Format (ELF),
this variable holds the raw offset of the executable’s entry point in case we
are scanning a file. If we are scanning a running process, the entrypoint will
hold the virtual address of the main executable’s entry point. A typical use of
this variable is to look for some pattern at the entry point to detect packers
or simple file infectors.

.. code-block:: yara

    rule EntryPointExample1
    {
        strings:
            $a = { E8 00 00 00 00 }

        condition:
            $a at entrypoint
    }

    rule EntryPointExample2
    {
        strings:
            $a = { 9C 50 66 A1 ?? ?? ?? 00 66 A9 ?? ?? 58 0F 85 }

        condition:
            $a in (entrypoint..entrypoint + 10)
    }

The presence of the ``entrypoint`` variable in a rule implies that only PE or
ELF files can satisfy that rule. If the file is not a PE or ELF, any rule using
this variable evaluates to false.

.. warning:: The ``entrypoint`` variable is deprecated, you should use the
    equivalent ``pe.entry_point`` from the :ref:`pe-module` instead. Starting
    with YARA 3.0 you'll get a warning if you use ``entrypoint`` and it will be
    completely removed in future versions.


Accessing data at a given position
----------------------------------

There are many situations in which you may want to write conditions that depend
on data stored at a certain file offset or virtual memory address, depending on
if we are scanning a file or a running process. In those situations you can use
one of the following functions to read data from the file at the given offset::

    int8(<offset or virtual address>)
    int16(<offset or virtual address>)
    int32(<offset or virtual address>)

    uint8(<offset or virtual address>)
    uint16(<offset or virtual address>)
    uint32(<offset or virtual address>)

    int8be(<offset or virtual address>)
    int16be(<offset or virtual address>)
    int32be(<offset or virtual address>)

    uint8be(<offset or virtual address>)
    uint16be(<offset or virtual address>)
    uint32be(<offset or virtual address>)

The ``intXX`` functions read 8, 16, and 32 bits signed integers from
<offset or virtual address>, while functions ``uintXX`` read unsigned integers.
Both 16 and 32 bit integers are considered to be little-endian. If you
want to read a big-endian integer use the corresponding function ending
in ``be``. The <offset or virtual address> parameter can be any expression returning
an unsigned integer, including the return value of one the ``uintXX`` functions
itself. As an example let's see a rule to distinguish PE files:

.. code-block:: yara

    rule IsPE
    {
        condition:
            // MZ signature at offset 0 and ...
            uint16(0) == 0x5A4D and
            // ... PE signature at offset stored in MZ header at 0x3C
            uint32(uint32(0x3C)) == 0x00004550
    }


Sets of strings
---------------

There are circumstances in which it is necessary to express that the file should
contain a certain number strings from a given set. None of the strings in the
set are required to be present, but at least some of them should be. In these
situations the ``of`` operator can be used.

.. code-block:: yara

    rule OfExample1
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"
            $c = "dummy3"

        condition:
            2 of ($a,$b,$c)
    }

This rule requires that at least two of the strings in the set ($a,$b,$c)
must be present in the file, but it does not matter which two. Of course, when
using this operator, the number before the ``of`` keyword must be less than or
equal to the number of strings in the set.

The elements of the set can be explicitly enumerated like in the previous
example, or can be specified by using wild cards. For example:

.. code-block:: yara

    rule OfExample2
    {
        strings:
            $foo1 = "foo1"
            $foo2 = "foo2"
            $foo3 = "foo3"

        condition:
            2 of ($foo*)  // equivalent to 2 of ($foo1,$foo2,$foo3)
    }

    rule OfExample3
    {
        strings:
            $foo1 = "foo1"
            $foo2 = "foo2"

            $bar1 = "bar1"
            $bar2 = "bar2"

        condition:
            3 of ($foo*,$bar1,$bar2)
    }

You can even use ``($*)`` to refer to all the strings in your rule, or write
the equivalent keyword ``them`` for more legibility.

.. code-block:: yara

    rule OfExample4
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"
            $c = "dummy3"

        condition:
            1 of them // equivalent to 1 of ($*)
    }

In all the examples above, the number of strings have been specified by a
numeric constant, but any expression returning a numeric value can be used.
The keywords ``any`` and ``all`` can be used as well.

.. code-block:: yara

    all of them       // all strings in the rule
    any of them       // any string in the rule
    all of ($a*)      // all strings whose identifier starts by $a
    any of ($a,$b,$c) // any of $a, $b or $c
    1 of ($*)         // same that "any of them"

Applying the same condition to many strings
-------------------------------------------

There is another operator very similar to ``of`` but even more powerful, the
``for..of`` operator. The syntax is:

.. code-block:: yara

    for expression of string_set : ( boolean_expression )

And its meaning is: from those strings in ``string_set`` at least ``expression``
of them must satisfy ``boolean_expression``.

In other words: ``boolean_expression`` is evaluated for every string in
``string_set`` and there must be at least ``expression`` of them returning
True.

Of course, ``boolean_expression`` can be any boolean expression accepted in
the condition section of a rule, except for one important detail: here you
can (and should) use a dollar sign ($) as a place-holder for the string being
evaluated. Take a look at the following expression:

.. code-block:: yara

    for any of ($a,$b,$c) : ( $ at pe.entry_point  )

The $ symbol in the boolean expression is not tied to any particular string,
it will be $a, and then $b, and then $c in the three successive evaluations
of the expression.

Maybe you already realised that the ``of`` operator is a special case of
``for..of``. The following expressions are the same:

.. code-block:: yara

    any of ($a,$b,$c)
    for any of ($a,$b,$c) : ( $ )

You can also employ the symbols #, @, and ! to make reference to the number of
occurrences, the first offset, and the length of each string respectively.

.. code-block:: yara

    for all of them : ( # > 3 )
    for all of ($a*) : ( @ > @b )

Using anonymous strings with ``of`` and ``for..of``
---------------------------------------------------

When using the ``of`` and ``for..of`` operators followed by ``them``, the
identifier assigned to each string of the rule is usually superfluous. As
we are not referencing any string individually we do not need to provide
a unique identifier for each of them. In those situations you can declare
anonymous strings with identifiers consisting only of the $ character, as in
the following example:

.. code-block:: yara

    rule AnonymousStrings
    {
        strings:
            $ = "dummy1"
            $ = "dummy2"

        condition:
            1 of them
    }


Iterating over string occurrences
---------------------------------

As seen in :ref:`string-offsets`, the offsets or virtual addresses where a given
string appears within a file or process address space can be accessed by
using the syntax: @a[i], where i is an index indicating which occurrence
of the string $a you are referring to. (@a[1], @a[2],...).

Sometimes you will need to iterate over some of these offsets and guarantee
they satisfy a given condition. For example:

.. code-block:: yara

    rule Occurrences
    {
        strings:
            $a = "dummy1"
            $b = "dummy2"

        condition:
            for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
    }

The previous rule says that the first three occurrences of $b should be 10
bytes away from the first three occurrences of $a.

The same condition could be written also as:

.. code-block:: yara

    for all i in (1..3) : ( @a[i] + 10 == @b[i] )

Notice that we’re using a range (1..3) instead of enumerating the index
values (1,2,3). Of course, we’re not forced to use constants to specify range
boundaries, we can use expressions as well like in the following example:

.. code-block:: yara

    for all i in (1..#a) : ( @a[i] < 100 )

In this case we’re iterating over every occurrence of $a (remember that #a
represents the number of occurrences of $a). This rule is specifying that every
occurrence of $a should be within the first 100 bytes of the file.

In case you want to express that only some occurrences of the string
should satisfy your condition, the same logic seen in the ``for..of`` operator
applies here:

.. code-block:: yara

    for any i in (1..#a) : ( @a[i] < 100 )
    for 2 i in (1..#a) : ( @a[i] < 100 )

In summary, the syntax of this operator is:

.. code-block:: yara

    for expression identifier in indexes : ( boolean_expression )


Iterators
---------

In YARA 4.0 the ``for..of`` operator was improved and now it can be used to
iterate not only over integer enumerations and ranges (e.g: 1,2,3,4 and 1..4),
but also over any kind of iterable data type, like arrays and dictionaries
defined by YARA modules. For example, the following expression is valid in
YARA 4.0:

.. code-block:: yara

    for any section in pe.sections : ( section.name == ".text" )

This is equivalent to:

.. code-block:: yara

    for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == ".text" )

The new syntax is more natural and easy to understand, and is the recommended
way of expressing this type of conditions in newer versions of YARA.

While iterating dictionaries you must provide two variable names that will
hold the key and value for each entry in the dictionary, for example:

.. code-block:: yara

    for any k,v in some_dict : ( k == "foo" and v == "bar" )

In general the ``for..of`` operator has the form:

.. code-block:: yara

    for <quantifier> <variables> in <iterable> : ( <some condition using the loop variables> )

Where `<quantifier>` is either `any`, `all` or an expression that evaluates to
the number of items in the iterator that must satisfy the condition, `<variables>`
is a comma-separated list of variable names that holds the values for the
current item (the number of variables depend on the type of `<iterable>`) and
`<iterable>` is something that can be iterated.


.. _referencing-rules:

Referencing other rules
-----------------------

When writing the condition for a rule you can also make reference to a
previously defined rule in a manner that resembles a function invocation of
traditional programming languages. In this way you can create rules that
depend on others. Let's see an example:

.. code-block:: yara

    rule Rule1
    {
        strings:
            $a = "dummy1"

        condition:
            $a
    }

    rule Rule2
    {
        strings:
            $a = "dummy2"

        condition:
            $a and Rule1
    }

As can be seen in the example, a file will satisfy Rule2 only if it contains
the string "dummy2" and satisfies Rule1. Note that it is strictly necessary to
define the rule being invoked before the one that will make the invocation.

More about rules
================

There are some aspects of YARA rules that have not been covered yet, but are
still very important. These are: global rules, private rules, tags and
metadata.

Global rules
------------

Global rules give you the possibility of imposing restrictions in all your
rules at once. For example, suppose that you want all your rules to ignore
files that exceed a certain size limit. You could go rule by rule making
the required modifications to their conditions, or just write a global rule
like this one:

.. code-block:: yara

    global rule SizeLimit
    {
        condition:
            filesize < 2MB
    }

You can define as many global rules as you want, they will be evaluated
before the rest of the rules, which in turn will be evaluated only if all
global rules are satisfied.

Private rules
-------------

Private rules are a very simple concept. They are just rules that are not
reported by YARA when they match on a given file. Rules that are not reported
at all may seem sterile at first glance, but when mixed with the possibility
offered by YARA of referencing one rule from another (see
:ref:`referencing-rules`) they become useful. Private rules can serve as
building blocks for other rules, and at the same time prevent cluttering
YARA's output with irrelevant information. To declare a rule as private
just add the keyword ``private`` before the rule declaration.

.. code-block:: yara

    private rule PrivateRuleExample
    {
        ...
    }

You can apply both ``private`` and ``global`` modifiers to a rule, resulting in
a global rule that does not get reported by YARA but must be satisfied.

Rule tags
---------

Another useful feature of YARA is the possibility of adding tags to rules.
Those tags can be used later to filter YARA's output and show only the rules
that you are interested in. You can add as many tags as you want to a rule,
they are declared after the rule identifier as shown below:

.. code-block:: yara

    rule TagsExample1 : Foo Bar Baz
    {
        ...
    }

    rule TagsExample2 : Bar
    {
        ...
    }


Tags must follow the same lexical convention of rule identifiers, therefore
only alphanumeric characters and underscores are allowed, and the tag cannot
start with a digit. They are also case sensitive.

When using YARA you can output only those rules which are tagged with the tag
or tags that you provide.


Metadata
--------

Besides the string definition and condition sections, rules can also have a
metadata section where you can put additional information about your rule.
The metadata section is defined with the keyword ``meta`` and contains
identifier/value pairs like in the following example:

.. code-block:: yara

    rule MetadataExample
    {
        meta:
            my_identifier_1 = "Some string data"
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
    }

As can be seen in the example, metadata identifiers are always followed by
an equals sign and the value assigned to them. The assigned values can be
strings (valid UTF8 only), integers, or one of the boolean values true or false.
Note that identifier/value pairs defined in the metadata section cannot be used
in the condition section, their only purpose is to store additional information
about the rule.

.. _using-modules:

Using modules
=============

Modules are extensions to YARA's core functionality. Some modules like
the :ref:`PE module <pe-module>` and the :ref:`Cuckoo module <cuckoo-module>`
are officially distributed with YARA and additional ones can be created by
third-parties or even yourself as described in :ref:`writing-modules`.

The first step to using a module is importing it with the ``import`` statement.
These statements must be placed outside any rule definition and followed by
the module name enclosed in double-quotes. Like this:

.. code-block:: yara

    import "pe"
    import "cuckoo"

After importing the module you can make use of its features, always using
``<module name>.`` as a prefix to any variable or function exported by the
module. For example:

.. code-block:: yara

    pe.entry_point == 0x1000
    cuckoo.http_request(/someregexp/)

.. _undefined-values:

Undefined values
================

Modules often leave variables in an undefined state, for example when the
variable doesn't make sense in the current context (think of ``pe.entry_point``
while scanning a non-PE file). YARA handles undefined values in a way that allows
the rule to keep its meaningfulness. Take a look at this rule:

.. code-block:: yara

    import "pe"

    rule Test
    {
        strings:
            $a = "some string"

        condition:
            $a and pe.entry_point == 0x1000
    }

If the scanned file is not a PE you wouldn't expect this rule to match the file,
even if it contains the string, because **both** conditions (the presence of
the string and the right value for the entry point) must be satisfied. However,
if the condition is changed to:

.. code-block:: yara

    $a or pe.entry_point == 0x1000

You would expect the rule to match in this case if the file contains the string,
even if it isn't a PE file. That's exactly how YARA behaves. The logic is as
follows:

* Arithmetic and bitwise operators return an undefined value if some of their
  operands are undefined.

* Boolean operators `and` and `or` will treat undefined operands as `false`.

* Boolean `not` operator returns false if the operand is undefined.

* Comparison operators and any other operator whose result is a boolean (like
  the ``contains`` and ``matches`` operators) will return `false` if any of
  their operands are undefined.

In the expression above, `pe.entry_point == 0x1000` will be false, because
`pe.entry_point` is undefined, and the `==` operator returns false if any of its
operands are undefined.


External variables
==================

External variables allow you to define rules that depend on values provided
from the outside. For example, you can write the following rule:

.. code-block:: yara

    rule ExternalVariableExample1
    {
        condition:
            ext_var == 10
    }

In this case ``ext_var`` is an external variable whose value is assigned at
run-time (see ``-d`` option of command-line tool, and ``externals`` parameter of
``compile`` and ``match`` methods in yara-python). External variables could be
of types: integer, string or boolean; their type depends on the value assigned
to them. An integer variable can substitute any integer constant in the
condition and boolean variables can occupy the place of boolean expressions.
For example:

.. code-block:: yara

    rule ExternalVariableExample2
    {
        condition:
            bool_ext_var or filesize < int_ext_var
    }

External variables of type string can be used with the operators: ``contains``
and ``matches``. The ``contains`` operator returns true if the string contains
the specified substring. The ``matches`` operator returns true if the string
matches the given regular expression.

.. code-block:: yara

    rule ExternalVariableExample3
    {
        condition:
            string_ext_var contains "text"
    }

    rule ExternalVariableExample4
    {
        condition:
            string_ext_var matches /[a-z]+/
    }

You can use regular expression modifiers along with the ``matches`` operator,
for example, if you want the regular expression from the previous example
to be case insensitive you can use ``/[a-z]+/i``. Notice the ``i`` following the
regular expression in a Perl-like manner. You can also use the ``s`` modifier
for single-line mode, in this mode the dot matches all characters including
line breaks. Of course both modifiers can be used simultaneously, like in the
following example:

.. code-block:: yara

    rule ExternalVariableExample5
    {
        condition:
            /* case insensitive single-line mode */
            string_ext_var matches /[a-z]+/is
    }

Keep in mind that every external variable used in your rules must be defined
at run-time, either by using the ``-d`` option of the command-line tool, or by
providing the ``externals`` parameter to the appropriate method in
``yara-python``.

Including files
===============

In order to allow for more flexible organization of your rules files,
YARA provides the ``include`` directive. This directive works in a similar way
to the *#include* pre-processor directive in C programs, which inserts the
content of the specified source file into the current file during compilation.
The following example will include the content of *other.yar* into the current
file:

.. code-block:: yara

    include "other.yar"

The base path when searching for a file in an ``include`` directive will be the
directory where the current file resides. For this reason, the file *other.yar*
in the previous example should be located in the same directory of the current
file. However, you can also specify relative paths like these:

.. code-block:: yara

    include "./includes/other.yar"
    include "../includes/other.yar"

Or use absolute paths:

.. code-block:: yara

    include "/home/plusvic/yara/includes/other.yar"

In Windows, both forward and back slashes are accepted, but don’t forget to
write the drive letter:

.. code-block:: yara

    include "c:/yara/includes/other.yar"
    include "c:\\yara\\includes\\other.yar"
