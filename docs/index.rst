.. yara documentation master file, created by
   sphinx-quickstart on Tue Jul  8 11:04:03 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to YARA's documentation!
================================

YARA is a tool aimed at (but not limited to) helping malware researchers to
identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. Each description, a.k.a rule, consists of a set of strings and a
boolean expression which determine its logic. Let's see an example::

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

The above rule is telling YARA that any file containing one of the three strings
must be reported as silent_banker. This is just a simple example, more complex
and powerful rules can be created by using wild-cards, case-insensitive strings, regular expressions, special operators and many other features that you'll find explained in this documentation.

Contents:

.. toctree::
   :maxdepth: 3

   gettingstarted
   writingrules
   modules
   writingmodules
   commandline



