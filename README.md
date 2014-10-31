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
* [Tanium](http://www.tanium.com/)
* [Trend Micro](http://www.trendmicro.com)
* [Metaflows](http://www.metaflows.com)

Are you using it? Want to see your site listed here?
