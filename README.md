[![Join the chat at https://gitter.im/plusvic/yara](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/plusvic/yara?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


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

If you plan to use YARA to scan compressed files (.zip, .tar, etc) you should
take a look at [yextend](https://github.com/BayshoreNetworks/yextend), a very
helpful extension to YARA developed and open-sourced by Bayshore Networks.

## Who's using YARA

* [ActiveCanopy](https://activecanopy.com/)
* [Adlice](http://www.adlice.com/)
* [BAE Systems](http://www.baesystems.com/home?r=ai)
* [Bayshore Networks, Inc.](http://www.bayshorenetworks.com)
* [Blue Coat](http://www.bluecoat.com/products/malware-analysis-appliance)
* [Blueliv](http://www.blueliv.com)
* [CrowdStrike FMS](https://github.com/CrowdStrike/CrowdFMS)
* [Fidelis XPS](http://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [FireEye, Inc.](http://www.fireeye.com)
* [Fox-IT](https://www.fox-it.com)
* [FSF](https://github.com/EmersonElectricCo/fsf)
* [Guidance Software](http://www.guidancesoftware.com/endpointsecurity)
* [Heroku](https://heroku.com)
* [jsunpack-n](http://jsunpack.jeek.org/)
* [Koodous](https://koodous.com/)
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [Lastline, Inc.](http://www.lastline.com)
* [Metaflows](http://www.metaflows.com)
* [osquery](http://www.osquery.io)
* [PhishMe](http://phishme.com/)
* [Picus Security](http://www.picussecurity.com/)
* [Radare2](http://rada.re)
* [Raytheon Cyber Products, Inc.](http://www.raytheoncyber.com/capabilities/products/sureview-threatprotection/)
* [ReversingLabs](http://reversinglabs.com)
* [RSA ECAT](http://www.emc.com/security/rsa-ecat.htm)
* [SpamStopsHere](https://www.spamstopshere.com)
* [Symantec](http://www.symantec.com)
* [Tanium](http://www.tanium.com/)
* [The DigiTrust Group](http://www.digitrustgroup.com/)
* [ThreatConnect](http://www.threatconnect.com)
* [ThreatStream, Inc.](http://threatstream.com)
* [Thug](https://github.com/buffer/thug)
* [Trend Micro](http://www.trendmicro.com)
* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [We Watch Your Website](http://www.wewatchyourwebsite.com/)
* [Websense](http://www.websense.com)
* [x64dbg](http://x64dbg.com)
* [YALIH](https://github.com/Masood-M/YALIH)

Are you using it? Want to see your site listed here?
