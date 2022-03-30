[![Join the chat at https://gitter.im/VirusTotal/yara](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/VirusTotal/yara?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![AppVeyor build status](https://ci.appveyor.com/api/projects/status/7glqg19w4oolm7pr?svg=true)](https://ci.appveyor.com/project/plusvic/yara)
[![Coverity status](https://scan.coverity.com/projects/9057/badge.svg?flat=1)](https://scan.coverity.com/projects/plusvic-yara)



## YARA in a nutshell

YARA is a tool aimed at (but not limited to) helping malware researchers to
identify and classify malware samples. With YARA you can create descriptions of
malware families (or whatever you want to describe) based on textual or binary
patterns. Each description, a.k.a. rule, consists of a set of strings and a
boolean expression which determine its logic. Let's see an example:

```yara
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        threat_level = 3
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
you'll find explained in [YARA's documentation](https://yara.readthedocs.org/).

YARA is multi-platform, running on Windows, Linux and Mac OS X, and can be used
through its command-line interface or from your own Python scripts with the
yara-python extension.

## Additional resources

Do you use GitHub for storing your YARA rules? [YARA-CI](https://yara-ci.cloud.virustotal.com)
may be a useful addition to your toolbelt. This is GitHub application that provides
continuous testing for your rules, helping you to identify common mistakes and
false positives.

If you plan to use YARA to scan compressed files (.zip, .tar, etc) you should
take a look at [yextend](https://github.com/BayshoreNetworks/yextend), a very
helpful extension to YARA developed and open-sourced by Bayshore Networks.

Additionally, the guys from [InQuest](https://inquest.net/) have curated an
awesome list of [YARA-related stuff](https://github.com/InQuest/awesome-yara).

## Who's using YARA

* [ActiveCanopy](https://activecanopy.com/)
* [Adlice](https://www.adlice.com/)
* [AlienVault](https://otx.alienvault.com/)
* [Avast](https://www.avast.com/)
* [BAE Systems](https://www.baesystems.com/home?r=ai)
* [Bayshore Networks, Inc.](https://www.bayshorenetworks.com)
* [BinaryAlert](https://github.com/airbnb/binaryalert)
* [Blueliv](https://www.blueliv.com)
* [Cisco Talos Intelligence Group](https://talosintelligence.com/)
* [Claroty](https://claroty.com/continuous-threat-detection)
* [Cloudina Security](https://cloudina.co.uk)
* [Cofense](https://cofense.com)
* [Conix](https://www.conix.fr)
* [CounterCraft](https://www.countercraft.eu)
* [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo)
* [Cyber Triage](https://www.cybertriage.com)
* [Cybereason](https://www.cybereason.com)
* [Digita Security](https://digitasecurity.com/product/uxprotect)
* [Dragos Platform](https://dragos.com/platform/)
* [Dtex Systems](https://dtexsystems.com)
* [ESET](https://www.eset.com)
* [ESTsecurity](https://www.estsecurity.com)
* [Fidelis XPS](https://www.fidelissecurity.com/network-security-appliance/Fidelis-XPS)
* [FireEye, Inc.](https://www.fireeye.com)
* [Forcepoint](https://www.forcepoint.com)
* [Fox-IT](https://www.fox-it.com)
* [FSF](https://github.com/EmersonElectricCo/fsf)
* [Guidance Software](https://www.guidancesoftware.com/endpointsecurity)
* [Heroku](https://heroku.com)
* [Hornetsecurity](https://www.hornetsecurity.com/en/)
* [ICS Defense](https://icsdefense.net/)
* [InQuest](https://www.inquest.net/)
* [Joe Security](https://www.joesecurity.org)
* [Kaspersky Lab](https://www.kaspersky.com)
* [KnowBe4](https://www.knowbe4.com)
* [Koodous](https://koodous.com/)
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [Lastline, Inc.](https://www.lastline.com)
* [libguestfs](https://www.libguestfs.org/)
* [LimaCharlie](https://limacharlie.io/)
* [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
* [Malwation](https://malwation.com/)
* [McAfee Advanced Threat Defense](https://mcafee.com/atd)
* [Metaflows](https://www.metaflows.com)
* [NBS System](https://www.nbs-system.com/)
* [Nextron Systems](https://www.nextron-systems.com)
* [Nozomi Networks](https://www.nozominetworks.com)
* [osquery](https://www.osquery.io)
* [Payload Security](https://www.payload-security.com)
* [PhishMe](https://phishme.com/)
* [Picus Security](https://www.picussecurity.com/)
* [Radare2](https://rada.re)
* [Raytheon Cyber Products, Inc.](http://www.raytheoncyber.com/capabilities/products/sureview-threatprotection/)
* [RedSocks Security](https://redsocks.eu/)
* [ReversingLabs](https://reversinglabs.com)
* [RSA ECAT](https://www.emc.com/security/rsa-ecat.htm)
* [Scanii](https://scanii.com)
* [SecondWrite](https://www.secondwrite.com)
* [SonicWall](https://www.sonicwall.com/)
* [SpamStopsHere](https://www.spamstopshere.com)
* [Spyre](https://github.com/spyre-project/spyre)
* [stoQ](https://stoq.punchcyber.com)
* [SumoLogic](https://sumologic.com)
* [Tanium](https://www.tanium.com/)
* [Tenable Network Security](https://www.tenable.com/)
* [The DigiTrust Group](https://www.digitrustgroup.com/)
* [ThreatConnect](https://www.threatconnect.com/)
* [ThreatStream, Inc.](https://www.threatstream.com)
* [Thug](https://github.com/buffer/thug)
* [TouchWeb](https://www.touchweb.fr)
* [Trend Micro](https://www.trendmicro.com)
* [VirusTotal Intelligence](https://www.virustotal.com/intelligence/)
* [VMRay](https://www.vmray.com/)
* [Volexity](https://www.volexity.com/products-overview/volcano/)
* [We Watch Your Website](https://www.wewatchyourwebsite.com/)
* [x64dbg](https://x64dbg.com)
* [YALIH](https://github.com/Masood-M/YALIH)

Are you using it? Want to see your site listed here?
