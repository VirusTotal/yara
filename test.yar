import "pe"

rule M_Dropper_DRIPDRIVE_2 {
	meta:
		author = "Mandiant"
		md5 = "c8ebaf77bb9905ef84b28510de6c9d0e"
		date_created = "2024-01-08"
		date_modified = "2024-01-08"
		rev = "1"
	strings:
		$s1 = "########:download ok!" ascii wide
		$s2 = "########:run command line:" ascii wide
		$s3 = "########:start install cef!" ascii wide
		$s4 = "/install" wide
		$s5 = "/update" wide
		$s6 = "MachineGuid" wide
		$s7 = "SOFTWARE\\Microsoft\\Cryptography" wide
		$asm1 = { 84 C0 75 ?? 2B F1 0F 57 C0 66 0F 13 44 24 ?? 39 5C 24 ?? 7C ?? 8B 7C 24 ?? 7F ?? 3B FB 76 ?? 8B 44 24 ?? 8B 4C 24 ?? 89 44 24 ?? 89 4C 24 ?? 53 56 50 51 E8 ?? ?? ?? ?? 8B 4C 24 ?? 8B 54 24 ?? 8A 44 04 ?? 30 04 11 83 C1 01 8B 44 24 ?? 13 C3 89 4C 24 ?? 89 44 24 ?? 3B 44 24 ?? 7C ?? 7F ?? 3B CF 72 ?? }
	condition:
		(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (for any i in (0 .. pe.number_of_resources - 1) : ( pe.resources[i].type_string == "F\x00I\x00L\x00E\x00" )) and (4 of ($s*)) and (all of ($asm*))
}

import "pe"

rule M_APT_Dropper_DRIPDRIVE_1 {
	meta:
		author = "Mandiant"
		date_created = "2024-02-06"
		date_modified = "2024-02-06"
		md5 = "cc3b8573e7955c3fa90d98343f389732"
		rev = 1
	strings:
		$str1 = "########:start install cef!"
		$str2 = "########:delete xp file:%s!"
		$str3 = "########:install cef ok!"
		$str4 = "########:start update cef!"
		$str5 = "########:no use update and run wintool!"
		$str6 = "########:download update!"
		$str7 = "########:download failed!"
		$str8 = "########:download ok!"
		$str9 = "decrypt ok!"
		$str10 = "########:install update close!"
		$str11 = "########:run command line" wide fullword
		$p1 = "Global\\GUID(A3AC453A-543D-4FC6-9465-F8897B8F67E5)" wide fullword
		$p2 = "/install" wide fullword
		$p3 = "/update" wide fullword
		$p4 = "TASKKILL /F /IM %s" wide fullword
	condition:
		uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 8 of ($str*) and all of ($p*) and for any i in (0 .. pe.number_of_resources - 1) : ( pe.resources[i].type_string == "F\x00I\x00L\x00E\x00" )
}
