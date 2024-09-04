/*
TeslaRVNG / Yakuza ransomware
*/


rule TeslaRVNG
{
    meta:
        author = "rivitna"
        family = "ransomware.teslarvng.windows"
        description = "TeslaRVNG / Yakuza ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "encrypted local size :\x00" ascii
        $s1 = "\x0D\x0AEncrypted Network size :\x00" ascii
        $s2 = "Finished Locals \x0D\x0A\x00" ascii
        $s3 = "running after 5 seconds, close proccess for cancelling\x00" ascii
        $s4 = "\x00renameeachfile\x00" ascii
        $s5 = "\x00networkonlyprintadmins\x00" ascii
        $s6 = "DeFaUlTID\x00" ascii
        $s7 = ":\\windows\\logg.bat\x00" wide
        $s8 = " \x0D\x0AHard Disk Used Sizes::\x00" ascii
        $s9 = "Invaild Handle in log saving \x00" wide
        $s10 = "defering rest of  win partion \x00" wide
        $s11 = "My Sample Service: ServiceMain: SetServiceStatus returned error\x00" wide
        $s12 = "readchedEnd \x0D\x0A doing final jobs" wide
        $s13 = "\x00noting on network \x00" wide
        $s14 = "setting cpu pririty to aboe normall" wide
        $s15 = "\\programdata\\adobe\\extension manager cc\\logs\\\x00" wide
        $s16 = "\\users\\\\[^\\\\]*\\\\ntuser.dat[^\\\\]*$" wide
        $s17 = "s on defered windrive \x00" wide
        $s18 = "{557cf401-1a04-11d3-9a73-0000f81ef32e}\x00" wide
        $s19 = "\x00-irs\x00" wide
        $s20 = "\x00chacha faild\x00" wide
        $s21 = "rngerror ,disabable av\x00" wide
        $s22 = "antoher process is already running, therminating\x00" wide
        $s23 = "will rename each file after encrypted " wide
        $s24 = "ont shutdown machine after encryption " wide
        $s25 = "SCHTASKS /create /tn logg /sc MINUTE /mo 10 /tr \"c:\\windows\\logg.bat\"" wide
        $s26 = "will stop encrypting and exit " wide
        $s27 = " extesions were exclueded and wont be encrypted" wide
        $s28 = "autospread (ingnoring avs) enabled , file name in target machine will be c:\\windows\\" wide

        $h0 = { BA 03 0D 00 00 41 B8 07 0F 01 00 49 89 }
        $h1 = { C6 44 3? 02 7F 66 C7 04 3? DC 2D }
        $h2 = { 00 00 FE E7 6B B3 0F 85 }
        $h3 = { BA 4B 00 00 00 4D 89 ?? 41 B9 CC 05 00 00 E8 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            ((1 of ($h*)) and (5 of ($s*))) or
            (10 of ($s*))
        )
}
