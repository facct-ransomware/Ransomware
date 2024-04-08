/*
Sojusz ransomware
*/


rule Sojusz
{
    meta:
        author = "rivitna"
        company = "F.A.C.C.T. LLC"
        family = "ransomware.sojusz.windows"
        description = "Sojusz ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "postgresql-x64-9.4\x0D\x0AUniFi\x0D\x0Avmms\x0D\x0Awrapper" wide
        $s1 = "wxServerView\x0D\x0Azhudongfangyu\x0D\x0AZhuDongFangYu.exe" wide
        $s2 = ".kpdx\x00.kwm\x00.laccdb\x00.lay\x00.la" wide
        $s3 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" wide
        $s4 = "\x00NO Free P\x00" wide
        $s5 = "%s|DELIMITER|Name(domain): %s(%s)\x0D\x0A" wide
        $s6 = "CMD->PowerShell - Done!\x0D\x0A--\x0D\x0A" ascii

        $h0 = { BB 00 10 00 00 83 FE F8 7F 0D 6A 04 53 6A 72 6A 00
                ( E8 ?? | FF 15 ) [4] 83 FE EC 7F 0D 6A 04 53 6A 63
                6A 00 ( E8 | FF 15 ) }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            ((1 of ($h*)) and (2 of ($s*))) or
            (4 of ($s*))
        )
}
