/*
Muliaka ransomware
*/


rule Muliaka_loader
{
    meta:
        author = "rivitna"
        family = "ransomware.muliaka.loader"
        description = "Muliaka ransomware Windows loader"
        severity = 10
        score = 100

    strings:
        $s0 = "PeParserErr" ascii
        $s1 = "PeLoaderErr" ascii
        $s2 = "NtProtectVmErr" ascii
        $s3 = "LoadLibararyFail" ascii
        $s4 = "NtAllocVmErr" ascii
        $s5 = "MismatchedLoader" ascii
        $s6 = "\\release\\deps\\hello_world.pdb" ascii
        $s7 = { 0B 02 00 00 74 ?? [0-1] B? 05 ( 41 81 | 81 ) ?? 0B 01 00 00 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (7 of ($s*))
        )
}


rule Muliaka_ESXi
{
    meta:
        author = "rivitna"
        family = "ransomware.muliaka.esxi"
        description = "Muliaka ransomware ESXi"
        severity = 10
        score = 100

    strings:
        $s0 = "crypt_file_one" ascii
        $s1 = "crypt_file_two" ascii
        $s2 = "visit_dirs_two" ascii
        $s3 = "valid_file_one" ascii
        $s4 = "Send an email to " ascii
        $s5 = { 48 B8 24 24 24 24 24 24 24 24 48 89 84 24 ?? 0? 00 00
                48 89 84 24 }

    condition:
        (uint32(0) == 0x464C457F) and
        (
            (4 of ($s*))
        )
}
