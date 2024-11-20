/*
Mimic ransomware
*/


rule Mimic
{
    meta:
        author = "rivitna"
        family = "ransomware.mimic.windows"
        description = "Mimic ransomware"
        severity = 10
        score = 100

    strings:
        $s0 = "iskey\x00" ascii
        $s1 = "\x00DontDecompileMePlease\x00" ascii
        $s2 = "\x00session.tmp\x00" ascii
        $s3 = "\x00Keys array %32!=0\x00" ascii
        $s4 = "ID_PLACEHOLDER" ascii xor(0xFF)
        $s5 = "Creative Cloud;dbeng50;dbsnmp;encsvc;" ascii xor(0xFF)
        $s6 = "AcronisAgent;ARSM;backup;BackupExecAgent" ascii xor(0xFF)
        $s7 = "MSSQL$KAV_CS_ADMIN_KIT" ascii xor(0xFF)
        $s8 = "zip;rar;" ascii xor(0xFF)
        $s9 = "\x00Mimic " wide
        $s10 = "[+] Shadow copy is deleted: %s" wide
        $s11 = "[-] Failed to delete Shadow copy. HRESULT = %i" wide
        $s12 = "-e watch -pid " wide
        $s13 = "[*] ======= Repeat scan once more..." wide
        $s14 = "[*] CLONE INFO: I'm " wide
        $s15 = "] Auto-elevation " wide
        $s16 = "\\Everything" wide
        $s17 = "[-] Everything " wide
        $s18 = "[-] Exception in SetPrivilegeAll. Code %lu." wide
        $s19 = "[-] Can't remove R/O attribute, file %s! Code %lu" wide

        $h0 = { E0 3F 33 33 33 33 33 33 E3 3F 33 33 33 33 33 33 EB 3F
                66 66 66 66 66 66 F6 3F }
        $h1 = { 68 03 10 00 00 68 00 04 00 00 6A FF 5? E8 [4] 6A 00 6A 20
                68 04 10 00 00 68 00 04 00 00 6A FF 5? E8 [4] 5? 6A 20
                68 05 10 00 00 68 00 04 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (filesize > 1000KB) and (filesize < 10000KB) and
        (
            (7 of them)
        )
}


rule Mimic_dropper
{
    meta:
        author = "rivitna"
        family = "ransomware.mimic.windows"
        description = "Mimic ransomware dropper"
        severity = 10
        score = 100

    strings:
       $h = { 37 7A 61 2E 65 78 65 20 78 20 2D 79 20 2D 70
              3? 3? 3? 3? [8-12] 3? 3? 3? 3?
              20 45 76 65 72 79 74 68 69 6E 67 36 34 2E 64 6C 6C 22 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (filesize > 1500KB) and (filesize < 10000KB) and
        (
            $h in (100000..(filesize - 1000000))
        )
}
