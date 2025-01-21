/*
Surtr ransomware
*/


rule Surtr
{
    meta:
        author = "rivitna"
        family = "ransomware.surtr"
        description = "Surtr ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "BgIAAACkAABSU0Ex" ascii
        $s1 = "RSA Encrypt -( %s )failed: 0x%08x\n" ascii
        $s2 = "RSA initialization and KEYGEN-( %s )failed: 0x%08x\n" ascii
        $s3 = "hPUB_C key import failed :  %s\n" ascii
        $s4 = "\x00PUBLIC KEY BASE64 " ascii
        $s5 = "\n\tRunning in safemode is enabled ...\n\n" ascii
        $s6 = "\x00nocloseprocesses\x00" ascii
        $s7 = "\x00nowindowshide\x00" ascii
        $s8 = "\x00runinsafemode\x00" ascii
        $s9 = " find or Gen\n" ascii
        $s10 = "\",\"cryptstatus\":\"Complete\"}" ascii
        $s11 = "SurtrRansomware" wide
        $s12 = "SurtrMUTEX" wide
        $s13 = "SURTR_README." wide
        $s14 = "NoRunAnyWay" wide
        $s15 = "C:\\ProgramData\\Service\\" wide
        $s16 = "VeeamEnterpriseManagerSvc" wide
        $s17 = "McAfeeFrameworkMcAfeeFramework" wide
        $s18 = "User is Banned, do not try again" wide
        $s19 = "WARNING. Self Protection Is Enable." wide
        $s20 = "WARNING. SandBox/Debugger Detected!!!" wide
        $s21 = "Analyzer Proccess Detected !!!" wide

        $h0 = { C1 C0 09 C1 CA 0A 33 D0 8B 8? [2] 00 00 C1 C8 08 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            ((1 of ($h*)) and (5 of ($s*))) or
            (8 of ($s*))
        )
}
