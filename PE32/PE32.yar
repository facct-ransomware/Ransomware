/*
PE32 ransomware
*/


rule PE32
{
    meta:
        author = "rivitna"
        family = "ransomware.pe32"
        description = "PE32 ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "18e1ad78-b4f7-4a53-8c3c-78ace48fdc7f" ascii
        $s1 = "pe32spe32f" ascii
        $s2 = "context.pe32c" ascii
        $s3 = "pe32lockfile.lock" ascii
        $s4 = "lock.pe32" ascii
        $s5 = "PE32-KEY" ascii
        $s6 = "What drive do you want to encrypt:? (Empty means all)" ascii
        $s7 = "Staring UltraFast Round\n "ascii
        $s8 = "Fast Compeleted\n" ascii
        $s9 = "Slow Compeleted\n" ascii
        $s10 = "UltraFast Compeleted\n" ascii
        $s11 = "failed to resolve api.telegram.com" ascii
        $s12 = " (chunk_skip_v" ascii
        $s13 = "Slow max reached" ascii
        $s14 = "Base index exaustions" ascii
        $s15 = "struct EncryptionContext with " ascii
        $s16 = "struct RoundData with " ascii
        $s17 = "No key on aes_chain" ascii
        $s18 = "Encryption Context mismatch" ascii
        $s19 = "IvChainBytes Invalid len" ascii

        $h0 = { 4C 69 ?? AF 13 00 00 49 C1 ?? 18 4? 69 ?? FF F2 00 00 [4-8]
                66 81 E9 01 0D }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($s*)) or
            ((1 of ($h*)) and (3 of ($s*)))
        )
}
