/*
LokiLocker/BlackBit ransomware
*/

import "pe"


rule LokiLocker_obfuscation
{
    meta:
        author = "rivitna"
        company = "F.A.C.C.T."
        family = "ransomware.lokilocker"
        description = "LokiLocker/BlackBit ransomware Windows"
        severity = 7
        score = 70

    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and
        (filesize > 400000) and (filesize < 540000) and
        ((pe.checksum == 0x00023BFB) or
         (pe.timestamp == 0x5000A574) or
         ((pe.data_directories[6].size == 28) and
          (uint32(pe.rva_to_offset(pe.data_directories[6].virtual_address) + 4)
           == 0x5000A574))) and
        (pe.resources[0].type == pe.RESOURCE_TYPE_RCDATA) and
        (pe.resources[0].name_string == "_\x00_\x00") and
        (pe.resources[0].length > 250000) and
        (pe.resources[0].length < 400000) and
        (pe.resources[1].type == pe.RESOURCE_TYPE_RCDATA) and
        (pe.resources[1].name_string == "~\x00") and
        (pe.resources[1].length == 32)
}
