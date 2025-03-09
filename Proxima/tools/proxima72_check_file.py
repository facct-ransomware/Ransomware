# MIT License
#
# Copyright (c) 2025 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import sys
import io
import os
import struct


# Check Proxima/BlackShadow (72) encrypted file
# .Hercul, .Dominik, .Elons, .Abram, .Frank, .Funder, .Key2030, .Arthur,
# .Bpant, .Thomas, .innoken, .innok, .RealBer, .Contacto, .contac, .Xp64,
# .Louis


METADATA_PUBKEY_POS = 16
METADATA_PUBKEY_SIZE = 32
METADATA_PUBKEY_CRC_POS = 60
METADATA_SIZE = 72


# CRC32
CRC32_POLY = 0x4C11DB7
crc32_table = None


def create_crc32_table() -> list:
    """Create CRC32 table"""

    table = list(range(256))

    for i in range(256):
        x = i << 24
        for j in range(8):
            if x & 0x80000000:
                x = (x << 1) ^ CRC32_POLY
            else:
                x <<= 1
        table[i] = x & 0xFFFFFFFF

    return table


def crc32(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Get CRC32"""

    global crc32_table
    if not crc32_table:
        crc32_table = create_crc32_table()

    for b in data:
        crc = ((crc & 0xFFFFFF) << 8) ^ crc32_table[((crc >> 24) & 0xFF) ^ b]
    return crc


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

    pub_key_data = metadata[METADATA_PUBKEY_POS :
                            METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE]

    # Check public key CRC32
    pub_key_crc, = struct.unpack_from('<L', metadata,
                                      METADATA_PUBKEY_CRC_POS)
    return (pub_key_crc == crc32(pub_key_data))


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
res = is_file_encrypted(filename)
print('Footer:', 'OK' if res else 'Failed')
