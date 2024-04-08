# © 2023-2024 F.A.C.C.T. LLC. All Rights Reserved.

import sys
import os
import io


CFG_SEED = 0x673
CFG_MUL = 0x7FFFFFED
CFG_ADD = 0x7FFFFFC3
CFG_MOD = 0x7FFFFFFF


def decrypt_cfg_data(enc_data):
    """Decrypt configuration data"""

    data = bytearray(enc_data)

    n = CFG_SEED

    for i in range(len(data)):
        n = (((n * CFG_MUL) + CFG_ADD) & 0xFFFFFFFF) % CFG_MOD
        data[i] ^= n & 0xFF

    return data


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    enc_data = f.read()

data = decrypt_cfg_data(enc_data)

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(data)
