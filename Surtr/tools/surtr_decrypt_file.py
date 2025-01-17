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
import shutil
from Crypto.PublicKey import RSA
import surtr_crypt
import hc128


RANSOM_EXT = '.Surtr'

RANSOM_SUFFIX_PREFIX = '.['
RANSOM_SUFFIX_POSTFIX = ']'


# RSA
RSA_KEY_SIZE = 128

# HC-128
KEY_SIZE = 32
IV_SIZE = 32


# Footer
ENC_MARKER1 = b'SURTR'
ENC_MARKER2 = b'****'
FOOTER_SIZE = len(ENC_MARKER1) + RSA_KEY_SIZE + len(ENC_MARKER2)


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_SIZE:
            return False

        # Read footer
        f.seek(-FOOTER_SIZE, 2)
        footer = f.read(FOOTER_SIZE)

        # Check footer markers
        if ((footer[:len(ENC_MARKER1)] != ENC_MARKER1) or
            (footer[-len(ENC_MARKER2):] != ENC_MARKER2)):
            return False

        orig_file_size = file_size - FOOTER_SIZE
        print('original file size:', orig_file_size)

        # Decrypt key data
        enc_key_data = footer[len(ENC_MARKER1):
                              len(ENC_MARKER1) + RSA_KEY_SIZE]
        key_data = surtr_crypt.rsa_decrypt(enc_key_data, priv_key)
        if not key_data:
            print('RSA private key: Failed')
            return False

        print('RSA private key: OK')

        # Decrypt data (HC-128)
        key = key_data[:KEY_SIZE]
        iv = key_data[KEY_SIZE : KEY_SIZE + IV_SIZE]
        cipher = hc128.HC128(key, iv)

        if orig_file_size <= 0x1400000:

            # Small/medium file
            if orig_file_size <= 0x100000:
                block_size = orig_file_size
                block_positions = [0]
            elif orig_file_size <= 0x500000:
                block_size = 0x70000
                block_positions = [0, orig_file_size - block_size]
            else:
                block_size = 0x100000
                block_step = (orig_file_size // 2) - 0x80000
                block_positions = [0, block_step, 2 * block_step]

            for pos in block_positions:

                # Decrypt block
                f.seek(pos)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                data = cipher.process_bytes(enc_data)

                f.seek(pos)
                f.write(data)

        else:
            
            # Large file
            num_blocks = orig_file_size // 0xA00000
            block_size = 0x100000
            block_step = 0xA00000

            for i in range(num_blocks):

                # Decrypt block
                if i != num_blocks - 1:
                    pos = i * block_step
                else:
                    pos = orig_file_size - block_size

                f.seek(pos)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                data = cipher.process_bytes(enc_data)

                f.seek(pos)
                f.write(data)

        # Remove footer
        f.truncate(orig_file_size)
        
    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read session private RSA key BLOB
with io.open('./sprivkey.bin', 'rb') as f:
    priv_key_blob = f.read()

# Get session private RSA key from BLOB
priv_key = surtr_crypt.rsa_construct_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

new_filename = None

# Get original file name
if filename.endswith(RANSOM_SUFFIX_POSTFIX + RANSOM_EXT):
    pos = filename.rfind(RANSOM_SUFFIX_POSTFIX + RANSOM_SUFFIX_PREFIX)
    if pos > 0:
        pos = filename.rfind(RANSOM_SUFFIX_PREFIX, 0, pos)
        if pos > 0:
            new_filename = filename[:pos]

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
