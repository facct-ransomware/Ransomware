# MIT License
#
# Copyright (c) 2024 Andrey Zhdanov (rivitna)
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
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA
import secles_crypt


RANSOM_EXT = '.secles'

RANSOM_EXT_PREFIX = '.id['


ENC_MARKER1 = 0xB36BE7FE
ENC_MARKER2 = b'\xDC\x2D\x7F'


# Metadata
SETTINGS_SIZE = 3

METADATA_MARKER_SIZE = 4
METADATA_SKEYINDEX_SIZE = 4
METADATA_ENCDATA_POS = METADATA_MARKER_SIZE + METADATA_SKEYINDEX_SIZE

METADATA2_SIZE = secles_crypt.CHACHA_KEYDATA_SIZE + SETTINGS_SIZE


FASTMODE_MAX_BLOCK_SIZE = 0x200000


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:
        # Read marker
        marker1 = int.from_bytes(f.read(4), byteorder='little')
        if marker1 != ENC_MARKER1:
            return False

        f.seek(-len(ENC_MARKER2), 2)
        marker2 = f.read(len(ENC_MARKER2))

    return (marker2 == ENC_MARKER2)


def decrypt_file(filename: str,
                 s_rsa_priv_key_data: bytes,
                 s_ecc_priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        rsa_priv_key = RSA.import_key(s_rsa_priv_key_data)
        rsa_key_size = rsa_priv_key.size_in_bytes()

        metadata_size = METADATA_ENCDATA_POS + rsa_key_size

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < metadata_size + len(ENC_MARKER2):
            return False

        # Read metadata
        metadata = f.read(metadata_size)

        marker, s_key_index = struct.unpack_from('<2L', metadata, 0)

        print('metadata size:', metadata_size)
        print('marker: %08X' % marker)
        print('session key index:', s_key_index)

        # Decrypt metadata (RSA OAEP)
        enc_data1 = metadata[METADATA_ENCDATA_POS:
                             METADATA_ENCDATA_POS + rsa_key_size]
        enc_data2 = secles_crypt.rsa_decrypt(enc_data1, rsa_priv_key)
        if not enc_data2:
            print('RSA private key: failed')
            return False

        print('RSA private key: OK')

        orig_file_size = file_size - (metadata_size + len(ENC_MARKER2))
        print('original file size:', orig_file_size)

        enc_metadata2 = enc_data2[:METADATA2_SIZE]
        ecc_pub_key_data = enc_data2[METADATA2_SIZE:
                                     METADATA2_SIZE +
                                     secles_crypt.X25519_KEY_SIZE]

        # Derive metadata key and nonce
        metadata_key_data = \
            secles_crypt.derive_encryption_key_data(s_ecc_priv_key_data,
                                                    ecc_pub_key_data)
        metadata_key = metadata_key_data[:secles_crypt.CHACHA_KEY_SIZE]
        metadata_n = metadata_key_data[secles_crypt.CHACHA_KEY_SIZE:
                                       secles_crypt.CHACHA_KEYDATA_SIZE]

        # Decrypt metadata 2
        metadata2 = secles_crypt.chacha20_decrypt(enc_metadata2,
                                                  metadata_key, metadata_n)
        # Parse metadata 2
        key = metadata2[:secles_crypt.CHACHA_KEY_SIZE]
        n = metadata2[secles_crypt.CHACHA_KEY_SIZE:
                      secles_crypt.CHACHA_KEYDATA_SIZE]
        skip_blocks, block_size_64k = \
            struct.unpack_from('<BH', metadata2,
                               secles_crypt.CHACHA_KEYDATA_SIZE)

        print('skip blocks:', skip_blocks)
        print('block size [64 KB]:', block_size_64k)

        block_size = block_size_64k << 16
        block_space = 0

        if skip_blocks != 0:
            if block_size > FASTMODE_MAX_BLOCK_SIZE:
                block_size = FASTMODE_MAX_BLOCK_SIZE
            block_space = skip_blocks * block_size
        if block_size > orig_file_size:
            block_size = orig_file_size

        # Decrypt file data (ChaCha20)
        nonce = (16 - len(n)) * b'\0' + n
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()

        # Decrypt first block
        if block_size <= metadata_size:
            enc_data = f.read(block_size)
        else:
            enc_data2 = f.read(block_size - metadata_size)
            f.seek(orig_file_size)
            enc_data1 = f.read(metadata_size)
            enc_data = enc_data1 + enc_data2

        data = decryptor.update(enc_data)

        f.seek(0)
        f.write(data)

        # Decrypt middle blocks
        pos = block_size + block_space
        if (skip_blocks != 0) and (orig_file_size > block_size):
            stop_pos = orig_file_size - block_size
        else:
            stop_pos = orig_file_size

        while pos < stop_pos:

            # Decrypt block
            f.seek(pos)

            size = min(block_size, stop_pos - pos)
            enc_data = f.read(size)
            if enc_data == b'':
                break

            data = decryptor.update(enc_data)

            f.seek(pos)
            f.write(data)

            pos += block_size + block_space

        if (skip_blocks != 0) and (orig_file_size > block_size):
            # Decrypt last block

            if orig_file_size >= 2 * block_size:
                pos = orig_file_size - block_size
                size = block_size
            else:
                pos = block_size
                size = orig_file_size - block_size

            f.seek(pos)
            enc_data = f.read(size)

            data = decryptor.update(enc_data)

            f.seek(pos)
            f.write(data)

        # Remove metadata
        f.truncate(orig_file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
if not is_file_encrypted(filename):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

with io.open('./srsa_privkey.bin', 'rb') as f:
    s_rsa_priv_key_data = f.read()

with io.open('./secc_privkey.bin', 'rb') as f:
    s_ecc_priv_key_data = f.read()

# Get original file name
new_filename = None

if filename.endswith(RANSOM_EXT):

    pos = filename.rfind(RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, s_rsa_priv_key_data, s_ecc_priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)
