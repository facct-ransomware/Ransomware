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
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384


RANSOM_EXT = '.secles'

RANSOM_EXT_PREFIX = '.id['


ENC_MARKER1 = 0xB36BE7FE
ENC_MARKER2 = b'\xDC\x2D\x7F'


# x25519
X25519_KEY_SIZE = 32

# ChaCha20
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8


# Metadata
SETTINGS_SIZE = 3

METADATA1_MARKER_SIZE = 4
METADATA1_UNK1_SIZE = 4
METADATA1_ENCDATA_POS = METADATA1_MARKER_SIZE + METADATA1_UNK1_SIZE

METADATA3_SIZE = CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE + SETTINGS_SIZE
METADATA2_SIZE = METADATA3_SIZE + X25519_KEY_SIZE


FASTMODE_MAX_BLOCK_SIZE = 0x200000


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:
        # Read marker
        marker = int.from_bytes(f.read(4), byteorder='little')

    return (marker == ENC_MARKER1)


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA384)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def decrypt_file(filename: str, srsa_priv_key_data: bytes,
                 spriv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        rsa_priv_key = RSA.import_key(srsa_priv_key_data)
        rsa_key_size = rsa_priv_key.size_in_bytes()
        metadata1_size = METADATA1_ENCDATA_POS + rsa_key_size

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < metadata1_size + len(ENC_MARKER2):
            return False

        # Read metadata
        metadata1 = f.read(metadata1_size)

        marker, unk1 = struct.unpack_from('<2L', metadata1, 0)

        print('metadata size:', metadata1_size)
        print('marker: %08X' % marker)
        print('unknown 1:', unk1)

        # Decrypt metadata (RSA OAEP)
        enc_metadata2 = metadata1[METADATA1_ENCDATA_POS:
                                  METADATA1_ENCDATA_POS + rsa_key_size]
        metadata2 = rsa_decrypt(enc_metadata2, rsa_priv_key)
        if not metadata2:
            print('RSA private key: failed')
            return False

        print('RSA private key: OK')

        orig_file_size = file_size - (metadata1_size + len(ENC_MARKER2))
        print('original file size:', orig_file_size)

        enc_metadata3 = metadata2[:METADATA3_SIZE]
        pub_key_data = metadata2[METADATA3_SIZE:
                                 METADATA3_SIZE + X25519_KEY_SIZE]

        # Derive x25519 shared secret
        priv_key = X25519PrivateKey.from_private_bytes(spriv_key_data)
        pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
        shared_secret = priv_key.exchange(pub_key)

        # Derive metadata key and nonce
        metadata_key_data = hashlib.sha384(shared_secret).digest()
        metadata_key = metadata_key_data[:CHACHA_KEY_SIZE]
        metadata_n = metadata_key_data[CHACHA_KEY_SIZE:
                                       CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]

        # Decrypt encryption key and nonce
        metadata_nonce = 8 * b'\0' + metadata_n
        cipher = Cipher(algorithms.ChaCha20(metadata_key, metadata_nonce),
                        mode=None)
        decryptor = cipher.decryptor()
        metadata3 = decryptor.update(enc_metadata3)

        key = metadata3[:CHACHA_KEY_SIZE]
        nonce = metadata3[CHACHA_KEY_SIZE:
                          CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]

        skip_blocks = metadata3[CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]
        block_size_64k = metadata3[CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE + 1]
        block_size_4g = metadata3[CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE + 2]

        print('skip blocks:', skip_blocks)
        print('block size [64 KB]:', block_size_64k)
        print('block size [4 GB]:', block_size_4g)

        block_size = ((block_size_4g << 16) | block_size_64k) << 16
        block_space = 0

        if skip_blocks != 0:
            if block_size > FASTMODE_MAX_BLOCK_SIZE:
                block_size = FASTMODE_MAX_BLOCK_SIZE
            block_space = (skip_blocks + 1) * block_size
        if block_size > orig_file_size:
            block_size = orig_file_size

        # Decrypt data (ChaCha20)
        nonce = 8 * b'\0' + nonce
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()

        # Decrypt first block
        enc_data2 = f.read(block_size - metadata1_size)

        f.seek(orig_file_size)
        enc_data1 = f.read(metadata1_size)

        data = decryptor.update(enc_data1 + enc_data2)

        f.seek(0)
        f.write(data)

        # Decrypt blocks
        pos = block_size + block_space

        while pos < orig_file_size:

            # Decrypt block
            f.seek(pos)

            size = min(block_size, orig_file_size - pos)
            enc_data = f.read(size)
            if enc_data == b'':
                break

            data = decryptor.update(enc_data)

            f.seek(pos)
            f.write(data)

            pos += size + block_space

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
    srsa_priv_key_data = f.read()

with io.open('./sprivkey.bin', 'rb') as f:
    spriv_key_data = f.read()

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
if not decrypt_file(new_filename, srsa_priv_key_data, spriv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)
