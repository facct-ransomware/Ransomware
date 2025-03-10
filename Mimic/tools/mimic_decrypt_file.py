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
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


RANSOM_EXT = '.xxxxxxxxxx'


# Encryption marker
ENC_MARKER = b'iskey\0'


# HKDF info
HKDF_INFO = b'DontDecompileMePlease'


# x25519
X25519_KEY_SIZE = 32

# ChaCha20
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 12
CHACHA_COUNTER = b'\1\0\0\0'
CHACHA_NONCE = CHACHA_COUNTER + b'\0' * CHACHA_NONCE_SIZE
ENCODED_KEY_LEN = 43


# Metadata
METADATA_PERCFORFILES_POS = 0
METADATA_PERCFORFILES_SIZE = 1
METADATA_FOOTERSIZE_POS = (METADATA_PERCFORFILES_POS +
                           METADATA_PERCFORFILES_SIZE)
METADATA_FOOTERSIZE_SIZE = 1
METADATA_PUBKEY_POS = METADATA_FOOTERSIZE_POS + METADATA_FOOTERSIZE_SIZE
METADATA_ENCKEY_POS = METADATA_PUBKEY_POS + X25519_KEY_SIZE
METADATA_FILESIZE_POS = METADATA_ENCKEY_POS + CHACHA_KEY_SIZE
METADATA_FILESIZE_SIZE = 8
METADATA_ENCPERCENT_POS = METADATA_FILESIZE_POS + METADATA_FILESIZE_SIZE
METADATA_ENCPERCENT_SIZE = 1
METADATA_VER_POS = METADATA_ENCPERCENT_POS + METADATA_ENCPERCENT_SIZE
METADATA_VER_SIZE = 1
METADATA_ENCMARKER_POS = METADATA_VER_POS + METADATA_VER_SIZE
METADATA_ENCMARKER_SIZE = len(ENC_MARKER)
METADATA_SIZE = METADATA_ENCMARKER_POS + METADATA_ENCMARKER_SIZE


V2_PART_MIN_FILE_SIZE = 0x3200000
V3_MIN_BIG_FILE_SIZE = 0xA00000
ENC_BLOCK_SIZE1 = 0x80000
ENC_BLOCK_SIZE2 = 0x100000
MAX_ENC_BLOCK_SIZE = 0x800000


def derive_encryption_key(priv_key_data: bytes,
                          pub_key_data: bytes) -> bytes:
    """Derive encryption key"""

    # Derive x25519 shared secret
    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)

    # Derive encryption key (HKDF)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=CHACHA_KEY_SIZE,
                salt=None, info=HKDF_INFO)
    return hkdf.derive(shared_secret)


def chacha20_decrypt(enc_data: bytes, key: bytes) -> bytes:
    """ChaCha20 decrypt data"""

    cipher = Cipher(algorithms.ChaCha20(key, CHACHA_NONCE), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(enc_data)


def get_checksum(s: bytes):
    """Get data checksum"""

    n = 0.
    for i, b in enumerate(s):
        if b >= 128:
            b = b - 256
        n += b * (0.00001 if (i & 1 == 0) else 0.0001)
    return n


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Derive metadata encryption key
        pub_key_data = metadata[METADATA_PUBKEY_POS:
                                METADATA_PUBKEY_POS + X25519_KEY_SIZE]
        metadata_key = derive_encryption_key(priv_key_data, pub_key_data)

        # Decrypt and check encryption marker
        enc_m_data = metadata[METADATA_ENCMARKER_POS:
                              METADATA_ENCMARKER_POS +
                              METADATA_ENCMARKER_SIZE]
        marker = chacha20_decrypt(enc_m_data, metadata_key)
        if marker != ENC_MARKER:
            print('encryption marker: failed')
            return False

        print('encryption marker: OK')

        # Decrypt data encryption key
        enc_k_data = metadata[METADATA_ENCKEY_POS:
                              METADATA_ENCKEY_POS + CHACHA_KEY_SIZE]
        key = chacha20_decrypt(enc_k_data, metadata_key)

        # Decrypt original file size
        enc_fs_data = metadata[METADATA_FILESIZE_POS:
                               METADATA_FILESIZE_POS +
                               METADATA_FILESIZE_SIZE]
        fs_data = chacha20_decrypt(enc_fs_data, metadata_key)
        orig_file_size = int.from_bytes(fs_data, byteorder='little')
        print('original file size:', orig_file_size)

        # Decrypt encryption percent
        enc_p_data = metadata[METADATA_ENCPERCENT_POS:
                              METADATA_ENCPERCENT_POS +
                              METADATA_ENCPERCENT_SIZE]
        p_data = chacha20_decrypt(enc_p_data, metadata_key)
        enc_percent = p_data[0]
        print('encryption percent:', enc_percent)

        # Decrypt version
        enc_ver_data = metadata[METADATA_VER_POS:
                                METADATA_VER_POS + METADATA_VER_SIZE]
        ver_data = chacha20_decrypt(enc_ver_data, metadata_key)
        ver = ver_data[0]
        print('version:', chr(ver))

        if ver >= 0x33:

            # Version 3 or above

            # Decrypt footer size
            enc_fts_data = metadata[METADATA_FOOTERSIZE_POS:
                                    METADATA_FOOTERSIZE_POS +
                                    METADATA_FOOTERSIZE_SIZE]
            fts_data = chacha20_decrypt(enc_fts_data, metadata_key)
            footer_size = fts_data[0]
            print('footer size:', footer_size)

            # Decrypt percent for files [MB]
            enc_pff_data = metadata[METADATA_PERCFORFILES_POS:
                                    METADATA_PERCFORFILES_POS +
                                    METADATA_PERCFORFILES_SIZE]
            pff_data = chacha20_decrypt(enc_pff_data, metadata_key)
            perc_for_files = pff_data[0]
            print('% for files [MB]:', perc_for_files)

            part_min_file_size = perc_for_files << 20

        else:

            # Version 1, 2
            part_min_file_size = V2_PART_MIN_FILE_SIZE

        if orig_file_size < part_min_file_size:

            # Solid
            print('mode: solid')

            pos = 0

            while pos < orig_file_size:

                # Decrypt block
                size = min(MAX_ENC_BLOCK_SIZE, orig_file_size - pos)

                f.seek(pos)
                enc_data = f.read(size)
                if enc_data == b'':
                    break

                data = chacha20_decrypt(enc_data, key)

                f.seek(pos)
                f.write(data)

                pos += size

        else:

            # Part
            print('mode: part')

            if (ver >= 0x33) and (orig_file_size < V3_MIN_BIG_FILE_SIZE):
                block_size1 = ENC_BLOCK_SIZE1
            else:
                block_size1 = ENC_BLOCK_SIZE2

            # Decrypt first block
            f.seek(0)
            enc_data = f.read(block_size1)

            data = chacha20_decrypt(enc_data, key)

            f.seek(0)
            f.write(data)

            # Decrypt middle blocks
            key_b64 = base64.urlsafe_b64encode(key)[:ENCODED_KEY_LEN]
            x = get_checksum(key_b64)

            rem_size = orig_file_size - 2 * block_size1
            n = 2 * (rem_size >> 24) + 1
            num_blocks = int(((int(n / 0.6) - n) + 1) * (x * 1.4) + n)
            part_size = rem_size // num_blocks
            enc_part_size = (part_size * enc_percent) // 100
            min_block_size = int(enc_part_size * 0.85)
            max_block_size = 2 * enc_part_size - min_block_size
            if max_block_size > part_size:
                max_block_size = part_size
                min_block_size = 2 * enc_part_size - part_size

            for i in range(num_blocks):

                # Decrypt block
                j = i
                if j > ENCODED_KEY_LEN:
                    j = (j % ENCODED_KEY_LEN) - 1
                if j <= 0:
                    j = 1
                x = get_checksum(key_b64[ENCODED_KEY_LEN - j:]) * 1.4
                size = min(MAX_ENC_BLOCK_SIZE,
                           int(min_block_size +
                               (max_block_size - min_block_size + 1) * x))
                pos = int(part_size * i + block_size1 +
                          x * (part_size - size + 1))
                size = min(size, orig_file_size - pos)

                f.seek(pos)
                enc_data = f.read(size)
                if enc_data == b'':
                    break

                data = chacha20_decrypt(enc_data, key)

                f.seek(pos)
                f.write(data)

            # Decrypt last block
            pos = orig_file_size - block_size1
            f.seek(pos)
            enc_data = f.read(block_size1)

            data = chacha20_decrypt(enc_data, key)

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

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
