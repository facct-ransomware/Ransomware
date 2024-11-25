# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
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
from Crypto.Cipher import AES
import loki_crypt


RANSOM_EXT = '.BlackBit'


# AES GCM
KEY_SIZE = 32
NONCE_SIZE = 12
MAC_TAG_SIZE = 16


MIN_BIG_FILE_SIZE = 1572864

ENC_BLOCK_SIZE = 0x40000


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        metadata_size = priv_key.size_in_bytes()

        if file_size < metadata_size:
            return False

        file_size -= metadata_size

        # Read metadata
        f.seek(file_size)
        enc_metadata = f.read(metadata_size)

        # Decrypt metadata (RSA OAEP)
        metadata = loki_crypt.rsa_decrypt(enc_metadata, priv_key)
        if not metadata:
            print('RSA private key: Failed')
            return False

        print('RSA private key: OK')

        if file_size < MIN_BIG_FILE_SIZE:

            # Full
            key = metadata[:KEY_SIZE]
            nonce = metadata[KEY_SIZE : KEY_SIZE + NONCE_SIZE]
            tag = metadata[KEY_SIZE + NONCE_SIZE :
                           KEY_SIZE + NONCE_SIZE + MAC_TAG_SIZE]
            cipher = AES.new(key, AES.MODE_GCM, nonce)

            f.seek(0)

            size = file_size
            while size != 0:

                # Read block
                block_size = min(size, ENC_BLOCK_SIZE)
                enc_data = f.read(block_size)
                bytes_read = len(enc_data)
                if bytes_read == 0:
                    break

                # Decrypt block (AES GCM)
                data = cipher.decrypt(enc_data)

                # Write block
                f.seek(-bytes_read, 1)
                f.write(data)

                size -= bytes_read

            try:
                cipher.verify(tag)
            except ValueError:
                return False

        else:

            # Spot encryption
            block_positions = \
                [ 0,
                  (file_size // 2) - (ENC_BLOCK_SIZE // 2),
                  file_size - ENC_BLOCK_SIZE ]

            key_data_pos = 0

            for block_pos in block_positions:

                key = metadata[key_data_pos : key_data_pos + KEY_SIZE]
                key_data_pos += KEY_SIZE
                nonce = metadata[key_data_pos : key_data_pos + NONCE_SIZE]
                key_data_pos += NONCE_SIZE
                tag = metadata[key_data_pos : key_data_pos + MAC_TAG_SIZE]
                key_data_pos += MAC_TAG_SIZE

                # Read block
                f.seek(block_pos)
                enc_data = f.read(ENC_BLOCK_SIZE)

                # Decrypt block (AES GCM)
                data = loki_crypt.aes_gcm_decrypt(enc_data, key, nonce, tag)
                if not data:
                    return False

                # Write block
                f.seek(block_pos)
                f.write(data)

        # Remove metadata
        f.truncate(file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey.xml', 'rt') as f:
    key_xml_str = f.read()

# Get RSA private key from XML string
priv_key = loki_crypt.get_rsa_key_from_xml(key_xml_str, True)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key XML string')
    sys.exit(1)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
