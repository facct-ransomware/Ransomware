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
import base64
from Crypto.Cipher import AES


END_MARKER = b'U12H6AN=='


KEY_LEN = 32
NONCE_LEN = 12


def encode_and_encrypt(data: bytes,
                       key: bytes, nonce: bytes,
                       end_marker: bytes = b'') -> bytes:
    """Encode and encrypt data"""

    enc_data = base64.b64encode(data + end_marker)

    cipher = AES.new(key, AES.MODE_GCM, nonce)
    enc_data, tag = cipher.encrypt_and_digest(enc_data)
    enc_data += tag

    return base64.b64encode(enc_data)


def encrypt_data(data: bytes, key: bytes, nonces: bytes,
                 end_marker: bytes) -> bytes:
    """Encrypt data"""

    # Encode and encrypt data (stage 1)
    enc_data = encode_and_encrypt(data, key, nonces[:NONCE_LEN])

    # Encode and encrypt data (stage 2)
    return encode_and_encrypt(enc_data + enc_data, key, nonces[NONCE_LEN:],
                              END_MARKER)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

with io.open('./cfg_key.bin', 'rb') as f:
    key = f.read(KEY_LEN)

with io.open('./cfg_nonces.bin', 'rb') as f:
    nonces = f.read(2 * NONCE_LEN)

filename = sys.argv[1]
with io.open(filename, 'rb') as f:
    enc_data = f.read()

data = encrypt_data(enc_data, key, nonces, b'AppData')
if data is None:
    print('Failed to decrypt')
    sys.exit(1)

new_filename = filename + '.enc'
with io.open(new_filename, 'wb') as f:
    f.write(data)

print('Done!')
