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

import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA1)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def decrypt_session_key_data(enc_session_key_data: bytes,
                             master_priv_key_data: bytes) -> bytes:
    """Decrypt session key data"""

    master_priv_key = RSA.import_key(master_priv_key_data)
    rsa_key_size = master_priv_key.size_in_bytes()

    enc_data = b''

    # Decode Base64
    lines = enc_session_key_data.splitlines()
    for l in lines:
        enc_data += base64.b64decode(l)

    num_chunks, rem = divmod(len(enc_data), rsa_key_size)
    if (num_chunks == 0) or (rem != 0):
        return None

    key_data = b''

    # Decrypt session key chunks
    for enc_chunk in (enc_data[i : i + rsa_key_size] for i
                      in range(0, len(enc_data), rsa_key_size)):
        # Decrypt session key chunk
        chunk = rsa_decrypt(enc_chunk, master_priv_key)
        if not chunk:
            return None
        key_data += chunk
        if chunk[-1] != 0x0A:
            key_data += b'\n'

    return key_data


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io
    import os
    import base64

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('./rsa_privkey.txt', 'rt') as f:
        master_priv_key_data = base64.b64decode(f.read())

    with io.open(filename, 'rb') as f:
        enc_session_key_data = f.read()

    # Decrypt session private key data
    session_key_data = decrypt_session_key_data(enc_session_key_data,
                                                master_priv_key_data)
    if not session_key_data:
        print('Error: Failed to decrypt session private key')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(session_key_data)
