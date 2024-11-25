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

import base64
import xml.etree.ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Cipher import AES


NUM_MASTER_KEYS = 5


def get_rsa_key_component_value(element: ET.Element,
                                component_name: str) -> int | None:
    """Get RSA key component value"""

    el = element.find(component_name)
    if el is None:
        return None

    return int.from_bytes(base64.b64decode(el.text), byteorder='big')


def get_rsa_key_from_xml(key_xml_str: str,
                         is_private: bool) -> RSA.RsaKey | None:
    """Get RSA key from XML string"""

    root = ET.fromstring(key_xml_str)
    if root.tag != 'RSAKeyValue':
        return None

    # Public key
    n = get_rsa_key_component_value(root, 'Modulus')
    if n is None:
        return None
    e = get_rsa_key_component_value(root, 'Exponent')
    if e is None:
        return None

    if not is_private:
        return RSA.construct((n, e))

    # Private key
    p = get_rsa_key_component_value(root, 'P')
    if p is None:
        return None
    q = get_rsa_key_component_value(root, 'Q')
    if p is None:
        return None
    dp = get_rsa_key_component_value(root, 'DP')
    if dp is None:
        return None
    dq = get_rsa_key_component_value(root, 'DQ')
    if dq is None:
        return None
    iq = get_rsa_key_component_value(root, 'InverseQ')
    if iq is None:
        return None
    d = get_rsa_key_component_value(root, 'D')
    if d is None:
        return None

    # Check RSA key components (P, Q, DP, DQ)
    if (dp != d % (p - 1)) or (dq != d % (q - 1)):
        return None

    return RSA.construct((n, e, d, p, q))


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes | None:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA1)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def aes_gcm_decrypt(enc_data: bytes,
                    key: bytes, nonce: bytes,
                    tag: bytes) -> bytes | None:
    """AES GCM decrypt data"""

    cipher = AES.new(key, AES.MODE_GCM, nonce)

    try:
        return cipher.decrypt_and_verify(enc_data, tag)
    except ValueError:
        return None


def decrypt_session_key_data(enc_session_key_data: bytes,
    master_priv_keys: list[RSA.RsaKey]) -> tuple[bytes, bytes] | None:
    """Decrypt session key data"""

    # Decrypt system information
    priv_key = master_priv_keys[NUM_MASTER_KEYS - 1]
    rsa_key_size = priv_key.size_in_bytes()
    enc_data = enc_session_key_data[:rsa_key_size]
    sys_info = rsa_decrypt(enc_data, priv_key)
    if not sys_info:
        return None

    # Decrypt session private key
    pos = rsa_key_size
    session_key_data = b''

    for priv_key in master_priv_keys[:NUM_MASTER_KEYS - 1]:

        # Decrypt data chunk
        rsa_key_size = priv_key.size_in_bytes()
        enc_data_chunk = enc_session_key_data[pos : pos + rsa_key_size]
        data_chunk = rsa_decrypt(enc_data_chunk, priv_key)
        if not data_chunk:
            return None

        session_key_data += data_chunk
        pos += rsa_key_size

    return sys_info, session_key_data


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    # Load master private keys
    with io.open('./rsa_privkeys.txt', 'rt') as f:
        key_xml_list = f.read().splitlines()

    master_priv_keys = []

    for i in range(NUM_MASTER_KEYS):

        # Get RSA private key from XML string
        priv_key = get_rsa_key_from_xml(key_xml_list[i], True)
        if (priv_key is None) or not priv_key.has_private():
            print('Error: Invalid RSA private key XML string')
            sys.exit(1)

        master_priv_keys.append(priv_key)

    with io.open(filename, 'rb') as f:
        enc_session_key_data = base64.b64decode(f.read())

    # Decrypt session private key data
    session_key_data = decrypt_session_key_data(enc_session_key_data,
                                                master_priv_keys)
    if not session_key_data:
        print('Error: Failed to decrypt session private key')
        sys.exit(1)

    new_filename = filename + '.info'
    with io.open(new_filename, 'wb') as f:
        f.write(session_key_data[0])

    new_filename = filename + '.key'
    with io.open(new_filename, 'wb') as f:
        f.write(session_key_data[1])
