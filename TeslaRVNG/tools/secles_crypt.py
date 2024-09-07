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

import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384


# File markers
MARKER_SIZE = 2
# s-file marker
S_MARKER = b'\x2D\1'
# o-file marker
O_MARKER = b'\x56\1'


# Session key data
SESSION_KEYDATA_MARKER1 = b'>^'
SESSION_KEYDATA_MARKER2 = b'<~'
SESSION_KEYDATA_MARKER3 = b':A6N'
SESSION_KEYDATA_MARKER4 = b'Z5,'

VICTIM_ID_LEN = 20
SESSION_KEY_INDEX_SIZE = 4


# x25519
X25519_KEY_SIZE = 32

# AES GCM
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_KEYDATA_SIZE = AES_KEY_SIZE + AES_NONCE_SIZE
MAC_TAG_SIZE = 16

# ChaCha20
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8
CHACHA_KEYDATA_SIZE = CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE


MIN_SESSION_KEYDATA_SIZE = (len(SESSION_KEYDATA_MARKER1) + VICTIM_ID_LEN +
                            len(SESSION_KEYDATA_MARKER2) +
                            SESSION_KEY_INDEX_SIZE +
                            len(SESSION_KEYDATA_MARKER3) + X25519_KEY_SIZE +
                            len(SESSION_KEYDATA_MARKER4))


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA384)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def aes_gcm_decrypt(enc_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES GCM decrypt data"""

    if len(enc_data) < MAC_TAG_SIZE:
        return None

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, enc_data, None)
    except InvalidTag:
        return None


def chacha20_decrypt(enc_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """ChaCha20 decrypt data"""

    n = (16 - len(nonce)) * b'\0' + nonce
    cipher = Cipher(algorithms.ChaCha20(key, n), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(enc_data)


def derive_encryption_key_data(ecc_priv_key_data: bytes,
                               ecc_pub_key_data: bytes) -> bytes:
    """Derive encryption key data"""

    # Derive x25519 shared secret
    priv_key = X25519PrivateKey.from_private_bytes(ecc_priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(ecc_pub_key_data)
    shared_secret = priv_key.exchange(pub_key)

    # Derive encryption key data
    return hashlib.sha384(shared_secret).digest()


def decrypt_session_key_data(enc_session_key_data: bytes,
                             m_rsa_priv_key_data: bytes,
                             m_ecc_priv_key_data: bytes) -> bytes:
    """Decrypt session key data"""

    rsa_priv_key = RSA.import_key(m_rsa_priv_key_data)
    rsa_key_size = rsa_priv_key.size_in_bytes()

    if len(enc_session_key_data) < rsa_key_size:
        return None

    enc_aes_key_data = enc_session_key_data[-rsa_key_size:]
    enc_data1 = enc_session_key_data[:-rsa_key_size]

    # Decrypt AES GCM key and nonce
    aes_key_data = rsa_decrypt(enc_aes_key_data, rsa_priv_key)
    if not aes_key_data:
        return None

    # Decrypt data (AES GCM)
    aes_key = aes_key_data[:AES_KEY_SIZE]
    aes_nonce = aes_key_data[AES_KEY_SIZE : AES_KEYDATA_SIZE]
    enc_data2 = aes_gcm_decrypt(enc_data1, aes_key, aes_nonce)
    if not enc_data2 or (len(enc_data2) < X25519_KEY_SIZE):
        return None

    ecc_pub_key_data = enc_data2[-X25519_KEY_SIZE:]
    enc_data2 = enc_data2[:-X25519_KEY_SIZE]

    # Derive ChaCha20 key and nonce
    chacha_key_data = derive_encryption_key_data(m_ecc_priv_key_data,
                                                 ecc_pub_key_data)
    chacha_key = chacha_key_data[:CHACHA_KEY_SIZE]
    chacha_nonce = chacha_key_data[CHACHA_KEY_SIZE : CHACHA_KEYDATA_SIZE]

    # Decrypt data (ChaCha20)
    return chacha20_decrypt(enc_data2, chacha_key, chacha_nonce)


def parse_session_key_data(
    session_key_data: bytes,
    pos: int = 0) -> tuple[bytes, int, bytes, bytes] | None:
    """Parse session key data"""

    if pos + MIN_SESSION_KEYDATA_SIZE >= len(session_key_data):
        return None

    p2 = pos + len(SESSION_KEYDATA_MARKER1) + VICTIM_ID_LEN
    p3 = p2 + len(SESSION_KEYDATA_MARKER2) + SESSION_KEY_INDEX_SIZE
    p4 = p3 + len(SESSION_KEYDATA_MARKER3) + X25519_KEY_SIZE

    # Check markers
    m1 = session_key_data[pos : pos + len(SESSION_KEYDATA_MARKER1)]
    m2 = session_key_data[p2 : p2 + len(SESSION_KEYDATA_MARKER2)]
    m3 = session_key_data[p3 : p3 + len(SESSION_KEYDATA_MARKER3)]
    m4 = session_key_data[p4 : p4 + len(SESSION_KEYDATA_MARKER4)]
    if ((m1 != SESSION_KEYDATA_MARKER1) or
        (m2 != SESSION_KEYDATA_MARKER2) or
        (m3 != SESSION_KEYDATA_MARKER3) or
        (m4 != SESSION_KEYDATA_MARKER4)):
        return None

    victim_id = session_key_data[pos + len(SESSION_KEYDATA_MARKER1) : p2]
    key_index_data = session_key_data[p2 + len(SESSION_KEYDATA_MARKER2) : p3]
    key_index = int.from_bytes(key_index_data, byteorder='little')
    ecc_key = session_key_data[p3 + len(SESSION_KEYDATA_MARKER3) : p4]
    rsa_key = session_key_data[p4 + len(SESSION_KEYDATA_MARKER4):]
    return victim_id, key_index, ecc_key, rsa_key


def extract_s_session_keys(
    enc_data: bytes,
    rsa_priv_key_data: bytes,
    ecc_priv_key_data: bytes) -> list[bytes, int, bytes, bytes]:
    """Extract session keys from s-file"""

    # Decrypt session key data
    session_key_data = decrypt_session_key_data(enc_session_key_data,
                                                rsa_priv_key_data,
                                                ecc_priv_key_data)
    if not session_key_data:
        return []

    # Parse session key data
    session_keys = parse_session_key_data(session_key_data)
    if not session_keys:
        return []

    return [session_keys]


def extract_o_session_keys(
    enc_data: bytes,
    rsa_priv_key_data: bytes,
    ecc_priv_key_data: bytes) -> list[bytes, int, bytes, bytes]:
    """Extract session keys from o-file"""

    session_key_list = []

    while True:

        # Decrypt session key data
        session_key_data = decrypt_session_key_data(enc_data,
                                                    rsa_priv_key_data,
                                                    ecc_priv_key_data)
        if not session_key_data:
            break

        pos = len(session_key_data)

        while True:

            # Find marker 1
            pos = session_key_data.rfind(SESSION_KEYDATA_MARKER1, 0, pos)
            if pos < 0:
                return session_key_list

            # Parse session key data
            if pos + MIN_SESSION_KEYDATA_SIZE >= len(session_key_data):
                continue
            session_keys = parse_session_key_data(session_key_data, pos)
            if session_keys:
                session_key_list.append(session_keys)
                enc_data = session_key_data[:pos]
                break

    return session_key_list


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io
    import os
    import errno


    def mkdirs(dir):
        """Create directory hierarchy"""

        try:
            os.makedirs(dir)

        except OSError as exception:
            if (exception.errno != errno.EEXIST):
                raise

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    # Read master keys
    with io.open('./rsa_privkey0.bin', 'rb') as f:
        m_rsa_priv_key_data0 = f.read()
    with io.open('./ecc_privkey0.bin', 'rb') as f:
        m_ecc_priv_key_data0 = f.read()
    with io.open('./rsa_privkey1.bin', 'rb') as f:
        m_rsa_priv_key_data1 = f.read()
    with io.open('./ecc_privkey1.bin', 'rb') as f:
        m_ecc_priv_key_data1 = f.read()

    with io.open(filename, 'rb') as f:
        enc_session_key_data = f.read()

    # Check file marker
    marker = enc_session_key_data[-MARKER_SIZE:]
    if (marker != S_MARKER) and (marker != O_MARKER):
        print('Error: Invalid file marker')
        sys.exit(1)

    enc_session_key_data = enc_session_key_data[:-MARKER_SIZE]

    if marker == S_MARKER:
        # s-file
        session_key_list = extract_s_session_keys(enc_session_key_data,
                                                  m_rsa_priv_key_data0,
                                                  m_ecc_priv_key_data0)
    else:
        # o-file
        session_key_list = extract_o_session_keys(enc_session_key_data,
                                                  m_rsa_priv_key_data1,
                                                  m_ecc_priv_key_data1)

    if not session_key_list:
        print('Error: Failed to decrypt session keys')
        sys.exit(1)

    dest_dir = filename + '.keys/'
    mkdirs(dest_dir)

    for (victim_id, key_index, ecc_key, rsa_key) in session_key_list:

        key_filename = '%s_%08X_' % (victim_id.decode(), key_index)
        key_filepath = dest_dir + key_filename
        # Save X25519 private key
        with io.open(key_filepath + 'secc_privkey.bin', 'wb') as f:
            f.write(ecc_key)
        # Save RSA private key
        with io.open(key_filepath + 'srsa_privkey.bin', 'wb') as f:
            f.write(rsa_key)
