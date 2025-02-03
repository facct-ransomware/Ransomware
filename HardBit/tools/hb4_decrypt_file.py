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
import struct
import shutil
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES


# AES CBC
AES_BLOCK_SIZE = 16
KEY_SIZE = 32
IV_SIZE = AES_BLOCK_SIZE

SALT = b'Ivan Medvedev'


# Footer
FOOTER_SIZE = 5 * 8


def derive_encryption_key(password: bytes) -> bytes:
    """Derive encryption key"""

    return PBKDF2(password, SALT, KEY_SIZE, 1000)


# PKCS #5 padding
pkcs5_unpad = lambda s: s[:-s[-1]]


def decrypt_aes_cbc(enc_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data (AES CBC)"""

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs5_unpad(cipher.decrypt(enc_data))


def decrypt_file(filename: str, key: bytes, iv: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_SIZE:
            return False

        # Read footer
        f.seek(-FOOTER_SIZE, 2)
        footer = f.read(FOOTER_SIZE)

        name_data_size, block2_size, orig_file_size, moved_data_size, \
            block1_size = struct.unpack_from('<5Q', footer, 0)

        print('file name data size:', name_data_size)
        print('block #2 size: %08X' % block2_size)
        print('original file size:', orig_file_size)
        print('moved data size:', moved_data_size)
        print('block #1 size: %08X' % block1_size)

        additional_data_size = name_data_size + moved_data_size
        footer_size = FOOTER_SIZE + additional_data_size

        # Check file size
        if ((file_size < footer_size + block2_size + block1_size) or
            (file_size < orig_file_size + footer_size)):
            return False

        # Read additional data
        f.seek(-footer_size, 2)
        additional_data = f.read(additional_data_size)

        # Original file name
        enc_name_data = additional_data[:name_data_size]
        name_data = decrypt_aes_cbc(enc_name_data, key, iv)
        orig_file_name = name_data.decode('UTF-16LE')
        print('original file name: \"%s\"' % orig_file_name)

        #Decrypt block 1
        f.seek(0)
        enc_data = f.read(block1_size)

        data = decrypt_aes_cbc(enc_data, key, iv)

        f.seek(0)
        f.write(data)

        if moved_data_size != 0:
            # Restore original data
            f.write(additional_data[name_data_size:])

        #Decrypt block 2
        block2_pos = block2_size + footer_size
        f.seek(-block2_pos, 2)

        enc_data = f.read(block2_size)

        data = decrypt_aes_cbc(enc_data, key, iv)
        if data != b'':
            f.seek(-block2_pos, 2)
            f.write(data)

        # Remove footer
        f.truncate(orig_file_size)

    # Restore original file name
    dest_filename = os.path.join(os.path.abspath(os.path.dirname(filename)),
                                 orig_file_name)
    if os.path.isfile(dest_filename):
        os.remove(dest_filename)
    os.rename(filename, dest_filename)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read password
with io.open('./password.txt', 'rb') as f:
    password = f.read()

# Read IV
with io.open('./iv.bin', 'rb') as f:
    iv = f.read(IV_SIZE)

# Derive encryption key
key = derive_encryption_key(password)

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, key, iv):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
