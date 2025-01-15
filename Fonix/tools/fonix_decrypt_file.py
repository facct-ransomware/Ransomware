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
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
import fonix_crypt


RANSOM_EXT1 = '.RYK'
RANSOM_EXT2 = '.RYKCRYPT'

RANSOM_SUFFIX_PREFIX = '.['
RANSOM_SUFFIX_POSTFIX = ']'


# Footer
ENC_MARKER1 = b'HERMES'
ENC_MARKER2 = b'##'


# Archive and database file extensions
IMPORTANT_FILE_EXTS = (
    '.MDF', '.SQL', '.EDB', '.TXT', '.VHD', '.VBK', '.VIB', '.VBM', '.VLB',
    '.VSM', '.VOM', '.BAK', '.BACK', '.ORG', '.NBF', '.NBA', '.SET', '.MBK',
    '.NCO', '.GHO', '.DAT_OLD', '.ADI', '.TRN', '.BKP', '.PBD', '.XML',
    '.VHDX', '.VDX', '.BACKUP', '.BMS', '.HM4', '.DBK', '.BAC', '.FDB',
    '.ACCDB', '.ACCDC', '.ADB', '.ACCDE', '.ADF', '.DB-JOURNAL', '.DB-SHM',
    '.DB-WAL', '.DB1', '.DB2', '.DB3', '.DBC', '.LDF', '.4DD', '.ADT', '.DB',
    '.DBF', '.DTA', '.GDB', '.GTABLE', '.MYD', '.SDF', '.SQLITE', '.WDB',
    '.WMDB', '.MYOB', '.TAX', '.YNAB', '.MYO', '.QBW', '.QBB', '.QBM',
    '.QBO', '.001', '.002', '.003', '.PDF', '.DOC', '.DOCM', '.DOCX',
    '.DOTX', '.DOTM', '.ODT', '.XLS', '.XLSX', '.XLSM', '.XLTX', '.XLTM',
    '.XLAM', '.XLSB', '.ODS', '.PPT', '.PPTX', '.PPTM', '.PTOX', '.POTM',
    '.PPSX', '.PPSM', '.ODP', '.XML'
)


# Salsa20 / ChaCha20
NONCE_SIZE = 8


HEADER_ENC_MAX_SIZE = 300000
VIP_BLOCK_SIZE = 20000
VIP_BLOCK_STEP = 800000


MIN_BASE64_LINE_LEN = 64


def is_important_file_ext(filename: str) -> bool:
    """Check if the file extension is important"""

    fname = os.path.basename(filename).upper()
    return fname.endswith(IMPORTANT_FILE_EXTS)


def decrypt_file(filename: str, partly_enc: bool,
                 priv_key_data: bytes) -> bool:
    """Decrypt file"""

    priv_key = RSA.import_key(priv_key_data)
    rsa_key_size = priv_key.size_in_bytes()

    min_enc_key_size = ((rsa_key_size + 2) // 3) * 4
    max_num_line_feeds = ((min_enc_key_size + (MIN_BASE64_LINE_LEN - 1)) //
                          MIN_BASE64_LINE_LEN)
    min_footer_size = (len(ENC_MARKER1) + len(ENC_MARKER2) +
                       2 * min_enc_key_size)
    max_footer_size = min_footer_size + 2 * max_num_line_feeds

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < min_footer_size:
            return False

        # Read footer
        try:
            f.seek(-max_footer_size, 2)
        except OSError:
            f.seek(0)

        footer = f.read()
        if not footer.endswith(ENC_MARKER2):
            return False

        pos = footer.find(ENC_MARKER1)
        if pos < 0:
            return False

        enc_key_data = footer[pos + len(ENC_MARKER1) : -len(ENC_MARKER2)]
        if len(enc_key_data) % 2 != 0:
            return False

        footer_size = len(footer) - pos
        print('footer size:', footer_size)

        orig_file_size = file_size - footer_size
        print('original file size:', orig_file_size)

        # Decrypt key
        enc_key = base64.b64decode(enc_key_data[:len(enc_key_data) // 2])
        key = fonix_crypt.rsa_decrypt(enc_key, priv_key)
        if not key:
            print('RSA private key: Failed')
            return False

        # Decrypt nonce
        enc_nonce = base64.b64decode(enc_key_data[len(enc_key_data) // 2:])
        nonce = fonix_crypt.rsa_decrypt(enc_nonce, priv_key)
        if not nonce:
            print('RSA private key: Failed')
            return False

        print('RSA private key: OK')

        n = nonce[:NONCE_SIZE]

        # Decrypt data
        if not partly_enc:

            # Mode: full / header
            if orig_file_size <= HEADER_ENC_MAX_SIZE:
                # mode: header, ChaCha20
                print('mode: full, chacha20')
                enc_size = orig_file_size
                cipher = ChaCha20.new(key=key, nonce=n)
            else:
                # mode: full, Salsa20
                print('mode: header, salsa20')
                enc_size = HEADER_ENC_MAX_SIZE
                cipher = Salsa20.new(key=key, nonce=n)

            f.seek(0)
            enc_data = f.read(enc_size)

            data = cipher.decrypt(enc_data)

            f.seek(0)
            f.write(data)

        else:

            # Mode: partly
            if is_important_file_ext(filename):

                # Important file
                print('mode: partly, chacha20')

                cipher = ChaCha20.new(key=key, nonce=n)

                pos = 0
                while pos < orig_file_size:

                    block_size = min(VIP_BLOCK_SIZE, orig_file_size - pos)

                    f.seek(pos)
                    enc_data = f.read(block_size)
                    if enc_data == b'':
                        break

                    data = cipher.decrypt(enc_data)

                    f.seek(pos)
                    f.write(data)

                    pos += VIP_BLOCK_STEP

            else:

                # Decrypt first and last blocks
                print('mode: partly, salsa20')

                block_size = int(orig_file_size * 0.02)
                block_positions = [0, orig_file_size - block_size]

                cipher = Salsa20.new(key=key, nonce=n)

                for pos in block_positions:

                    f.seek(pos)
                    enc_data = f.read(block_size)

                    data = cipher.decrypt(enc_data)

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

with io.open('./sprivkey.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

# Check ransom extension
if filename.endswith(RANSOM_EXT1):
    partly_enc = False
    ransom_ext = RANSOM_EXT1
elif filename.endswith(RANSOM_EXT2):
    partly_enc = True
    ransom_ext = RANSOM_EXT2
else:
    print('Error: Unknown ransom extension')
    sys.exit(1)

new_filename = None

# Get original file name
if filename.endswith(RANSOM_SUFFIX_POSTFIX + ransom_ext):
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
if not decrypt_file(new_filename, partly_enc, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
