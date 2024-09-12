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
import errno
import struct


DEFAULT_VER = '6.3'


# Fields
FIELD_UNKNOWN = 0
FIELD_STR = 1
FIELD_TEXT = 2
FIELD_UINT8 = 3
FIELD_UINT32 = 4
FIELD_KEYARRAY = 5
FIELD_SETTINGS = 6

FIELD_EXT = 'extension'
FIELD_NOTE = 'note'
FIELD_NOTE_NAME = 'note name'
FIELD_LOCKER_NAME = 'locker name'

FIELDS = [
    ( FIELD_EXT,              FIELD_STR ),
    ( FIELD_NOTE,             FIELD_TEXT ),
    ( 'encrypt percent',      FIELD_UINT8 ),
    ( 'priority_extens',      FIELD_TEXT ),
    ( 'black_processes',      FIELD_TEXT ),
    ( 'black_services',       FIELD_TEXT ),
    ( 'white_extens',         FIELD_TEXT ),
    ( 'white_files',          FIELD_TEXT ),
    ( 'white_folders',        FIELD_TEXT ),
    ( 'exec_commands',        FIELD_TEXT ),
    ( FIELD_NOTE_NAME,        FIELD_STR ),
    ( 'file max size [KB]',   FIELD_UINT32 ),
    ( 'process max RAM [MB]', FIELD_UINT32 ),
    ( 'settings',             FIELD_SETTINGS ),
    ( FIELD_LOCKER_NAME,      FIELD_STR ),
    ( 'key_array',            FIELD_KEYARRAY ),
]


# Settings
SETTING_UNKNOWN = 0
SETTING_BOOL = 1
SETTING_UINT8 = 2

SETTING_PRIORITY_MODIFY =   ( 'priority modify',        SETTING_BOOL )
SETTING_SELF_DELETE =       ( 'self delete',            SETTING_BOOL )
SETTING_LOG_LEVEL =         ( 'log level',              SETTING_UINT8 )
SETTING_LOG_CHECKSUM =      ( 'log check sum',          SETTING_BOOL )
SETTING_DISABLE_DEFENDER =  ( 'disable defender',       SETTING_BOOL )
SETTING_SKIP_NETWORK =      ( 'skip network',           SETTING_BOOL )
SETTING_ENCR_SHARE =        ( 'encrypt share',          SETTING_BOOL )
SETTING_ENCR_NET_PRIO =     ( 'encrypt net prio',       SETTING_BOOL )
SETTING_ENCR_NET_DRIVE =    ( 'encrypt net drive',      SETTING_BOOL )
SETTING_ENCR_HID_FOLDERS =  ( 'encrypt hidden folders', SETTING_BOOL )
SETTING_PERC_FOR_FILES =    ( '% for files [MB]',       SETTING_UINT8 )
SETTING_WIPE_PARALLEL =     ( 'wipe parallel',          SETTING_BOOL )
SETTING_WIPE_DRIVES =       ( 'wipe drives',            SETTING_BOOL )
SETTING_DEL_LOG =           ( 'delete log at end',      SETTING_BOOL )
SETTING_RESERVE_MODE =      ( 'reserve mode',           SETTING_UINT8 )
SETTING_GUI_MODE =          ( 'gui mode',               SETTING_BOOL )
SETTING_APPEND_KEY_TO_EXT = ( 'append key to ext',      SETTING_BOOL )

# Reserve mode
RESERVE_MODES = {
    0: 'None',
    1: 'Partial',
    2: 'Full',
}

# v4.0
SETTINGS_V40 = [
    SETTING_PRIORITY_MODIFY,
    SETTING_SKIP_NETWORK,
    SETTING_SELF_DELETE,
    SETTING_LOG_CHECKSUM,
    SETTING_LOG_LEVEL
]

# v4.2
SETTINGS_V42 = [ SETTING_WIPE_PARALLEL ] + SETTINGS_V40

# v4.3
SETTINGS_V43 = [
    SETTING_WIPE_PARALLEL,
    SETTING_PRIORITY_MODIFY,
    SETTING_ENCR_SHARE,
    SETTING_ENCR_NET_DRIVE,
    SETTING_ENCR_NET_PRIO,
    SETTING_SELF_DELETE,
    SETTING_LOG_CHECKSUM,
    SETTING_DISABLE_DEFENDER,
    SETTING_LOG_LEVEL,
]

# v5.4, v6.3
SETTINGS_V54 = [
    SETTING_WIPE_DRIVES,
    SETTING_PRIORITY_MODIFY,
    SETTING_ENCR_SHARE,
    SETTING_ENCR_NET_DRIVE,
    SETTING_ENCR_NET_PRIO,
    SETTING_SELF_DELETE,
    SETTING_LOG_CHECKSUM,
    SETTING_DISABLE_DEFENDER,
    SETTING_LOG_LEVEL,
    SETTING_RESERVE_MODE,
    SETTING_PERC_FOR_FILES,
    SETTING_ENCR_HID_FOLDERS,
    SETTING_DEL_LOG,
]

# v7.x
SETTINGS_V70 = [
    SETTING_WIPE_DRIVES,
    SETTING_PRIORITY_MODIFY,
    SETTING_ENCR_SHARE,
    SETTING_ENCR_NET_DRIVE,
    SETTING_GUI_MODE,
    SETTING_SELF_DELETE,
    SETTING_LOG_CHECKSUM,
    SETTING_DISABLE_DEFENDER,
    SETTING_LOG_LEVEL,
    SETTING_RESERVE_MODE,
    SETTING_PERC_FOR_FILES,
    SETTING_ENCR_HID_FOLDERS,
    SETTING_DEL_LOG,
    SETTING_APPEND_KEY_TO_EXT,
]

# Settings for versions
SETTINGS = {
  '4.0': SETTINGS_V40,
  '4.2': SETTINGS_V42,
  '4.3': SETTINGS_V43,
  '5.4': SETTINGS_V54,
  '6.3': SETTINGS_V54,
  '7.x': SETTINGS_V70,
}


NOTE_EXT = '.txt'
LOCKER_EXT = '.exe'


ENC_KEY_SIZE = 32


CONFIG_RES_TYPE = 10  # RT_RCDATA
CONFIG_RES_NAME = '1'
CONFIG_RES_ID = 1033


def find_res_entry(res_name, file_data: bytes, res_pos: int,
                   offset: int) -> int:
    """Find resource entry"""

    is_name_id = isinstance(res_name, int)
    if not is_name_id and not isinstance(res_name, str):
        return -1

    pos = res_pos + (offset & 0x7FFFFFFF)

    num_named, num_ids = struct.unpack_from('<HH', file_data, pos + 12)

    pos += 16
    if is_name_id:
        pos += num_named * 8
        num_entries = num_ids
    else:
        num_entries = num_named
        res_name = res_name.encode('UTF-16-LE')

    for i in range(num_entries):

        nm, ofs = struct.unpack_from('<LL', file_data, pos + i * 8)
        if is_name_id:
            if res_name == nm:
                return ofs
        else:
            if nm & 0x80000000 != 0:
                name_pos = res_pos + (nm & 0x7FFFFFFF)
                name_len, = struct.unpack_from('<H', file_data, name_pos)
                name_pos += 2
                if res_name == file_data[name_pos : name_pos + 2 * name_len]:
                    return ofs

    return -1


def get_pe_hdr_pos(file_data: bytes) -> int | None:
    """Get PE header position"""

    mz_sign, = struct.unpack_from('<H', file_data, 0)
    if (mz_sign != 0x5A4D):
        return None

    nt_hdr_pos, = struct.unpack_from('<L', file_data, 0x3C)

    pe_sign, = struct.unpack_from('<L', file_data, nt_hdr_pos)
    if (pe_sign != 0x00004550):
        return None

    return nt_hdr_pos


def extract_pe_res(file_data: bytes,
                   res_type, res_name, res_id) -> bytes | None:
    """Extract PE file resource"""

    # Get PE header position
    nt_hdr_pos = get_pe_hdr_pos(file_data)
    if nt_hdr_pos is None:
        return None

    # Parse PE header
    img_hdr_pos = nt_hdr_pos + 4
    num_sections, = struct.unpack_from('<H', file_data, img_hdr_pos + 2)
    opt_hdr_pos = img_hdr_pos + 0x14
    opt_hdr_size, = struct.unpack_from('<H', file_data, img_hdr_pos + 0x10)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    first_section_hdr_pos = nt_hdr_pos + nt_hdr_size
    opt_hdr_magic, = struct.unpack_from('<H', file_data, opt_hdr_pos)
    is_x64 = (opt_hdr_magic == 0x20B)

    # Directory
    dir_pos = opt_hdr_pos + 0x5C
    if is_x64:
        dir_pos += 0x10
    num_datadirs, = struct.unpack_from('<L', file_data, dir_pos)
    if num_datadirs > 16:
        num_datadirs = 16

    if num_datadirs < 3:
        return None

    # Resource directory entry
    res_rva, res_size = struct.unpack_from('<LL', file_data, dir_pos + 20)
    res_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_vsize, s_rva, s_psize, s_pos = struct.unpack_from('<4L', file_data,
                                                            pos + 8)
        if (s_pos != 0) and (res_rva >= s_rva):
            ofs = res_rva - s_rva
            if ofs + res_size <= s_psize:
                res_pos = s_pos + ofs
                break

        pos += 0x28

    if res_pos is None:
        return None

    # Find resource type entry
    ofs = find_res_entry(res_type, file_data, res_pos, 0)
    if (ofs == -1) or (ofs & 0x80000000 == 0):
        return None

    # Find resource name entry
    ofs = find_res_entry(res_name, file_data, res_pos, ofs)
    if (ofs == -1) or (ofs & 0x80000000 == 0):
        return None

    # Find resource ID entry
    ofs = find_res_entry(res_id, file_data, res_pos, ofs)
    if (ofs == -1) or (ofs & 0x80000000 != 0):
        return None

    res_data_rva, res_data_size = struct.unpack_from('<LL', file_data,
                                                     res_pos + ofs)
    res_data_pos = res_pos + (res_data_rva - res_rva)
    return file_data[res_data_pos : res_data_pos + res_data_size]


def get_pe_file_size(file_data: bytes) -> int | None:
    """Get PE file size"""

    # Get PE header position
    nt_hdr_pos = get_pe_hdr_pos(file_data)
    if nt_hdr_pos is None:
        return None

    # Parse PE header
    img_hdr_pos = nt_hdr_pos + 4
    num_sections, = struct.unpack_from('<H', file_data, img_hdr_pos + 2)
    opt_hdr_pos = img_hdr_pos + 0x14
    opt_hdr_size, = struct.unpack_from('<H', file_data, img_hdr_pos + 0x10)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    first_section_hdr_pos = nt_hdr_pos + nt_hdr_size

    pe_file_size = 0

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):
        s_psize, s_pos = struct.unpack_from('<2L', file_data, pos + 16)
        if s_pos != 0:
            pe_file_size = max(pe_file_size, s_pos + s_psize)
        pos += 0x28

    return pe_file_size


def read_uint8(data: bytes, pos: int) -> (int | None, int):
    """Read uint8"""

    if not (1 <= pos <= len(data)):
        return None, pos
    p = pos - 1
    return data[p], p


def read_uint32(data: bytes, pos: int) -> (int | None, int):
    """Read uint32"""

    if not (4 <= pos <= len(data)):
        return None, pos
    p = pos - 4
    n, = struct.unpack_from('<L', data, p)
    return n, p


def read_uint64(data: bytes, pos: int) -> (int | None, int):
    """Read uint64"""

    if not (8 <= pos <= len(data)):
        return None, pos
    p = pos - 8
    n, = struct.unpack_from('<Q', data, p)
    return n, p


def read_str(data: bytes, pos: int) -> (str | None, int):
    """Read string"""

    # Read data size
    size, p = read_uint32(data, pos)
    if (size is None) or (size > p):
        return None, pos
    p -= size
    s = data[p : p + size]
    i = s.find(0)
    if i >= 0:
        s = s[:i]
    return s.decode(), p


def read_blob_data(data: bytes, pos: int) -> (bytes | None, int):
    """Read BLOB data"""

    # Read data size
    size, p = read_uint64(data, pos)
    if (size is None) or (size > p):
        return None, pos
    p -= size
    return data[p : p + size], p


def mkdirs(dir: str) -> None:
    """Create directory hierarchy"""

    try:
        os.makedirs(dir)

    except OSError as exception:
        if (exception.errno != errno.EEXIST):
            raise


def save_data_to_file(filename: str, data: bytes):
    """Save data to file"""
    with io.open(filename, 'wb') as f:
        f.write(data)


def save_text_to_file(filename: str, s: str):
    """Save text to file"""
    with io.open(filename, 'wt', encoding='utf-8') as f:
        f.write(s)


#
# Main
#
if not (2 <= len(sys.argv) <= 3):
    print('Usage:', sys.argv[0], 'filename [-v<VER>]')
    print()
    print('supported versions:', ', '.join(SETTINGS.keys()))
    print('default version:', DEFAULT_VER)
    sys.exit(0)

filename = sys.argv[1]

# Version
ver = DEFAULT_VER
if len(sys.argv) == 3:
    ver_arg = sys.argv[2]
    if ver_arg.startswith('-v'):
        ver = ver_arg[len('-v'):]

settings = SETTINGS.get(ver)
if settings is None:
    print('Error: Unknown version.')
    sys.exit(1)

print('version:', ver)

with io.open(filename, 'rb') as f:
    file_data = f.read()

# Extract encrypted configuration data from resources
cfg_data = extract_pe_res(file_data, CONFIG_RES_TYPE, CONFIG_RES_NAME,
                          CONFIG_RES_ID)
if not cfg_data:

    # Try to extract encrypted configuration data from overlay
    pe_file_size = get_pe_file_size(file_data)
    if pe_file_size >= len(file_data):
        print('Error: Configuration data not found.')
        sys.exit(1)

    cfg_data = file_data[pe_file_size:]

# Decrypt configuration data
cfg_data = bytearray(cfg_data)
for i in range(len(cfg_data)):
    cfg_data[i] ^= 0xFF
cfg_data = bytes(cfg_data)

# Create destination directory
dest_dir = filename + '.cfg/'
mkdirs(dest_dir)

print('cfg data size: %d' % len(cfg_data))

save_data_to_file(dest_dir + 'cfg_data.bin', cfg_data)

ok = False
ransom_note = None
ransom_note_name = 'ransom_note.txt'
settings_data = None

pos = len(cfg_data)

for fld_name, fld_type in FIELDS:

    if fld_type == FIELD_STR:

        # Read string
        s, pos = read_str(cfg_data, pos)
        if s is None:
            break

        if s:
            if fld_name == FIELD_NOTE_NAME:
                s += NOTE_EXT
                ransom_note_name = s
            if fld_name == FIELD_LOCKER_NAME:
                s += LOCKER_EXT
        print(fld_name + (': \"%s\"' % s))

    elif fld_type == FIELD_TEXT:

        # Read string
        text, pos = read_str(cfg_data, pos)
        if text is None:
            break

        if fld_name == FIELD_NOTE:
            ransom_note = text
        else:
            save_text_to_file(dest_dir + fld_name + '.txt', text)
            print(fld_name, 'saved to file.')

    elif fld_type == FIELD_UINT8:

        # Read uint8
        n, pos = read_uint8(cfg_data, pos)
        if n is None:
            break

        print(fld_name + ':', n)

    elif fld_type == FIELD_UINT32:

        # Read uint32
        n, pos = read_uint32(cfg_data, pos)
        if n is None:
            break

        print(fld_name + ':', n)

    elif fld_type == FIELD_SETTINGS:

        # Settings
        print('settings:')

        for stg_name, stg_type in settings:

            v, pos = read_uint8(cfg_data, pos)
            if v is None:
                break

            if stg_type == SETTING_BOOL:
                v = 'yes' if (v != 0) else 'no'
            else:
                if stg_name == SETTING_RESERVE_MODE[0]:
                    m = RESERVE_MODES.get(v)
                    if m is not None:
                        v = m
            print('  ' + stg_name + ':', v)

    elif fld_type == FIELD_KEYARRAY:

        # Read BLOB data
        key_array, pos = read_blob_data(cfg_data, pos)
        if not key_array:
            break

        num_keys, rem = divmod(len(key_array), ENC_KEY_SIZE)
        if rem != 0:
            print('Error: Invalid key array.')

        print('keys:', num_keys)
        save_data_to_file(dest_dir + fld_name + '.bin', key_array)
        print('key array saved to file.')

    else:
        break

else:
    ok = True

# Save ransom note
if ransom_note:
    save_text_to_file(dest_dir + ransom_note_name, ransom_note)
    print('ransom note saved to file.')

if not ok:
    print('Error: Invalid configuration data.')
    sys.exit(1)

print('garbage size:', pos)
