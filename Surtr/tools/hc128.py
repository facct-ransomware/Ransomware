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

import struct


BLOCK_SIZE = 64


MASK32 = 0xFFFFFFFF

ror32 = lambda v, s: ((v & MASK32) >> s) | ((v << (32 - s)) & MASK32)

f1 = lambda x: ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3)
f2 = lambda x: ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10)


def _bytes_to_ui32(data):
    """Convert a bytearray to array of ui32 sized ints"""

    return list(struct.unpack('<' + str(len(data) // 4) + 'L', data))


class HC128(object):

    """Pure python implementation of HC-128 cipher"""

    @staticmethod
    def h1(T, x):
        """h1 function"""

        a = x & 0xFF
        c = (x >> 16) & 0xFF
        return (T[512 + a] + T[512 + 256 + c]) & MASK32


    @staticmethod
    def h2(T, x):
        """h2 function"""

        a = x & 0xFF
        c = (x >> 16) & 0xFF
        return (T[a] + T[256 + c]) & MASK32


    @staticmethod
    def step_P(T, X, u, v, a, b, c, d):
        """One step of HC-128, update P and generate 32 bits keystream"""

        tem0 = ror32(T[v], 23)
        tem1 = ror32(X[c], 10)
        tem2 = ror32(X[b], 8)
        tem3 = HC128.h1(T, X[d])
        T[u] = (T[u] + tem2 + (tem0 ^ tem1)) & MASK32
        X[a] = T[u]
        return (tem3 ^ T[u])


    @staticmethod
    def step_Q(T, Y, u, v, a, b, c, d):
        """One step of HC-128, update Q and generate 32 bits keystream"""

        tem0 = ror32(T[v], 32 - 23)
        tem1 = ror32(Y[c], 32 - 10)
        tem2 = ror32(Y[b], 32 - 8)
        tem3 = HC128.h2(T, Y[d])
        T[u] = (T[u] + tem2 + (tem0 ^ tem1)) & MASK32
        Y[a] = T[u]
        return (tem3 ^ T[u])


    @staticmethod
    def update_P(T, X, u, v, a, b, c, d):
        """Update table P"""

        tem0 = ror32(T[v], 23)
        tem1 = ror32(X[c], 10)
        tem2 = ror32(X[b], 8)
        tem3 = HC128.h1(T, X[d])
        T[u] = ((T[u] + tem2 + (tem0 ^ tem1)) ^ tem3) & MASK32
        X[a] = T[u]


    @staticmethod
    def update_Q(T, Y, u, v, a, b, c, d):
        """One step of HC-128, update Q and generate 32 bits keystream"""

        tem0 = ror32(T[v], 32 - 23)
        tem1 = ror32(Y[c], 32 - 10)
        tem2 = ror32(Y[b], 32 - 8)
        tem3 = HC128.h2(T, Y[d])
        T[u] = ((T[u] + tem2 + (tem0 ^ tem1)) ^ tem3) & MASK32
        Y[a] = T[u]


    def _setup_update(self):
        """But use the outputs to update P and Q. Each time 16 steps"""

        cc = self.counter1024 & 0x1FF
        dd = (cc + 16) & 0x1FF

        if self.counter1024 < 512:

            HC128.update_P(self.T, self.X, cc+ 0, cc+ 1,  0, 6,13, 4)
            HC128.update_P(self.T, self.X, cc+ 1, cc+ 2,  1, 7,14, 5)
            HC128.update_P(self.T, self.X, cc+ 2, cc+ 3,  2, 8,15, 6)
            HC128.update_P(self.T, self.X, cc+ 3, cc+ 4,  3, 9, 0, 7)
            HC128.update_P(self.T, self.X, cc+ 4, cc+ 5,  4,10, 1, 8)
            HC128.update_P(self.T, self.X, cc+ 5, cc+ 6,  5,11, 2, 9)
            HC128.update_P(self.T, self.X, cc+ 6, cc+ 7,  6,12, 3,10)
            HC128.update_P(self.T, self.X, cc+ 7, cc+ 8,  7,13, 4,11)
            HC128.update_P(self.T, self.X, cc+ 8, cc+ 9,  8,14, 5,12)
            HC128.update_P(self.T, self.X, cc+ 9, cc+10,  9,15, 6,13)
            HC128.update_P(self.T, self.X, cc+10, cc+11, 10, 0, 7,14)
            HC128.update_P(self.T, self.X, cc+11, cc+12, 11, 1, 8,15)
            HC128.update_P(self.T, self.X, cc+12, cc+13, 12, 2, 9, 0)
            HC128.update_P(self.T, self.X, cc+13, cc+14, 13, 3,10, 1)
            HC128.update_P(self.T, self.X, cc+14, cc+15, 14, 4,11, 2)
            HC128.update_P(self.T, self.X, cc+15, dd+ 0, 15, 5,12, 3)

        else:

            cc += 512
            dd += 512
            HC128.update_Q(self.T, self.Y, cc+ 0, cc+ 1,  0, 6,13, 4)
            HC128.update_Q(self.T, self.Y, cc+ 1, cc+ 2,  1, 7,14, 5)
            HC128.update_Q(self.T, self.Y, cc+ 2, cc+ 3,  2, 8,15, 6)
            HC128.update_Q(self.T, self.Y, cc+ 3, cc+ 4,  3, 9, 0, 7)
            HC128.update_Q(self.T, self.Y, cc+ 4, cc+ 5,  4,10, 1, 8)
            HC128.update_Q(self.T, self.Y, cc+ 5, cc+ 6,  5,11, 2, 9)
            HC128.update_Q(self.T, self.Y, cc+ 6, cc+ 7,  6,12, 3,10)
            HC128.update_Q(self.T, self.Y, cc+ 7, cc+ 8,  7,13, 4,11)
            HC128.update_Q(self.T, self.Y, cc+ 8, cc+ 9,  8,14, 5,12)
            HC128.update_Q(self.T, self.Y, cc+ 9, cc+10,  9,15, 6,13)
            HC128.update_Q(self.T, self.Y, cc+10, cc+11, 10, 0, 7,14)
            HC128.update_Q(self.T, self.Y, cc+11, cc+12, 11, 1, 8,15)
            HC128.update_Q(self.T, self.Y, cc+12, cc+13, 12, 2, 9, 0)
            HC128.update_Q(self.T, self.Y, cc+13, cc+14, 13, 3,10, 1)
            HC128.update_Q(self.T, self.Y, cc+14, cc+15, 14, 4,11, 2)
            HC128.update_Q(self.T, self.Y, cc+15, dd+ 0, 15, 5,12, 3)

        self.counter1024 = (self.counter1024 + 16) & 0x3FF


    def __init__(self, key, iv):
        """Initialize key and IV"""

        if (len(key) != 16) and (len(key) != 32):
            raise ValueError('Key must be 16 or 32 bytes long')

        if (len(iv) != 16) and (len(iv) != 32):
            raise ValueError('IV must be 16 or 32 bytes long')

        k = _bytes_to_ui32(key)
        if len(k) == 4:
            k += k

        v = _bytes_to_ui32(iv)
        if len(v) == 4:
            v += v

        self.T = [0] * 1024
        self.X = [0] * 16
        self.Y = [0] * 16
        self.counter1024 = 0
        self.keystream = None
        self.block_pos = 0

        # Expand the key and IV into the table T
        # (expand the key and IV into the table P and Q)
        for i in range(8):
            self.T[i] = k[i]
            self.T[8 + i] = v[i]
        for i in range(16, 256 + 16, 1):
            self.T[i] = (f2(self.T[i - 2]) + self.T[i - 7] +
                         f1(self.T[i - 15]) + self.T[i - 16] + i) & MASK32
        for i in range(16):
            self.T[i] = self.T[256 + i]
        for i in range(16, 1024, 1):
            self.T[i] = (f2(self.T[i - 2]) + self.T[i - 7] +
                         f1(self.T[i - 15]) + self.T[i - 16] +
                         256 + i) & MASK32

        # Initialize X and Y
        for i in range(16):
            self.X[i] = self.T[512 - 16 + i]
        for i in range(16):
            self.Y[i] = self.T[512 + 512 - 16 + i]

        # Run the cipher 1024 steps before generating the output
        for i in range(64):
            self._setup_update()


    def _generate_keystream(self):
        """16 steps of HC-128, generate 512 bits keystream"""

        ks = [0] * 16

        cc = self.counter1024 & 0x1FF
        dd = (cc + 16) & 0x1FF

        if self.counter1024 < 512:

            ks[ 0] = HC128.step_P(self.T, self.X, cc+ 0, cc+ 1,  0, 6,13, 4)
            ks[ 1] = HC128.step_P(self.T, self.X, cc+ 1, cc+ 2,  1, 7,14, 5)
            ks[ 2] = HC128.step_P(self.T, self.X, cc+ 2, cc+ 3,  2, 8,15, 6)
            ks[ 3] = HC128.step_P(self.T, self.X, cc+ 3, cc+ 4,  3, 9, 0, 7)
            ks[ 4] = HC128.step_P(self.T, self.X, cc+ 4, cc+ 5,  4,10, 1, 8)
            ks[ 5] = HC128.step_P(self.T, self.X, cc+ 5, cc+ 6,  5,11, 2, 9)
            ks[ 6] = HC128.step_P(self.T, self.X, cc+ 6, cc+ 7,  6,12, 3,10)
            ks[ 7] = HC128.step_P(self.T, self.X, cc+ 7, cc+ 8,  7,13, 4,11)
            ks[ 8] = HC128.step_P(self.T, self.X, cc+ 8, cc+ 9,  8,14, 5,12)
            ks[ 9] = HC128.step_P(self.T, self.X, cc+ 9, cc+10,  9,15, 6,13)
            ks[10] = HC128.step_P(self.T, self.X, cc+10, cc+11, 10, 0, 7,14)
            ks[11] = HC128.step_P(self.T, self.X, cc+11, cc+12, 11, 1, 8,15)
            ks[12] = HC128.step_P(self.T, self.X, cc+12, cc+13, 12, 2, 9, 0)
            ks[13] = HC128.step_P(self.T, self.X, cc+13, cc+14, 13, 3,10, 1)
            ks[14] = HC128.step_P(self.T, self.X, cc+14, cc+15, 14, 4,11, 2)
            ks[15] = HC128.step_P(self.T, self.X, cc+15, dd+ 0, 15, 5,12, 3)

        else:

            cc += 512
            dd += 512
            ks[ 0] = HC128.step_Q(self.T, self.Y, cc+ 0, cc+ 1,  0, 6,13, 4)
            ks[ 1] = HC128.step_Q(self.T, self.Y, cc+ 1, cc+ 2,  1, 7,14, 5)
            ks[ 2] = HC128.step_Q(self.T, self.Y, cc+ 2, cc+ 3,  2, 8,15, 6)
            ks[ 3] = HC128.step_Q(self.T, self.Y, cc+ 3, cc+ 4,  3, 9, 0, 7)
            ks[ 4] = HC128.step_Q(self.T, self.Y, cc+ 4, cc+ 5,  4,10, 1, 8)
            ks[ 5] = HC128.step_Q(self.T, self.Y, cc+ 5, cc+ 6,  5,11, 2, 9)
            ks[ 6] = HC128.step_Q(self.T, self.Y, cc+ 6, cc+ 7,  6,12, 3,10)
            ks[ 7] = HC128.step_Q(self.T, self.Y, cc+ 7, cc+ 8,  7,13, 4,11)
            ks[ 8] = HC128.step_Q(self.T, self.Y, cc+ 8, cc+ 9,  8,14, 5,12)
            ks[ 9] = HC128.step_Q(self.T, self.Y, cc+ 9, cc+10,  9,15, 6,13)
            ks[10] = HC128.step_Q(self.T, self.Y, cc+10, cc+11, 10, 0, 7,14)
            ks[11] = HC128.step_Q(self.T, self.Y, cc+11, cc+12, 11, 1, 8,15)
            ks[12] = HC128.step_Q(self.T, self.Y, cc+12, cc+13, 12, 2, 9, 0)
            ks[13] = HC128.step_Q(self.T, self.Y, cc+13, cc+14, 13, 3,10, 1)
            ks[14] = HC128.step_Q(self.T, self.Y, cc+14, cc+15, 14, 4,11, 2)
            ks[15] = HC128.step_Q(self.T, self.Y, cc+15, dd+ 0, 15, 5,12, 3)

        self.counter1024 = (self.counter1024 + 16) & 0x3FF

        self.keystream = struct.pack('<16L', *ks)


    @staticmethod
    def _xor_block(block, ks, block_pos=0):
        """XOR block"""

        out = bytearray(block)
        for i in range(len(out)):
            out[i] ^= ks[i + block_pos]
        return bytes(out)


    def process_bytes(self, data):
        """Encrypt/decrypt the data"""

        out = b''

        block_pos = self.block_pos

        pos = 0

        if block_pos != 0:

            # Encrypt the first unaligned block
            rlen = min(BLOCK_SIZE - block_pos, len(data))
            out += HC128._xor_block(data[:rlen], self.keystream, block_pos)
            block_pos += rlen
            if block_pos == BLOCK_SIZE:
                block_pos = 0
            pos = rlen

        if pos < len(data):

            # Encrypt blocks
            for block in (data[i : i + BLOCK_SIZE] for i
                          in range(pos, len(data), BLOCK_SIZE)):

                self._generate_keystream()
                out += HC128._xor_block(block, self.keystream)

            block_pos = (len(data) - pos) % BLOCK_SIZE

        self.block_pos = block_pos

        return out
