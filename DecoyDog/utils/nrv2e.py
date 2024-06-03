# Released under the MIT License
#
# Copyright (c) Hackumo (https://github.com/hackumo)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import struct


class BitStream:
    def __init__(self, buffer: bytearray):
        self.offset = 0
        self.count = 0
        self.bits_buffer = 0
        self.buffer = buffer

    def read_bit(self) -> int:
        if self.count == 0:
            self.count = 31
            self.bits_buffer = struct.unpack('<L', self.buffer[self.offset:self.offset + 4])[0]
            self.offset += 4
        else:
            self.count -= 1
        return (self.bits_buffer >> self.count) & 1

    def read_byte(self) -> int:
        byte = self.buffer[self.offset]
        self.offset += 1
        return byte

    def empty(self) -> bool:
        return self.offset >= len(self.buffer) and self.count == 0


def decompress(encoded: bytearray) -> bytearray:
    output = bytearray()
    stream = BitStream(encoded)

    last_offset = 1

    while not stream.empty():
        if stream.read_bit() == 1:  # Copy next byte
            output.append(stream.read_byte())
        else:  # Compression
            offset = 2 + stream.read_bit()
            while stream.read_bit() == 0:
                offset = ((offset - 1) << 1) + stream.read_bit()
                offset = (offset << 1) + stream.read_bit()

            if offset == 2:  # Use last offset and read length from bit
                offset = last_offset
                length = stream.read_bit()
            else:  # Read length
                offset = ((offset - 3) << 8) + stream.read_byte()
                if offset >= 0xffffffff:
                    break
                length = (offset ^ 1) & 1  # One bit of length in offset
                offset = (offset >> 1) + 1
                last_offset = offset

            if length:
                length = 1 + stream.read_bit()
            elif stream.read_bit() == 1:
                length = 3 + stream.read_bit()
            else:
                length = 2 + stream.read_bit()
                while stream.read_bit() == 0:
                    length = (length << 1) + stream.read_bit()
                length += 3

            if offset > 0x500:
                length += 1

            for i in range(length + 1):
                output.append(output[-offset])

    return output
